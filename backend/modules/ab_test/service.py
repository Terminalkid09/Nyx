"""Multi-identity replay: run one request as two users and diff the answers.

The question this answers is the one a single-identity scanner cannot: "does
user B get A's data?" Send the same request with two credential sets (and
optionally with none at all) and compare what comes back.

The classifier is pure and lives next to the transport, the same shape as the
exploit verifier: ``classify`` never touches the network, so the interesting
logic is unit-testable, while ``run_comparison`` performs the three requests and
feeds it.

Deliberate limits: three sequential requests, no redirect following (a redirect
would silently replay with whichever cookies the client kept), 64 KB of body
compared, and no finding is written. An identical response across identities is
a *signal* to look, not a confirmed vulnerability: two tenants can legitimately
return the same public page.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import httpx

from modules.auto_exploit.verifier import body_similarity

MAX_BODY_CHARS = 64 * 1024
PREVIEW_CHARS = 400
SAME_BODY_THRESHOLD = 0.95
MOSTLY_SAME_THRESHOLD = 0.70
DENIED_STATUSES = frozenset({401, 403, 404})

# Tokens a server rotates on every response (CSRF, nonces, session ids, uuids)
# would otherwise make two identical pages look different.
_VOLATILE = re.compile(r"\b(?:[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,}|\d{6,})\b")


@dataclass(frozen=True)
class Identity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Sample:
    label: str
    status: int = 0
    body: str = ""
    length: int = 0
    content_type: str = ""
    location: str | None = None
    challenge: str | None = None
    time_ms: int = 0
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return 200 <= self.status < 300

    @property
    def denied(self) -> bool:
        return self.status in DENIED_STATUSES

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "status": self.status,
            "length": self.length,
            "content_type": self.content_type,
            "location": self.location,
            "challenge": self.challenge,
            "time_ms": self.time_ms,
            "error": self.error,
            "body_preview": (self.body or "")[:PREVIEW_CHARS],
        }


@dataclass
class DiffResult:
    verdict: str
    severity: str | None
    confidence: float
    similarity: float
    signals: list[str]
    samples: list[Sample]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "similarity": round(self.similarity, 4),
            "signals": list(self.signals),
            "samples": [sample.to_dict() for sample in self.samples],
        }


def normalise(body: str) -> str:
    """Replace per-response tokens so two identical pages compare equal."""
    return _VOLATILE.sub("<token>", body or "")


def _similarity(a: Sample, b: Sample) -> float:
    return body_similarity(normalise(a.body)[:MAX_BODY_CHARS], normalise(b.body)[:MAX_BODY_CHARS])


def classify(first: Sample, second: Sample, anonymous: Sample | None = None) -> DiffResult:
    """Compare the two identities (and the anonymous request, when present)."""
    samples = [first, second] + ([anonymous] if anonymous is not None else [])

    if first.error or second.error:
        return DiffResult(
            verdict="inconclusive",
            severity=None,
            confidence=0.0,
            similarity=0.0,
            signals=["request_failed"],
            samples=samples,
        )

    similarity = _similarity(first, second)
    signals: list[str] = []

    if first.succeeded and second.succeeded:
        if similarity >= SAME_BODY_THRESHOLD:
            verdict, severity = "suspected_idor", "high"
            confidence = similarity
            signals = ["both_identities_succeeded", "same_body"]
        elif similarity >= MOSTLY_SAME_THRESHOLD:
            verdict, severity = "review", "medium"
            confidence = similarity
            signals = ["both_identities_succeeded", "mostly_same_body"]
        else:
            verdict, severity = "isolated", None
            confidence = 1.0 - similarity
            signals = ["both_identities_succeeded", "different_body"]
    elif first.succeeded and second.denied:
        verdict, severity = "isolated", None
        confidence = 0.9
        signals = ["second_identity_denied"]
    elif first.denied and second.succeeded:
        verdict, severity = "review", "medium"
        confidence = 0.6
        signals = ["first_identity_denied"]
    elif first.denied and second.denied:
        verdict, severity = "inconclusive", None
        confidence = 0.2
        signals = ["no_identity_has_access"]
    else:
        verdict, severity = "inconclusive", None
        confidence = 0.2
        signals = ["unexpected_status"]

    if anonymous is not None and not anonymous.error:
        if anonymous.succeeded and first.succeeded:
            anonymous_similarity = _similarity(anonymous, first)
            if anonymous_similarity >= SAME_BODY_THRESHOLD:
                verdict, severity = "unauthenticated_access", "high"
                confidence = max(confidence, anonymous_similarity)
                signals.append("anonymous_sees_the_same_body")

    if first.length != second.length:
        signals.append("length_differs")

    return DiffResult(
        verdict=verdict,
        severity=severity,
        confidence=min(confidence, 1.0),
        similarity=similarity,
        signals=signals,
        samples=samples,
    )


def _identity_headers(base: dict[str, str], identity: Identity) -> dict[str, str]:
    merged = dict(base or {})
    merged.update(identity.headers or {})
    return merged


def _anonymous_headers(base: dict[str, str], identities: tuple[Identity, ...]) -> dict[str, str]:
    """Base headers minus anything an identity used to authenticate."""
    strip = {name.lower() for identity in identities for name in identity.headers}
    return {name: value for name, value in (base or {}).items() if name.lower() not in strip}


async def _send(
    client: httpx.AsyncClient,
    label: str,
    request: dict,
    headers: dict[str, str],
) -> Sample:
    started = time.monotonic()
    try:
        response = await client.request(
            method=request.get("method", "GET"),
            url=request["url"],
            headers=headers,
            content=request.get("body"),
        )
    except Exception as exc:  # noqa: BLE001 — a failed leg is a result, not a crash
        return Sample(label=label, error=str(exc), time_ms=int((time.monotonic() - started) * 1000))
    return Sample(
        label=label,
        status=response.status_code,
        body=response.text,
        length=len(response.content or b""),
        content_type=response.headers.get("content-type", ""),
        location=response.headers.get("location"),
        challenge=response.headers.get("www-authenticate"),
        time_ms=int((time.monotonic() - started) * 1000),
    )


async def run_comparison(
    request: dict,
    identity_a: Identity,
    identity_b: Identity,
    anonymous: bool = True,
    client: httpx.AsyncClient | None = None,
) -> DiffResult:
    """Send the request once per identity (plus anonymous) and classify."""
    from core.roe import pace

    base_headers = request.get("headers") or {}
    owned = client is None
    if owned:
        client = httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False)
    try:
        await pace(request["url"])
        first = await _send(client, identity_a.name, request, _identity_headers(base_headers, identity_a))
        await pace(request["url"])
        second = await _send(client, identity_b.name, request, _identity_headers(base_headers, identity_b))
        anon_sample: Sample | None = None
        if anonymous:
            await pace(request["url"])
            anon_sample = await _send(
                client,
                "anonymous",
                request,
                _anonymous_headers(base_headers, (identity_a, identity_b)),
            )
    finally:
        if owned:
            await client.aclose()
    return classify(first, second, anon_sample)
