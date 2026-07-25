import json
import base64
import hmac
import hashlib
import struct
import time
from datetime import datetime, timezone, timedelta
from typing import Literal
from urllib.parse import urlparse, parse_qs

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/auth", tags=["auth-testing"])


class JWTToken(BaseModel):
    token: str


class JWTDecodedResponse(BaseModel):
    header: dict
    payload: dict
    signature: str
    valid: bool


class JWTBruteRequest(BaseModel):
    token: str
    wordlist: list[str] = []


class JWTCrackRequest(BaseModel):
    token: str
    secret: str


class JWTAnalyzeResponse(BaseModel):
    header: dict
    payload: dict
    signature: str
    issues: list[dict]


class OAuthDebugRequest(BaseModel):
    redirect_uri: str | None = None
    client_id: str | None = None
    scope: str | None = None
    response_type: str | None = None
    state: str | None = None
    raw_url: str | None = None


COMMON_HMAC_SECRETS = [
    "secret", "password", "123456", "admin", "jwt_secret",
    "changeme", "test", "key", "token", "pass", "qwerty",
    "abc123", "letmein", "monkey", "dragon", "master",
    "supersecret", "mysecret", "mykey", "default",
    "1234567890", "123456789", "abcdef", "111111",
]


def _b64_decode(data: str) -> dict | None:
    try:
        padded = data + "=" * (4 - len(data) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _decode_jwt(token: str) -> tuple[dict | None, dict | None, str | None]:
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    signature = parts[2]
    return header, payload, signature


def _b64_encode(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _hmac_sign(header_b64: str, payload_b64: str, secret: str, alg: str = "HS256") -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    if alg == "HS256":
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(secret.encode(), msg, hashlib.sha384).digest()
    elif alg == "HS512":
        sig = hmac.new(secret.encode(), msg, hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


@router.post("/jwt/decode", response_model=JWTDecodedResponse)
async def jwt_decode(body: JWTToken):
    header, payload, signature = _decode_jwt(body.token)
    if not header or not payload:
        raise HTTPException(400, detail="Invalid JWT token")
    return JWTDecodedResponse(
        header=header,
        payload=payload,
        signature=signature or "",
        valid=True,
    )


@router.post("/jwt/analyze", response_model=JWTAnalyzeResponse)
async def jwt_analyze(body: JWTToken):
    header, payload, signature = _decode_jwt(body.token)
    if not header or not payload:
        raise HTTPException(400, detail="Invalid JWT token")

    issues = []
    alg = header.get("alg", "")

    if alg == "none":
        issues.append({
            "severity": "critical",
            "title": "None Algorithm",
            "description": "JWT uses 'none' algorithm, allowing signature bypass.",
            "remediation": "Reject tokens with alg: none on the server.",
        })

    if alg in ("HS256", "HS384", "HS512"):
        parts = body.token.split(".")
        header_b64, payload_b64 = parts[0], parts[1]
        for secret in COMMON_HMAC_SECRETS:
            expected_sig = _hmac_sign(header_b64, payload_b64, secret, alg)
            if expected_sig == signature:
                issues.append({
                    "severity": "critical",
                    "title": "Weak HMAC Secret",
                    "description": f"JWT signed with weak/guessable secret: '{secret}'.",
                    "remediation": "Use a strong, randomly generated secret of at least 256 bits.",
                })
                break

    if "kid" in header:
        kid = header["kid"]
        if kid.startswith("http://") or kid.startswith("https://") or kid.startswith("file://"):
            issues.append({
                "severity": "high",
                "title": "KID Injection (Path Traversal)",
                "description": f"The kid header contains a URI: '{kid}'. May allow path traversal or SSRF.",
                "remediation": "Validate that kid references a known key, not an arbitrary URI.",
            })
        if ".." in kid or kid.startswith("/"):
            issues.append({
                "severity": "high",
                "title": "KID Path Traversal",
                "description": f"The kid header contains path traversal characters: '{kid}'.",
                "remediation": "Sanitize kid parameter to prevent directory traversal.",
            })

    if "jku" in header:
        jku = header["jku"]
        issues.append({
            "severity": "high",
            "title": "JKU Header Present",
            "description": f"JKU header set to '{jku}'. May allow SSRF or untrusted key injection.",
            "remediation": "Remove JKU header or validate the URL against an allowlist.",
        })

    if alg == "RS256" and header.get("jwk"):
        issues.append({
            "severity": "high",
            "title": "Embedded JWK (Algorithm Confusion)",
            "description": "Token includes embedded JWK. May enable algorithm confusion if server trusts embedded keys.",
            "remediation": "Do not trust embedded JWKs for signature verification.",
        })

    if "alg" in header and payload.get("alg"):
        issues.append({
            "severity": "medium",
            "title": "Algorithm Confusion Risk",
            "description": "Algorithm specified in both header and payload. Potential confusion attack.",
            "remediation": "Ensure server validates algorithm strictly and does not fall back.",
        })

    exp = payload.get("exp")
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        if exp_dt < datetime.now(timezone.utc):
            issues.append({
                "severity": "info",
                "title": "Expired Token",
                "description": f"Token expired at {exp_dt.isoformat()}.",
                "remediation": "Issue new tokens with a future expiration.",
            })

    return JWTAnalyzeResponse(
        header=header,
        payload=payload,
        signature=signature or "",
        issues=issues,
    )


@router.post("/jwt/brute")
async def jwt_brute(body: JWTBruteRequest):
    parts = body.token.split(".")
    if len(parts) != 3:
        raise HTTPException(400, detail="Invalid JWT token")

    header_b64, payload_b64, signature = parts[0], parts[1], parts[2]
    header = _b64_decode(header_b64)
    if not header:
        raise HTTPException(400, detail="Cannot decode JWT header")

    alg = header.get("alg", "HS256")
    if alg not in ("HS256", "HS384", "HS512"):
        raise HTTPException(400, detail=f"Algorithm '{alg}' is not HMAC-based, cannot brute force")

    wordlist = body.wordlist or COMMON_HMAC_SECRETS
    found = None

    for word in wordlist:
        expected_sig = _hmac_sign(header_b64, payload_b64, word, alg)
        if expected_sig == signature:
            found = word
            break

    return {
        "found": found is not None,
        "secret": found,
        "algorithm": alg,
        "attempts": len(wordlist),
    }


@router.post("/jwt/crack")
async def jwt_crack(body: JWTCrackRequest):
    parts = body.token.split(".")
    if len(parts) != 3:
        raise HTTPException(400, detail="Invalid JWT token")

    header_b64, payload_b64, signature = parts[0], parts[1], parts[2]
    header = _b64_decode(header_b64)
    if not header:
        raise HTTPException(400, detail="Cannot decode JWT header")

    alg = header.get("alg", "HS256")
    if alg not in ("HS256", "HS384", "HS512"):
        raise HTTPException(400, detail="Cannot verify non-HMAC algorithm")

    expected_sig = _hmac_sign(header_b64, payload_b64, body.secret, alg)
    valid = expected_sig == signature

    return {
        "valid": valid,
        "algorithm": alg,
        "provided_secret": body.secret,
    }


@router.post("/oauth/debug")
async def oauth_debug(body: OAuthDebugRequest):
    issues = []

    raw_url = body.raw_url
    params = {}

    if raw_url:
        parsed = urlparse(raw_url)
        qs = parse_qs(parsed.query)
        for k, v in qs.items():
            params[k] = v[0] if len(v) == 1 else v

    if body.redirect_uri:
        params["redirect_uri"] = body.redirect_uri
    if body.client_id:
        params["client_id"] = body.client_id
    if body.scope:
        params["scope"] = body.scope
    if body.response_type:
        params["response_type"] = body.response_type
    if body.state:
        params["state"] = body.state

    redirect_uri = params.get("redirect_uri", "")
    client_id = params.get("client_id", "")
    scope = params.get("scope", "")
    response_type = params.get("response_type", "")

    if redirect_uri:
        parsed_uri = urlparse(redirect_uri)
        if parsed_uri.scheme != "https":
            issues.append({
                "severity": "high",
                "title": "Non-HTTPS Redirect URI",
                "description": "Redirect URI does not use HTTPS, allowing interception of auth codes/tokens.",
                "remediation": "Use HTTPS for all redirect URIs.",
            })
        if "openid" in scope or "oidc" in scope.lower():
            issues.append({
                "severity": "info",
                "title": "OpenID Connect Scope Detected",
                "description": "Scope includes OpenID Connect, adding identity layer to OAuth.",
            })
        if "*" in redirect_uri or redirect_uri.endswith("*"):
            issues.append({
                "severity": "critical",
                "title": "Wildcard Redirect URI",
                "description": "Redirect URI contains wildcard, enabling open redirect attacks.",
                "remediation": "Use exact-match redirect URIs without wildcards.",
            })

    if response_type:
        if "," in response_type or " " in response_type:
            types = response_type.replace(",", " ").split()
            if "code" in types and "token" in types:
                issues.append({
                    "severity": "high",
                    "title": "Hybrid Response Type (code + token)",
                    "description": "Response type mixes code and token, potential for access token leakage via referrer headers.",
                    "remediation": "Avoid hybrid flows unless absolutely necessary.",
                })
        if response_type == "token":
            issues.append({
                "severity": "medium",
                "title": "Implicit Flow (token response_type)",
                "description": "Implicit flow returns access token in URL fragment, vulnerable to leakage.",
                "remediation": "Use authorization code flow with PKCE instead.",
            })

    if not state:
        issues.append({
            "severity": "medium",
            "title": "Missing State Parameter",
            "description": "No state parameter found. CSRF attack against OAuth flow is possible.",
            "remediation": "Include a cryptographically random state parameter.",
        })

    if not client_id:
        issues.append({
            "severity": "low",
            "title": "Missing Client ID",
            "description": "No client_id parameter found in request.",
        })

    if "localhost" in redirect_uri or "127.0.0.1" in redirect_uri:
        issues.append({
            "severity": "low",
            "title": "Localhost Redirect URI",
            "description": "Redirect URI points to localhost; may be used for native app impersonation attacks.",
            "remediation": "Use custom URI schemes for native apps instead.",
        })

    return {
        "parsed_params": params,
        "issues": issues,
        "misconfigurations_found": len(issues),
    }
