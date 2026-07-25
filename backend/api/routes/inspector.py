from fastapi import APIRouter
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qs
import re
import json

router = APIRouter(prefix="/api/inspector", tags=["inspector"])


class RequestData(BaseModel):
    method: str = "GET"
    url: str = ""
    headers: dict = {}
    body: str | None = None


class ResponseData(BaseModel):
    status_code: int = 200
    headers: dict = {}
    body: str | None = None


class InspectRequest(BaseModel):
    request: RequestData
    response: ResponseData | None = None


class ParsedParam(BaseModel):
    name: str
    value: str
    suspicious: bool = False


class CookieInfo(BaseModel):
    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    secure: bool = False
    http_only: bool = False


class AnalyzeRequestResult(BaseModel):
    parsed_params: list[ParsedParam]
    cookies: list[CookieInfo]
    content_type: str
    body_size: int
    param_count: int
    suspicious_params: list[ParsedParam]
    headers_count: int
    has_body: bool


class SecurityHeaders(BaseModel):
    content_security_policy: str | None = None
    x_content_type_options: str | None = None
    x_frame_options: str | None = None
    strict_transport_security: str | None = None
    x_xss_protection: str | None = None


class CacheHeaders(BaseModel):
    cache_control: str | None = None
    pragma: str | None = None
    expires: str | None = None


class AnalyzeResponseResult(BaseModel):
    content_type: str
    content_length: int
    cookies_set: list[CookieInfo]
    security_headers: SecurityHeaders
    cache_headers: CacheHeaders
    server_info: str
    suspicious_content: list[str]


class InspectResult(BaseModel):
    request_analysis: AnalyzeRequestResult | None = None
    response_analysis: AnalyzeResponseResult | None = None


SUSPICIOUS_CHARS = re.compile(r'[<>\'";]')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
INTERNAL_PATH_RE = re.compile(r'(/admin|/config|/debug|/internal|/private|/secret|/\.git|/\.env|\/etc\/|\/proc\/|file://|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)', re.IGNORECASE)


def _parse_url_params(url: str) -> list[ParsedParam]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    params = []
    for name, values in qs.items():
        for val in values:
            suspicious = bool(SUSPICIOUS_CHARS.search(val))
            params.append(ParsedParam(name=name, value=val, suspicious=suspicious))
    return params


def _parse_body_params(body_str: str | None) -> list[ParsedParam]:
    params = []
    if not body_str:
        return params
    try:
        data = json.loads(body_str)
        if isinstance(data, dict):
            for key, val in data.items():
                val_str = str(val)
                suspicious = bool(SUSPICIOUS_CHARS.search(val_str))
                params.append(ParsedParam(name=key, value=val_str, suspicious=suspicious))
        return params
    except (json.JSONDecodeError, ValueError):
        pass
    if '&' in body_str and '=' in body_str:
        for part in body_str.split('&'):
            if '=' in part:
                name, val = part.split('=', 1)
                suspicious = bool(SUSPICIOUS_CHARS.search(val))
                params.append(ParsedParam(name=name, value=val, suspicious=suspicious))
    return params


def _parse_cookies_from_headers(headers: dict, source: str = "header") -> list[CookieInfo]:
    cookies = []
    raw = headers.get("Cookie" if source == "request" else "Set-Cookie", "")
    if not raw:
        return cookies
    if source == "response":
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                name, rest = part.split("=", 1)
                cookie = CookieInfo(name=name.strip(), value=rest.strip() or "")
                cookies.append(cookie)
        return cookies
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            name, val = part.split("=", 1)
            cookies.append(CookieInfo(name=name.strip(), value=val.strip() or ""))
    return cookies


def _detect_content_type(headers: dict, body: str | None = None) -> str:
    ct = headers.get("Content-Type", headers.get("content-type", ""))
    if ct:
        return ct
    if body is not None:
        try:
            json.loads(body)
            return "application/json"
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        if body.startswith("<?xml") or body.startswith("<"):
            return "application/xml"
    return ""


def _check_suspicious_content(body: str | None) -> list[str]:
    findings = []
    if not body:
        return findings
    for match in EMAIL_RE.finditer(body):
        findings.append(f"Email address found: {match.group()}")
    for match in IP_RE.finditer(body):
        findings.append(f"IP address found: {match.group()}")
    for match in INTERNAL_PATH_RE.finditer(body):
        findings.append(f"Internal path/pattern found: {match.group()}")
    return findings


def _build_security_headers(headers: dict) -> SecurityHeaders:
    h = {k.lower(): v for k, v in headers.items()}
    return SecurityHeaders(
        content_security_policy=h.get("content-security-policy"),
        x_content_type_options=h.get("x-content-type-options"),
        x_frame_options=h.get("x-frame-options"),
        strict_transport_security=h.get("strict-transport-security"),
        x_xss_protection=h.get("x-xss-protection"),
    )


def _build_cache_headers(headers: dict) -> CacheHeaders:
    h = {k.lower(): v for k, v in headers.items()}
    return CacheHeaders(
        cache_control=h.get("cache-control"),
        pragma=h.get("pragma"),
        expires=h.get("expires"),
    )


@router.post("/analyze-request", response_model=AnalyzeRequestResult)
async def analyze_request(data: RequestData):
    url_params = _parse_url_params(data.url)
    body_params = _parse_body_params(data.body)
    all_params = url_params + body_params
    suspicious = [p for p in all_params if p.suspicious]
    cookies = _parse_cookies_from_headers(data.headers, source="request")
    content_type = _detect_content_type(data.headers, data.body)
    body_size = len(data.body) if data.body else 0

    return AnalyzeRequestResult(
        parsed_params=all_params,
        cookies=cookies,
        content_type=content_type,
        body_size=body_size,
        param_count=len(all_params),
        suspicious_params=suspicious,
        headers_count=len(data.headers),
        has_body=body_size > 0,
    )


@router.post("/analyze-response", response_model=AnalyzeResponseResult)
async def analyze_response(data: ResponseData):
    content_type = data.headers.get("Content-Type", data.headers.get("content-type", ""))
    content_length_str = data.headers.get("Content-Length", data.headers.get("content-length", "0"))
    try:
        content_length = int(content_length_str)
    except (ValueError, TypeError):
        content_length = len(data.body) if data.body else 0
    cookies = _parse_cookies_from_headers(data.headers, source="response")
    security = _build_security_headers(data.headers)
    cache = _build_cache_headers(data.headers)
    server = data.headers.get("Server", data.headers.get("server", ""))
    suspicious = _check_suspicious_content(data.body)

    return AnalyzeResponseResult(
        content_type=content_type,
        content_length=content_length,
        cookies_set=cookies,
        security_headers=security,
        cache_headers=cache,
        server_info=server,
        suspicious_content=suspicious,
    )


@router.post("/inspect", response_model=InspectResult)
async def inspect(data: InspectRequest):
    request_analysis = await analyze_request(data.request)
    response_analysis = None
    if data.response:
        response_analysis = await analyze_response(data.response)
    return InspectResult(
        request_analysis=request_analysis,
        response_analysis=response_analysis,
    )
