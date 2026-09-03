"""Regression tests for the active-scanner param injection bug.

All injection-type active checks used to silently no-op when the target
parameter was not already present in the base request URL:

    if param in params:
        params[param] = payload

Since target_params are explicitly requested by the caller (scanner /
UI), a param that is missing from the base URL must be ADDED, not skipped.
Otherwise scanning a fresh URL with discovered params never sends any
payload — the check just re-requests the original page unchanged.

These tests assert that, given a base request WITHOUT query params, every
injection check still issues a request whose URL contains the new param.
"""
import pytest
from unittest.mock import AsyncMock, patch


BASE_REQUEST_NO_PARAMS = {
    "method": "GET",
    "url": "http://example.com/page",
    "headers": {"Host": "example.com"},
}


def _collect_request_urls(mock_client) -> list[str]:
    """Extract every URL the client was asked to fetch."""
    urls: list[str] = []
    for call in mock_client.request.call_args_list:
        if call.kwargs.get("url"):
            urls.append(call.kwargs["url"])
        elif call.args:
            urls.append(str(call.args[0]))
    return urls


# A representative sample of the ~55 injection checks that shared the bug.
def _checks():
    from modules.scanner.active.checks import (
        lfi, xss, sqli, ssrf, ssti, open_redirect, nosqli,
        xss_variants, sqli_variants,
    )
    from modules.scanner.active.checks.active_header_injection import (
        ActiveHeaderInjectionCheck,
    )
    from modules.scanner.active.checks.active_sqli_blind import (
        ActiveSqliBlindCheck,
    )
    return [
        xss.XssCheck(),
        xss_variants.XssVariantsCheck(),
        sqli.SQLiCheck(),
        sqli_variants.SqliVariantsCheck(),
        lfi.LfiCheck(),
        ssrf.SsrfCheck(),
        # NOTE: XxeCheck is intentionally excluded — it injects into the
        # request body (XML), not the URL query string.
        ssti.SstiCheck(),
        open_redirect.OpenRedirectCheck(),
        nosqli.NoSqlInjectionCheck(),
        ActiveHeaderInjectionCheck(),
        ActiveSqliBlindCheck(),
    ]


@pytest.mark.parametrize("check", [pytest.param(c, id=c.name) for c in _checks()])
@pytest.mark.asyncio
async def test_param_not_in_url_is_injected(check):
    """A param missing from the base URL must be added, not skipped."""
    mock_response = AsyncMock()
    mock_response.text = "generic response body"
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html"}

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.request.return_value = mock_response

    with patch("httpx.AsyncClient", return_value=mock_client):
        await check.run(BASE_REQUEST_NO_PARAMS, ["newparam"])

    urls = _collect_request_urls(mock_client)
    assert urls, f"{check.name} never issued any request"
    injected = [u for u in urls if "newparam=" in u]
    assert injected, (
        f"{check.name} never injected the target param into the URL "
        f"(got: {urls[:3]}). If the guard 'if param in params' is back, "
        "checks silently no-op on params absent from the base request."
    )


@pytest.mark.asyncio
async def test_param_in_url_still_injected():
    """Existing params must keep being replaced by the payload."""
    from modules.scanner.active.checks.xss import XssCheck

    check = XssCheck()
    base = {
        "method": "GET",
        "url": "http://example.com/page?foo=1",
        "headers": {},
    }
    mock_response = AsyncMock()
    mock_response.text = "<script>alert(1)</script>"
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html"}

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.request.return_value = mock_response

    with patch("httpx.AsyncClient", return_value=mock_client):
        results = await check.run(base, ["foo"])

    assert len(results) >= 1
    # The payload must have been substituted into the existing param.
    urls = _collect_request_urls(mock_client)
    assert any("foo=" in u and "foo=1" not in u.split("foo=")[1][:3] for u in urls)
