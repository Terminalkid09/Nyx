"""Centralized proxy configuration for all HTTP clients."""

_proxy_config_service = None

def set_proxy_config_service(service):
    global _proxy_config_service
    _proxy_config_service = service

def get_httpx_proxies(target_host: str = "") -> dict:
    if _proxy_config_service:
        return _proxy_config_service.get_httpx_proxy_args(target_host)
    return {}

def get_playwright_proxy(target_host: str = "") -> dict | None:
    if _proxy_config_service:
        return _proxy_config_service.get_playwright_proxy_args(target_host)
    return None
