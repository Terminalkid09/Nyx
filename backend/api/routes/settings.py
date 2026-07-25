from fastapi import APIRouter
from pydantic import BaseModel
from core.config import settings

router = APIRouter(prefix="/api/settings", tags=["settings"])

_proxy_host = settings.PROXY_HOST
_proxy_port = settings.PROXY_PORT
_proxy_mode = settings.PROXY_MODE


class ProxySettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    mode: str = "transparent"


class SettingsResponse(BaseModel):
    proxy: ProxySettings
    api_host: str
    api_port: int


@router.get("/proxy", response_model=ProxySettings)
async def get_proxy_settings():
    return ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode)


@router.put("/proxy", response_model=ProxySettings)
async def update_proxy_settings(settings_data: ProxySettings):
    global _proxy_host, _proxy_port, _proxy_mode
    _proxy_host = settings_data.host
    _proxy_port = settings_data.port
    _proxy_mode = settings_data.mode
    return ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode)


@router.get("/", response_model=SettingsResponse)
async def get_all_settings():
    return SettingsResponse(
        proxy=ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode),
        api_host=settings.API_HOST,
        api_port=settings.API_PORT,
    )
