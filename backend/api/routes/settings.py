import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])

_proxy_host = settings.PROXY_HOST
_proxy_port = settings.PROXY_PORT
_proxy_mode = settings.PROXY_MODE

ALLOWED_PROXY_MODES = ("regular", "transparent")


class ProxySettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)
    mode: str = "transparent"

    @field_validator("mode")
    @classmethod
    def _valid_mode(cls, value: str) -> str:
        value = (value or "").strip().lower()
        if value not in ALLOWED_PROXY_MODES:
            raise ValueError(f"mode must be one of {ALLOWED_PROXY_MODES}")
        return value


class SettingsResponse(BaseModel):
    proxy: ProxySettings
    api_host: str
    api_port: int


@router.get("/proxy", response_model=ProxySettings)
async def get_proxy_settings():
    return ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode)


@router.put("/proxy", response_model=ProxySettings)
async def update_proxy_settings(settings_data: ProxySettings, request: Request):
    global _proxy_host, _proxy_port, _proxy_mode

    engine = getattr(request.app.state, "proxy_engine", None)
    if engine is None:
        _proxy_host, _proxy_port, _proxy_mode = (
            settings_data.host, settings_data.port, settings_data.mode,
        )
        return ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode)

    previous = (engine.host, engine.port, engine.mode)

    def _apply(host: str, port: int, mode: str) -> None:
        engine.stop()
        engine.host, engine.port, engine.mode = host, port, mode
        engine.start(engine.fastapi_loop)

    try:
        _apply(settings_data.host, settings_data.port, settings_data.mode)
    except Exception as e:
        logger.error("Failed to restart proxy with new settings: %s", e)
        # Leaving the engine stopped silently killed capture for the rest of
        # the session (and, with IP forwarding half-torn-down, could take the
        # host's networking with it). Roll back to the last working config.
        try:
            _apply(*previous)
            restored = True
        except Exception as restore_error:  # noqa: BLE001
            logger.error("Proxy rollback failed: %s", restore_error)
            restored = False
        detail = f"Failed to restart proxy: {e}"
        detail += ". Previous settings restored." if restored else ". Proxy is stopped — restart the backend."
        raise HTTPException(status_code=500, detail=detail)

    _proxy_host, _proxy_port, _proxy_mode = (
        settings_data.host, settings_data.port, settings_data.mode,
    )
    return ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode)


@router.get("/", response_model=SettingsResponse)
async def get_all_settings():
    return SettingsResponse(
        proxy=ProxySettings(host=_proxy_host, port=_proxy_port, mode=_proxy_mode),
        api_host=settings.API_HOST,
        api_port=settings.API_PORT,
    )
