import httpx
import logging
import os
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from api.deps import get_db
from core.storage.models import UpstreamProxy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/proxy-config", tags=["proxy_config"])


class ProxyConfigCreate(BaseModel):
    enabled: bool = False
    host: str
    port: int
    protocol: str = "http"
    username: str | None = None
    password: str | None = None
    auth_enabled: bool = False
    dns_resolution: str = "proxy"
    scope_only: bool = False
    exclude_hosts: list[str] = []


class ProxyConfigUpdate(BaseModel):
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    username: str | None = None
    password: str | None = None
    auth_enabled: bool | None = None
    dns_resolution: str | None = None
    scope_only: bool | None = None
    exclude_hosts: list[str] | None = None


class ProxyConfigResponse(BaseModel):
    id: str
    enabled: bool
    host: str
    port: int
    protocol: str
    username: str | None = None
    password: str | None = None
    auth_enabled: bool
    dns_resolution: str
    scope_only: bool
    exclude_hosts: list[str]


class ProxyTestRequest(BaseModel):
    host: str
    port: int
    protocol: str = "http"
    username: str | None = None
    password: str | None = None
    auth_enabled: bool = False


class ProxyTestResponse(BaseModel):
    success: bool
    ip: str | None = None
    error: str | None = None


def _proxy_to_dict(proxy: UpstreamProxy, include_secret: bool = False) -> dict:
    data = {
        "id": str(proxy.id),
        "enabled": proxy.enabled,
        "host": proxy.host,
        "port": proxy.port,
        "protocol": proxy.protocol,
        "username": proxy.username,
        "auth_enabled": proxy.auth_enabled,
        "dns_resolution": proxy.dns_resolution,
        "scope_only": proxy.scope_only,
        "exclude_hosts": proxy.exclude_hosts,
        "password_set": bool(proxy.password),
    }
    if include_secret:
        data["password"] = proxy.password
    return data


@router.get("/")
async def get_config(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UpstreamProxy).order_by(UpstreamProxy.enabled.desc(), UpstreamProxy.created_at)
    )
    proxies = result.scalars().all()
    if not proxies:
        return None
    enabled = [p for p in proxies if p.enabled]
    if enabled:
        return _proxy_to_dict(enabled[0])
    return _proxy_to_dict(proxies[0])


@router.get("/active")
async def get_active_config(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UpstreamProxy).where(UpstreamProxy.enabled == True).limit(1)
    )
    proxy = result.scalar_one_or_none()
    if not proxy:
        raise HTTPException(status_code=404, detail="No active proxy configuration found")
    return _proxy_to_dict(proxy)


@router.post("/")
async def create_config(data: ProxyConfigCreate, db: AsyncSession = Depends(get_db)):
    proxy = UpstreamProxy(
        enabled=data.enabled,
        host=data.host,
        port=data.port,
        protocol=data.protocol,
        username=data.username,
        password=data.password,
        auth_enabled=data.auth_enabled,
        dns_resolution=data.dns_resolution,
        scope_only=data.scope_only,
        exclude_hosts=data.exclude_hosts,
    )
    if data.enabled:
        existing = (await db.execute(
            select(UpstreamProxy).where(UpstreamProxy.enabled == True)
        )).scalars().all()
        for p in existing:
            p.enabled = False

    db.add(proxy)
    await db.commit()
    await db.refresh(proxy)
    return _proxy_to_dict(proxy)


@router.put("/{proxy_id}")
async def update_config(proxy_id: UUID, data: ProxyConfigUpdate, db: AsyncSession = Depends(get_db)):
    proxy = await db.get(UpstreamProxy, proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy configuration not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(proxy, field, value)

    if data.enabled:
        existing = (await db.execute(
            select(UpstreamProxy).where(
                UpstreamProxy.enabled == True,
                UpstreamProxy.id != proxy_id,
            )
        )).scalars().all()
        for p in existing:
            p.enabled = False

    await db.commit()
    await db.refresh(proxy)
    return _proxy_to_dict(proxy)


@router.delete("/{proxy_id}")
async def delete_config(proxy_id: UUID, db: AsyncSession = Depends(get_db)):
    proxy = await db.get(UpstreamProxy, proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy configuration not found")
    await db.delete(proxy)
    await db.commit()
    return {"detail": "Proxy configuration deleted"}


@router.post("/{proxy_id}/toggle")
async def toggle_config(proxy_id: UUID, db: AsyncSession = Depends(get_db)):
    proxy = await db.get(UpstreamProxy, proxy_id)
    if not proxy:
        raise HTTPException(status_code=404, detail="Proxy configuration not found")

    if not proxy.enabled:
        existing = (await db.execute(
            select(UpstreamProxy).where(
                UpstreamProxy.enabled == True,
                UpstreamProxy.id != proxy_id,
            )
        )).scalars().all()
        for p in existing:
            p.enabled = False
        proxy.enabled = True
    else:
        proxy.enabled = False

    await db.commit()
    await db.refresh(proxy)
    return _proxy_to_dict(proxy)


@router.post("/test")
async def test_proxy(data: ProxyTestRequest) -> ProxyTestResponse:
    auth = ""
    if data.auth_enabled and data.username:
        import urllib.parse
        user = urllib.parse.quote(data.username, safe="")
        pwd = urllib.parse.quote(data.password or "", safe="")
        auth = f"{user}:{pwd}@"

    proxy_url = f"{data.protocol}://{auth}{data.host}:{data.port}"

    try:
        async with httpx.AsyncClient(
            proxies={"http://": proxy_url, "https://": proxy_url},
            verify=False,
            timeout=10,
        ) as client:
            test_url = os.environ.get("NYX_PROXY_TEST_URL", "http://httpbin.org/ip")
            resp = await client.get(test_url)
            if resp.status_code == 200:
                body = resp.json()
                return ProxyTestResponse(success=True, ip=body.get("origin", "unknown"))
            return ProxyTestResponse(
                success=False,
                error=f"Unexpected status code: {resp.status_code}",
            )
    except Exception as e:
        return ProxyTestResponse(success=False, error=str(e))


@router.get("/local-ips")
async def get_local_ips():
    import socket
    ips = []
    try:
        hostname = socket.gethostname()
        for addr in socket.getaddrinfo(hostname, None):
            ip = addr[4][0]
            if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
                if ip not in ips:
                    ips.append(ip)
        if not ips:
            ips.append("127.0.0.1")
    except Exception:
        ips = ["127.0.0.1"]
    return {"ips": ips}
