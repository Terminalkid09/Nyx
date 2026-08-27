import uuid
import importlib.util
import sys
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from api.deps import get_db
from core.storage.models import Plugin

router = APIRouter(prefix="/api/plugins", tags=["plugins"])

logger = logging.getLogger(__name__)


class PluginRegister(BaseModel):
    name: str
    path: str
    hook_type: str = "request"
    description: str | None = None
    version: str = "1.0.0"
    config: dict = {}


class PluginUpdate(BaseModel):
    name: str | None = None
    path: str | None = None
    hook_type: str | None = None
    description: str | None = None
    version: str | None = None
    config: dict | None = None


class PluginResponse(BaseModel):
    id: uuid.UUID
    name: str
    path: str
    enabled: bool
    hook_type: str
    description: str | None
    version: str
    config: dict
    created_at: str

    model_config = {"from_attributes": True}


_loaded_plugins: dict[str, object] = {}


PLUGINS_DIR = Path(__file__).parent.parent.parent / "plugins"


def _validate_plugin_path(path: str) -> Path:
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise HTTPException(400, f"Plugin file not found: {path}")
    if not resolved.suffix == ".py":
        raise HTTPException(400, "Plugin must be a .py file")
    try:
        resolved.relative_to(PLUGINS_DIR)
    except ValueError:
        raise HTTPException(400, f"Plugin must be inside {PLUGINS_DIR}")
    return resolved


def _load_plugin_module(path: str, name: str) -> object | None:
    try:
        spec = importlib.util.spec_from_file_location(f"nyx_plugins.{name}", path)
        if not spec or not spec.loader:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"nyx_plugins.{name}"] = module
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.error("Failed to load plugin '%s' from %s: %s", name, path, e)
        return None


def _unload_plugin(name: str):
    mod_name = f"nyx_plugins.{name}"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    _loaded_plugins.pop(name, None)


@router.get("", response_model=list[PluginResponse])
async def list_plugins(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Plugin).order_by(Plugin.name))
    items = []
    for p in result.scalars().all():
        items.append({
            "id": p.id,
            "name": p.name,
            "path": p.path,
            "enabled": p.enabled,
            "hook_type": p.hook_type,
            "description": p.description,
            "version": p.version,
            "config": p.config,
            "created_at": p.created_at.isoformat() if p.created_at else "",
        })
    return items


@router.post("", response_model=PluginResponse, status_code=201)
async def register_plugin(body: PluginRegister, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(Plugin).where(Plugin.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail="Plugin with this name already exists")

    _validate_plugin_path(body.path)
    plugin = Plugin(
        name=body.name,
        path=body.path,
        hook_type=body.hook_type,
        description=body.description,
        version=body.version,
        config=body.config,
    )
    db.add(plugin)
    await db.commit()
    await db.refresh(plugin)

    module = _load_plugin_module(body.path, body.name)
    if module:
        _loaded_plugins[body.name] = module

    return {
        "id": plugin.id,
        "name": plugin.name,
        "path": plugin.path,
        "enabled": plugin.enabled,
        "hook_type": plugin.hook_type,
        "description": plugin.description,
        "version": plugin.version,
        "config": plugin.config,
        "created_at": plugin.created_at.isoformat() if plugin.created_at else "",
    }


@router.put("/{plugin_id}", response_model=PluginResponse)
async def update_plugin(plugin_id: uuid.UUID, body: PluginUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(404, detail="Plugin not found")

    old_name = plugin.name
    # Validate the new path BEFORE mutating the row: comparing against the old
    # *path* (not the name) is what actually detects a path change, and
    # validating first keeps the stored row consistent when validation fails.
    if body.path and body.path != plugin.path:
        _validate_plugin_path(body.path)
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(plugin, key, value)
    await db.commit()
    await db.refresh(plugin)

    if old_name in _loaded_plugins:
        _unload_plugin(old_name)
    if plugin.enabled:
        module = _load_plugin_module(plugin.path, plugin.name)
        if module:
            _loaded_plugins[plugin.name] = module

    return {
        "id": plugin.id,
        "name": plugin.name,
        "path": plugin.path,
        "enabled": plugin.enabled,
        "hook_type": plugin.hook_type,
        "description": plugin.description,
        "version": plugin.version,
        "config": plugin.config,
        "created_at": plugin.created_at.isoformat() if plugin.created_at else "",
    }


@router.delete("/{plugin_id}", status_code=204)
async def uninstall_plugin(plugin_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(404, detail="Plugin not found")

    _unload_plugin(plugin.name)
    await db.delete(plugin)
    await db.commit()


@router.post("/{plugin_id}/toggle", response_model=PluginResponse)
async def toggle_plugin(plugin_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(404, detail="Plugin not found")

    plugin.enabled = not plugin.enabled
    await db.commit()
    await db.refresh(plugin)

    if plugin.enabled:
        module = _load_plugin_module(plugin.path, plugin.name)
        if module:
            _loaded_plugins[plugin.name] = module
    else:
        _unload_plugin(plugin.name)

    return {
        "id": plugin.id,
        "name": plugin.name,
        "path": plugin.path,
        "enabled": plugin.enabled,
        "hook_type": plugin.hook_type,
        "description": plugin.description,
        "version": plugin.version,
        "config": plugin.config,
        "created_at": plugin.created_at.isoformat() if plugin.created_at else "",
    }


@router.post("/reload")
async def reload_plugins(db: AsyncSession = Depends(get_db)):
    _loaded_plugins.clear()
    result = await db.execute(select(Plugin).where(Plugin.enabled == True))
    loaded = 0
    failed = 0
    for plugin in result.scalars().all():
        module = _load_plugin_module(plugin.path, plugin.name)
        if module:
            _loaded_plugins[plugin.name] = module
            loaded += 1
        else:
            failed += 1
    return {
        "loaded": loaded,
        "failed": failed,
        "total": loaded + failed,
    }
