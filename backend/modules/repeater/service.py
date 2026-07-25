import uuid
import time
import json
import asyncio
import re
import httpx
from typing import Optional

from core.storage.database import AsyncSessionLocal
from core.storage.models import RepeaterTab as RepeaterTabModel, RepeaterHistory as RepeaterHistoryModel
from sqlalchemy import select


class RequestEntry:
    def __init__(self, method, url, headers, body=None, response_status=None,
                 response_headers=None, response_body=None, time_ms=None, timestamp=None):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.response_status = response_status
        self.response_headers = response_headers
        self.response_body = response_body
        self.time_ms = time_ms
        self.timestamp = timestamp or time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


class RepeaterTab:
    def __init__(self, id, name):
        self.id = id
        self.name = name
        self.request_history = []


class RepeaterService:
    def __init__(self):
        self._tabs: dict[str, RepeaterTab] = {}
        try:
            asyncio.run(self._load_tabs())
        except RuntimeError:
            try:
                asyncio.get_running_loop().create_task(self._load_tabs())
            except RuntimeError:
                pass

    async def _load_tabs(self):
        try:
            async with AsyncSessionLocal() as session:
                stmt = select(RepeaterTabModel)
                result = await session.execute(stmt)
                for db_tab in result.scalars().all():
                    tab = RepeaterTab(id=db_tab.id, name=db_tab.name)
                    hist_stmt = select(RepeaterHistoryModel).where(
                        RepeaterHistoryModel.tab_id == db_tab.id
                    )
                    hist_result = await session.execute(hist_stmt)
                    for h in hist_result.scalars().all():
                        entry = RequestEntry(
                            method=h.method,
                            url=h.url,
                            headers=h.headers,
                            body=h.body,
                            response_status=h.response_status,
                            response_headers=h.response_headers,
                            response_body=h.response_body,
                            time_ms=h.time_ms,
                            timestamp=h.timestamp,
                        )
                        tab.request_history.append(entry)
                    self._tabs[db_tab.id] = tab
        except Exception:
            pass

    async def _save_tab(self, tab_id: str, name: str):
        try:
            async with AsyncSessionLocal() as session:
                session.add(RepeaterTabModel(id=tab_id, name=name))
                await session.commit()
        except Exception:
            pass

    async def _delete_tab(self, tab_id: str):
        try:
            async with AsyncSessionLocal() as session:
                stmt = select(RepeaterTabModel).where(RepeaterTabModel.id == tab_id)
                result = await session.execute(stmt)
                db_tab = result.scalar_one_or_none()
                if db_tab:
                    await session.delete(db_tab)
                    await session.commit()
        except Exception:
            pass

    async def _save_history(self, tab_id: str, entry: RequestEntry):
        try:
            async with AsyncSessionLocal() as session:
                session.add(RepeaterHistoryModel(
                    tab_id=tab_id,
                    method=entry.method,
                    url=entry.url,
                    headers=entry.headers,
                    body=entry.body,
                    response_status=entry.response_status,
                    response_headers=entry.response_headers,
                    response_body=entry.response_body,
                    time_ms=entry.time_ms,
                    timestamp=entry.timestamp,
                ))
                await session.commit()
        except Exception:
            pass

    def create_tab(self, name: str = "Untitled", request_data: Optional[dict] = None) -> RepeaterTab:
        tab_id = str(uuid.uuid4())[:8]
        tab = RepeaterTab(id=tab_id, name=name)
        if request_data:
            entry = RequestEntry(
                method=request_data.get("method", "GET"),
                url=request_data.get("url", ""),
                headers=request_data.get("headers", {}),
                body=request_data.get("body"),
            )
            tab.request_history.append(entry)
        self._tabs[tab_id] = tab
        try:
            asyncio.get_running_loop().create_task(self._save_tab(tab_id, name))
        except RuntimeError:
            pass
        return tab

    def close_tab(self, tab_id: str) -> bool:
        tab = self._tabs.pop(tab_id, None)
        if tab:
            try:
                asyncio.get_running_loop().create_task(self._delete_tab(tab_id))
            except RuntimeError:
                pass
            return True
        return False

    def get_tabs(self) -> list[RepeaterTab]:
        return list(self._tabs.values())

    def get_tab(self, tab_id: str) -> Optional[RepeaterTab]:
        return self._tabs.get(tab_id)

    def get_history(self, tab_id: str) -> list:
        tab = self._tabs.get(tab_id)
        if not tab:
            return []
        return tab.request_history

    async def send_request(self, tab_id: str, method: str, url: str, headers: dict, body: Optional[str]) -> Optional[dict]:
        if not self._tabs:
            await self._load_tabs()
        tab = self._tabs.get(tab_id)
        if not tab:
            return None
        entry = RequestEntry(method=method, url=url, headers=headers, body=body)
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            try:
                resp = await client.request(method=method, url=url, headers=headers, content=body)
                entry.response_status = resp.status_code
                entry.response_headers = dict(resp.headers)
                entry.response_body = resp.text
                entry.time_ms = int(resp.elapsed.total_seconds() * 1000)
            except httpx.TimeoutException:
                entry.response_status = 504
                entry.response_headers = {}
                entry.response_body = "Request timed out"
                entry.time_ms = 30000
            except Exception as e:
                entry.response_status = 0
                entry.response_headers = {}
                entry.response_body = str(e)
                entry.time_ms = 0
        tab.request_history.append(entry)
        await self._save_history(tab_id, entry)
        return {
            "status": entry.response_status,
            "headers": entry.response_headers,
            "body": entry.response_body,
            "time_ms": entry.time_ms,
        }

    @staticmethod
    def _parse_response_body(body_text: str, content_type: str) -> dict:
        if not body_text:
            return {"raw": "", "pretty": "", "hex": ""}
        pretty = body_text
        if content_type:
            ct = content_type.lower()
            if "json" in ct:
                try:
                    parsed = json.loads(body_text)
                    pretty = json.dumps(parsed, indent=2)
                except (json.JSONDecodeError, TypeError):
                    pass
            elif "html" in ct:
                indent = 0
                parts = re.split(r'(</?[^>]+>)', body_text)
                result_parts = []
                for part in parts:
                    if not part:
                        continue
                    if part.startswith("</") and part.endswith(">"):
                        indent = max(0, indent - 1)
                        result_parts.append("\n" + "  " * indent + part)
                    elif part.startswith("<") and not part.startswith("</") and not part.startswith("<!"):
                        result_parts.append("\n" + "  " * indent + part)
                        if not part.endswith("/>"):
                            indent += 1
                    elif part.strip():
                        result_parts.append("\n" + "  " * indent + part.strip())
                pretty = "".join(result_parts).strip()
        hex_view = " ".join(f"{b:02x}" for b in body_text.encode("utf-8"))
        return {"raw": body_text, "pretty": pretty, "hex": hex_view}
