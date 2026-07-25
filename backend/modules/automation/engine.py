import asyncio
import logging
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.IGNORECASE)
API_PATTERNS = re.compile(r'/api/|/v\d+/|/graphql|/rest/', re.IGNORECASE)
STATIC_EXTENSIONS = re.compile(r'\.(jpg|jpeg|png|gif|css|js|woff|ttf|ico|svg|webp|bmp|ico|pdf)$', re.IGNORECASE)


class AutoScanEngine:
    def __init__(self, event_bus, passive_scanner, active_scanner):
        self.event_bus = event_bus
        self.passive_scanner = passive_scanner
        self.active_scanner = active_scanner
        self.discovered_urls: dict[str, dict] = {}
        self.pending_queue: list[dict] = []
        self._subscriptions = []
        self._queue_task = None
        self._running = False

        self.auto_active_scan = True
        self.max_concurrent_active_scans = 3
        self.scan_delay_ms = 500

        self._learning_mode = True
        self._learning_domains: set[str] = set()
        self._learning_paths: dict[str, int] = defaultdict(int)
        self._learning_start: datetime | None = None
        self._auto_scope: dict = {"include": [], "exclude": []}

    async def start(self):
        self._running = True
        self.event_bus.subscribe('request.captured', self._on_request_captured)
        self.event_bus.subscribe('response.received', self._on_response_received)
        self._queue_task = asyncio.create_task(self._queue_loop())
        logger.info("AutoScanEngine started")

    def stop(self):
        self._running = False
        self.event_bus.unsubscribe('request.captured', self._on_request_captured)
        self.event_bus.unsubscribe('response.received', self._on_response_received)
        if self._queue_task:
            self._queue_task.cancel()
        self.pending_queue.clear()
        logger.info("AutoScanEngine stopped")

    async def _on_request_captured(self, event: dict):
        url = event.get('url', '')
        if not url:
            return

        await self._learn_from_traffic(url)

        self._add_discovered(url, 'request', event)

        await self._run_passive(event)

        new_params = self._extract_new_params(url)
        if new_params and self.auto_active_scan:
            self._enqueue_scan(url, new_params, event)

        extracted = self._extract_urls_from_request(event)
        for u in extracted:
            self._add_discovered(u, 'request_extracted', event)

    async def _on_response_received(self, event: dict):
        await self._run_passive(event)

        body = event.get('body', '') or ''
        extracted = self._extract_urls_from_body(body, event.get('content_type', ''))
        for u in extracted:
            self._add_discovered(u, 'response_body', event)

        if API_PATTERNS.search(body):
            endpoints = self._extract_api_endpoints(body)
            for ep in endpoints:
                self._add_discovered(ep, 'api_endpoint', event)

        redirect_url = self._get_redirect_url(event)
        if redirect_url:
            self._add_discovered(redirect_url, 'redirect', event)

    async def _run_passive(self, event: dict):
        try:
            await self.passive_scanner._on_response(event)
        except Exception as e:
            logger.error("Passive scan error: %s", e)

    def _add_discovered(self, url: str, source: str, event: dict):
        if url not in self.discovered_urls:
            self.discovered_urls[url] = {
                'url': url,
                'source': source,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'host': urlparse(url).hostname or '',
            }
            try:
                asyncio.create_task(self._publish_url_discovered(url, source))
            except RuntimeError:
                pass

    async def _publish_url_discovered(self, url: str, source: str):
        await self.event_bus.publish({
            'type': 'automation.url_discovered',
            'url': url,
            'source': source,
        })

    def _extract_urls_from_request(self, event: dict) -> list[str]:
        urls = []
        url = event.get('url', '')
        if url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for values in qs.values():
                for v in values:
                    if v.startswith('http://') or v.startswith('https://'):
                        urls.append(v)
        return urls

    def _extract_urls_from_body(self, body: str, content_type: str) -> list[str]:
        urls = set()
        for match in URL_PATTERN.finditer(body):
            val = match.group(1)
            if val.startswith('http://') or val.startswith('https://') or val.startswith('/') or val.startswith('.'):
                urls.add(val)
        return list(urls)

    def _extract_api_endpoints(self, body: str) -> list[str]:
        endpoints = set()
        for match in URL_PATTERN.finditer(body):
            val = match.group(1)
            if API_PATTERNS.search(val):
                endpoints.add(val)
        return list(endpoints)

    def _get_redirect_url(self, event: dict) -> str | None:
        headers = event.get('headers', {}) or {}
        location = headers.get('location') or headers.get('Location')
        if location:
            return location
        return None

    def _extract_new_params(self, url: str) -> list[str] | None:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return None
        params = list(qs.keys())
        for item in self.pending_queue:
            if item.get('url') == url:
                existing = set(item.get('params', []))
                new = [p for p in params if p not in existing]
                if new:
                    item['params'].extend(new)
                return None
        return params

    def _enqueue_scan(self, url: str, params: list[str], event: dict):
        parsed = urlparse(url)
        priority = 2 if API_PATTERNS.search(url) else 1
        self.pending_queue.append({
            'url': url,
            'params': params,
            'priority': priority,
            'host': parsed.hostname or '',
            'discovered_at': datetime.now(timezone.utc).isoformat(),
        })

    async def _queue_loop(self):
        while self._running:
            await self._process_batch()
            await asyncio.sleep(self.scan_delay_ms / 1000.0)

    async def _process_batch(self):
        if not self.pending_queue or not self.auto_active_scan:
            return

        self.pending_queue.sort(key=lambda x: (-x['priority'], x['host']))

        batch = self.pending_queue[:self.max_concurrent_active_scans]
        self.pending_queue = self.pending_queue[self.max_concurrent_active_scans:]

        tasks = []
        for item in batch:
            tasks.append(self._scan_url(item))
        if tasks:
            await asyncio.gather(*tasks)

    async def _scan_url(self, item: dict):
        url = item['url']
        params = item['params']
        logger.info("Active scanning %s with params %s", url, params)

        await self.event_bus.publish({
            'type': 'automation.scan_started',
            'url': url,
            'checks_count': len(params),
        })

        base_request = {
            'method': 'GET',
            'url': url,
            'headers': {'User-Agent': 'Nyx-AutoScan/1.0'},
            'body': None,
        }

        try:
            results = await self.active_scanner.run_checks(base_request, params)
            logger.info("Scan of %s complete: %d findings", url, len(results))
        except Exception as e:
            logger.error("Active scan of %s failed: %s", url, e)

    async def _learn_from_traffic(self, url: str):
        if not self._learning_mode:
            return

        if self._learning_start is None:
            self._learning_start = datetime.now(timezone.utc)

        elapsed = datetime.now(timezone.utc) - self._learning_start
        if elapsed > timedelta(minutes=2):
            self._learning_mode = False
            self._auto_scope = self._build_auto_scope()
            logger.info("AutoScope: learned scope for domains %s", list(self._learning_domains))
            await self.event_bus.publish({
                "type": "automation.scope_learned",
                "scope": self._auto_scope,
            })
            return

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if domain:
            self._learning_domains.add(domain)
        path = parsed.path or "/"
        self._learning_paths[path] += 1

    def _build_auto_scope(self) -> dict:
        include = list(self._learning_domains)
        exclude = [f".*{ext}$" for ext in [".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".woff", ".ttf", ".ico", ".svg", ".webp", ".bmp", ".pdf"]]
        return {"include": include, "exclude": exclude}

    def get_auto_scope(self) -> dict:
        return dict(self._auto_scope)

    def get_discovered_urls(self) -> list[dict]:
        return list(self.discovered_urls.values())

    def get_pending_scans(self) -> list[dict]:
        return [
            {'url': item['url'], 'priority': item['priority']}
            for item in self.pending_queue
        ]

    def get_config(self) -> dict:
        return {
            'auto_active_scan': self.auto_active_scan,
            'max_concurrent': self.max_concurrent_active_scans,
            'scan_delay_ms': self.scan_delay_ms,
        }

    def update_config(self, config: dict):
        if 'auto_active_scan' in config:
            self.auto_active_scan = bool(config['auto_active_scan'])
        if 'max_concurrent' in config:
            self.max_concurrent_active_scans = int(config['max_concurrent'])
        if 'scan_delay_ms' in config:
            self.scan_delay_ms = int(config['scan_delay_ms'])
