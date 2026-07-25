import asyncio
import logging
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin

from core.events.bus import EventBus

logger = logging.getLogger(__name__)


@dataclass
class FormAutoFillConfig:
    values: dict[str, str] = field(default_factory=lambda: {
        "email": "test@example.com",
        "password": "Passw0rd!",
        "name": "John Doe",
        "username": "testuser",
        "search": "test",
        "tel": "555-0000",
        "url": "https://example.com",
        "number": "12345",
    })


@dataclass
class LoginMacroStep:
    url: str
    method: str = "GET"
    body: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlProgressEvent:
    job_id: str
    type: str = "crawl.progress"
    discovered_urls: list[str] = field(default_factory=list)
    forms_found: list[dict] = field(default_factory=list)
    pages_visited: int = 0
    total_pages: int = 0
    current_url: str = ""
    status: str = "running"


class CrawlerService:
    def __init__(
        self,
        event_bus: EventBus,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8080,
    ):
        self.event_bus = event_bus
        self.proxy = {"server": f"http://{proxy_host}:{proxy_port}"}
        self._stop_flag: dict[str, bool] = defaultdict(bool)

    def stop(self, job_id: str):
        self._stop_flag[job_id] = True

    async def crawl(
        self,
        start_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        scope_include: Optional[list[str]] = None,
        scope_exclude: Optional[list[str]] = None,
        scope_exclude_content_types: Optional[list[str]] = None,
        max_concurrent_pages: int = 3,
        respect_nofollow: bool = True,
        extract_sitemap: bool = True,
        max_retries: int = 2,
        cookie_consent_dismiss: bool = True,
        form_fill_config: Optional[dict[str, str]] = None,
        login_macro: Optional[list[dict]] = None,
        headers: Optional[dict[str, str]] = None,
        respect_robots_txt: bool = True,
        job_id: Optional[str] = None,
    ) -> dict:
        job_id = job_id or str(uuid.uuid4())
        self._stop_flag[job_id] = False

        include = scope_include or []
        exclude = scope_exclude or []
        exclude_content_types = scope_exclude_content_types or [
            "image/", "font/", "video/", "audio/", "application/font",
        ]
        fill_config = FormAutoFillConfig(values=form_fill_config or {})
        macro_steps = [LoginMacroStep(**s) for s in (login_macro or [])]
        extra_headers = headers or {}

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_url, 0)]
        discovered_urls: list[str] = []
        forms_found: list[dict] = []
        base_domain = urlparse(start_url).netloc
        retry_count: dict[str, int] = defaultdict(int)

        disallowed_prefixes: list[str] = []
        if respect_robots_txt:
            disallowed_prefixes = await self._fetch_robots_txt(start_url)

        sitemap_urls: list[str] = []
        if extract_sitemap:
            sitemap_urls = await self._fetch_sitemap(start_url)
            for su in sitemap_urls:
                if su not in visited:
                    queue.append((su, 0))

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed; falling back to basic BFS")
            result = await self._fallback_bfs(
                start_url, base_domain, max_depth, max_pages,
                include, exclude, disallowed_prefixes,
            )
            return {
                "job_id": job_id,
                "status": "completed",
                "discovered_urls": result,
                "forms_found": [],
                "pages_visited": len(result),
            }

        collected_cookies: list[dict] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                proxy=self.proxy,
                args=["--ignore-certificate-errors"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=extra_headers if extra_headers else None,
            )

            if macro_steps:
                login_page = await context.new_page()
                try:
                    for i, step in enumerate(macro_steps):
                        logger.info("Executing login macro step %d: %s %s", i + 1, step.method, step.url)
                        await self._execute_login_step(login_page, step)
                        await login_page.wait_for_load_state("networkidle", timeout=15000)

                        auth_info = await self._detect_auth_success(login_page)
                        if auth_info.get("authenticated"):
                            logger.info("Auth detected after macro step %d: %s", i + 1, auth_info.get("method"))

                        collected_cookies = await context.cookies()
                        logger.info("Captured %d cookies after macro step %d", len(collected_cookies), i + 1)

                    auth_tokens = await self._capture_auth_tokens(login_page)
                    if auth_tokens:
                        logger.info("Auth tokens captured: %s", list(auth_tokens.keys()))
                except Exception as e:
                    logger.error("Login macro failed: %s", e)
                finally:
                    await login_page.close()

            sem = asyncio.Semaphore(max_concurrent_pages)
            pages_visited = 0

            async def process_url(url: str, depth: int):
                nonlocal pages_visited
                async with sem:
                    if self._stop_flag.get(job_id):
                        return
                    if url in visited:
                        return
                    if depth > max_depth:
                        return
                    if not self._is_in_scope(url, include, exclude, base_domain):
                        return
                    if disallowed_prefixes and self._is_disallowed(url, disallowed_prefixes):
                        return

                    visited.add(url)

                    if collected_cookies:
                        await context.add_cookies(collected_cookies)

                    page = await context.new_page()

                    try:
                        if cookie_consent_dismiss:
                            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                            await self._dismiss_cookie_consent(page)
                            await page.wait_for_load_state("networkidle", timeout=15000)
                        else:
                            await page.goto(url, wait_until="networkidle", timeout=15000)

                        await page.wait_for_timeout(1000)
                        await self._auto_scroll(page)

                        links = await page.eval_on_selector_all(
                            "a[href]",
                            "elements => elements.map(e => e.href)",
                        )

                        if respect_nofollow:
                            nofollow_links = await page.evaluate("""
                                () => {
                                    return Array.from(document.querySelectorAll('a[href][rel~="nofollow"]'))
                                        .map(a => a.href);
                                }
                            """)
                            nofollow_set = set(nofollow_links)
                            links = [l for l in links if l not in nofollow_set]

                        forms = await self._extract_forms(page)
                        for form in forms:
                            form["page_url"] = url
                            forms_found.append(form)

                        for form in forms:
                            try:
                                await self._fill_and_submit_form(page, form, fill_config)
                            except Exception as e:
                                logger.debug("Form fill/submit failed: %s", e)

                        ajax_urls = await self._extract_ajax_urls(page)
                        all_js_urls = await self._extract_js_urls(page)

                        await page.close()
                        pages_visited += 1

                        await self.event_bus.publish({
                            "type": "crawl.progress",
                            "job_id": job_id,
                            "discovered_urls": discovered_urls.copy(),
                            "forms_found": forms_found.copy(),
                            "pages_visited": pages_visited,
                            "total_pages": max_pages,
                            "current_url": url,
                            "status": "running",
                        })

                        all_new = set(links) | set(ajax_urls) | set(all_js_urls)
                        for link in all_new:
                            parsed = urlparse(link)
                            if parsed.netloc == base_domain and link not in visited:
                                queue.append((link, depth + 1))
                                discovered_urls.append(link)

                    except Exception as e:
                        logger.debug("Error crawling %s: %s", url, e)
                        retry_count[url] = retry_count.get(url, 0) + 1
                        if retry_count[url] < max_retries:
                            queue.append((url, depth))
                            logger.debug("Will retry %s (attempt %d)", url, retry_count[url])
                        try:
                            await page.close()
                        except Exception:
                            pass

            while queue and pages_visited < max_pages:
                if self._stop_flag.get(job_id):
                    break
                tasks = []
                batch = []
                while queue and len(batch) < max_concurrent_pages * 2:
                    url, depth = queue.pop(0)
                    if url not in visited:
                        batch.append((url, depth))
                for url, depth in batch:
                    tasks.append(process_url(url, depth))
                if tasks:
                    await asyncio.gather(*tasks)

            await browser.close()

        result = {
            "job_id": job_id,
            "status": "stopped" if self._stop_flag.get(job_id) else "completed",
            "discovered_urls": list(set(discovered_urls)),
            "forms_found": forms_found,
            "pages_visited": pages_visited,
        }

        await self.event_bus.publish({
            "type": "crawl.progress",
            **result,
            "total_pages": max_pages,
            "current_url": "",
            "status": result["status"],
        })

        return result

    async def _fetch_robots_txt(self, start_url: str) -> list[str]:
        try:
            import httpx
            parsed = urlparse(start_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(robots_url)
                if resp.status_code == 200:
                    return self._parse_robots_txt(resp.text)
        except Exception as e:
            logger.debug("Failed to fetch robots.txt: %s", e)
        return []

    def _parse_robots_txt(self, text: str) -> list[str]:
        disallowed: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.append(path)
        return disallowed

    async def _fetch_sitemap(self, start_url: str) -> list[str]:
        urls = []
        try:
            import httpx
            from xml.etree import ElementTree
            parsed = urlparse(start_url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(sitemap_url)
                if resp.status_code == 200:
                    root = ElementTree.fromstring(resp.content)
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    for loc in root.findall(".//sm:loc", ns):
                        text = loc.text
                        if text:
                            urls.append(text)
                    logger.info("Extracted %d URLs from sitemap.xml", len(urls))
        except Exception as e:
            logger.debug("Failed to fetch sitemap.xml: %s", e)
        return urls

    def _is_disallowed(self, url: str, disallowed_prefixes: list[str]) -> bool:
        parsed = urlparse(url)
        path = parsed.path
        for prefix in disallowed_prefixes:
            if path.startswith(prefix):
                return True
        return False

    async def _auto_scroll(self, page) -> None:
        try:
            await page.evaluate("""
                async () => {
                    await new Promise((resolve) => {
                        let totalHeight = 0;
                        const distance = 300;
                        const timer = setInterval(() => {
                            const scrollHeight = document.body.scrollHeight;
                            window.scrollBy(0, distance);
                            totalHeight += distance;
                            if (totalHeight >= scrollHeight) {
                                clearInterval(timer);
                                resolve();
                            }
                        }, 100);
                    });
                }
            """)
        except Exception:
            pass

    async def _dismiss_cookie_consent(self, page) -> None:
        try:
            await page.evaluate("""
                () => {
                    const patterns = ['accept', 'ok', 'got it', 'consent', 'agree', 'allow', 'yes'];
                    const buttons = document.querySelectorAll('button, a, input[type="button"], input[type="submit"]');
                    for (const btn of buttons) {
                        const text = (btn.textContent || btn.value || '').toLowerCase().trim();
                        for (const p of patterns) {
                            if (text === p || text.startsWith(p) || text.includes(p)) {
                                btn.click();
                                return;
                            }
                        }
                    }
                    const divs = document.querySelectorAll('[class*="cookie"], [id*="cookie"], [class*="consent"], [id*="consent"]');
                    for (const div of divs) {
                        const btns = div.querySelectorAll('button, a');
                        for (const btn of btns) {
                            const text = (btn.textContent || '').toLowerCase().trim();
                            for (const p of patterns) {
                                if (text === p || text.startsWith(p)) {
                                    btn.click();
                                    return;
                                }
                            }
                        }
                    }
                }
            """)
        except Exception:
            pass

    async def _execute_login_step(self, page, step: LoginMacroStep) -> None:
        extra_headers = step.headers or {}
        if step.method.upper() == "GET":
            await page.goto(step.url, wait_until="networkidle", timeout=15000)
        else:
            await page.goto(step.url, wait_until="networkidle", timeout=15000)
            if step.body:
                await page.evaluate(
                    "async (body) => { await fetch(location.href, { method: 'POST', body: body, headers: {'Content-Type': 'application/x-www-form-urlencoded'} }) }",
                    step.body,
                )

    async def _detect_auth_success(self, page) -> dict:
        try:
            result = await page.evaluate("""
                () => {
                    const body = document.body;
                    if (!body) return { authenticated: false };

                    const text = (document.body.textContent || '').toLowerCase();

                    const indicators = {
                        logout: !!document.querySelector('[href*="logout"], [href*="signout"], a:contains("Logout"), a:contains("Sign Out")'),
                        user_avatar: !!document.querySelector('[class*="avatar"], [class*="user-icon"], img[class*="avatar"]'),
                        user_name: !!document.querySelector('[class*="username"], [class*="user-name"], [id*="welcome"]'),
                        welcome: text.includes('welcome') || text.includes('dashboard') || text.includes('my account'),
                        no_login_form: !document.querySelector('input[type="password"], input[name*="password"]'),
                    };

                    const auth_score = [indicators.logout, indicators.user_avatar, indicators.user_name, indicators.welcome].filter(Boolean).length;
                    return {
                        authenticated: auth_score >= 2 || (indicators.welcome && indicators.no_login_form),
                        method: Object.entries(indicators).filter(([k,v]) => v).map(([k]) => k).join(', '),
                        indicators: indicators,
                    };
                }
            """)
            return result
        except Exception:
            return {"authenticated": False}

    async def _capture_auth_tokens(self, page) -> dict:
        try:
            tokens = await page.evaluate("""
                () => {
                    const result = {};
                    try {
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            if (key && (key.includes('token') || key.includes('auth') || key.includes('session') || key.includes('jwt'))) {
                                result[key] = localStorage.getItem(key);
                            }
                        }
                    } catch(e) {}
                    try {
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            if (key && (key.includes('token') || key.includes('auth') || key.includes('session') || key.includes('jwt'))) {
                                result['session_' + key] = sessionStorage.getItem(key);
                            }
                        }
                    } catch(e) {}
                    return result;
                }
            """)
            return tokens
        except Exception:
            return {}

    def _is_in_scope(
        self,
        url: str,
        include: list[str],
        exclude: list[str],
        base_domain: str,
    ) -> bool:
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != base_domain:
            return False

        for pattern in exclude:
            if pattern in url or re.search(pattern, url):
                return False

        if include:
            for pattern in include:
                if pattern in url or re.search(pattern, url):
                    return True
            return False

        return True

    async def _extract_forms(self, page) -> list[dict]:
        forms = await page.evaluate("""
            () => {
                const forms = document.querySelectorAll('form');
                return Array.from(forms).map(form => ({
                    id: form.id || '',
                    name: form.name || '',
                    action: form.action || '',
                    method: (form.method || 'get').toUpperCase(),
                    inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(el => ({
                        type: el.type || 'text',
                        name: el.name || '',
                        id: el.id || '',
                        placeholder: el.placeholder || '',
                        value: el.value || '',
                        tag: el.tagName.toLowerCase(),
                    })),
                }));
            }
        """)
        return forms

    async def _extract_ajax_urls(self, page) -> list[str]:
        try:
            urls = await page.evaluate("""
                () => {
                    const found = [];

                    // data-* attributes containing URLs
                    const dataAttrs = ['data-url', 'data-href', 'data-remote', 'data-endpoint', 'data-api', 'data-src', 'data-action'];
                    document.querySelectorAll('*').forEach(el => {
                        for (const attr of dataAttrs) {
                            const val = el.getAttribute(attr);
                            if (val && (val.startsWith('http') || val.startsWith('/'))) {
                                found.push(val);
                            }
                        }
                    });

                    // Event handlers with URLs in onclick
                    document.querySelectorAll('[onclick], [onchange], [onsubmit]').forEach(el => {
                        const handler = el.getAttribute('onclick') || el.getAttribute('onchange') || '';
                        const urlMatch = handler.match(/(?:location|window\\.location|href)\\s*[=:]\\s*['"]([^'"]+)['"]/);
                        if (urlMatch) found.push(urlMatch[1]);
                        const fetchMatch = handler.match(/(?:fetch|ajax|get|post)\\s*\\(\\s*['"]([^'"]+)['"]/);
                        if (fetchMatch) found.push(fetchMatch[1]);
                    });

                    // fetch() calls in inline scripts
                    document.querySelectorAll('script:not([src])').forEach(script => {
                        const content = script.textContent || '';
                        const fetchMatches = content.matchAll(/(?:fetch|XMLHttpRequest\\.open|axios|\\.get|\\.post|\\.put|\\.delete)\\s*\\(\\s*['"]([^'"]+)['"]/g);
                        for (const m of fetchMatches) found.push(m[1]);

                        // url: / endpoint: / api: / patterns in objects
                        const urlProps = content.matchAll(/(?:url|endpoint|api|path|service)\\s*:\\s*['"]([^'"]+)['"]/g);
                        for (const m of urlProps) found.push(m[1]);
                    });

                    return found.filter(u => u.startsWith('http') || u.startsWith('/'));
                }
            """)
            return urls
        except Exception:
            return []

    async def _extract_js_urls(self, page) -> list[str]:
        try:
            js_urls = await page.evaluate("""
                () => {
                    const found = [];

                    // Monkey-patch fetch to capture URLs
                    // We inject a script to intercept future fetches
                    const origFetch = window.fetch;
                    window.fetch = function(input, init) {
                        const url = typeof input === 'string' ? input : (input.url || '');
                        if (url && (url.startsWith('http') || url.startsWith('/'))) {
                            window.__capturedFetchUrls = window.__capturedFetchUrls || [];
                            window.__capturedFetchUrls.push(url);
                        }
                        return origFetch.apply(this, arguments);
                    };

                    // Also patch XMLHttpRequest
                    const origOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url) {
                        if (url && (typeof url === 'string') && (url.startsWith('http') || url.startsWith('/'))) {
                            window.__capturedFetchUrls = window.__capturedFetchUrls || [];
                            window.__capturedFetchUrls.push(url);
                        }
                        return origOpen.apply(this, arguments);
                    };

                    // Check existing scripts for URLs
                    document.querySelectorAll('script[src]').forEach(s => {
                        if (s.src) found.push(s.src);
                    });
                    document.querySelectorAll('link[rel="preload"][href], link[rel="prefetch"][href]').forEach(l => {
                        if (l.href) found.push(l.href);
                    });

                    return found;
                }
            """)
            return js_urls
        except Exception:
            return []

    async def _fill_and_submit_form(
        self,
        page,
        form: dict,
        config: FormAutoFillConfig,
    ) -> None:
        values = config.values

        for inp in form.get("inputs", []):
            field_type = inp.get("type", "text")
            field_name = inp.get("name", "")
            field_id = inp.get("id", "")

            fill_value = (
                values.get(field_name)
                or values.get(field_id)
                or values.get(field_type)
            )
            if fill_value:
                selector = f"#{inp['id']}" if inp['id'] else f"[name='{field_name}']"
                try:
                    await page.fill(selector, fill_value)
                except Exception:
                    try:
                        await page.evaluate(
                            "(sel, val) => { const el = document.querySelector(sel); if (el) el.value = val; }",
                            selector,
                            fill_value,
                        )
                    except Exception:
                        pass

        form_selector = f"#{form['id']}" if form['id'] else f"[name='{form['name']}']"
        if not form_selector:
            form_selector = "form"

        try:
            submit_btn = await page.query_selector(f"{form_selector} [type='submit'], {form_selector} button[type='submit']")
            if submit_btn:
                await submit_btn.click()
                await page.wait_for_timeout(2000)
        except Exception:
            try:
                await page.evaluate("(sel) => { const f = document.querySelector(sel); if (f) f.submit(); }", form_selector)
                await page.wait_for_timeout(2000)
            except Exception:
                pass

    async def _fallback_bfs(
        self,
        start_url: str,
        base_domain: str,
        max_depth: int,
        max_pages: int,
        include: list[str],
        exclude: list[str],
        disallowed_prefixes: list[str],
    ) -> list[str]:
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_url, 0)]
        discovered: list[str] = []

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                while queue and len(visited) < max_pages:
                    url, depth = queue.pop(0)
                    if url in visited or depth > max_depth:
                        continue

                    if not self._is_in_scope(url, include, exclude, base_domain):
                        continue

                    if disallowed_prefixes and self._is_disallowed(url, disallowed_prefixes):
                        continue

                    visited.add(url)

                    try:
                        resp = await client.get(url, follow_redirects=True)
                        links = re.findall(r'href=["\'](https?://[^"\']+)["\']', resp.text)
                        for link in links:
                            parsed = urlparse(link)
                            if parsed.netloc == base_domain and link not in visited:
                                queue.append((link, depth + 1))
                                discovered.append(link)
                    except Exception:
                        pass
        except ImportError:
            pass

        return list(set(discovered))
