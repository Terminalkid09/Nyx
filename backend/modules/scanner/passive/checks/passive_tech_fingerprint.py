"""Advanced technology fingerprinting — Wappalyzer-style detection.

Detects frameworks, libraries, CMS, CDNs, and cloud services from:
  - HTTP response headers (Server, X-Powered-By, Set-Cookie, etc.)
  - HTML meta tags and script sources
  - JavaScript globals and patterns
  - Specific file paths and URL patterns
  - Cookie names

Runs passively on every response — no extra requests.
"""
import re
from modules.scanner.base_check import BaseCheck, CheckResult

# ── Header-based fingerprints ──────────────────────────────────────────────

HEADER_FINGERPRINTS: list[tuple[str, re.Pattern, str]] = [
    # Server header
    (r'(?i)Apache[/]?[\d.]*', re.compile(r'(?i)server:\s*Apache[/]?[\d.]*', re.IGNORECASE), 'Apache HTTP Server'),
    (r'(?i)nginx[/]?[\d.]*', re.compile(r'(?i)server:\s*nginx[/]?[\d.]*'), 'Nginx'),
    (r'(?i)Microsoft-IIS[/]?[\d.]*', re.compile(r'(?i)server:\s*Microsoft-IIS[/]?[\d.]*'), 'Microsoft IIS'),
    (r'(?i)cloudflare', re.compile(r'(?i)server:\s*cloudflare'), 'Cloudflare'),
    (r'(?i)Caddy', re.compile(r'(?i)server:\s*Caddy'), 'Caddy'),
    (r'(?i)LiteSpeed', re.compile(r'(?i)server:\s*LiteSpeed'), 'LiteSpeed'),
    (r'(?i)openresty[/]?[\d.]*', re.compile(r'(?i)server:\s*openresty'), 'OpenResty'),
    (r'(?i)gunicorn[/]?[\d.]*', re.compile(r'(?i)server:\s*gunicorn'), 'Gunicorn'),
    # X-Powered-By
    (r'(?i)PHP[/]?[\d.]*', re.compile(r'(?i)x-powered-by:\s*PHP[/]?[\d.]*'), 'PHP'),
    (r'(?i)ASP\.NET', re.compile(r'(?i)x-powered-by:\s*ASP\.NET'), 'ASP.NET'),
    (r'(?i)Express', re.compile(r'(?i)x-powered-by:\s*Express'), 'Express.js'),
    (r'(?i)Next\.js', re.compile(r'(?i)x-powered-by:\s*Next\.js'), 'Next.js'),
    (r'(?i)Nuxt', re.compile(r'(?i)x-powered-by:\s*Nuxt'), 'Nuxt.js'),
    (r'(?i)Remix', re.compile(r'(?i)x-powered-by:\s*Remix'), 'Remix'),
    (r'(?i)Rails', re.compile(r'(?i)x-powered-by:\s*Rails'), 'Ruby on Rails'),
    (r'(?i)Django[/]?[\d.]*', re.compile(r'(?i)x-powered-by:\s*Django'), 'Django'),
    (r'(?i)Laravel', re.compile(r'(?i)x-powered-by:\s*Laravel'), 'Laravel'),
    (r'(?i)Flask', re.compile(r'(?i)x-powered-by:\s*Flask'), 'Flask'),
    (r'(?i)Spring[/]?[\d.]*', re.compile(r'(?i)x-powered-by:\s*Spring'), 'Spring Boot'),
    # CSP (reveals allowed CDNs/services)
    (r'(?i)cdn\.jsdelivr\.net', re.compile(r'cdn\.jsdelivr\.net'), 'jsDelivr CDN'),
    (r'(?i)cdnjs\.cloudflare\.com', re.compile(r'cdnjs\.cloudflare\.com'), 'CDNJS'),
    (r'(?i)unpkg\.com', re.compile(r'unpkg\.com'), 'UNPKG CDN'),
    (r'(?i)firebase', re.compile(r'firebase'), 'Firebase'),
    (r'(?i)supabase', re.compile(r'supabase'), 'Supabase'),
    (r'(?i)vercel', re.compile(r'vercel'), 'Vercel'),
    (r'(?i)netlify', re.compile(r'netlify'), 'Netlify'),
    (r'(?i)heroku', re.compile(r'heroku'), 'Heroku'),
    (r'(?i)aws\.amazon\.com|amazonaws\.com', re.compile(r'aws\.amazon\.com|amazonaws\.com'), 'AWS'),
    (r'(?i)azure', re.compile(r'azure'), 'Microsoft Azure'),
    (r'(?i)googleapis\.com', re.compile(r'googleapis\.com'), 'Google Cloud / APIs'),
    # Set-Cookie reveals backend framework
    (r'(?i)PHPSESSID', re.compile(r'(?i)Set-Cookie:.*PHPSESSID'), 'PHP Sessions'),
    (r'(?i)JSESSIONID', re.compile(r'(?i)Set-Cookie:.*JSESSIONID'), 'Java (J2EE) Sessions'),
    (r'(?i)ASP\.NET_SessionId', re.compile(r'(?i)Set-Cookie:.*ASP\.NET_SessionId'), 'ASP.NET Sessions'),
    (r'(?i)laravel_session', re.compile(r'(?i)Set-Cookie:.*laravel_session'), 'Laravel Sessions'),
    (r'(?i)rack\.session', re.compile(r'(?i)Set-Cookie:.*rack\.session'), 'Rack/Ruby Sessions'),
    (r'(?i)sessionid=', re.compile(r'(?i)Set-Cookie:.*sessionid='), 'Django Sessions'),
    (r'(?i)connect\.sid', re.compile(r'(?i)Set-Cookie:.*connect\.sid'), 'Express.js Sessions'),
    (r'(?i)wordpress_logged_in|wp-settings', re.compile(r'(?i)Set-Cookie:.*(wordpress_logged_in|wp-settings)'), 'WordPress'),
    (r'(?i)shopify', re.compile(r'(?i)Set-Cookie:.*shopify'), 'Shopify'),
    # X-Frame-Options (SAMEORIGIN often from older frameworks)
    (r'(?i)SAMEORIGIN', re.compile(r'(?i)x-frame-options:\s*SAMEORIGIN'), ''),
]

# ── HTML body fingerprints (meta tags, script sources, CSS class names) ────

BODY_FINGERPRINTS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'(?i)<meta\s+name="?generator"?\s+content="?WordPress\s*[\d.]*"?[^>]*>'), 'WordPress', 'CMS'),
    (re.compile(r'(?i)wp-content/(?:plugins|themes)/'), 'WordPress', 'CMS'),
    (re.compile(r'(?i)/wp-includes/(?:js|css)/'), 'WordPress', 'CMS'),
    (re.compile(r'(?i)Drupal\.settings\b|/sites/default/files/'), 'Drupal', 'CMS'),
    (re.compile(r'(?i)Magento_|/skin/frontend/'), 'Magento', 'CMS'),
    (re.compile(r'(?i)shopify\.com|cdn\.shopify\.com'), 'Shopify', 'Platform'),
    (re.compile(r'(?i)wix\.com|static\.wixstatic\.com'), 'Wix', 'Platform'),
    (re.compile(r'(?i)squarespace\.com|static1\.squarespace\.com'), 'Squarespace', 'Platform'),
    (re.compile(r'(?i)webflow\.com|cdn\.webflow\.com'), 'Webflow', 'Platform'),
    # JS frameworks
    (re.compile(r'(?i)/(?:react|react-dom)@[\d.]+\.js|/react\.production\.min\.js'), 'React', 'Library'),
    (re.compile(r'(?i)/(?:vue|vuex)@[\d.]+\.js|/vue\.(?:runtime\.)?(?:global\.)?(?:prod|min)\.js'), 'Vue.js', 'Library'),
    (re.compile(r'(?i)/(?:angular(?:[.-]?min)?\.js|@angular/)'), 'Angular', 'Library'),
    (re.compile(r'(?i)/svelte(?:-internal)?\.js|sveltekit'), 'Svelte', 'Library'),
    (re.compile(r'(?i)/jquery[\d.-]*\.(?:min\.)?js'), 'jQuery', 'Library'),
    (re.compile(r'(?i)/bootstrap[\d.-]*\.(?:min\.)?(?:js|css)'), 'Bootstrap', 'CSS Framework'),
    (re.compile(r'(?i)/tailwindcss[\d.-]*|tailwind\.config'), 'Tailwind CSS', 'CSS Framework'),
    # CDN libs
    (re.compile(r'(?i)cdn\.jsdelivr\.net/npm/(\w[\w.-]*)'), 'jsDelivr', 'CDN'),
    (re.compile(r'(?i)unpkg\.com/(\w[\w.-]*)'), 'UNPKG', 'CDN'),
    (re.compile(r'(?i)cdnjs\.cloudflare\.com/ajax/libs/(\w[\w.-]*)'), 'CDNJS', 'CDN'),
    # Analytics & Tracking
    (re.compile(r'(?i)googletagmanager\.com/gtm|gtag\s*\(|ga\s*\(\s*["\']create'), 'Google Analytics', 'Analytics'),
    (re.compile(r'(?i)analytics\.google\.com/analytics\.js'), 'Google Analytics (UA)', 'Analytics'),
    (re.compile(r'(?i)googletagmanager\.com/gtag/js'), 'Google Tag Manager', 'Tag Manager'),
    (re.compile(r'(?i)cdn\.segment\.com/analytics\.js'), 'Segment', 'Analytics'),
    (re.compile(r'(?i)connect\.facebook\.net/fbevents\.js|fbq\s*\('), 'Facebook Pixel', 'Analytics'),
    # WebSockets
    (re.compile(r'(?i)socket\.io/|socket\.io-client'), 'Socket.IO', 'Realtime'),
    (re.compile(r'(?i)pusher\.com/|Pusher\('), 'Pusher', 'Realtime'),
    # Maps
    (re.compile(r'(?i)maps\.googleapis\.com/maps|google\.maps\.'), 'Google Maps', 'Maps'),
    (re.compile(r'(?i)api\.mapbox\.com/mapbox'), 'Mapbox', 'Maps'),
    (re.compile(r'(?i)leafletjs\.com|L\.map\('), 'Leaflet', 'Maps'),
    # Fonts
    (re.compile(r'(?i)fonts\.googleapis\.com'), 'Google Fonts', 'Font'),
    (re.compile(r'(?i)use\.fontawesome\.com|font-awesome'), 'Font Awesome', 'Icon'),
    # Captcha / Security
    (re.compile(r'(?i)recaptcha/api\.js|grecaptcha'), 'reCAPTCHA', 'Security'),
    (re.compile(r'(?i)hcaptcha\.com/1/api\.js'), 'hCaptcha', 'Security'),
    (re.compile(r'(?i)turnstile\.cloudflare\.com'), 'Cloudflare Turnstile', 'Security'),
    # Font-end meta frameworks
    (re.compile(r'(?i)__NEXT_DATA__|/_next/static/'), 'Next.js', 'Framework'),
    (re.compile(r'(?i)__NUXT__|/_nuxt/'), 'Nuxt.js', 'Framework'),
    (re.compile(r'(?i)__GATSBY__|/gatsby-'), 'Gatsby', 'Framework'),
]


class PassiveTechFingerprintCheck(BaseCheck):
    """Passively fingerprint technologies from response headers and HTML."""

    name = "passive_tech_fingerprint"

    def _scan_headers(self, headers_text: str) -> list[tuple[str, str]]:
        """Scan raw header block for technology signatures."""
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        for _, pattern, name in HEADER_FINGERPRINTS:
            if not name or name in seen:
                continue
            if pattern.search(headers_text):
                found.append((name, 'Server / Infrastructure'))
                seen.add(name)
        return found

    def _scan_body(self, body: str) -> list[tuple[str, str]]:
        """Scan HTML body for technology signatures."""
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        body_lower = body.lower()
        for pattern, name, category in BODY_FINGERPRINTS:
            if name in seen:
                continue
            if pattern.search(body_lower):
                found.append((name, category))
                seen.add(name)
        return found

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results: list[CheckResult] = []

        body = event.get("body") or ""
        if not isinstance(body, str):
            body = str(body)

        # Reconstruct headers block from the event
        headers = event.get("headers") or {}
        if isinstance(headers, dict):
            headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        else:
            headers_text = str(headers)

        technologies: list[tuple[str, str]] = []
        technologies.extend(self._scan_headers(headers_text))
        technologies.extend(self._scan_body(body[:300_000]))  # first 300KB is enough

        if technologies:
            # Deduplicate and group
            seen: set[str] = set()
            unique: list[str] = []
            categories: set[str] = set()
            for name, cat in technologies:
                if name.lower() not in seen:
                    unique.append(name)
                    seen.add(name.lower())
                    categories.add(cat)

            results.append(CheckResult(
                triggered=True,
                severity='info',
                title=f'Technology Stack: {", ".join(unique[:20])}',
                description=(
                    f'Detected {len(unique)} technologies across '
                    f'{len(categories)} categories: {", ".join(sorted(categories))}. '
                    f'Full stack: {", ".join(unique)}'
                ),
                evidence=f'Technologies: {", ".join(unique)}',
                remediation='Review technology stack for known vulnerabilities, outdated versions, and end-of-life components.',
                cwe='CWE-1104',
            ))

        return results