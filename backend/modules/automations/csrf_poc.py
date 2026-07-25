import logging
from urllib.parse import urlparse, parse_qs
from core.events.bus import EventBus

logger = logging.getLogger(__name__)

class CsrfPocService:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus

    def generate_poc(self, request: dict, form_data: dict | None = None) -> str:
        """Generate an HTML CSRF PoC from a request dict.
        
        request: dict with method, url, headers, body
        form_data: optional dict of form field name -> value overrides
        
        Returns self-contained HTML page with auto-submitting form.
        """
        method = request.get("method", "POST")
        url = request.get("url", "")
        body = request.get("body", "")
        content_type = ""
        for h in (request.get("headers") or {}).items():
            if h[0].lower() == "content-type":
                content_type = h[1]
        
        # Parse body or URL params into form fields
        fields = []
        if method == "GET" or not body:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for name, values in qs.items():
                val = values[0] if values else ""
                if form_data and name in form_data:
                    val = form_data[name]
                fields.append((name, val))
        else:
            if "application/json" in content_type:
                # JSON body - can't easily make a form PoC, use fetch instead
                return self._generate_fetch_poc(method, url, body, form_data)
            # Form URL encoded or multipart
            for pair in body.split("&"):
                if "=" in pair:
                    name, val = pair.split("=", 1)
                    import urllib.parse
                    name = urllib.parse.unquote(name)
                    val = urllib.parse.unquote(val)
                    if form_data and name in form_data:
                        val = form_data[name]
                    fields.append((name, val))
        
        if not fields:
            fields.append(("_csrf_tester", "1"))
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Nyx CSRF PoC</title>
</head>
<body>
    <h2>Nyx CSRF Proof of Concept</h2>
    <p>Target: {url}</p>
    <form id="csrf-form" action="{url}" method="{method}">
"""
        for name, val in fields:
            html += f'        <input type="hidden" name="{name}" value="{val}" />\n'
        
        html += """        <input type="submit" value="Submit request" />
    </form>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-submit after 1 second (or click manually)
            // document.getElementById('csrf-form').submit();
        });
    </script>
</body>
</html>"""
        return html

    def _generate_fetch_poc(self, method: str, url: str, body: str, form_data: dict | None = None) -> str:
        """Generate CSRF PoC using JavaScript fetch() for JSON APIs."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Nyx CSRF PoC (JSON)</title>
</head>
<body>
    <h2>Nyx CSRF Proof of Concept (JSON)</h2>
    <p>Target: {url}</p>
    <button onclick="sendRequest()">Send CSRF Request</button>
    <pre id="output"></pre>
    <script>
        function sendRequest() {{
            fetch('{url}', {{
                method: '{method}',
                credentials: 'include',
                headers: {{ 'Content-Type': 'application/json' }},
                body: `{body.replace('`', '\\`')}`
            }})
            .then(r => r.text())
            .then(t => document.getElementById('output').textContent = t)
            .catch(e => document.getElementById('output').textContent = 'Error: ' + e);
        }}
    </script>
</body>
</html>"""
