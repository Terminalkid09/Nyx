import re
import httpx
import logging

logger = logging.getLogger(__name__)

SERVER_SIGNATURES: dict[str, list[dict]] = {
    "apache": [
        {"pattern": r"apache", "in": "server"},
        {"pattern": r"(mod_ssl|mod_perl|mod_python)", "in": "server"},
    ],
    "nginx": [
        {"pattern": r"nginx", "in": "server"},
    ],
    "iis": [
        {"pattern": r"iis|microsoft-iis|asp\.net", "in": "server", "flags": re.I},
        {"pattern": r"x-aspnet-version|x-powered-by: asp\.net", "in": "headers", "flags": re.I},
    ],
    "tomcat": [
        {"pattern": r"apache-tomcat|jakarta", "in": "server", "flags": re.I},
    ],
    "jetty": [
        {"pattern": r"jetty", "in": "server", "flags": re.I},
    ],
    "caddy": [
        {"pattern": r"caddy", "in": "server", "flags": re.I},
    ],
    "nodejs": [
        {"pattern": r"node\.?js|express", "in": "x-powered-by", "flags": re.I},
    ],
    "django": [
        {"pattern": r"django|wsgi", "in": "server", "flags": re.I},
        {"pattern": r"csrf|sessionid", "in": "cookies", "flags": re.I},
    ],
    "flask": [
        {"pattern": r"flask|werkzeug", "in": "server", "flags": re.I},
    ],
    "rails": [
        {"pattern": r"rails|ruby", "in": "x-powered-by", "flags": re.I},
        {"pattern": r"_session", "in": "cookies", "flags": re.I},
    ],
    "php": [
        {"pattern": r"php|php/", "in": "x-powered-by", "flags": re.I},
        {"pattern": r"phpsessid", "in": "cookies", "flags": re.I},
    ],
    "wordpress": [
        {"pattern": r"wordpress|wp-content|wp-admin", "in": "body", "flags": re.I},
        {"pattern": r"wordpress_|wp-settings", "in": "cookies", "flags": re.I},
    ],
    "shopify": [
        {"pattern": r"x-shopid|x-shopify", "in": "headers", "flags": re.I},
    ],
    "cloudflare": [
        {"pattern": r"cloudflare", "in": "server", "flags": re.I},
        {"pattern": r"__cfduid|cf-ray", "in": "headers", "flags": re.I},
    ],
    "akamai": [
        {"pattern": r"akamai", "in": "server", "flags": re.I},
    ],
    "fastly": [
        {"pattern": r"fastly", "in": "server", "flags": re.I},
    ],
    "varnish": [
        {"pattern": r"varnish", "in": "via|x-varnish", "flags": re.I},
    ],
    "haproxy": [
        {"pattern": r"haproxy", "in": "server", "flags": re.I},
    ],
    "gunicorn": [
        {"pattern": r"gunicorn", "in": "server", "flags": re.I},
    ],
    "envoy": [
        {"pattern": r"envoy", "in": "server", "flags": re.I},
    ],
    "traefik": [
        {"pattern": r"traefik", "in": "server", "flags": re.I},
    ],
}

OS_SIGNATURES: dict[str, list[dict]] = {
    "linux": [
        {"pattern": r"linux|ubuntu|debian|centos|red hat|fedora", "in": "server", "flags": re.I},
    ],
    "windows": [
        {"pattern": r"windows|win32|win64", "in": "server", "flags": re.I},
    ],
    "freebsd": [
        {"pattern": r"freebsd", "in": "server", "flags": re.I},
    ],
}

WAF_SIGNATURES: dict[str, list[dict]] = {
    "cloudflare": [{"pattern": r"cloudflare", "in": "server", "flags": re.I}],
    "modsecurity": [{"pattern": r"mod_security|modsecurity", "in": "server", "flags": re.I}],
    "aws_waf": [{"pattern": r"aws|amazon", "in": "x-amzn-", "flags": re.I}],
    "imperva": [{"pattern": r"incapsula|imperva", "in": "server", "flags": re.I}],
    "akamai": [{"pattern": r"akamai", "in": "server", "flags": re.I}],
    "f5": [{"pattern": r"bigip|f5", "in": "server", "flags": re.I}],
    "sucuri": [{"pattern": r"sucuri|cloudproxy", "in": "x-sucuri", "flags": re.I}],
    "barracuda": [{"pattern": r"barracuda", "in": "server", "flags": re.I}],
}


async def fingerprint_server(target_url: str, timeout: int = 15) -> dict:
    info: dict[str, str | list[str]] = {
        "server": "",
        "version": "",
        "os": "",
        "technologies": [],
        "waf": [],
        "headers": {},
        "cookies": [],
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(target_url)
    except Exception as e:
        logger.debug("Server fingerprint failed for %s: %s", target_url, e)
        return {"error": str(e), **info}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    info["headers"] = dict(headers)
    info["server"] = headers.get("server", "")
    info["version"] = _extract_version(headers.get("server", ""))
    cookie_list = [f"{c.name}={c.value}" for c in resp.cookies.jar]
    cookie_str = "; ".join(cookie_list)
    info["cookies"] = cookie_list

    all_text_for_body = ""
    try:
        all_text_for_body = resp.text[:100000]
    except Exception:
        pass

    def _match_signatures(sigs: dict[str, list[dict]], key: str) -> list[str]:
        found = []
        for name, rules in sigs.items():
            for rule in rules:
                target = ""
                loc = rule.get("in", "server")
                if loc == "server":
                    target = headers.get("server", "")
                elif loc == "headers":
                    target = str(headers)
                elif loc in ("x-powered-by", "x-sucuri", "x-amzn-"):
                    target = str(headers)
                elif loc == "cookies":
                    target = cookie_str
                elif loc == "body":
                    target = all_text_for_body
                elif loc == "via" or loc == "x-varnish":
                    target = headers.get(loc, "")
                flags = rule.get("flags", 0)
                pattern = rule["pattern"]
                if isinstance(pattern, str):
                    pattern = re.compile(pattern, flags) if isinstance(flags, int) else re.compile(pattern)
                if isinstance(pattern, re.Pattern):
                    if pattern.search(target):
                        found.append(name)
                        break
                else:
                    if pattern in target:
                        found.append(name)
                        break
        return found

    info["technologies"] = _match_signatures(SERVER_SIGNATURES, "technologies")
    info["os"] = ", ".join(_match_signatures(OS_SIGNATURES, "os"))
    info["waf"] = _match_signatures(WAF_SIGNATURES, "waf")

    return info


def _extract_version(server_header: str) -> str:
    m = re.search(r"((?:\d+\.)+\d+)", server_header)
    return m.group(1) if m else ""


def select_checks_for_target(fingerprint: dict) -> dict[str, list[str]]:
    techs = [t.lower() for t in fingerprint.get("technologies", [])]
    recommended: dict[str, list[str]] = {"prioritize": [], "skip": []}

    tech_check_map: dict[str, list[str]] = {
        "apache": ["active_default_admin", "active_default_admin2", "active_default_admin3"],
        "nginx": ["active_default_admin", "active_swagger_exposed"],
        "iis": ["active_weak_ciphers", "active_tls_v10", "active_tls_v11"],
        "tomcat": ["active_spring_actuator", "active_default_admin"],
        "wordpress": ["active_wordpress_enum"],
        "django": ["active_django_debug"],
        "flask": ["active_flask_debug"],
        "express": ["active_express_debug"],
        "laravel": ["active_laravel_debug"],
        "rails": ["active_rails_secret"],
    }

    for tech, checks in tech_check_map.items():
        if tech in techs:
            recommended["prioritize"].extend(checks)

    wafs = [w.lower() for w in fingerprint.get("waf", [])]
    if wafs:
        recommended["skip"].extend(["active_sqli", "active_xss", "active_ssrf_variants"])
        recommended["note"] = "WAF detected, injection checks may be blocked"

    return recommended
