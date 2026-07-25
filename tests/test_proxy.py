import requests
import time

PROXY = "http://127.0.0.1:8080"
API_URL = "http://localhost:8000"

def test_health():
    print("=== Step 1: Health Check ===")
    try:
        r = requests.get(f"{API_URL}/health", timeout=5)
        print(f"  Backend health: {r.json()}")
        return True
    except Exception as e:
        print(f"  FAIL: Backend not reachable: {e}")
        return False

def test_proxy():
    print("\n=== Step 2: Proxy Test ===")
    proxies = {"http": PROXY, "https": PROXY}
    test_url = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    print(f"  Sending traffic to {test_url} via proxy {PROXY}")
    try:
        resp = requests.get(test_url, proxies=proxies, timeout=30)
        print(f"  Response status: {resp.status_code}")
        print(f"  Response length: {len(resp.text)} chars")
        return True
    except Exception as e:
        print(f"  FAIL: Proxy connection failed: {e}")
        return False

def test_api_endpoints():
    print("\n=== Step 3: API Endpoints Test ===")
    endpoints = [
        ("GET", "/api/sessions"),
        ("GET", "/api/requests"),
        ("GET", "/api/findings"),
        ("GET", "/api/match-replace/"),
        ("GET", "/api/triage/findings/recent?hours=48"),
        ("GET", "/api/triage/findings/grouped"),
        ("GET", "/api/pipeline"),
        ("GET", "/api/interceptor/paused"),
        ("GET", "/api/automation/config"),
        ("GET", "/api/automation/discovered"),
        ("GET", "/api/scope"),
        ("GET", "/api/scan-policies"),
    ]
    ok = 0
    fail = 0
    for method, path in endpoints:
        try:
            if method == "GET":
                r = requests.get(f"{API_URL}{path}", timeout=5)
            status = r.status_code
            label = "OK" if status < 400 else "ERR"
            if status < 400:
                ok += 1
            else:
                fail += 1
            print(f"  [{label}] {method} {path} -> {status}")
        except Exception as e:
            fail += 1
            print(f"  [ERR] {method} {path} -> {e}")
    
    print(f"\n  Results: {ok} OK, {fail} FAIL out of {len(endpoints)}")
    return fail == 0

def test_repeater():
    print("\n=== Step 4: Repeater Test ===")
    try:
        payload = {
            "method": "GET",
            "url": "http://testphp.vulnweb.com/",
            "headers": {"User-Agent": "Nyx-Test/1.0"},
            "body": ""
        }
        r = requests.post(f"{API_URL}/api/repeater/send", json=payload, timeout=15)
        print(f"  Repeater response status: {r.status_code}")
        if r.status_code < 400:
            data = r.json()
            print(f"  Response keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
            return True
        else:
            print(f"  Repeater error: {r.text[:200]}")
            return False
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

def test_decoder():
    print("\n=== Step 5: Decoder Test ===")
    try:
        payload = {"input": "SGVsbG8gV29ybGQ=", "codec": "base64_decode"}
        r = requests.post(f"{API_URL}/api/decoder/transform", json=payload, timeout=5)
        print(f"  Decoder response status: {r.status_code}")
        if r.status_code < 400:
            data = r.json()
            print(f"  Decoded: {data}")
            return True
        else:
            print(f"  Error: {r.text[:200]}")
            return False
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

def test_active_scanner():
    print("\n=== Step 6: Active Scanner (Quick) ===")
    try:
        payload = {
            "base_request": {
                "method": "GET",
                "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
                "headers": {},
                "body": ""
            },
            "target_params": ["cat"],
            "checks": ["sqli_error_based"]
        }
        r = requests.post(f"{API_URL}/api/active-scanner/run", json=payload, timeout=60)
        print(f"  Active Scanner response status: {r.status_code}")
        if r.status_code < 400:
            data = r.json()
            print(f"  Result: {data}")
            return True
        else:
            print(f"  Error: {r.text[:300]}")
            return False
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

def test_websocket():
    print("\n=== Step 7: WebSocket Test ===")
    try:
        import websockets
        import asyncio

        async def ws_test():
            async with websockets.connect("ws://localhost:8000/ws/traffic") as ws:
                print("  WebSocket connected!")
                return True

        return asyncio.get_event_loop().run_until_complete(ws_test())
    except ImportError:
        print("  SKIP: websockets library not installed")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("  NYX END-TO-END TEST SUITE")
    print("=" * 50)
    
    results = {}
    results["health"] = test_health()
    results["proxy"] = test_proxy()
    results["api"] = test_api_endpoints()
    results["repeater"] = test_repeater()
    results["decoder"] = test_decoder()
    results["active_scanner"] = test_active_scanner()
    results["websocket"] = test_websocket()
    
    print("\n" + "=" * 50)
    print("  SUMMARY")
    print("=" * 50)
    for name, passed in results.items():
        icon = "PASS" if passed else "FAIL"
        print(f"  [{icon}] {name}")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    print(f"\n  Total: {passed}/{total} passed")
