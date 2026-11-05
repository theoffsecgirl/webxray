import sys
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import webxray  # noqa: E402


@pytest.fixture(autouse=True)
def reset_http_config():
    yield
    webxray.SCAN_HEADERS.clear()
    webxray.SCAN_PROXIES = None
    webxray.ScanSession.verify_tls = True
    webxray.ScanSession.min_interval = 0.0
    webxray.ScanSession._last_request = 0.0


@pytest.fixture()
def server():
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((time.monotonic(), self.path, dict(self.headers)))
            u = urlparse(self.path)
            q = parse_qs(u.query).get("q", [""])[0]
            if u.path == "/":
                body = '<a href="/search?q=hola">buscar</a><a href="/safe?q=hola">safe</a>'
            elif u.path == "/search":
                body = f"<p>Resultados para {q}</p>"  # reflejo sin escapar -> XSS
            else:
                body = f"<p>Resultados para {escape(q)}</p>"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", seen
    srv.shutdown()


def test_headers_and_cookie_reach_every_request(server):
    base, seen = server
    webxray.configure_http(["X-Bugbounty: theoffsecgirl"], "session=abc", None, False, 0)
    urls = webxray.discover_urls(base, max_depth=1, timeout=5)
    session = webxray.make_session()
    for u in urls:
        webxray.check_xss(session, u, timeout=5)
    assert len(seen) >= 3
    assert all(h.get("X-Bugbounty") == "theoffsecgirl" for _, _, h in seen)
    assert all(h.get("Cookie") == "session=abc" for _, _, h in seen)


def test_rate_limit_spaces_requests(server):
    base, seen = server
    webxray.configure_http([], None, None, False, rate=10)  # 1 peticion cada 0.1s
    s = webxray.make_session()
    for _ in range(5):
        s.get(base + "/safe?q=x", timeout=5)
    times = [t for t, _, _ in seen]
    assert times[-1] - times[0] >= 0.35


def test_xss_detection_still_works(server):
    base, _ = server
    s = webxray.make_session()
    hits = webxray.check_xss(s, base + "/search?q=hola", timeout=5)
    assert any(f["parameter"] == "q" and f["confidence"] == "unescaped" for f in hits)
    safe = webxray.check_xss(s, base + "/safe?q=hola", timeout=5)
    assert safe and all(f["confidence"] == "escaped" for f in safe)


def test_invalid_header_exits():
    with pytest.raises(SystemExit):
        webxray.configure_http(["sin-dos-puntos"], None, None, False, 0)


def test_insecure_overrides_explicit_verify():
    webxray.configure_http([], None, None, True, 0)
    captured = {}

    class Probe(webxray.ScanSession):
        def send(self, request, **kwargs):  # noqa: D401
            captured["verify"] = kwargs.get("verify")
            raise webxray.requests.ConnectionError("stop")

    with pytest.raises(webxray.requests.ConnectionError):
        Probe().get("https://example.invalid/", verify=True, timeout=1)
    assert captured["verify"] is False
