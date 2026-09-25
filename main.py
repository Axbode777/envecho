import os, socket, struct, json
from http.server import BaseHTTPRequestHandler, HTTPServer

FALCON = ("falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", 12691)

def pg_startup_probe(user, db, sslmode=False, timeout=8):
    """Return the PG auth response type: R-message auth code."""
    try:
        raw = socket.create_connection(FALCON, timeout=timeout)
        if sslmode:
            raw.sendall(struct.pack('!II', 8, 80877103))
            resp = raw.recv(1)
            if resp != b'S':
                raw.close()
                return f"no-SSL ({resp!r})"
        s = raw
        import ssl as _ssl
        ctx = _ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=_ssl.CERT_NONE
        if sslmode:
            s = ctx.wrap_socket(raw, server_hostname=FALCON[0])
        ps = b'user\x00'+user.encode()+b'\x00database\x00'+db.encode()+b'\x00\x00'
        s.sendall(struct.pack('!II', 8+len(ps)) + struct.pack('!I', 196608) + ps)
        hdr = s.recv(5)
        t = hdr[0:1]
        ln = struct.unpack('!I', hdr[1:5])[0]
        body = s.recv(ln-4)
        s.close()
        if t == b'R':
            code = struct.unpack('!I', body[:4])[0]
            names = {0:'trust',2:'kerberos5',3:'cleartext',5:'md5',10:'scram'}
            return names.get(code, f'code{code}')
        return f"type={t!r} body={body[:60]!r}"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"

TESTS = [
    ("avnadmin","postgres",True),
    ("avnadmin","defaultdb",True),
    ("falcon","postgres",True),
    ("postgres","postgres",True),
    ("avnadmin","postgres",False),
]
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/pghandshake":
            out = "=== PG HANDSHAKE (from inside Aiven app pod) ===\n"
            for u, d, sslm in TESTS:
                out += f"user={u} db={d} ssl={sslm} -> {pg_startup_probe(u, d, sslm)}\n"
            self.send_response(200); self.end_headers()
            self.wfile.write(out.encode()); return
        self.send_response(200); self.end_headers()
        self.wfile.write(b"/pghandshake\n")
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
