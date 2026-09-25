import os, socket, struct
from http.server import BaseHTTPRequestHandler, HTTPServer

FALCON = ("falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", 12691)

def recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise EOFError(f'EOF at {len(buf)}/{n}')
        buf += c
    return buf

def pg_auth_type(user, db, use_ssl=True, timeout=8):
    try:
        raw = socket.create_connection(FALCON, timeout=timeout)
        if use_ssl:
            raw.sendall(struct.pack('!II', 8, 80877103))
            r = recv_exact(raw, 1)
            if r != b'S':
                raw.close()
                return f'ssl-refused({r!r})'
            ctx = __import__('ssl').create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = __import__('ssl').CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=FALCON[0])
        else:
            s = raw
        ps = b'user\x00' + user.encode() + b'\x00database\x00' + db.encode() + b'\x00\x00'
        s.sendall(struct.pack('!I', 8 + len(ps)) + struct.pack('!I', 196608) + ps)
        hdr = recv_exact(s, 5)
        t = hdr[0:1]
        ln = struct.unpack('!I', hdr[1:5])[0]
        body = recv_exact(s, ln - 4) if ln > 4 else b''
        s.close()
        if t == b'R' and len(body) >= 4:
            code = struct.unpack('!I', body[:4])[0]
            names = {0:'TRUST',2:'kerberos5',3:'CLEARTEXT',5:'MD5',10:'SCRAM'}
            extra = body[4:20] if code in (5,) else b''
            return f'{names.get(code, code)} salt={extra.hex()}'
        return f'msg={t!r} body={body[:80]!r}'
    except Exception as e:
        return f'ERR {type(e).__name__}: {e}'

TESTS = [("avnadmin","postgres"),("avnadmin","defaultdb"),("falcon","postgres"),
         ("postgres","postgres"),("flag","postgres"),("avnadmin","postgres")]
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/pghandshake":
            out = ["=== PG AUTH-TYPE PROBE v2 ==="]
            for i, (u, d) in enumerate(TESTS):
                out.append(f"{i}: user={u} db={d} ssl=True -> {pg_auth_type(u, d, True)}")
            self.send_response(200); self.end_headers()
            self.wfile.write(("\n".join(out)).encode()); return
        self.send_response(200); self.end_headers()
        self.wfile.write(b"/pghandshake\n")
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
