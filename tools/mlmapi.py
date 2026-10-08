"""Minimal SUSE Multi-Linux Manager JSON-over-HTTP API client (stdlib only).

Credentials come from a file (MLM_CRED_FILE, lines "user name: ..." and "password: ...") and are
never printed or put on a command line. TLS is verified against the MLM CA (MLM_CA) using the MLM
FQDN as SNI/hostname, while connecting to MLM_HOST (IP or name) — useful when the workstation
cannot resolve the FQDN.

Env: MLM_FQDN, MLM_CA, MLM_CRED_FILE, optional MLM_HOST (defaults to MLM_FQDN).

Observed on MLM 5.2.0:
  * some read methods must be called with POST (system.getScriptResults: GET -> HTTP 403 HTML);
  * a self-signed MLM CA without "Basic Constraints: critical" is rejected by Python >= 3.13 strict
    mode. Only VERIFY_X509_STRICT is cleared here; chain and hostname verification stay on.
"""
import http.client, json, os, socket, ssl
from urllib.parse import urlencode

FQDN = os.environ.get("MLM_FQDN", "")
HOST = os.environ.get("MLM_HOST", FQDN)
CTX = ssl.create_default_context(cafile=os.environ.get("MLM_CA"))
CTX.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)


class _Conn(http.client.HTTPSConnection):
    def connect(self):
        s = socket.create_connection((HOST, 443), 600)
        self.sock = CTX.wrap_socket(s, server_hostname=FQDN)


class API:
    def __init__(self, cred_file=None):
        cred = {}
        with open(cred_file or os.environ["MLM_CRED_FILE"]) as fh:
            for line in fh:
                k, _, v = line.partition(":")
                cred[k.strip()] = v.strip()
        self.cookie = None
        r = self._req("POST", "auth/login", {"login": cred["user name"], "password": cred["password"]})
        if not r.get("success"):
            raise SystemExit("MLM login failed")

    def _req(self, method, path, body=None, params=None):
        c = _Conn(FQDN, timeout=600)
        url = "/rhn/manager/api/" + path + ("?" + urlencode(params) if params else "")
        h = {"Content-Type": "application/json", "Host": FQDN}
        if self.cookie:
            h["Cookie"] = self.cookie
        c.request(method, url, json.dumps(body) if body is not None else None, h)
        resp = c.getresponse()
        data = resp.read()
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie" and v.startswith("pxt-session-cookie="):
                self.cookie = v.split(";")[0]
        try:
            return json.loads(data)
        except ValueError:
            return {"success": False, "status": resp.status, "raw": data[:300].decode(errors="replace")}

    def get(self, path, **params):
        return self._req("GET", path, params=params or None)

    def post(self, path, body=None):
        return self._req("POST", path, body or {})

    def logout(self):
        self._req("POST", "auth/logout", {})
