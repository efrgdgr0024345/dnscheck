#!/usr/bin/env python3
"""Fixed ACME hook for this fork. Credential values are data, never shell source."""
import base64
import ipaddress
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def make_request(mode, environ):
    if mode not in ("auth", "cleanup"):
        raise ValueError("hook mode must be auth or cleanup")
    endpoint = environ["DNSCHECK_CHALLENGE_URL"]
    if any(ord(c) <= 32 or ord(c) == 127 for c in endpoint):
        raise ValueError("challenge endpoint must not contain whitespace or control characters")
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or "?" in endpoint or "#" in endpoint:
        raise ValueError("challenge endpoint must be HTTPS without credentials, query or fragment")
    if parsed.netloc.endswith(":") or (parsed.port is not None and not 1 <= parsed.port <= 65535):
        raise ValueError("challenge endpoint port is invalid")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii")
        if len(hostname) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in hostname.split(".")):
            raise ValueError("challenge endpoint hostname is invalid")
    token_path = Path(environ["DNSCHECK_SECRET_FILE"])
    with token_path.open("rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("token file must be a private regular file (0600)")
        data = source.read(1025)
        if len(data) > 1024:
            raise ValueError("token file is too large")
        token = data.strip().decode("ascii")
    if len(token) != 43 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in token):
        raise ValueError("token must encode 32 random bytes as unpadded base64url")
    raw = base64.urlsafe_b64decode(token + "=")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != token:
        raise ValueError("token encoding is not canonical")
    validation = environ["CERTBOT_VALIDATION"]
    if len(validation) != 43 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in validation):
        raise ValueError("challenge value must encode 32 bytes as unpadded base64url")
    challenge = base64.urlsafe_b64decode(validation + "=")
    if len(challenge) != 32 or base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii") != validation:
        raise ValueError("challenge encoding is not canonical")
    data = urllib.parse.urlencode({"txt": validation}).encode("ascii")
    return urllib.request.Request(endpoint, data=data, method="POST" if mode == "auth" else "DELETE",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/x-www-form-urlencoded"})

def main():
    try:
        mode = sys.argv[1] if len(sys.argv) == 2 else ""
        delay = int(os.environ.get("DNSCHECK_PROPAGATION_SECONDS", "10"))
        if not 0 <= delay <= 60:
            raise ValueError("propagation delay must be between 0 and 60 seconds")
        request = make_request(mode, os.environ)
        opener = urllib.request.build_opener(NoRedirects())
        with opener.open(request, timeout=15) as response:
            if not 200 <= response.status < 300:
                raise ValueError("challenge update was rejected")
            response.read(16384)
        if mode == "auth":
            time.sleep(delay)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"Challenge API returned HTTP {exc.code}; response body and credentials were not logged")
    except Exception as exc:
        # Avoid printing request objects, credentials, or server-controlled bodies.
        raise SystemExit(f"Challenge hook failed ({type(exc).__name__}); check endpoint, token file, and network")

if __name__ == "__main__":
    main()
