"""Exercise the real Nginx template with only disposable loopback services.

Created for the dnscheck security changes, 2026-10-12. Original application:
Brian Shea / addr.tools. See COPYRIGHT, LICENSE, and CREDITS.md.
"""

import contextlib
import grp
import http.client
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest


REPO = Path(__file__).resolve().parents[2]
FAKE_AUTHORIZATION = "Bearer local-proxy-test-value"
UNIX_UPSTREAM = "http://unix:/var/lib/dnscheck/addrd.sock:"


def nginx_path(path):
    """Quote paths in generated configuration without permitting variables."""
    value = str(path)
    if any(char in value for char in ("\n", "\r", "$")):
        raise ValueError("test paths cannot contain newlines or Nginx variables")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Backend(http.server.BaseHTTPRequestHandler):
    """An echo stub: these tests check the proxy, not application authorization."""

    def handle_request(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 <= size <= 16384:
            self.send_error(413)
            return
        body = self.rfile.read(size).decode("utf-8")
        status = int(self.headers.get("X-Test-Backend-Status", "200"))
        if status not in (200, 400, 403, 429, 503):
            status = 500
        response = json.dumps({
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get_all("Authorization", []),
            "client_ips": self.headers.get_all("X-Addr-Client-IP", []),
            "real_ips": self.headers.get_all("X-Real-IP", []),
            "body": body,
        }).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Test-Backend-Reached", "1")
        self.end_headers()
        self.wfile.write(response)

    do_GET = do_POST = do_PUT = do_DELETE = handle_request

    def log_message(self, format, *args):
        # Credentials and request bodies are never written to a test log.
        pass


class ProxyTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        requested = os.environ.get("DNSCHECK_NGINX", "nginx")
        cls.nginx = shutil.which(requested)
        if cls.nginx is None:
            if "DNSCHECK_NGINX" in os.environ:
                raise RuntimeError("DNSCHECK_NGINX does not identify an executable")
            raise unittest.SkipTest("Nginx is not on PATH; set DNSCHECK_NGINX to run the proxy gate")
        openssl = shutil.which("openssl")
        if openssl is None:
            raise RuntimeError("OpenSSL CLI is required for disposable test certificates")

        temporary = tempfile.TemporaryDirectory(prefix="dnscheck-nginx-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.website = cls.directory / "website"
        shutil.copytree(REPO / "website", cls.website)
        cls.certificate = cls.directory / "certificate.pem"
        cls.private_key = cls.directory / "private-key.pem"
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cls.private_key), "-out", str(cls.certificate),
            "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ], check=True, capture_output=True, timeout=15)
        cls.private_key.chmod(0o600)
        cls.tls = ssl.create_default_context(cafile=str(cls.certificate))

        backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        backend.daemon_threads = True
        backend_thread = threading.Thread(
            target=lambda: backend.serve_forever(poll_interval=0.05), daemon=True
        )
        backend_thread.start()

        def stop_backend():
            backend.shutdown()
            backend.server_close()
            backend_thread.join(timeout=2)

        cls.addClassCleanup(stop_backend)
        cls.backend_port = backend.server_port
        # Reserve both ports at once so the allocator cannot select one twice.
        with contextlib.ExitStack() as stack:
            ports = []
            for _ in range(2):
                listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                listener.bind(("127.0.0.1", 0))
                ports.append(listener.getsockname()[1])
            cls.http_port, cls.https_port = ports
        if min(ports) <= 1024:
            raise RuntimeError("the test requires unprivileged ephemeral ports")

        cls.syntax_config = cls.make_config("unix-syntax", use_stub=False)
        cls.runtime_config = cls.make_config("loopback-runtime", use_stub=True)
        cls.syntax_result = cls.check_config(cls.syntax_config)
        cls.check_config(cls.runtime_config)

    @classmethod
    def make_config(cls, name, *, use_stub):
        directory = cls.directory / name
        directory.mkdir()
        template = (REPO / "configs/nginx-http.conf").read_text()
        if UNIX_UPSTREAM not in template:
            raise AssertionError("the expected upstream changed; review the test adapter")

        for snippet in ("security-headers.conf", "listen_http.conf", "listen_https.conf"):
            content = (REPO / "configs" / snippet).read_text()
            if snippet.startswith("listen_"):
                tls = snippet == "listen_https.conf"
                port = cls.https_port if tls else cls.http_port
                original_port = 443 if tls else 80
                suffix = " ssl" if tls else ""
                v4 = f"listen {original_port}{suffix};"
                v6 = f"listen [::]:{original_port}{suffix};"
                if content.count(v4) != 1 or content.count(v6) != 1:
                    raise AssertionError("listen snippets changed; review the loopback adapter")
                content = content.replace(v4, f"listen 127.0.0.1:{port}{suffix};")
                # Retain IPv6 directive syntax for -t. Runtime uses IPv4 only
                # so IPv6 availability is not a prerequisite for this gate.
                content = content.replace(v6, (
                    "# IPv4-only local test listener" if use_stub
                    else f"listen [::1]:{port}{suffix};"
                ))
            (directory / snippet).write_text(content)
            template = template.replace(
                f"/etc/nginx/dnscheck/{snippet}", nginx_path(directory / snippet)
            )

        template = re.sub(
            r"\b(root|alias) /srv/dnscheck/website/([^;]+);",
            lambda match: f"{match[1]} {nginx_path(str(cls.website) + '/' + match[2])};",
            template,
        )
        template = re.sub(
            r"ssl_certificate /var/lib/dnscheck-certificates/[^;]+;",
            f"ssl_certificate {nginx_path(cls.certificate)};", template,
        )
        template = re.sub(
            r"ssl_certificate_key /var/lib/dnscheck-certificates/[^;]+;",
            f"ssl_certificate_key {nginx_path(cls.private_key)};", template,
        )
        template = template.replace(
            "/var/log/nginx/dnscheck-access.log", nginx_path(directory / "access.log")
        )
        if use_stub:
            template = template.replace(UNIX_UPSTREAM, f"http://127.0.0.1:{cls.backend_port}")
            # Refuse to run if a future template adds a different upstream.
            for target in re.findall(r"\bproxy_pass\s+([^;]+);", template):
                if not re.fullmatch(rf"http://127\.0\.0\.1:{cls.backend_port}(?:/[^\s]*)?", target):
                    raise AssertionError("runtime configuration contains a non-test upstream")

        user = ""
        if os.geteuid() == 0:
            # A single foreground worker keeps the invoking test user's access
            # to its private temp directory; do not switch to nobody when root.
            user = f"user {pwd.getpwuid(os.geteuid()).pw_name} {grp.getgrgid(os.getegid()).gr_name};\n"
        config = directory / "nginx.conf"
        config.write_text(
            user + "daemon off;\nmaster_process off;\n"
            f"pid {nginx_path(directory / 'nginx.pid')};\n"
            f"error_log {nginx_path(directory / 'error.log')} warn;\n"
            "events { worker_connections 128; }\n"
            "http {\n"
            "types { text/html html; text/css css; application/javascript js; }\n"
            f"client_body_temp_path {nginx_path(directory / 'client-body')};\n"
            f"proxy_temp_path {nginx_path(directory / 'proxy')};\n"
            + template + "\n}\n"
        )
        return config

    @classmethod
    def command(cls, config):
        return [cls.nginx, "-e", "stderr", "-p", str(config.parent) + "/", "-c", str(config)]

    @classmethod
    def check_config(cls, config):
        result = subprocess.run(cls.command(config) + ["-t"], capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise AssertionError(f"nginx -t failed:\n{result.stderr}")
        return result

    def setUp(self):
        # Fresh Nginx per test gives each case independent rate-limit state.
        self.error_output = tempfile.TemporaryFile(mode="w+b")
        self.addCleanup(self.error_output.close)
        self.process = subprocess.Popen(
            self.command(self.runtime_config), stdout=subprocess.DEVNULL, stderr=self.error_output
        )
        self.watchdog = threading.Timer(30, self.process.kill)
        self.watchdog.daemon = True
        self.watchdog.start()
        self.addCleanup(self.stop_nginx)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.error_output.seek(0)
                detail = self.error_output.read(65536).decode("utf-8", errors="replace")
                self.fail(f"temporary Nginx exited during startup: {detail}")
            try:
                with socket.create_connection(("127.0.0.1", self.https_port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.025)
        self.fail("temporary Nginx did not listen within five seconds")

    def stop_nginx(self):
        self.watchdog.cancel()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGQUIT)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)

    def request(self, host, path="/", *, method="GET", headers=None, body=None, tls=True):
        # A Host header selects the virtual server. It is never resolved, and
        # http.client does not use proxy environment variables or follow redirects.
        if tls:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", self.https_port, timeout=3, context=self.tls
            )
        else:
            connection = http.client.HTTPConnection("127.0.0.1", self.http_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers={"Host": host, **(headers or {})})
            response = connection.getresponse()
            payload = response.read(1 << 20)
            return response.status, response.headers, payload
        finally:
            connection.close()

    def assert_security_headers(self, headers):
        self.assertEqual(headers.get_all("Strict-Transport-Security"), ["max-age=31536000"])
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy", ""))

    def assert_backend(self, result, *, status=200):
        actual_status, headers, payload = result
        self.assertEqual(actual_status, status, payload[:200])
        self.assertEqual(headers.get("X-Test-Backend-Reached"), "1", payload[:200])
        self.assert_security_headers(headers)
        return json.loads(payload)

    def test_original_unix_upstream_syntax(self):
        text = self.syntax_config.read_text()
        self.assertIn(UNIX_UPSTREAM, text)
        self.assertNotIn(f"http://127.0.0.1:{self.backend_port}", text)
        self.assertEqual(self.syntax_result.returncode, 0)

    def test_effective_security_headers_on_static_and_shared_assets(self):
        for host, page in (
            ("addr.tools", "/"), ("dnscheck.tools", "/"),
            ("myaddr.tools", "/claim.html"), ("dyn.addr.tools", "/"),
            ("challenges.addr.tools", "/"), ("info.addr.tools", "/info.html"),
            ("myip.addr.tools", "/help.html"),
        ):
            for path in (page, "/man.css", "/js/util.js"):
                with self.subTest(host=host, path=path):
                    status, headers, payload = self.request(host, path)
                    self.assertEqual(status, 200, payload[:200])
                    self.assertTrue(payload)
                    self.assert_security_headers(headers)
        status, headers, _ = self.request("myaddr.tools", "/nonexistent-test-file")
        self.assertEqual(status, 404)
        self.assert_security_headers(headers)

    def test_effective_security_headers_on_api_success_and_errors(self):
        for host, path in (
            ("addr.tools", "/dns/example.invalid/A"),
            ("dnscheck.tools", "/dns/example.invalid/A"),
            ("info.addr.tools", "/dns/example.invalid/A"),
            ("myaddr.tools", "/reg"), ("myaddr.tools", "/update"),
            ("dyn.addr.tools", "/"), ("challenges.addr.tools", "/"),
        ):
            with self.subTest(host=host, path=path):
                self.assert_backend(self.request(host, path, headers={"Authorization": FAKE_AUTHORIZATION}))
        for host, path, status in (
            ("myaddr.tools", "/reg", 503), ("dyn.addr.tools", "/", 403),
        ):
            with self.subTest(host=host, status=status):
                self.assert_backend(self.request(host, path, headers={
                    "Authorization": FAKE_AUTHORIZATION, "X-Test-Backend-Status": str(status),
                }), status=status)

    def test_bearer_only_get_routes_to_api_without_query_parameters(self):
        for host, api in (("dyn.addr.tools", "/dyn"), ("challenges.addr.tools", "/challenges")):
            with self.subTest(host=host):
                status, headers, payload = self.request(host)
                self.assertEqual(status, 200)
                self.assertNotEqual(headers.get("X-Test-Backend-Reached"), "1")
                self.assertIn(b"<!DOCTYPE html>", payload)
                observed = self.assert_backend(self.request(host, headers={"Authorization": FAKE_AUTHORIZATION}))
                self.assertEqual(observed["method"], "GET")
                self.assertEqual(observed["path"], api)
                self.assertEqual(observed["authorization"], [FAKE_AUTHORIZATION])

    def test_named_location_redirects_preserve_mutation_method_body_and_auth(self):
        for host, api in (("dyn.addr.tools", "/dyn"), ("challenges.addr.tools", "/challenges")):
            for method in ("POST", "PUT", "DELETE"):
                with self.subTest(host=host, method=method):
                    body = "txt=local%2Bencoded%2Ftest"
                    observed = self.assert_backend(self.request(host, method=method, body=body, headers={
                        "Authorization": FAKE_AUTHORIZATION,
                        "Content-Type": "application/x-www-form-urlencoded",
                    }))
                    self.assertEqual(observed["method"], method)
                    self.assertEqual(observed["path"], api)
                    self.assertEqual(observed["body"], body)
                    self.assertEqual(observed["authorization"], [FAKE_AUTHORIZATION])

    def test_client_ip_header_is_overwritten_on_every_proxy_route(self):
        for host, path in (
            ("addr.tools", "/dns/example.invalid/A"),
            ("dnscheck.tools", "/dns/example.invalid/A"),
            ("info.addr.tools", "/dns/example.invalid/A"),
            ("myaddr.tools", "/reg"), ("myaddr.tools", "/update"),
            ("dyn.addr.tools", "/"), ("challenges.addr.tools", "/"),
            ("ws.dnscheck.tools", "/watch/" + "a" * 32),
        ):
            with self.subTest(host=host, path=path):
                headers = {
                    "Authorization": FAKE_AUTHORIZATION,
                    "X-Addr-Client-IP": "203.0.113.7", "x-addr-client-ip": "198.51.100.7",
                    "X-Real-IP": "192.0.2.7", "CF-Connecting-IP": "203.0.113.8",
                }
                if host == "ws.dnscheck.tools":
                    headers.update({"Connection": "Upgrade", "Upgrade": "websocket"})
                observed = self.assert_backend(self.request(host, path, headers=headers))
                self.assertEqual(observed["client_ips"], ["127.0.0.1"])
                self.assertEqual(observed["real_ips"], ["127.0.0.1"])

    def test_diagnostic_no_store_and_exact_cors_over_http_and_https(self):
        for tls in (False, True):
            for origin in (
                None, "https://dnscheck.tools", "https://dnscheckXtools",
                "https://dnscheck.tools.attacker.invalid", "https://attacker.dnscheck.tools",
                "https://dnscheck.tools:444", "http://dnscheck.tools", "null",
            ):
                with self.subTest(tls=tls, origin=origin):
                    status, headers, payload = self.request(
                        "local-test.test.dnscheck.tools", tls=tls,
                        headers={} if origin is None else {"Origin": origin},
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(payload, b"Connected\n")
                    self.assertEqual(headers.get("Cache-Control"), "no-store")
                    self.assertEqual(headers.get("X-Robots-Tag"), "noindex, nofollow")
                    self.assertIn("Origin", headers.get("Vary", ""))
                    allowed = "https://dnscheck.tools" if origin == "https://dnscheck.tools" else None
                    self.assertEqual(headers.get("Access-Control-Allow-Origin"), allowed)
                    # Diagnostic HTTP probes intentionally have no HSTS policy.
                    self.assertIsNone(headers.get("Strict-Transport-Security"))


if __name__ == "__main__":
    unittest.main()
