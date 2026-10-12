"""Security regressions for the fixed hook; no tests contact real HTTP services."""
import base64
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import stat
import tempfile
import types
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from email.message import Message


REPOSITORY = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "dnscheck_certbot_hook_tests", REPOSITORY / "scripts" / "certbot-hook.py"
)
HOOK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOOK)


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class SyntheticHTTPS(urllib.request.HTTPSHandler):
    """Returns a synthetic redirect without opening a connection."""

    def __init__(self, status):
        super().__init__()
        self.status = status
        self.requests = []

    def https_open(self, request):
        self.requests.append(request)
        headers = Message()
        headers["Location"] = "https://different.example.invalid/receiver"
        response = urllib.response.addinfourl(
            io.BytesIO(b"Synthetic redirect body"), headers,
            request.full_url, self.status,
        )
        response.msg = "Synthetic redirect"
        return response


class CertbotHookTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.token_path = Path(self.temporary.name) / "secret.token"
        # These deterministic public fixtures are deliberately not real secrets.
        self.secret = encoded(bytes(range(32)))
        self.challenge = encoded(bytes(reversed(range(32))))
        self.token_path.write_text(self.secret + "\n", encoding="ascii")
        self.token_path.chmod(0o600)
        self.environ = {
            "DNSCHECK_CHALLENGE_URL": "https://challenge.example.invalid/api",
            "DNSCHECK_SECRET_FILE": str(self.token_path),
            "CERTBOT_VALIDATION": self.challenge,
            "DNSCHECK_PROPAGATION_SECONDS": "0",
        }
        # A test regression must never turn into a real network connection.
        self.network_guard = mock.patch.object(
            socket, "create_connection",
            side_effect=AssertionError("network connections are forbidden in script tests"),
        )
        self.network_guard.start()
        self.addCleanup(self.network_guard.stop)

    def test_auth_and_cleanup_use_encoded_body_and_one_bearer_header(self):
        for mode, expected_method in (("auth", "POST"), ("cleanup", "DELETE")):
            with self.subTest(mode=mode):
                request = HOOK.make_request(mode, self.environ)
                self.assertEqual(request.get_method(), expected_method)
                self.assertEqual(request.full_url, self.environ["DNSCHECK_CHALLENGE_URL"])
                headers = {key.lower(): value for key, value in request.header_items()}
                self.assertEqual(headers["authorization"], "Bearer " + self.secret)
                self.assertEqual(headers["content-type"], "application/x-www-form-urlencoded")
                self.assertEqual(
                    urllib.parse.parse_qs(request.data.decode("ascii"), strict_parsing=True),
                    {"txt": [self.challenge]},
                )
                self.assertEqual(urllib.parse.urlsplit(request.full_url).query, "")
                self.assertNotIn(self.secret, request.full_url)
                self.assertNotIn(self.secret, request.data.decode("ascii"))
                self.assertNotIn(self.challenge, request.full_url)

    def test_only_declared_hook_modes_are_accepted(self):
        for mode in ("", "delete-all", "POST", "auth; printf unsafe"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                HOOK.make_request(mode, self.environ)

    def test_insecure_credentials_and_malformed_urls_are_rejected(self):
        rejected = (
            "http://challenge.example.invalid/api",
            "file:///tmp/token",
            "https:///api",
            "https://",
            "not-a-url",
            "https://user:password@challenge.example.invalid/api",
            "https://@challenge.example.invalid/api",
            "https://challenge.example.invalid/api?secret=" + self.secret,
            "https://challenge.example.invalid/api?other=value",
            "https://challenge.example.invalid/api#fragment",
            "https://challenge.example.invalid:invalid/api",
            "https://challenge.example.invalid:99999/api",
            "https://challenge.example.invalid:0/api",
            "https://challenge.example.invalid/\npath",
            "https://challenge.example.invalid/\rpath",
            "https://bad host.example.invalid/api",
            "https://[invalid-address]/api",
            "https://-invalid.example.invalid/api",
        )
        for endpoint in rejected:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                HOOK.make_request("auth", dict(self.environ, DNSCHECK_CHALLENGE_URL=endpoint))

    def test_valid_https_domain_ip_and_explicit_port_urls_remain_supported(self):
        for endpoint in (
            "https://challenge.example.invalid/api",
            "https://challenge.example.invalid:8443/api",
            "https://127.0.0.1/api",
            "https://[::1]:8443/api",
        ):
            with self.subTest(endpoint=endpoint):
                request = HOOK.make_request("auth", dict(self.environ, DNSCHECK_CHALLENGE_URL=endpoint))
                self.assertEqual(request.full_url, endpoint)

    def test_canonical_token_and_challenge_values_are_required(self):
        invalid = (
            "password", "", "A" * 42, "A" * 44,
            "A" * 42 + "B",  # Decodes to32 bytes but has nonzero padding bits.
            "+" * 43, "/" * 43, "A" * 42 + "=",
            "A" * 40 + "&x=", "$(printf SHOULD_NOT_RUN)",
        )
        for token in invalid:
            with self.subTest(field="secret", value=token):
                self.token_path.write_text(token, encoding="ascii")
                with self.assertRaises(ValueError):
                    HOOK.make_request("auth", self.environ)
        self.token_path.write_text(self.secret + "\n", encoding="ascii")
        for value in invalid:
            with self.subTest(field="txt", value=value), self.assertRaises(ValueError):
                HOOK.make_request("auth", dict(self.environ, CERTBOT_VALIDATION=value))

    def test_non_ascii_secret_is_rejected_before_request_construction(self):
        self.token_path.write_bytes(b"\xff" * 43)
        with self.assertRaises(UnicodeError):
            HOOK.make_request("auth", self.environ)

    @unittest.skipUnless(os.name == "posix", "POSIX private file mode enforcement")
    def test_group_or_world_readable_token_file_is_rejected(self):
        for mode in (0o640, 0o604, 0o644):
            with self.subTest(mode=oct(mode)):
                self.token_path.chmod(mode)
                with self.assertRaises(ValueError):
                    HOOK.make_request("auth", self.environ)

    def test_nonregular_token_file_is_rejected(self):
        # A fake fstat avoids opening a potentially blocking FIFO/device.
        fake_stat = types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
        with mock.patch.object(HOOK.os, "fstat", return_value=fake_stat):
            with self.assertRaises(ValueError):
                HOOK.make_request("auth", self.environ)

    def test_oversized_token_file_is_not_accepted_by_trimming_a_prefix(self):
        self.token_path.write_bytes(self.secret.encode("ascii") + b" " * 1200)
        with self.assertRaisesRegex(ValueError, "too large"):
            HOOK.make_request("auth", self.environ)

    def test_redirects_never_forward_the_bearer_request(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                synthetic = SyntheticHTTPS(code)
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), HOOK.NoRedirects(), synthetic,
                )
                request = HOOK.make_request("auth", self.environ)
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    opener.open(request, timeout=0.1)
                self.assertEqual(caught.exception.code, code)
                caught.exception.close()
                self.assertEqual(len(synthetic.requests), 1)
                self.assertEqual(synthetic.requests[0].full_url, self.environ["DNSCHECK_CHALLENGE_URL"])

    def invoke_main(self, mode, opener):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(HOOK.sys, "argv", ["certbot-hook.py", mode]):
            with mock.patch.dict(HOOK.os.environ, self.environ, clear=True):
                with mock.patch.object(HOOK.urllib.request, "build_opener", return_value=opener) as factory:
                    with mock.patch.object(HOOK.time, "sleep") as sleep:
                        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            HOOK.main()
        return factory, sleep, stdout.getvalue(), stderr.getvalue()

    def test_main_uses_no_redirect_policy_timeout_and_bounded_response_read(self):
        for mode, status, expected_method in (("auth", 201, "POST"), ("cleanup", 204, "DELETE")):
            with self.subTest(mode=mode):
                response = mock.MagicMock()
                response.status = status
                response.__enter__.return_value = response
                response.read.return_value = b"OK"
                opener = mock.Mock()
                opener.open.return_value = response
                factory, sleep, stdout, stderr = self.invoke_main(mode, opener)
                self.assertIsInstance(factory.call_args.args[0], HOOK.NoRedirects)
                opener.open.assert_called_once()
                self.assertEqual(opener.open.call_args.kwargs, {"timeout": 15})
                self.assertEqual(opener.open.call_args.args[0].get_method(), expected_method)
                response.read.assert_called_once_with(16384)
                if mode == "auth":
                    sleep.assert_called_once_with(0)
                else:
                    sleep.assert_not_called()
                self.assertEqual(stdout + stderr, "")

    def test_invalid_propagation_delay_fails_before_request_or_open(self):
        for mode in ("auth", "cleanup"):
            for delay in ("-1", "61", "invalid", "1.5", ""):
                with self.subTest(mode=mode, delay=delay):
                    environ = dict(self.environ, DNSCHECK_PROPAGATION_SECONDS=delay)
                    with (
                        mock.patch.object(HOOK.sys, "argv", ["certbot-hook.py", mode]),
                        mock.patch.dict(HOOK.os.environ, environ, clear=True),
                        mock.patch.object(HOOK, "make_request") as make_request,
                        mock.patch.object(HOOK.Path, "open") as token_open,
                        mock.patch.object(HOOK.urllib.request, "build_opener") as factory,
                        mock.patch.object(HOOK.time, "sleep") as sleep,
                    ):
                        with self.assertRaisesRegex(SystemExit, r"failed \(ValueError\)"):
                            HOOK.main()
                        make_request.assert_not_called()
                        token_open.assert_not_called()
                        factory.assert_not_called()
                        factory.return_value.open.assert_not_called()
                        sleep.assert_not_called()

    def test_error_messages_do_not_disclose_credentials_or_server_bodies(self):
        disclosure = "UNTRUSTED_BODY_" + self.secret + "_" + self.challenge
        for error in (
            urllib.error.HTTPError(
                self.environ["DNSCHECK_CHALLENGE_URL"], 401,
                disclosure, Message(), io.BytesIO(disclosure.encode("ascii")),
            ),
            urllib.error.URLError(disclosure),
        ):
            with self.subTest(kind=type(error).__name__):
                opener = mock.Mock()
                opener.open.side_effect = error
                with self.assertRaises(SystemExit) as caught:
                    self.invoke_main("auth", opener)
                message = str(caught.exception)
                self.assertNotIn(self.secret, message)
                self.assertNotIn(self.challenge, message)
                self.assertNotIn("UNTRUSTED_BODY", message)
                if isinstance(error, urllib.error.HTTPError):
                    self.assertIn("HTTP 401", message)
                    error.close()


if __name__ == "__main__":
    unittest.main()
