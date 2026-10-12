"""File and disclosure regressions for token generation; uses temporary files."""
import base64
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "dnscheck_create_token_tests", REPOSITORY / "scripts" / "create-token.py"
)
CREATE_TOKEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CREATE_TOKEN)


class CreateTokenTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "generated.token"

    def run_main(self, path=None, random_bytes=None):
        path = self.path if path is None else path
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(CREATE_TOKEN.sys, "argv", ["create-token.py", str(path)]):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                if random_bytes is None:
                    CREATE_TOKEN.main()
                else:
                    with mock.patch.object(CREATE_TOKEN.secrets, "token_bytes", return_value=random_bytes) as generate:
                        CREATE_TOKEN.main()
                        generate.assert_called_once_with(32)
        return stdout.getvalue(), stderr.getvalue()

    def test_generated_file_is_canonical_32_byte_token_and_private(self):
        stdout, stderr = self.run_main()
        contents = self.path.read_bytes()
        self.assertEqual(len(contents), 44)
        self.assertTrue(contents.endswith(b"\n"))
        token = contents[:-1]
        self.assertEqual(len(token), 43)
        self.assertNotIn(b"=", token)
        decoded = base64.urlsafe_b64decode(token + b"=")
        self.assertEqual(len(decoded), 32)
        self.assertEqual(base64.urlsafe_b64encode(decoded).rstrip(b"="), token)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertNotIn(token.decode("ascii"), stdout + stderr)
        self.assertEqual(stderr, "")

    def test_only_the_file_path_is_printed(self):
        # A deterministic public fixture makes accidental printing observable.
        known_bytes = bytes(range(32))
        known_token = base64.urlsafe_b64encode(known_bytes).rstrip(b"=")
        stdout, stderr = self.run_main(random_bytes=known_bytes)
        self.assertEqual(stdout, f"Created private token file: {self.path}\n")
        self.assertEqual(stderr, "")
        self.assertNotIn(known_token.decode("ascii"), stdout + stderr)
        self.assertEqual(self.path.read_bytes(), known_token + b"\n")

    def test_existing_file_is_never_overwritten(self):
        original = b"existing-credential-must-remain-unchanged\n"
        self.path.write_bytes(original)
        self.path.chmod(0o600)
        with self.assertRaises(FileExistsError):
            self.run_main()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_existing_symlink_is_not_followed_or_overwritten(self):
        target = self.path.with_name("protected-target")
        target.write_bytes(b"protected contents")
        self.path.symlink_to(target)
        with self.assertRaises(FileExistsError):
            self.run_main()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_bytes(), b"protected contents")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_dangling_symlink_is_not_followed_to_create_a_target(self):
        target = self.path.with_name("must-not-be-created")
        self.path.symlink_to(target)
        with self.assertRaises(FileExistsError):
            self.run_main()
        self.assertTrue(self.path.is_symlink())
        self.assertFalse(target.exists())

    def test_usage_error_creates_no_file(self):
        for argv in (["create-token.py"], ["create-token.py", str(self.path), "extra"]):
            with self.subTest(argv=argv), mock.patch.object(CREATE_TOKEN.sys, "argv", argv):
                with self.assertRaises(SystemExit) as caught:
                    CREATE_TOKEN.main()
                self.assertIn("Usage:", str(caught.exception))
                self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
