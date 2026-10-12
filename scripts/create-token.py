#!/usr/bin/env python3
"""Create a private 256-bit token file. Never display the token or overwrite a file."""
import base64
import os
import secrets
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: create-token.py NEW_TOKEN_FILE")
    path = Path(sys.argv[1])
    data = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=") + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    print(f"Created private token file: {path}")

if __name__ == "__main__":
    main()
