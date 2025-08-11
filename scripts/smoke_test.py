#!/usr/bin/env python3
"""
Simple smoke test for MySecretPVE using Flask's test client.

Checks:
- GET /login returns 200
- GET / redirects to /login (since login is required)

Usage:
  python scripts/smoke_test.py
"""

import os
import sys
from urllib.parse import urlparse

# Ensure repository root is on sys.path when running from anywhere
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from webapp import app


def main() -> int:
    with app.test_client() as client:
        # /login should be reachable without auth
        r = client.get("/login")
        if r.status_code != 200:
            print(f"/login unexpected status: {r.status_code}")
            return 1

        # / should redirect to /login when not logged in
        r = client.get("/", follow_redirects=False)
        if r.status_code not in (301, 302, 303, 307, 308):
            print(f"/ expected redirect, got: {r.status_code}")
            return 1
        loc = r.headers.get("Location", "")
        if "/login" not in loc:
            print(f"/ redirect did not point to /login, got: {loc}")
            return 1

    print("Smoke test passed: /login=200, /=redirect->/login")
    return 0


if __name__ == "__main__":
    sys.exit(main())
