#!/usr/bin/env python3
"""Download filter URLs in memory and report status, length, and SHA-256."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request


MAX_BYTES = 2_000_000


def probe(url: str) -> dict:
    request = urllib.request.Request(
        url, headers={"User-Agent": "adguard-feed-probe/1.0"}
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError(f"response exceeded {MAX_BYTES} bytes")
        first_line = data.splitlines()[0].decode("utf-8", errors="replace") if data else ""
        return {
            "url": url,
            "status": response.status,
            "final_url": response.url,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "first_line": first_line,
        }


def main() -> int:
    failed = False
    for url in sys.argv[1:]:
        try:
            result = probe(url)
        except Exception as error:  # A probe should report every candidate.
            failed = True
            result = {"url": url, "error": f"{type(error).__name__}: {error}"}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
