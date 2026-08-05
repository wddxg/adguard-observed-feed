#!/usr/bin/env python3
"""Render an AdGuardHome.yaml candidate with the observed feed enabled."""

from __future__ import annotations

import argparse
import pathlib


DEFAULT_ID = 2026080501
DEFAULT_NAME = "Observed Home DNS Blocklist"
DEFAULT_URL = (
    "https://ghproxy.net/https://raw.githubusercontent.com/"
    "wddxg/adguard-observed-feed/main/dist/adguard-home.txt"
)


def render_filters(url: str, name: str, filter_id: int) -> str:
    return "\n".join(
        [
            "filters:",
            "  - enabled: true",
            f"    url: {url}",
            f"    name: {name}",
            f"    id: {filter_id}",
            "  - enabled: false",
            "    url: https://anti-ad.net/easylist.txt",
            "    name: anti-AD (disabled after observed-feed rollout)",
            "    id: 1577113202",
            "  - enabled: false",
            "    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt",
            "    name: HaGeZi Multi NORMAL (disabled after observed-feed rollout)",
            "    id: 2026071901",
            "  - enabled: false",
            "    url: https://raw.githubusercontent.com/vokins/yhosts/master/data/tvbox.txt",
            "    name: tvbox (disabled; upstream is HTTP 404)",
            "    id: 1575018007",
        ]
    ) + "\n"


def render_config(current: str, url: str, name: str, filter_id: int) -> str:
    start = current.index("\nfilters:\n") + 1
    end = current.index("\nwhitelist_filters:", start) + 1
    return current[:start] + render_filters(url, name, filter_id) + current[end:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--name", default=DEFAULT_NAME)
    parser.add_argument("--id", type=int, default=DEFAULT_ID)
    args = parser.parse_args()

    rendered = render_config(args.current.read_text(encoding="utf-8"), args.url, args.name, args.id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
