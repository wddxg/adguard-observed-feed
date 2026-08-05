#!/usr/bin/env python3
"""Build a compact AdGuard Home DNS blocklist from observed and public data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import pathlib
import re
import urllib.request
from typing import Iterable


ADBLOCK_DOMAIN = re.compile(r"^\|\|([^\^$|/*]+)\^")
# DNS service records such as _apns._tcp.example.com are valid query names.
VALID_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_domain(value: str) -> str | None:
    value = value.strip().strip(".").lower()
    if not value or "*" in value or "/" in value or ":" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    if len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if any(not VALID_LABEL.fullmatch(label) for label in labels):
        return None
    return value


def extract_domains(text: str, source_format: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.lstrip("\ufeff").strip()
        if not line or line.startswith(("!", "#", "[", "@@")):
            continue

        candidates: list[str] = []
        match = ADBLOCK_DOMAIN.match(line)
        if match:
            candidates.append(match.group(1))
        elif source_format == "hosts":
            payload = line.split("#", 1)[0].split()
            if len(payload) >= 2:
                try:
                    ipaddress.ip_address(payload[0])
                except ValueError:
                    continue
                candidates.extend(payload[1:])
        elif source_format == "domains":
            candidates.append(line.split("#", 1)[0].strip())

        for candidate in candidates:
            domain = normalize_domain(candidate)
            if domain:
                domains.add(domain)
    return domains


def fetch_source(source: dict, cache_dir: pathlib.Path) -> tuple[bytes, pathlib.Path]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / f"{source['id']}.txt"
    request = urllib.request.Request(
        source["url"],
        headers={"User-Agent": "adguard-observed-feed/1.0"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(int(source["max_bytes"]) + 1)
    if len(data) > int(source["max_bytes"]):
        raise ValueError(f"{source['id']}: source exceeds max_bytes")
    prefix = data[:512].decode("utf-8", errors="ignore").strip().lower()
    if any(marker in prefix for marker in HTML_MARKERS):
        raise ValueError(f"{source['id']}: received HTML instead of a filter")
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(data)
    temporary.replace(target)
    return data, target


def load_observed(path: pathlib.Path) -> tuple[set[str], dict]:
    domains: set[str] = set()
    total_hits = 0
    first_seen = None
    last_seen = None
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            domain = normalize_domain(row.get("domain", ""))
            if not domain:
                raise ValueError(f"invalid observed domain: {row.get('domain')!r}")
            domains.add(domain)
            total_hits += int(row.get("hit_count", "0"))
            row_first = row.get("first_seen") or None
            row_last = row.get("last_seen") or None
            first_seen = min(filter(None, (first_seen, row_first)), default=None)
            last_seen = max(filter(None, (last_seen, row_last)), default=None)
    return domains, {
        "sha256": sha256_bytes(path.read_bytes()),
        "domain_count": len(domains),
        "total_hits": total_hits,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def is_covered(domain: str, rules: set[str]) -> bool:
    labels = domain.split(".")
    return any(".".join(labels[index:]) in rules for index in range(len(labels)))


def collapse_subdomains(domains: Iterable[str]) -> tuple[set[str], int]:
    candidates = set(domains)
    kept: set[str] = set()
    removed = 0
    for domain in sorted(candidates, key=lambda item: (item.count("."), item)):
        labels = domain.split(".")
        if any(".".join(labels[index:]) in kept for index in range(1, len(labels))):
            removed += 1
        else:
            kept.add(domain)
    return kept, removed


def build(
    sources_path: pathlib.Path,
    observed_path: pathlib.Path,
    output_path: pathlib.Path,
    report_path: pathlib.Path,
    cache_dir: pathlib.Path,
) -> dict:
    config = json.loads(sources_path.read_text(encoding="utf-8"))
    observed, observed_stats = load_observed(observed_path)
    public_union: set[str] = set()
    source_reports = []

    for source in config["sources"]:
        data, _cache_path = fetch_source(source, cache_dir)
        text = data.decode("utf-8-sig")
        domains = extract_domains(text, source["format"])
        if not int(source["min_domains"]) <= len(domains) <= int(source["max_domains"]):
            raise ValueError(
                f"{source['id']}: parsed {len(domains)} domains outside "
                f"{source['min_domains']}..{source['max_domains']}"
            )
        source_reports.append(
            {
                "id": source["id"],
                "name": source["name"],
                "url": source["url"],
                "homepage": source["homepage"],
                "license": source["license"],
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "parsed_domains": len(domains),
                "observed_domains_covered": sum(is_covered(item, domains) for item in observed),
            }
        )
        public_union.update(domains)

    public_collapsed, public_redundant = collapse_subdomains(public_union)
    observed_missing = {domain for domain in observed if not is_covered(domain, public_collapsed)}
    merged, merged_redundant = collapse_subdomains(public_collapsed | observed_missing)

    header = [
        "[Adblock Plus]",
        "! Title: Observed Home DNS Blocklist",
        "! Homepage: https://github.com/wddxg/adguard-observed-feed",
        "! Description: Observed AX6000 hits plus lightweight public DNS blocklists.",
        "! License: GPL-3.0; bundled source data retains its upstream license.",
        "! Expires: 7 days",
        f"! Rules: {len(merged)}",
        f"! Observed domains represented: {len(observed)}",
        "!",
    ]
    content = "\n".join(header + [f"||{domain}^" for domain in sorted(merged)]) + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8", newline="\n")

    report = {
        "schema_version": 1,
        "build_id": sha256_bytes(
            json.dumps(
                {
                    "observed": observed_stats["sha256"],
                    "sources": [item["sha256"] for item in source_reports],
                },
                sort_keys=True,
            ).encode()
        ),
        "observed": observed_stats,
        "sources": source_reports,
        "public": {
            "unique_domains_before_parent_collapse": len(public_union),
            "rules_after_parent_collapse": len(public_collapsed),
            "redundant_subdomains_removed": public_redundant,
            "observed_domains_covered": len(observed) - len(observed_missing),
        },
        "supplement": {
            "observed_domains_not_covered_by_public_rules": len(observed_missing)
        },
        "output": {
            "rules": len(merged),
            "redundant_subdomains_removed_during_merge": merged_redundant,
            "bytes": len(content.encode("utf-8")),
            "sha256": sha256_bytes(content.encode("utf-8")),
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=pathlib.Path, default=pathlib.Path("sources.json"))
    parser.add_argument(
        "--observed",
        type=pathlib.Path,
        default=pathlib.Path("data/observed-domain-hits.csv"),
    )
    parser.add_argument(
        "--output", type=pathlib.Path, default=pathlib.Path("dist/adguard-home.txt")
    )
    parser.add_argument(
        "--report", type=pathlib.Path, default=pathlib.Path("dist/build-report.json")
    )
    parser.add_argument("--cache", type=pathlib.Path, default=pathlib.Path(".cache/sources"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build(args.sources, args.observed, args.output, args.report, args.cache)
    print(json.dumps(report["output"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
