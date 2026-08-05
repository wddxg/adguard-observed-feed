# Observed Home DNS Blocklist

This repository builds one compact AdGuard Home subscription from:

- an anonymized snapshot of domains actually blocked on one home network;
- HaGeZi Multi LIGHT for broad, low-risk coverage;
- AdAway's small mobile advertising list;
- Perflyst's small Smart-TV telemetry list.

The observed CSV contains domain-level counters and timestamps only. It has no
client IP, MAC address, credential, query event, or household device mapping.
The complete SQLite profiler archive is intentionally excluded from GitHub.

## Subscription

AdGuard Home uses the China-friendly GitHub Raw proxy URL verified from
Windows, FN100, and the AX6000 itself. The expected length and SHA-256 are
recorded in `dist/deployment.json`:

`https://ghproxy.net/https://raw.githubusercontent.com/wddxg/adguard-observed-feed/main/dist/adguard-home.txt`

Canonical file:

`https://raw.githubusercontent.com/wddxg/adguard-observed-feed/main/dist/adguard-home.txt`

## Build

```sh
python build_filter.py
python -m unittest discover -s tests -v
```

The builder downloads every source with byte and parsed-domain limits, rejects
HTML error pages, normalizes domains, removes exact duplicates, and removes a
subdomain only when an explicit parent-domain rule already covers it. Build
metadata and source hashes are written to `dist/build-report.json`.

`automation/build.yml.example` is the weekly GitHub Actions workflow template.
It is kept outside `.github/workflows` because the publishing token did not
have GitHub's separate `workflow` scope. The generator itself is complete and
can also be run manually. The observed snapshot remains static until a
deliberate new measurement period is approved.

## Source licenses

- HaGeZi Multi LIGHT: GPL-3.0
- AdAway default blocklist: CC-BY-3.0
- Perflyst Smart-TV Blocklist: MIT

Repository code and the combined output are distributed under GPL-3.0. Source
attribution is retained in `sources.json` and `dist/build-report.json`.

## Safety

The output is intentionally much smaller than the prior AX6000 configuration.
Even so, a DNS list can break services. Router deployment must preserve the
current AdGuard YAML, validate the downloaded file before restart, retain
dnsmasq fallback on port 53, and verify public DNS, `.lan` DNS, DHCP, and
EasyTier after any subscription change.
