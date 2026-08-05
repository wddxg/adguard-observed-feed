# AdGuard observed feed deployment

Updated: 2026-08-05 18:06 CST

## Outcome

- Published `wddxg/adguard-observed-feed` with a compact AdGuard Home feed.
- Stopped and disabled the FN100 profiler after final SQLite `quick_check` and WAL checkpoint.
- Replaced AX6000's active `anti-AD` and `HaGeZi Multi NORMAL` subscriptions with one observed feed subscription via `ghproxy.net`.
- Kept the old subscriptions disabled in YAML for rollback reference.
- Archived then removed old disabled filter files from the router.

## Build

- Observed snapshot: `20260805-171204`.
- Observed domains: 866.
- Observed blocked events: 227,127.
- Output rules: 42,185.
- Output size: 942,143 bytes.
- Output SHA-256: `63d0c20d850031f8eaa5b7a29d5ea38ea070c8ceec169a14fc2673095bb77d53`.
- Public sources: HaGeZi Multi LIGHT, AdAway default blocklist, Perflyst Smart-TV Blocklist.
- Public sources covered 708 observed domains; the observed supplement added the remaining 158.

## AX6000 validation

- AdGuard Home: running on TCP/UDP 53.
- dnsmasq: running on DHCP 67 and DNS-forwarding port 1745.
- EasyTier: running; overlay routes remained present.
- DNS guard: `ADGUARD_HEALTHY`.
- Public DNS: `openwrt.org` resolved via `127.0.0.1`.
- Rewrite DNS: `fn.199938.xyz` resolved to `192.168.6.1`.
- LAN DNS: `FN100.lan` resolved to `192.168.6.100` plus IPv6 addresses.
- Block test: `auth.api.gitv.tv` resolved to `0.0.0.0` and `::`.
- NAS TCP test: `192.168.6.100:52567` succeeded.
- Overlay space after cleanup: 34.8 MiB available, 47% used.

## Rollback material

- Router backup directory: `/root/adguard-observed-feed-20260805-175947`.
- Local router backup archive: `ops/router-backup/adguard-observed-feed-20260805-175947.tgz`.
- Local disabled-filter archive: `ops/router-backup/adguard-disabled-filters-20260805.tgz`.
- Disabled-filter archive SHA-256: `8851ddcc705cfe47d0e2ada04d78744c1890508aa72c85501592e61e2ae40f0b`.

## Notes

- The full SQLite profiler archive is intentionally local only under `data/snapshots/` and is ignored by Git.
- The GitHub Actions workflow is published as `automation/build.yml.example` because the current GitHub token lacks `workflow` scope.
- Re-run `tools/probe_urls.py` before changing the proxy URL.
