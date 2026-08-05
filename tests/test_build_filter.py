import csv
import pathlib
import tempfile
import unittest

from build_filter import (
    collapse_subdomains,
    extract_domains,
    is_covered,
    load_observed,
    normalize_domain,
    observed_sort_key,
)


class FilterParsingTests(unittest.TestCase):
    def test_parses_supported_formats(self):
        self.assertEqual(
            extract_domains("||Ads.Example.com^\n@@||allow.example^\n! comment\n", "adblock"),
            {"ads.example.com"},
        )
        self.assertEqual(
            extract_domains("0.0.0.0 track.example\n127.0.0.1 localhost\n", "hosts"),
            {"track.example"},
        )
        self.assertEqual(
            extract_domains("telemetry.example # note\n*.invalid.example\n", "domains"),
            {"telemetry.example"},
        )

    def test_rejects_ips_and_invalid_names(self):
        self.assertIsNone(normalize_domain("127.0.0.1"))
        self.assertIsNone(normalize_domain("localhost"))
        self.assertIsNone(normalize_domain("bad domain.example"))
        self.assertEqual(normalize_domain("_apns._tcp.Example.COM"), "_apns._tcp.example.com")
        self.assertEqual(normalize_domain("Example.COM."), "example.com")

    def test_parent_rule_covers_and_collapses_children(self):
        rules, removed = collapse_subdomains(
            {"example.com", "ads.example.com", "deep.ads.example.com", "other.net"}
        )
        self.assertEqual(rules, {"example.com", "other.net"})
        self.assertEqual(removed, 2)
        self.assertTrue(is_covered("cdn.example.com", rules))
        self.assertFalse(is_covered("notexample.com", rules))

    def test_loads_observed_without_time_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "observed.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["domain", "hit_count"])
                writer.writeheader()
                writer.writerow({"domain": "_apns._tcp.jpush.cn", "hit_count": "7"})
                writer.writerow({"domain": "api.xiaomi.com", "hit_count": "3"})

            domains, stats = load_observed(path)

        self.assertEqual(domains, {"_apns._tcp.jpush.cn", "api.xiaomi.com"})
        self.assertEqual(stats["domain_count"], 2)
        self.assertEqual(stats["total_hits"], 10)
        self.assertNotIn("first_seen", stats)
        self.assertNotIn("last_seen", stats)

    def test_observed_sort_key_uses_second_last_domain_label(self):
        domains = ["b.qq.com", "xx.xx.xiaomi.com", "_apns._tcp.jpush.cn", "a.baidu.com"]
        self.assertEqual(
            sorted(domains, key=observed_sort_key),
            ["a.baidu.com", "_apns._tcp.jpush.cn", "b.qq.com", "xx.xx.xiaomi.com"],
        )


if __name__ == "__main__":
    unittest.main()
