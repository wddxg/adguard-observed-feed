import pathlib
import tempfile
import unittest

from build_filter import collapse_subdomains, extract_domains, is_covered, normalize_domain


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


if __name__ == "__main__":
    unittest.main()
