import unittest

from tools.render_adguard_yaml import render_config


class RenderAdGuardYamlTests(unittest.TestCase):
    def test_replaces_only_filter_block(self):
        current = "dns:\n  port: 53\nfilters:\n  - enabled: true\n    url: old\n    name: old\n    id: 1\nwhitelist_filters: []\nuser_rules: []\n"
        rendered = render_config(current, "https://example.test/filter.txt", "Observed", 99)
        self.assertIn("dns:\n  port: 53\n", rendered)
        self.assertIn("whitelist_filters: []\nuser_rules: []\n", rendered)
        self.assertIn("url: https://example.test/filter.txt", rendered)
        self.assertIn("id: 99", rendered)
        self.assertNotIn("url: old", rendered)


if __name__ == "__main__":
    unittest.main()

