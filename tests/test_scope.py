from __future__ import annotations

import unittest

from navhack.scope import Rule, Scope, ScopeError, parse_rule


class ScopeTests(unittest.TestCase):
    def test_domain_matches_self_and_subdomain(self) -> None:
        scope = Scope.parse(["example.com"])
        self.assertTrue(scope.check("example.com")[0])
        self.assertTrue(scope.check("a.b.example.com")[0])
        self.assertFalse(scope.check("notexample.com")[0])

    def test_wildcard_requires_subdomain(self) -> None:
        scope = Scope.parse(["*.example.com"])
        self.assertTrue(scope.check("api.example.com")[0])
        self.assertFalse(scope.check("example.com")[0])

    def test_cidr(self) -> None:
        scope = Scope.parse(["10.0.0.0/30"])
        self.assertTrue(scope.check("10.0.0.2")[0])
        self.assertFalse(scope.check("10.0.0.9")[0])

    def test_ip_range(self) -> None:
        scope = Scope.parse(["10.0.0.1-10.0.0.10"])
        self.assertTrue(scope.check("10.0.0.5")[0])
        self.assertFalse(scope.check("10.0.0.11")[0])

    def test_port_pinning(self) -> None:
        scope = Scope.parse(["example.com:8443"])
        self.assertTrue(scope.check("example.com", 8443)[0])
        self.assertFalse(scope.check("example.com", 443)[0])

    def test_url_entry(self) -> None:
        scope = Scope.parse(["https://app.example.com/portal"])
        self.assertTrue(scope.check("app.example.com", 443)[0])
        self.assertFalse(scope.check("other.example.com")[0])

    def test_ipv6_entry(self) -> None:
        scope = Scope.parse(["[::1]:8080"])
        self.assertTrue(scope.check("::1", 8080)[0])
        self.assertFalse(scope.check("::1", 80)[0])

    def test_empty_scope_rejects(self) -> None:
        self.assertFalse(Scope.parse([]).check("example.com")[0])

    def test_require_raises(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.parse(["a.test"]).require("b.test")

    def test_bad_entry(self) -> None:
        with self.assertRaises(ValueError):
            parse_rule("")

    def test_duplicate_add(self) -> None:
        scope = Scope.parse(["a.test"])
        scope.add("a.test")
        self.assertEqual(len(scope), 1)

    def test_entries_roundtrip(self) -> None:
        entries = ["a.test", "10.0.0.0/24", "*.b.test"]
        self.assertEqual(Scope.parse(entries).entries(), entries)

    def test_trailing_dot_and_case(self) -> None:
        self.assertTrue(Scope.parse(["Example.COM"]).check("EXAMPLE.com.")[0])

    def test_rule_describe(self) -> None:
        self.assertIn("domain", Rule(raw="a.test", kind="domain", value="a.test").describe())


if __name__ == "__main__":
    unittest.main()
