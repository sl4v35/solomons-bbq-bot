"""Unit tests: identifier detection, validation and phone parsing."""

from __future__ import annotations

import unittest

from stubs import *  # noqa: F401,F403 - ensures repo root is importable

from app.identifiers import IdentifierError, apex_domain, detect, parse_phone


class DetectAutoTests(unittest.TestCase):
    def test_domain(self):
        ident = detect("Example.COM")
        self.assertEqual(ident.kind, "domain")
        self.assertEqual(ident.value, "example.com")

    def test_subdomain_and_idn(self):
        self.assertEqual(detect("a.b.example.co.uk").value, "a.b.example.co.uk")
        self.assertEqual(detect("verdigristest.xn--p1ai").kind, "domain")

    def test_email(self):
        ident = detect("Some.User@Example.COM")
        self.assertEqual(ident.kind, "email")
        self.assertEqual(ident.value, "some.user@example.com")
        self.assertEqual(ident.meta["domain"], "example.com")

    def test_shared_provider_note(self):
        ident = detect("person@gmail.com")
        self.assertTrue(ident.meta["shared_provider"])
        self.assertTrue(any("shared mailbox provider" in note for note in ident.notes))

    def test_username(self):
        self.assertEqual(detect("torvalds").kind, "username")
        self.assertEqual(detect("@somebody").kind, "username")
        self.assertEqual(detect("@somebody").value, "somebody")

    def test_profile_url_becomes_username(self):
        ident = detect("https://github.com/Torvalds")
        self.assertEqual(ident.kind, "username")
        self.assertEqual(ident.value, "torvalds")
        self.assertEqual(ident.meta["origin_site"], "github")

    def test_plain_url_becomes_domain(self):
        ident = detect("https://www.example.com/some/path?x=1")
        self.assertEqual(ident.kind, "domain")
        self.assertEqual(ident.value, "www.example.com")

    def test_name(self):
        ident = detect("Alan Turing")
        self.assertEqual(ident.kind, "name")
        self.assertTrue(any("not proof" in note or "candidates" in note for note in ident.notes))

    def test_phone(self):
        ident = detect("+44 20 7123 4567")
        self.assertEqual(ident.kind, "phone")
        self.assertEqual(ident.value, "+442071234567")
        self.assertEqual(ident.meta["calling_code"], "+44")

    def test_bitcoin(self):
        for address in ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"):
            ident = detect(address)
            self.assertEqual(ident.kind, "bitcoin", address)
            self.assertIn("address_kind", ident.meta)

    def test_ethereum(self):
        ident = detect("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
        self.assertEqual(ident.kind, "ethereum")
        self.assertEqual(ident.meta["checksum"], "valid-checksum")
        lowercase = detect("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
        self.assertEqual(lowercase.meta["checksum"], "valid-no-checksum")

    def test_rejects_ip_addresses(self):
        for value in ("1.2.3.4", "8.8.8.8", "2001:db8::1", "http://1.2.3.4/path"):
            with self.subTest(value=value):
                with self.assertRaises(IdentifierError):
                    detect(value)

    def test_rejects_garbage(self):
        for value in ("", "   ", "not an identifier!!", "x" * 400, "\x00evil"):
            with self.subTest(value=repr(value[:12])):
                with self.assertRaises(IdentifierError):
                    detect(value)

    def test_rejects_numeric_tld(self):
        with self.assertRaises(IdentifierError):
            detect("foo.123")


class ForcedTypeTests(unittest.TestCase):
    def test_forced_domain_from_url(self):
        ident = detect("https://sub.example.com/x", forced_type="domain")
        self.assertEqual(ident.kind, "domain")
        self.assertEqual(ident.value, "sub.example.com")

    def test_forced_email_validation(self):
        with self.assertRaises(IdentifierError):
            detect("not-an-email", forced_type="email")
        with self.assertRaises(IdentifierError):
            detect("a@b", forced_type="email")

    def test_forced_username_strips_handle(self):
        self.assertEqual(detect("@Torvalds", forced_type="username").value, "torvalds")
        with self.assertRaises(IdentifierError):
            detect("-bad-", forced_type="username")

    def test_forced_name(self):
        self.assertEqual(detect("  alan   turing ", forced_type="name").value, "alan turing")
        with self.assertRaises(IdentifierError):
            detect("x", forced_type="name")

    def test_forced_bitcoin_checksum(self):
        with self.assertRaises(IdentifierError):
            detect("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", forced_type="bitcoin")
        with self.assertRaises(IdentifierError):
            detect("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                   forced_type="bitcoin")

    def test_forced_ethereum_checksum(self):
        with self.assertRaises(IdentifierError):
            detect("0x5AAEB6053F3E94C9b9A09f33669435E7Ef1BeAed", forced_type="ethereum")

    def test_unknown_type(self):
        with self.assertRaises(IdentifierError):
            detect("example.com", forced_type="passport")

    def test_forced_phone_rejects_short(self):
        with self.assertRaises(IdentifierError):
            detect("12345", forced_type="phone")


class PhoneTests(unittest.TestCase):
    def test_uk_number(self):
        data = parse_phone("+44 20 7123 4567")
        self.assertEqual(data["e164"], "+442071234567")
        self.assertEqual(data["calling_code"], "+44")
        self.assertIn("United Kingdom", data["country"])

    def test_nanp_assumption_is_disclosed(self):
        data = parse_phone("(555) 123-4567")
        self.assertEqual(data["e164"], "+15551234567")
        self.assertTrue(any("Assumed +1" in note for note in data["notes"]))

    def test_limitations_are_stated(self):
        data = parse_phone("+49 30 123456")
        joined = " ".join(data["notes"])
        self.assertIn("never sent to a third-party API", joined)
        self.assertIn("does not identify the owner", joined)
        self.assertIn("format and country calling code only", joined)

    def test_unknown_calling_code(self):
        data = parse_phone("+99912345678")
        self.assertEqual(data["calling_code"], "")
        self.assertIn("Unknown", data["country"])

    def test_too_long(self):
        with self.assertRaises(IdentifierError):
            parse_phone("+1234567890123456789")

    def test_toll_free_detected(self):
        ident = detect("+1 800 555 0100")
        self.assertTrue(any("toll-free" in note for note in ident.notes))


class ApexDomainTests(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(apex_domain("www.example.com"), "example.com")
        self.assertEqual(apex_domain("example.com"), "example.com")

    def test_two_level_suffixes(self):
        self.assertEqual(apex_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(apex_domain("a.b.example.com.au"), "example.com.au")

    def test_deep_subdomain(self):
        self.assertEqual(apex_domain("a.b.c.example.org"), "example.org")


if __name__ == "__main__":
    unittest.main()
