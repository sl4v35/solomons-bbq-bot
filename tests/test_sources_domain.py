"""Source tests for domain-oriented integrations, driven by captured response shapes."""

from __future__ import annotations

import unittest

from stubs import *  # noqa: F401,F403
from stubs import (
    BLOCKSTREAM_UNUSED,
    DOH_NXDOMAIN,
    HIBP_RANGE,
    OPENPHISH_FEED,
    OTX_EMPTY,
    OTX_POPULAR,
    RDAP_EXAMPLE,
    RDAP_EXPIRED,
    RDAP_RECENT,
    URLHAUS_API_EMPTY,
    URLHAUS_API_OK,
    URLHAUS_FEED,
    URLSCAN_EMPTY,
    URLSCAN_RESULTS,
    VIRUSTOTAL_DOMAIN,
    WAYBACK_AVAILABLE,
    WAYBACK_CDX,
    WAYBACK_NONE,
    UpstreamTimeout,
    context_for,
    dns_routes,
    make_fetcher,
    run_source,
)

from app.sources.base import (
    STATUS_NO_MATCH,
    STATUS_NOT_CHECKED,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
)


class DnsDohTests(unittest.TestCase):
    def test_full_answer_produces_evidence(self):
        fetcher, transport = make_fetcher(dns_routes("example.com"))
        result = run_source("dns_doh", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["a"], ["93.184.216.34"])
        self.assertEqual(result.data["spf"]["all"], "-all")
        self.assertEqual(result.data["dmarc"]["policy"], "reject")
        self.assertTrue(result.data["dnssec_validated"])
        titles = [f.title for f in result.findings]
        self.assertIn("Domain resolves in public DNS", titles)
        self.assertIn("Domain accepts email", titles)
        self.assertTrue(any("DNSSEC" in t for t in titles))
        self.assertTrue(any(t.startswith("DMARC published") for t in titles))
        self.assertTrue(any("strict 'fail all'" in t for t in titles))
        self.assertEqual(len(transport.calls), 6)

    def test_nxdomain_is_reported_as_a_fact_not_a_failure(self):
        fetcher, _ = make_fetcher([(r"dns\.google/resolve", DOH_NXDOMAIN)])
        result = run_source("dns_doh", context_for("definitely-not-registered.invalid", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_OK)
        self.assertTrue(result.data["nxdomain"])
        self.assertTrue(any(f.title == "Domain does not resolve in DNS" for f in result.findings))
        # No mail findings should be invented for a domain that does not exist.
        self.assertFalse(any("MX" in f.title for f in result.findings))
        self.assertFalse(any("SPF" in f.title for f in result.findings))

    def test_failed_query_is_never_reported_as_missing_record(self):
        fetcher, _ = make_fetcher(dns_routes("example.com", fail_types=("MX", "DMARC", "TXT")))
        result = run_source("dns_doh", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        titles = [f.title for f in result.findings]
        self.assertFalse(any("No MX records" in t for t in titles), titles)
        self.assertFalse(any("No SPF record" in t for t in titles), titles)
        self.assertFalse(any("No DMARC policy" in t for t in titles), titles)
        self.assertTrue(any("could not be completed" in t for t in titles), titles)
        self.assertEqual(sorted(result.data["partial_failures"]), ["DMARC", "MX", "TXT"])

    def test_all_queries_failing_is_source_unavailable(self):
        fetcher, _ = make_fetcher([(r"dns\.google/resolve", UpstreamTimeout("timed out"))])
        result = run_source("dns_doh", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("failed", result.message)
        self.assertEqual(result.findings, [])

    def test_permissive_spf_is_flagged_high(self):
        payload = {"Status": 0, "Answer": [{"name": "example.com.", "type": 16, "TTL": 60, "data": '"v=spf1 +all"'}]}
        routes = dns_routes("example.com")
        routes = [(pattern, payload) if "type=TXT" in pattern and "_dmarc" not in pattern else (pattern, response)
                  for pattern, response in routes]
        fetcher, _ = make_fetcher(routes)
        result = run_source("dns_doh", context_for("example.com", fetcher=fetcher))
        permissive = [f for f in result.findings if f.severity == "high" and "SPF" in f.title]
        self.assertTrue(permissive, [f.title for f in result.findings])
        self.assertEqual(result.data["spf"]["all"], "+all")

    def test_email_identifier_checks_the_mail_domain_only(self):
        fetcher, transport = make_fetcher(dns_routes("example.com"))
        result = run_source("dns_doh", context_for("person@example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        for call in transport.calls:
            self.assertNotIn("person@", call["url"])
            self.assertNotIn("person%40", call["url"])


class RdapTests(unittest.TestCase):
    def _routes(self, payload, status=200):
        return [(r"rdap\.org/domain/", (status, payload))]

    def test_events_use_event_action_and_event_date(self):
        fetcher, _ = make_fetcher(self._routes(RDAP_EXAMPLE))
        result = run_source("rdap", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["registered_at"], "1995-08-14T04:00:00Z")
        self.assertEqual(result.data["expires_at"], "2099-08-13T04:00:00Z")
        self.assertEqual(result.data["changed_at"], "2026-08-14T08:01:43Z")
        self.assertEqual(result.data["registrar"], "RESERVED-Internet Assigned Numbers Authority")
        self.assertEqual(result.data["registrar_iana_id"], "376")
        self.assertEqual(result.data["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertTrue(result.data["dnssec_delegation_signed"])
        self.assertTrue(any(f.title.startswith("Long-standing domain") for f in result.findings))
        self.assertTrue(any("DNSSEC" in f.title for f in result.findings))
        self.assertTrue(any("lock" in f.title.lower() for f in result.findings))

    def test_expiry_comparison_is_not_inverted(self):
        # A far-future expiry must never be reported as expired.
        fetcher, _ = make_fetcher(self._routes(RDAP_EXAMPLE))
        result = run_source("rdap", context_for("example.com", fetcher=fetcher))
        self.assertFalse(any("expired" in f.title.lower() or "expiring" in f.title.lower()
                             for f in result.findings))
        self.assertGreater(result.data["expires_in_days"], 30)

    def test_expired_registration_is_detected(self):
        fetcher, _ = make_fetcher(self._routes(RDAP_EXPIRED))
        result = run_source("rdap", context_for("lapsed.example", fetcher=fetcher, forced="domain"))
        titles = [f.title for f in result.findings]
        self.assertTrue(any(t.startswith("Registration expired") for t in titles), titles)
        self.assertTrue(any("on hold" in t for t in titles), titles)

    def test_recent_registration_is_flagged(self):
        fetcher, _ = make_fetcher(self._routes(RDAP_RECENT))
        result = run_source("rdap", context_for("newish.example", fetcher=fetcher, forced="domain"))
        recent = [f for f in result.findings if "Recently registered" in f.title]
        self.assertTrue(recent)
        self.assertEqual(recent[0].severity, "medium")
        self.assertLessEqual(result.data["age_days"], 90)

    def test_missing_record_is_no_match(self):
        fetcher, _ = make_fetcher(self._routes({"errorCode": 404, "title": "Not Found"}, status=404))
        result = run_source("rdap", context_for("nothing-here.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("404", result.message)

    def test_registry_error_is_unavailable_not_no_match(self):
        fetcher, _ = make_fetcher(self._routes({"error": "boom"}, status=503))
        result = run_source("rdap", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)

    def test_bootstrap_redirect_header_is_requested(self):
        fetcher, transport = make_fetcher(self._routes(RDAP_EXAMPLE))
        run_source("rdap", context_for("example.com", fetcher=fetcher))
        self.assertIn("application/rdap+json", transport.calls[0]["headers"]["Accept"])


class UrlscanTests(unittest.TestCase):
    def test_public_scan_records_are_info_not_a_verdict(self):
        fetcher, transport = make_fetcher([(r"urlscan\.io/api/v1/search", URLSCAN_RESULTS)])
        result = run_source("urlscan", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["total"], 6212)
        finding = result.findings[0]
        self.assertEqual(finding.severity, "info")
        self.assertIn("NOT a malicious verdict", finding.interpretation)
        self.assertIn("urlscan.io/result/", finding.links[0].url)
        # The paid verdict filter must not be used.
        self.assertNotIn("has:verdict", transport.calls[0]["url"])
        self.assertNotIn("verdict", transport.calls[0]["url"])

    def test_no_records_is_no_match(self):
        fetcher, _ = make_fetcher([(r"urlscan\.io/api/v1/search", URLSCAN_EMPTY)])
        result = run_source("urlscan", context_for("clean.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertEqual(result.findings, [])

    def test_rate_limit_is_reported_honestly(self):
        fetcher, _ = make_fetcher([(r"urlscan\.io/api/v1/search", (429, {}))])
        result = run_source("urlscan", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_RATE_LIMITED)


class OtxTests(unittest.TestCase):
    def test_pulses_are_labeled_as_claims(self):
        fetcher, _ = make_fetcher([(r"otx\.alienvault\.com", OTX_POPULAR)])
        result = run_source("otx", context_for("example.org", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["pulse_count"], 2)
        self.assertTrue(result.data["whitelisted"])
        pulse_finding = [f for f in result.findings if "pulse" in f.title][0]
        self.assertEqual(pulse_finding.severity, "medium")
        self.assertIn("NOT a verdict", pulse_finding.interpretation)
        self.assertTrue(any("popular / whitelisted" in f.title for f in result.findings))

    def test_no_pulses_is_no_match(self):
        fetcher, _ = make_fetcher([(r"otx\.alienvault\.com", OTX_EMPTY)])
        result = run_source("otx", context_for("clean.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_NO_MATCH)


class UrlhausTests(unittest.TestCase):
    def test_exact_host_match_from_public_feed(self):
        fetcher, transport = make_fetcher([(r"urlhaus\.abuse\.ch/downloads", URLHAUS_FEED)])
        result = run_source("urlhaus", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["matches"], ["http://example.com/bad/path"])
        finding = result.findings[0]
        self.assertEqual(finding.severity, "high")
        # Malicious URLs must never be rendered as clickable links.
        for link in finding.links:
            self.assertNotIn("payload.exe", link.url)
            self.assertNotIn("example.com/bad", link.url)
        self.assertTrue(any("do not visit" in (e.value or "").lower() or "plain text" in finding.summary.lower()
                            for e in finding.evidence) or "plain text" in finding.summary)

    def test_no_match_in_feed(self):
        fetcher, _ = make_fetcher([(r"urlhaus\.abuse\.ch/downloads", URLHAUS_FEED)])
        result = run_source("urlhaus", context_for("unlisted.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("not a full historical search", result.message)

    def test_feed_failure_explains_the_auth_key_requirement(self):
        fetcher, _ = make_fetcher([(r"urlhaus\.abuse\.ch/downloads", (503, {}))])
        result = run_source("urlhaus", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("Auth-Key", result.message)
        self.assertIn("Settings", result.hint)

    def test_auth_key_uses_the_api_and_not_the_feed(self):
        fetcher, transport = make_fetcher([
            (r"urlhaus-api\.abuse\.ch/v1/host/", URLHAUS_API_OK),
            (r"urlhaus\.abuse\.ch/downloads", URLHAUS_FEED),
        ])
        result = run_source("urlhaus", context_for("example.com", fetcher=fetcher, keys={"abusech": "KEY123"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(len(transport.calls), 1)
        self.assertIn("urlhaus-api", transport.calls[0]["url"])
        self.assertEqual(transport.calls[0]["headers"]["Auth-Key"], "KEY123")
        self.assertEqual(transport.calls[0]["body"], b"host=example.com")

    def test_auth_key_no_results(self):
        fetcher, _ = make_fetcher([(r"urlhaus-api\.abuse\.ch/v1/host/", URLHAUS_API_EMPTY)])
        result = run_source("urlhaus", context_for("example.org", fetcher=fetcher, forced="domain",
                                                   keys={"abusech": "KEY123"}))
        self.assertEqual(result.status, STATUS_NO_MATCH)

    def test_key_is_required_for_the_api_source_to_run(self):
        from app.sources import plan_for

        plan = dict(plan_for("domain", {}))
        spec = [s for s in plan if s.id == "urlhaus"][0]
        self.assertIsNotNone(plan[spec])
        self.assertEqual(plan[spec].status, STATUS_NOT_CHECKED)


class OpenphishTests(unittest.TestCase):
    def test_exact_host_match(self):
        fetcher, _ = make_fetcher([(r"openphish\.com/feed\.txt", OPENPHISH_FEED)])
        result = run_source("openphish", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.findings[0].severity, "high")
        self.assertEqual(result.data["matches"], ["http://example.com/secure/verify"])

    def test_falls_back_to_the_mirror(self):
        fetcher, transport = make_fetcher([
            (r"openphish\.com/feed\.txt", UpstreamTimeout("timed out")),
            (r"raw\.githubusercontent\.com/openphish", OPENPHISH_FEED),
        ])
        result = run_source("openphish", context_for("phishing-host.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_OK)
        self.assertIn("raw.githubusercontent.com", transport.calls[-1]["url"])

    def test_both_feeds_failing_is_unavailable(self):
        fetcher, _ = make_fetcher([
            (r"openphish\.com/feed\.txt", UpstreamTimeout("timed out")),
            (r"raw\.githubusercontent\.com/openphish", UpstreamTimeout("timed out")),
        ])
        result = run_source("openphish", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)

    def test_no_match_states_the_feed_scope(self):
        fetcher, _ = make_fetcher([(r"openphish\.com/feed\.txt", OPENPHISH_FEED)])
        result = run_source("openphish", context_for("clean.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("recent community feed only", result.data["feed_entries_checked"])


class WaybackTests(unittest.TestCase):
    def test_snapshot_and_first_capture(self):
        fetcher, transport = make_fetcher([
            (r"archive\.org/wayback/available", WAYBACK_AVAILABLE),
            (r"web\.archive\.org/cdx", WAYBACK_CDX),
        ])
        result = run_source("wayback", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["first_seen"], "19960110230000")
        self.assertEqual(result.data["first_seen_iso"], "1996-01-10T23:00:00Z")
        self.assertTrue(result.findings[0].links)
        # The availability API must be called with a bare domain (no scheme).
        availability_url = [c["url"] for c in transport.calls if "wayback/available" in c["url"]][0]
        self.assertIn("url=example.com", availability_url)
        self.assertNotIn("https%3A", availability_url)

    def test_no_snapshots_is_no_match(self):
        fetcher, _ = make_fetcher([
            (r"archive\.org/wayback/available", WAYBACK_NONE),
            (r"web\.archive\.org/cdx", "[]"),
        ])
        result = run_source("wayback", context_for("never-archived.example", fetcher=fetcher, forced="domain"))
        self.assertEqual(result.status, STATUS_NO_MATCH)

    def test_both_failing_is_unavailable(self):
        fetcher, _ = make_fetcher([
            (r"archive\.org/wayback/available", UpstreamTimeout("timed out")),
            (r"web\.archive\.org/cdx", UpstreamTimeout("timed out")),
        ])
        result = run_source("wayback", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)

    def test_email_identifier_uses_the_domain_part(self):
        fetcher, transport = make_fetcher([
            (r"archive\.org/wayback/available", WAYBACK_AVAILABLE),
            (r"web\.archive\.org/cdx", WAYBACK_CDX),
        ])
        run_source("wayback", context_for("person@example.com", fetcher=fetcher))
        for call in transport.calls:
            self.assertNotIn("person@", call["url"])


class VirusTotalTests(unittest.TestCase):
    def test_without_key_it_is_not_checked(self):
        fetcher, transport = make_fetcher([])
        result = run_source("virustotal", context_for("example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NOT_CHECKED)
        self.assertIn("API key", result.message)
        self.assertEqual(transport.calls, [])

    def test_with_key_the_report_is_used(self):
        fetcher, transport = make_fetcher([(r"virustotal\.com/api/v3/domains", VIRUSTOTAL_DOMAIN)])
        result = run_source("virustotal", context_for("example.com", fetcher=fetcher, keys={"virustotal": "VTKEY"}))
        self.assertEqual(result.status, STATUS_NO_MATCH)  # 0 malicious, 0 suspicious
        self.assertEqual(result.data["engines"], 92)
        self.assertEqual(transport.calls[0]["headers"]["x-apikey"], "VTKEY")
        self.assertEqual(result.findings[0].severity, "info")

    def test_bad_key_is_unavailable_with_a_hint(self):
        fetcher, _ = make_fetcher([(r"virustotal\.com/api/v3/domains", (401, {"error": {"code": "wrong-credentials"}}))])
        result = run_source("virustotal", context_for("example.com", fetcher=fetcher, keys={"virustotal": "BAD"}))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("API key", result.message)


class PasswordRangeTests(unittest.TestCase):
    def test_only_the_prefix_is_sent(self):
        fetcher, transport = make_fetcher([(r"api\.pwnedpasswords\.com/range/", HIBP_RANGE)])
        from app.passwords import fetch_range

        payload = fetch_range("5baa6", fetcher)
        self.assertEqual(payload["prefix"], "5BAA6")
        self.assertEqual(payload["entry_count"], 3)
        self.assertEqual(transport.calls[0]["url"], "https://api.pwnedpasswords.com/range/5BAA6")
        # The full SHA-1 (and obviously the password itself) must never leave the browser.
        self.assertNotIn("61e4c9b93f3f0682250b6cf8331b7ee68fd8", transport.calls[0]["url"])
        self.assertFalse(transport.calls[0]["body"])  # GET with no request body

    def test_invalid_prefix_is_rejected(self):
        fetcher, transport = make_fetcher([])
        from app.passwords import PasswordCheckError, fetch_range

        for bad in ("", "1234", "123456", "GGGGG", "my-password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"):
            with self.subTest(prefix=bad[:12]):
                with self.assertRaises(PasswordCheckError):
                    fetch_range(bad, fetcher)
        self.assertEqual(transport.calls, [])

    def test_unparsable_response_is_an_error_not_a_false_negative(self):
        fetcher, _ = make_fetcher([(r"api\.pwnedpasswords\.com/range/", "not-a-range-response\n")])
        from app.passwords import fetch_range

        with self.assertRaises(Exception):
            fetch_range("5BAA6", fetcher)


class UnusedFixtureTests(unittest.TestCase):
    def test_fixtures_are_importable(self):
        self.assertTrue(BLOCKSTREAM_UNUSED["address"])


if __name__ == "__main__":
    unittest.main()
