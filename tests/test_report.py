"""Tests for the deterministic summary engine, coverage maths and disclosures."""

from __future__ import annotations

import unittest

from stubs import *  # noqa: F401,F403

from app.identifiers import detect
from app.report import (
    ACTION_LINKS,
    ENGINE,
    ENGINE_NOTE,
    NO_AUTOMATION_NOTE,
    STANDING_LIMITATIONS,
    build_coverage,
    build_privacy_disclosure,
    build_summary,
)
from app.sources.base import (
    Evidence,
    Finding,
    SourceResult,
    STATUS_ERROR,
    STATUS_NO_MATCH,
    STATUS_NOT_CHECKED,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
)


def result(source_id: str, status: str, *, message: str = "", category: str = "identity",
           findings: list[Finding] | None = None, sends: str = "The identifier.",
           upstream_host: str = "") -> SourceResult:
    return SourceResult(source_id=source_id, source_name=source_id.replace("_", " ").title(), status=status,
                        message=message or status, category=category, findings=findings or [], sends=sends,
                        upstream_host=upstream_host)


def finding(source_id: str, title: str, severity: str = "info", category: str = "identity") -> Finding:
    return Finding(source_id=source_id, source_name=source_id.replace("_", " ").title(), title=title,
                   severity=severity, category=category, summary=f"Summary for {title}.")


def coverage_for(results, ident=None, **kwargs):
    ident = ident or detect("example.com")
    return build_coverage(ident, results, started_at="2026-10-07T09:00:00Z",
                          finished_at="2026-10-07T09:00:04Z", duration_ms=4000)


class CoverageTests(unittest.TestCase):
    def test_four_way_split_is_never_collapsed(self):
        results = [
            result("a", STATUS_OK, upstream_host="a.example"),
            result("b", STATUS_NO_MATCH, upstream_host="b.example"),
            result("c", STATUS_NOT_CHECKED, message="needs your API key"),
            result("d", STATUS_UNAVAILABLE, message="timed out", upstream_host="d.example"),
            result("e", STATUS_RATE_LIMITED, message="429", upstream_host="e.example"),
            result("f", STATUS_ERROR, message="crashed", upstream_host="f.example"),
        ]
        cov = coverage_for(results)
        self.assertEqual(cov["sources_planned"], 6)
        self.assertEqual(cov["sources_with_data"], 1)
        self.assertEqual(cov["sources_no_match"], 1)
        self.assertEqual(cov["sources_not_checked"], 1)
        # unavailable + rate_limited + error are all "we could not check"
        self.assertEqual(cov["sources_unavailable"], 3)
        self.assertEqual(cov["succeeded"], 2)
        self.assertEqual(cov["failed"], 3)
        self.assertEqual(cov["status_counts"][STATUS_NOT_CHECKED], 1)

    def test_not_checked_is_listed_with_its_reason_and_never_counted_as_no_match(self):
        results = [result("hibp_breaches", STATUS_NOT_CHECKED, message="needs your own HIBP API key")]
        cov = coverage_for(results)
        self.assertEqual(cov["sources_no_match"], 0)
        self.assertEqual(cov["not_checked_sources"][0]["reason"], "needs your own HIBP API key")
        self.assertIn("HIBP", cov["not_checked_sources"][0]["source"].upper())

    def test_unavailable_sources_are_listed_with_reasons(self):
        results = [result("rdap", STATUS_UNAVAILABLE, message="upstream timed out", upstream_host="rdap.org")]
        cov = coverage_for(results)
        self.assertEqual(len(cov["unavailable_sources"]), 1)
        self.assertIn("timed out", cov["unavailable_sources"][0]["reason"])

    def test_severity_histogram_covers_every_severity(self):
        results = [result("a", STATUS_OK, findings=[finding("a", "x", "high"), finding("a", "y", "info")])]
        cov = coverage_for(results)
        self.assertEqual(cov["findings_total"], 2)
        self.assertEqual(cov["findings_by_severity"]["high"], 1)
        self.assertEqual(cov["findings_by_severity"]["critical"], 0)
        self.assertEqual(sorted(cov["findings_by_severity"]),
                         ["critical", "high", "info", "low", "medium"])

    def test_queried_upstreams_disclose_which_hosts_were_contacted(self):
        results = [
            result("a", STATUS_OK, upstream_host="api.github.com"),
            result("b", STATUS_NO_MATCH, upstream_host="dns.google"),
            result("c", STATUS_NOT_CHECKED, upstream_host="haveibeenpwned.com"),
        ]
        cov = coverage_for(results)
        self.assertEqual(cov["queried_upstreams"], ["api.github.com", "dns.google"])
        self.assertEqual(cov["third_party_queries"], 2)


class SummaryTests(unittest.TestCase):
    def test_all_sources_failing_means_insufficient_data(self):
        results = [result("dns_doh", STATUS_UNAVAILABLE, message="timed out", category="infrastructure"),
                   result("rdap", STATUS_RATE_LIMITED, message="429", category="registry"),
                   result("hibp_breaches", STATUS_NOT_CHECKED, message="needs a key")]
        cov = coverage_for(results)
        summary = build_summary(detect("example.com"), results, cov)
        self.assertEqual(summary["data_confidence"], "insufficient-data")
        self.assertIn("Insufficient data", summary["headline"])
        ids = [s["id"] for s in summary["sections"]]
        self.assertIn("insufficient", ids)
        self.assertIn("why-no-data", ids)
        self.assertNotIn("exposure", ids)
        blob = " ".join(p["text"] for s in summary["sections"] for p in s["points"])
        self.assertIn("no conclusion", blob)
        self.assertIn("clean", blob)  # explicitly refuses to imply safety

    def test_confidence_is_never_called_a_score(self):
        results = [result("a", STATUS_OK, findings=[finding("a", "something", "medium")],
                          upstream_host="a.example")]
        summary = build_summary(detect("example.com"), results, coverage_for(results))
        self.assertEqual(summary["data_confidence"], "low")
        self.assertIn("NOT a privacy score", summary["data_confidence_note"])
        self.assertNotIn("score:", summary["headline"].lower())

    def test_confidence_rises_with_more_sources_answering(self):
        few = [result("a", STATUS_OK), result("b", STATUS_UNAVAILABLE), result("c", STATUS_UNAVAILABLE)]
        self.assertEqual(build_summary(detect("example.com"), few, coverage_for(few))["data_confidence"], "low")
        many = [result(f"s{i}", STATUS_OK) for i in range(6)]
        self.assertEqual(build_summary(detect("example.com"), many, coverage_for(many))["data_confidence"], "good")
        partial = [result(f"s{i}", STATUS_OK) for i in range(3)] + [result("bad", STATUS_UNAVAILABLE)]
        self.assertEqual(build_summary(detect("example.com"), partial, coverage_for(partial))["data_confidence"],
                         "moderate")

    def test_engine_is_labelled_as_rules_not_ai(self):
        results = [result("a", STATUS_OK)]
        summary = build_summary(detect("example.com"), results, coverage_for(results))
        self.assertEqual(summary["engine"], ENGINE)
        self.assertEqual(ENGINE, "deterministic-rules-v1")
        self.assertIn("No AI or language model", summary["engine_note"])
        self.assertIn("model-generated", summary["engine_note"])

    def test_high_severity_exposures_get_their_own_section(self):
        results = [result("github_commits", STATUS_OK, category="code-hosting",
                          findings=[finding("github_commits", "Email appears in commits", "high", "code-hosting")])]
        summary = build_summary(detect("a@b.com"), results, coverage_for(results, detect("a@b.com")))
        ids = [s["id"] for s in summary["sections"]]
        self.assertIn("exposure", ids)
        exposure = [s for s in summary["sections"] if s["id"] == "exposure"][0]
        self.assertEqual(exposure["points"][0]["text"], "Email appears in commits")
        self.assertEqual(exposure["source_ids"], ["github_commits"])

    def test_coverage_gaps_section_is_always_present_when_something_failed(self):
        results = [result("a", STATUS_OK), result("b", STATUS_NOT_CHECKED, message="needs a key"),
                   result("c", STATUS_UNAVAILABLE, message="timed out")]
        summary = build_summary(detect("example.com"), results, coverage_for(results))
        gaps = [s for s in summary["sections"] if s["id"] == "gaps"]
        self.assertTrue(gaps)
        text = " ".join(p["text"] for p in gaps[0]["points"])
        self.assertIn("NOT CHECKED", text)
        self.assertIn("SOURCE UNAVAILABLE", text)

    def test_interpretation_section_is_always_present(self):
        results = [result("a", STATUS_OK)]
        summary = build_summary(detect("example.com"), results, coverage_for(results))
        self.assertIn("interpretation", [s["id"] for s in summary["sections"]])

    def test_standing_limitations_are_attached_to_every_report(self):
        results = [result("a", STATUS_OK)]
        summary = build_summary(detect("example.com"), results, coverage_for(results))
        self.assertEqual(summary["limitations"], list(STANDING_LIMITATIONS))
        joined = " ".join(STANDING_LIMITATIONS)
        self.assertIn("never proof of the same person", joined)
        self.assertIn("not a verdict", joined)
        self.assertIn("format and country calling code only", joined)
        self.assertIn("no removal process", joined)
        self.assertIn("No privacy score", joined)

    def test_explicit_non_claims(self):
        results = [result("a", STATUS_OK)]
        summary = build_summary(detect("example.com"), results, coverage_for(results))
        joined = " ".join(summary["not_claims"]).lower()
        self.assertIn("paid people-search", joined)
        self.assertIn("dark web", joined)
        self.assertIn("removal, takedown or abuse request was submitted", joined)
        self.assertIn("numeric privacy or risk score", joined)
        self.assertIn("not legal advice", joined)


class ActionLinkTests(unittest.TestCase):
    def test_every_link_is_well_formed(self):
        seen = 0
        for kind, links in ACTION_LINKS.items():
            for link in links:
                seen += 1
                self.assertEqual(sorted(link), ["does", "label", "provider", "url"], (kind, link))
                self.assertTrue(link["url"].startswith(("https://", "mailto:")), link)
                self.assertTrue(link["label"].strip())
                self.assertTrue(link["does"].strip())
        self.assertGreater(seen, 15)

    def test_links_never_claim_automation(self):
        results = [result("a", STATUS_OK)]
        summary = build_summary(detect("person@example.com", forced_type="email"), results,
                                coverage_for(results, detect("person@example.com", forced_type="email")))
        self.assertEqual(summary["actions"]["note"], NO_AUTOMATION_NOTE)
        self.assertIn("never fills in, signs or submits", summary["actions"]["note"])
        self.assertIn("cannot tell you whether one was accepted", summary["actions"]["note"])

    def test_links_are_scoped_to_the_identifier_type(self):
        results = [result("a", STATUS_OK)]
        domain_summary = build_summary(detect("example.com"), results, coverage_for(results))
        labels = " ".join(link["label"] for link in domain_summary["actions"]["links"])
        self.assertIn("Wayback", labels)
        self.assertIn("urlscan", labels.lower())
        email_summary = build_summary(detect("person@example.com", forced_type="email"), results,
                                      coverage_for(results, detect("person@example.com", forced_type="email")))
        email_labels = " ".join(link["label"] for link in email_summary["actions"]["links"])
        self.assertIn("Gravatar", email_labels)
        self.assertIn("GitHub", email_labels)

    def test_registrar_abuse_contact_is_promoted_when_rdap_has_one(self):
        from app.sources.base import SourceResult as SR

        rdap = SR(source_id="rdap", source_name="RDAP", status=STATUS_OK, message="ok", category="registry",
                  data={"domain": "example.com", "abuse_email": "abuse@registrar.example"}, sends="The domain.")
        summary = build_summary(detect("example.com"), [rdap], coverage_for([rdap]))
        first = summary["actions"]["links"][0]
        self.assertEqual(first["url"], "mailto:abuse@registrar.example")
        self.assertEqual(first["provider"], "Registrar abuse contact")


class PrivacyDisclosureTests(unittest.TestCase):
    def test_rows_show_exactly_what_left_the_server(self):
        results = [
            result("github_user", STATUS_OK, sends="The username.", upstream_host="api.github.com"),
            result("phone_local", STATUS_OK, sends="Nothing.", upstream_host=""),
            result("hibp_breaches", STATUS_NOT_CHECKED, sends="The full email address.",
                   upstream_host="haveibeenpwned.com"),
        ]
        rows = build_privacy_disclosure(detect("torvalds"), results)
        self.assertEqual(len(rows), 3)
        by_source = {r["source"]: r for r in rows}
        self.assertEqual(by_source["Github User"]["identifier"], "torvalds")
        self.assertEqual(by_source["Github User"]["upstream"], "api.github.com")
        # A source that was not checked must not claim it sent anything.
        self.assertEqual(by_source["Hibp Breaches"]["identifier"], "(nothing - not checked)")

    def test_sources_without_a_sends_statement_are_omitted(self):
        rows = build_privacy_disclosure(detect("example.com"), [result("a", STATUS_OK, sends="")])
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
