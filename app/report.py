"""Evidence-based report generation.

This module is a **rule engine**, not a model.  It contains no AI, no LLM
calls and no learned weights: it reads the structured results produced by the
sources and assembles them into sections, with the interpretation caveats that
belong to each kind of evidence.  Every report it produces is labelled that way
in the UI and in the JSON.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .identifiers import Identifier
from .sources.base import (
    SEVERITY_ORDER,
    STATUS_ERROR,
    STATUS_NO_MATCH,
    STATUS_NOT_CHECKED,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
    SourceResult,
    utcnow_iso,
)

ENGINE = "deterministic-rules-v1"
ENGINE_NOTE = (
    "This summary was assembled by fixed rules in the Verdigris backend. No AI or language model is configured or "
    "called, and no text here is model-generated. Every statement points at the source result that produced it."
)

FAILED_STATUSES = (STATUS_UNAVAILABLE, STATUS_RATE_LIMITED, STATUS_ERROR)

STANDING_LIMITATIONS = [
    "Absence of a finding is not evidence of absence: several of these sources only cover recent or partial data.",
    "A matching username, handle or name is never proof of the same person. Handles are re-used, squatted and shared.",
    "Appearing in a threat-intel pulse, a public scan archive or a phishing feed is a third-party claim, not a verdict.",
    "Phone-number analysis establishes format and country calling code only - never the owner, the carrier, whether the "
    "line is active, or any location.",
    "This app queries public, keyless (or your-own-key) sources only. It does not query paid people-search, credit, "
    "court, carrier or 'full dark web' databases, does not crawl Tor, and does not attempt to bypass any login or "
    "access control.",
    "Blockchain data is public and permanent: there is no removal process for a Bitcoin or Ethereum address's history.",
    "Everything here is a snapshot of the moment the scan ran; upstream data changes constantly.",
    "Free-tier upstreams rate-limit by IP, so a 'source unavailable' or 'rate limited' row means 'we could not check', "
    "never 'nothing was found'.",
    "Gravatar lookups use an MD5 hash of the address; for common providers such hashes can be brute-forced by anyone.",
    "No privacy score is produced. When sources fail, the report says 'insufficient data' instead of implying safety.",
]

# Provider removal / reporting entry points.  ``tools/link_check.py`` verifies
# these in CI so the report never advertises a dead link.
ACTION_LINKS: dict[str, list[dict[str, str]]] = {
    "_universal": [
        {"provider": "Google Search", "label": "Remove outdated content from Google",
         "url": "https://support.google.com/websearch/troubleshooter/3111061",
         "does": "Google's own tool for removing a page that has already changed or disappeared."},
        {"provider": "Bing", "label": "Bing content removal request",
         "url": "https://www.bing.com/webmasters/contentremoval",
         "does": "Microsoft's form for removing a URL from Bing search results."},
        {"provider": "Internet Archive", "label": "Ask the Internet Archive to exclude a site from the Wayback Machine",
         "url": "https://archive.org/about/contact.php",
         "does": "Exclusion and removal requests go to the Archive's contact page or "
                 "info@archive.org (subject: 'Request for exclusion from web.archive.org')."},
        {"provider": "Have I Been Pwned", "label": "Opt an address out of HIBP breach search",
         "url": "https://haveibeenpwned.com/optout",
         "does": "HIBP's own opt-out for sensitive personal addresses (verification email required)."},
    ],
    "domain": [
        {"provider": "urlscan.io", "label": "urlscan.io scan removal / blocklist request",
         "url": "https://urlscan.io/about/",
         "does": "urlscan.io explains how to request removal or hiding of scans you own."},
        {"provider": "AlienVault OTX", "label": "Report or dispute an OTX indicator",
         "url": "https://otx.alienvault.com/",
         "does": "Open the pulse and use OTX's own reporting/support path to dispute an indicator."},
        {"provider": "ICANN", "label": "Registrar data (WHOIS/RDDS) inaccuracy complaint",
         "url": "https://www.icann.org/wicf/",
         "does": "ICANN's form for reporting inaccurate registration data."},
        {"provider": "abuse.ch", "label": "Dispute a URLhaus/OpenPhish listing",
         "url": "https://urlhaus.abuse.ch/",
         "does": "abuse.ch documents how listed hosts can be reported as false positives (account required)."},
        {"provider": "Google Safe Browsing", "label": "Report phishing (or request a re-review)",
         "url": "https://safebrowsing.google.com/safebrowsing/report_error/",
         "does": "Google's own form for reporting a phishing page or asking for a false positive to be re-reviewed."},
    ],
    "email": [
        {"provider": "GitHub", "label": "Ask GitHub to remove personal data / an exposed email",
         "url": "https://support.github.com/contact/private-information",
         "does": "GitHub's form for removing personal information from public repositories."},
        {"provider": "GitHub", "label": "Remove sensitive data from a repository",
         "url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
         "does": "How to rewrite history and rotate secrets after an email or token is committed."},
        {"provider": "Gravatar", "label": "Edit or delete your Gravatar profile",
         "url": "https://gravatar.com/profiles/edit",
         "does": "The profile is owned by whoever controls the address; you can remove fields or the profile."},
        {"provider": "Sourcegraph", "label": "Ask Sourcegraph to remove content from its public index",
         "url": "https://about.sourcegraph.com/contact",
         "does": "Sourcegraph's contact page for removal requests on public code search."},
    ],
    "username": [
        {"provider": "GitHub", "label": "Delete or anonymise a GitHub account",
         "url": "https://docs.github.com/en/account-and-profile/how-tos/account-management/deleting-your-personal-account",
         "does": "Account deletion removes public profile data; committed history may need a separate request."},
        {"provider": "GitLab", "label": "GitLab profile / account management",
         "url": "https://docs.gitlab.com/ee/user/profile/",
         "does": "How to clear profile fields or delete an account on GitLab.com."},
        {"provider": "Codeberg", "label": "Codeberg account deletion request",
         "url": "https://codeberg.org/Codeberg-e.V./requests",
         "does": "Codeberg's request tracker for account and data removal."},
        {"provider": "Keybase", "label": "Keybase account management",
         "url": "https://keybase.io/account",
         "does": "Your Keybase account page (proofs and profile data live here)."},
        {"provider": "Hacker News", "label": "Ask HN to delete your account",
         "url": "https://news.ycombinator.com/newsguidelines.html",
         "does": "HN's guidelines describe how to request account deletion (hn@ycombinator.com)."},
        {"provider": "Gravatar", "label": "Edit or delete your Gravatar profile",
         "url": "https://gravatar.com/profiles/edit",
         "does": "Remove the profile that a username lookup can return."},
    ],
    "name": [
        {"provider": "Wikipedia", "label": "Biographies of living persons noticeboard",
         "url": "https://en.wikipedia.org/wiki/Wikipedia:Biographies_of_living_persons/Noticeboard",
         "does": "Where problematic content about a living person is raised for editor review."},
        {"provider": "Wikipedia", "label": "Request article deletion / volunteer response",
         "url": "https://en.wikipedia.org/wiki/Wikipedia:Contact_us",
         "does": "Wikipedia's own contact routes, including for subjects of articles."},
        {"provider": "GitHub", "label": "Ask GitHub to remove personal data",
         "url": "https://support.github.com/contact/private-information",
         "does": "Applies when a name appears in a public profile, commit or file."},
    ],
    "phone": [
        {"provider": "Your carrier", "label": "Ask your carrier about number privacy options",
         "url": "https://www.fcc.gov/consumers/guides/stop-unwanted-robocalls-and-texts",
         "does": "Regulator guidance on unwanted calls; carrier-level privacy changes must come from the carrier."},
    ],
    "bitcoin": [
        {"provider": "Blockstream explorer", "label": "Explorer data (public chain data cannot be removed)",
         "url": "https://blockstream.info/",
         "does": "Explorers only mirror the public blockchain; there is no deletion mechanism for ledger entries."},
    ],
    "ethereum": [
        {"provider": "Etherscan", "label": "Etherscan address pages and support",
         "url": "https://etherscan.io/contactus",
         "does": "Explorer metadata (labels, comments) can be disputed; the underlying chain data cannot be removed."},
    ],
}

NO_AUTOMATION_NOTE = (
    "Verdigris only opens these pages in a new tab. It never fills in, signs or submits a removal, takedown or "
    "abuse request on your behalf, and it cannot tell you whether one was accepted."
)


def _severity_counts(findings: list[dict[str, Any]]) -> Counter:
    return Counter(f.get("severity", "info") for f in findings)


def build_privacy_disclosure(identifier: Identifier, results: list[SourceResult]) -> list[dict[str, str]]:
    """Exactly what left the server, per source (used in the UI and the JSON export)."""
    rows: list[dict[str, str]] = []
    for result in results:
        sent = (result.sends or "").strip()
        if not sent:
            continue
        actually_sent = result.status not in (STATUS_NOT_CHECKED,)
        rows.append({
            "source": result.source_name,
            "identifier": identifier.value if actually_sent else "(nothing - not checked)",
            "sent": sent,
            "upstream": result.upstream_host or "-",
            "status": result.status,
        })
    return rows


def build_coverage(identifier: Identifier, results: list[SourceResult], *, started_at: str,
                   finished_at: str, duration_ms: int) -> dict[str, Any]:
    statuses = Counter(r.status for r in results)
    findings = [f.as_dict() for r in results for f in r.findings]
    severities = _severity_counts(findings)
    succeeded = statuses[STATUS_OK] + statuses[STATUS_NO_MATCH]
    return {
        "identifier_type": identifier.kind,
        "identifier_type_label": identifier.meta.get("type_label", identifier.kind),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "sources_planned": len(results),
        "sources_with_data": statuses[STATUS_OK],
        "sources_no_match": statuses[STATUS_NO_MATCH],
        "sources_not_checked": statuses[STATUS_NOT_CHECKED],
        "sources_unavailable": statuses[STATUS_UNAVAILABLE] + statuses[STATUS_RATE_LIMITED] + statuses[STATUS_ERROR],
        "succeeded": succeeded,
        "failed": statuses[STATUS_UNAVAILABLE] + statuses[STATUS_RATE_LIMITED] + statuses[STATUS_ERROR],
        "findings_total": len(findings),
        "findings_by_severity": {sev: severities.get(sev, 0) for sev in SEVERITY_ORDER},
        "status_counts": dict(statuses),
        "not_checked_sources": [
            {"source": r.source_name, "reason": r.message} for r in results if r.status == STATUS_NOT_CHECKED
        ],
        "unavailable_sources": [
            {"source": r.source_name, "reason": r.message} for r in results if r.status in FAILED_STATUSES
        ],
        # A source that was deliberately not checked never contacted its upstream,
        # so it must not appear in the list of hosts that received the identifier.
        "queried_upstreams": sorted({r.upstream_host for r in results
                                     if r.upstream_host and r.status != STATUS_NOT_CHECKED}),
        "third_party_queries": sum(1 for r in results if r.upstream_host and r.status not in (STATUS_NOT_CHECKED,)),
    }


def _highest_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "none"
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 9))[0].get("severity", "info")


def build_summary(identifier: Identifier, results: list[SourceResult], coverage: dict[str, Any]) -> dict[str, Any]:
    findings = [f.as_dict() for r in results for f in r.findings]
    by_source = {r.source_id: r for r in results}
    severities = coverage["findings_by_severity"]
    succeeded = coverage["succeeded"]
    planned = coverage["sources_planned"]

    sections: list[dict[str, Any]] = []
    headline = ""
    data_confidence = "insufficient-data"

    if succeeded == 0:
        headline = "Insufficient data - no source could be checked"
        sections.append({
            "id": "insufficient",
            "title": "Insufficient data",
            "points": [{
                "severity": "info",
                "text": "None of the planned sources returned data for this identifier, so no conclusion - positive or "
                        "negative - can be drawn. Nothing here should be read as 'clean' or 'safe'.",
            }],
            "source_ids": [r.source_id for r in results],
        })
        reasons = Counter()
        for result in results:
            if result.status in FAILED_STATUSES:
                reasons["source unavailable / rate limited"] += 1
            elif result.status == STATUS_NOT_CHECKED:
                reasons["not checked (needs an API key or not applicable)"] += 1
        sections.append({
            "id": "why-no-data",
            "title": "Why there is no data",
            "points": [{"severity": "info", "text": f"{label}: {count} source(s)"} for label, count in reasons.items()],
            "source_ids": [],
        })
    else:
        top = _highest_severity(findings)
        counts = ", ".join(f"{sev}: {severities[sev]}" for sev in SEVERITY_ORDER if severities.get(sev))
        headline = (
            f"{len(findings)} finding(s) from {succeeded} source(s) that answered "
            f"(highest severity: {top}; {counts or 'no severity-bearing findings'})"
        )
        data_confidence = "good" if succeeded >= max(3, int(planned * 0.6)) and coverage["failed"] == 0 else (
            "moderate" if succeeded >= 2 else "low"
        )

    # --- Exposure sections, built only from real source output --------------
    exposure_sources = [r for r in results if r.findings and any(
        f.severity in ("high", "critical") for f in r.findings)]
    if exposure_sources:
        points = []
        for result in exposure_sources:
            for finding in result.findings:
                if finding.severity in ("high", "critical"):
                    points.append({"severity": finding.severity, "text": finding.title,
                                   "source_id": result.source_id})
        sections.append({"id": "exposure", "title": "Highest-severity exposures", "points": points,
                         "source_ids": sorted({p.get("source_id") for p in points if p.get("source_id")})})

    identity_sources = [r for r in results if r.category in ("identity", "code-hosting", "public-records")
                        and r.status == STATUS_OK]
    if identity_sources:
        points = []
        for result in identity_sources:
            for finding in result.findings:
                points.append({"severity": finding.severity, "text": finding.title, "source_id": result.source_id})
        sections.append({"id": "identity-footprint", "title": "Public profile & identity footprint",
                         "points": points[:10], "source_ids": [r.source_id for r in identity_sources]})

    infra_sources = [r for r in results if r.category in ("infrastructure", "registry", "archives") and r.status == STATUS_OK]
    if infra_sources:
        points = []
        for result in infra_sources:
            for finding in result.findings:
                points.append({"severity": finding.severity, "text": finding.title, "source_id": result.source_id})
        sections.append({"id": "infrastructure", "title": "Domain, registration & archive footprint",
                         "points": points[:12], "source_ids": [r.source_id for r in infra_sources]})

    threat_sources = [r for r in results if r.category == "threat-intel"]
    if threat_sources:
        points = []
        for result in threat_sources:
            if result.status == STATUS_OK:
                for finding in result.findings:
                    points.append({"severity": finding.severity, "text": finding.title, "source_id": result.source_id})
            elif result.status == STATUS_NO_MATCH:
                points.append({"severity": "info", "text": f"{result.source_name}: no match in the data it covers.",
                               "source_id": result.source_id})
            elif result.status in FAILED_STATUSES:
                points.append({"severity": "info",
                               "text": f"{result.source_name}: could not be checked ({result.message}).",
                               "source_id": result.source_id})
        sections.append({"id": "third-party-claims", "title": "Third-party threat-intel references (claims, not verdicts)",
                         "points": points[:10], "source_ids": [r.source_id for r in threat_sources]})

    # --- What was explicitly NOT found --------------------------------------
    clean = [r for r in results if r.status == STATUS_NO_MATCH]
    if clean:
        sections.append({
            "id": "no-match",
            "title": "Sources that answered with no match",
            "points": [{"severity": "info", "text": f"{r.source_name}: {r.message}", "source_id": r.source_id}
                       for r in clean[:12]],
            "source_ids": [r.source_id for r in clean],
        })

    unchecked = [r for r in results if r.status == STATUS_NOT_CHECKED]
    failed = [r for r in results if r.status in FAILED_STATUSES]
    if unchecked or failed:
        points = []
        for r in unchecked:
            points.append({"severity": "info", "text": f"{r.source_name} - NOT CHECKED: {r.message}",
                           "source_id": r.source_id})
        for r in failed:
            points.append({"severity": "info",
                           "text": f"{r.source_name} - SOURCE UNAVAILABLE: {r.message}", "source_id": r.source_id})
        sections.append({"id": "gaps", "title": "Coverage gaps in this report",
                         "points": points[:16], "source_ids": [r.source_id for r in unchecked + failed]})

    sections.append({
        "id": "interpretation",
        "title": "How to read this report",
        "points": [{"severity": "info", "text": text} for text in [
            "Findings describe what a public source returned at scan time; they are not accusations or conclusions about a person.",
            "Severity reflects how much of an exposure the evidence shows, not how likely it is to be about your subject.",
            "Where two identifiers agree (for example a signed Keybase proof plus a commit email), confidence rises - "
            "a single username match never does.",
        ]],
        "source_ids": [],
    })

    actions = list(ACTION_LINKS.get("_universal", []))
    actions += list(ACTION_LINKS.get(identifier.kind, []))
    if identifier.kind == "email":
        actions += [a for a in ACTION_LINKS["username"] if a["provider"] == "Gravatar"]

    rdap_data = (by_source.get("rdap").data if by_source.get("rdap") else {}) or {}
    registrar_abuse = rdap_data.get("abuse_email")
    if registrar_abuse:
        actions.insert(0, {
            "provider": "Registrar abuse contact",
            "label": f"Contact the registrar's abuse desk ({registrar_abuse})",
            "url": f"mailto:{registrar_abuse}",
            "does": f"Abuse contact published in the RDAP record for {rdap_data.get('domain', identifier.value)}.",
        })

    return {
        "engine": ENGINE,
        "engine_note": ENGINE_NOTE,
        "headline": headline,
        "data_confidence": data_confidence,
        "data_confidence_note": (
            "This describes how much of the planned source set actually answered. It is NOT a privacy score, a risk "
            "score or a safety rating."
        ),
        "generated_at": utcnow_iso(),
        "identifier_type": identifier.kind,
        "sections": sections,
        "coverage": coverage,
        "limitations": list(STANDING_LIMITATIONS),
        "actions": {"note": NO_AUTOMATION_NOTE, "links": actions},
        "not_claims": [
            "This report does not claim to query paid people-search, credit-header, court or carrier databases.",
            "This report does not claim to crawl the Tor network or any 'dark web' marketplace.",
            "This report does not claim any removal, takedown or abuse request was submitted.",
            "This report does not produce a numeric privacy or risk score.",
            "This report is not legal advice, and it is not a determination that anyone did anything wrong.",
        ],
    }
