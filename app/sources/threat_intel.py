"""Threat-intelligence reference sources.

These report *references* published by third parties.  None of them is a
verdict, and the findings say so explicitly: a domain appearing in a scan
archive or a user-submitted pulse is not automatically malicious.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from ..config import SETTINGS
from ..http_client import UpstreamError
from ..identifiers import apex_domain
from .base import (
    Evidence,
    Finding,
    SourceContext,
    SourceOutcome,
    STATUS_NOT_CHECKED,
    STATUS_NO_MATCH,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    parse_upstream_timestamp,
    source,
)


def _host_matches(candidate: str, targets: set[str]) -> bool:
    candidate = (candidate or "").strip().lower().rstrip(".")
    if not candidate:
        return False
    if candidate in targets:
        return True
    return candidate.startswith("www.") and candidate[4:] in targets


def _hosts_for(domain: str) -> set[str]:
    domain = domain.strip().lower().rstrip(".")
    apex = apex_domain(domain)
    hosts = {domain, apex}
    if domain.startswith("www."):
        hosts.add(domain[4:])
    return hosts


# ---------------------------------------------------------------------------
# urlscan.io - existing public scan records (search only, never a new scan)
# ---------------------------------------------------------------------------


@source(
    id="urlscan",
    name="urlscan.io public scans",
    category="threat-intel",
    applies_to=("domain",),
    sends="The domain name (in a public search query).",
    docs="https://urlscan.io/docs/api/",
    description="Searches urlscan.io for scan records that already exist publicly. It never submits a new scan.",
)
def urlscan(ctx: SourceContext) -> dict[str, Any]:
    domain = ctx.identifier.value
    headers: dict[str, str] = {}
    api_key = ctx.key("urlscan")
    if api_key:
        headers["API-Key"] = api_key
    # NOTE: the `has:verdict` / verdict filters require a paid plan, so the
    # query deliberately stays on the free `domain:` field.
    query = urllib.parse.quote(f"domain:{domain}", safe=":")
    url = f"https://urlscan.io/api/v1/search/?q={query}&size=5"
    payload = ctx.fetcher.get_json(
        url, headers=headers, timeout=SETTINGS.limits.per_source_timeout,
        cache_key=f"urlscan:{domain}", cache_ttl=SETTINGS.limits.cache_default_ttl,
    )
    results = payload.get("results") or []
    total = int(payload.get("total") or 0)
    if not results:
        return {
            "status": STATUS_NO_MATCH,
            "message": f"No public urlscan.io scan records were found for {domain} "
                       f"(search window is limited to the last {payload.get('search_date_limit_days', 30)} days).",
            "data": {"domain": domain, "total": total},
            "upstream_host": "urlscan.io",
        }

    latest = results[0]
    task = latest.get("task") or {}
    page = latest.get("page") or {}
    scanned_at = parse_upstream_timestamp(task.get("time"))
    uuid = latest.get("_id") or task.get("uuid") or ""
    result_url = f"https://urlscan.io/result/{uuid}/" if uuid else "https://urlscan.io/"
    domain_page = f"https://urlscan.io/domain/{domain}"

    evidence = [
        Evidence("Public scan records (30-day window)", str(total)),
        Evidence("Most recent scan", scanned_at or "unknown"),
        Evidence("Scanned URL", str(task.get("url") or "")[:200]),
        Evidence("Page title", str(page.get("title") or "")[:120]),
        Evidence("Server / IP", f"{page.get('server') or 'unknown'} @ {page.get('ip') or 'unknown'}"),
        Evidence("ASN", str(page.get("asnname") or "")[:120]),
    ]
    findings = [Finding(
        source_id="urlscan", source_name="urlscan.io public scans", severity="info",
        category="threat-intel",
        title=f"{total} public urlscan.io scan record(s) exist for this domain",
        summary=f"Someone submitted {domain} to urlscan.io at least {total} time(s) in the searchable window. "
                "Scans are submitted by users, researchers and companies, including for perfectly normal sites.",
        evidence=evidence,
        links=[Evidence("Most recent scan record", result_url), Evidence("urlscan.io domain history", domain_page)],
        observed_at=scanned_at,
        interpretation="Being scanned or archived by urlscan.io is NOT a malicious verdict. The site's own content and the "
                       "scan's verdict fields (paid API) would be needed for any stronger claim, and this app does not use them.",
    )]
    return {
        "status": STATUS_OK,
        "message": f"Found {total} public scan record(s) for {domain}; showing the most recent.",
        "findings": findings,
        "data": {
            "domain": domain, "total": total, "latest_uuid": uuid, "latest_scanned_at": scanned_at,
            "latest_url": task.get("url"), "latest_result_url": result_url,
            "page_title": page.get("title"), "ip": page.get("ip"), "asn": page.get("asnname"),
            "server": page.get("server"), "has_more": bool(payload.get("has_more")),
        },
        "upstream_host": "urlscan.io",
    }


# ---------------------------------------------------------------------------
# AlienVault OTX - user-submitted pulse references
# ---------------------------------------------------------------------------


@source(
    id="otx",
    name="AlienVault OTX",
    category="threat-intel",
    applies_to=("domain",),
    sends="The domain name (public indicator lookup).",
    docs="https://docs.alienvault.com/open-threat-exchange/",
    description="Counts and lists community 'pulses' that reference the domain. Pulses are user-submitted and unverified.",
)
def otx(ctx: SourceContext) -> dict[str, Any]:
    domain = ctx.identifier.value
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/general"
    headers: dict[str, str] = {}
    key = ctx.key("otx")
    if key:
        headers["X-OTX-API-KEY"] = key
    payload = ctx.fetcher.get_json(
        url, headers=headers, timeout=SETTINGS.limits.per_source_timeout,
        cache_key=f"otx:{domain}", cache_ttl=SETTINGS.limits.cache_default_ttl,
        max_bytes=2 * 1024 * 1024,  # pulse payloads can be large; we only keep summaries
    )
    pulse_info = payload.get("pulse_info") or {}
    count = int(pulse_info.get("count") or 0)
    pulses = pulse_info.get("pulses") or []
    validations = payload.get("validation") or []
    whitelisted = [v for v in validations if "whitelist" in str(v.get("source", "")).lower()
                   or "whitelist" in str(v.get("name", "")).lower()]
    popular = [v for v in validations if "popular" in str(v.get("name", "")).lower()
               or "rank" in str(v.get("message", "")).lower()]

    summaries = []
    for pulse in pulses[:5]:
        summaries.append({
            "name": str(pulse.get("name") or "")[:160],
            "created": parse_upstream_timestamp(pulse.get("created")),
            "author": (pulse.get("author") or {}).get("username", ""),
            "tags": [str(t) for t in (pulse.get("tags") or [])[:8]],
            "indicator_count": pulse.get("indicator_count"),
            "url": f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
        })

    data = {
        "domain": domain,
        "pulse_count": count,
        "pulses": summaries,
        "validations": [{"name": str(v.get("name", ""))[:80], "source": str(v.get("source", ""))[:40],
                         "message": str(v.get("message", ""))[:160]} for v in validations[:6]],
        "whitelisted": bool(whitelisted),
        "popular": bool(popular),
        "otx_url": f"https://otx.alienvault.com/indicator/domain/{domain}",
    }

    findings: list[Finding] = []
    if whitelisted or popular:
        findings.append(Finding(
            source_id="otx", source_name="AlienVault OTX", severity="info", category="threat-intel",
            title="Listed as a popular / whitelisted domain",
            summary="OTX validation entries mark this domain as popular or whitelisted, which is counter-evidence "
                    "against treating it as suspicious.",
            evidence=[Evidence("Validation", f"{v.get('name')} ({v.get('source')}): {v.get('message')}")
                      for v in (whitelisted + popular)[:4]],
            links=[Evidence("OTX indicator page", data["otx_url"])],
            interpretation="Rank/whitelist entries come from popularity lists; they are not a security guarantee either.",
        ))

    if count > 0:
        evidence = [Evidence("Pulses referencing this domain", str(count))]
        for item in summaries:
            evidence.append(Evidence(f"Pulse ({item['created'] or 'date unknown'})",
                                     f"{item['name']} - by {item['author'] or 'unknown'}"))
        links = [Evidence("OTX indicator page", data["otx_url"])]
        links += [Evidence(item["name"][:60] or "pulse", item["url"]) for item in summaries[:3]]
        findings.append(Finding(
            source_id="otx", source_name="AlienVault OTX", severity="medium", category="threat-intel",
            title=f"Referenced in {count} community threat-intel pulse(s)",
            summary=f"OTX users have included {domain} in {count} pulse(s). Pulses are unmoderated user submissions "
                    "and frequently contain popular, unrelated domains.",
            evidence=evidence, links=links,
            observed_at=summaries[0]["created"] if summaries else None,
            interpretation="A pulse reference is NOT a verdict of maliciousness. Open the pulse to see who submitted it, "
                           "when, and why - many pulses are bulk indicator dumps with little context.",
        ))
        status = STATUS_OK
        message = f"{count} OTX pulse(s) reference {domain}."
    else:
        status = STATUS_NO_MATCH
        message = f"No OTX pulses reference {domain}."
        if findings:
            status = STATUS_OK

    return {"status": status, "message": message, "findings": findings, "data": data,
            "upstream_host": "otx.alienvault.com"}


# ---------------------------------------------------------------------------
# URLhaus - malware URL feed (exact host match)
# ---------------------------------------------------------------------------

URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_recent/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"


def _feed_host_matches(ctx: SourceContext, feed_url: str, targets: set[str], *, max_bytes: int,
                       cache_key: str, source_label: str) -> list[str]:
    text = ctx.fetcher.get_text(
        feed_url, timeout=SETTINGS.limits.feed_timeout, max_bytes=max_bytes,
        cache_key=cache_key, cache_ttl=SETTINGS.limits.cache_feed_ttl,
    )
    matches: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            host = urllib.parse.urlsplit(line if "://" in line else "http://" + line).hostname or ""
        except ValueError:
            continue
        if _host_matches(host, targets):
            matches.append(line)
        if len(matches) >= 25:
            break
    return matches


@source(
    id="urlhaus",
    name="URLhaus malware URL feed",
    category="threat-intel",
    applies_to=("domain",),
    sends="Nothing leaves the app unless you add a free abuse.ch Auth-Key; the public feed is downloaded and matched locally against your domain.",
    docs="https://urlhaus.abuse.ch/api/",
    key_name="abusech",
    description="Exact host match against the URLhaus malware-URL dataset (public feed, or the query API with a free Auth-Key).",
)
def urlhaus(ctx: SourceContext) -> dict[str, Any]:
    domain = ctx.identifier.value
    targets = _hosts_for(domain)
    auth_key = ctx.key("abusech") or SETTINGS.abusech_auth_key
    matches: list[str] = []
    method = ""

    if auth_key:
        method = "urlhaus host API (with your Auth-Key)"
        payload = ctx.fetcher.post_form(
            URLHAUS_API, {"host": domain}, headers={"Auth-Key": auth_key, "User-Agent": "Verdigris/1.0"},
            timeout=SETTINGS.limits.per_source_timeout,
        )
        query_status = str(payload.get("query_status", "")).lower()
        if query_status in ("no_results", "no_result"):
            return {
                "status": STATUS_NO_MATCH,
                "message": f"URLhaus has no malware URLs recorded for host {domain}.",
                "data": {"domain": domain, "method": method, "query_status": query_status},
                "upstream_host": "urlhaus-api.abuse.ch",
            }
        if query_status not in ("ok",):
            raise SourceOutcome(
                STATUS_UNAVAILABLE,
                f"URLhaus API returned an unexpected status ('{query_status}') for host {domain}.",
                data={"query_status": query_status},
            )
        for entry in (payload.get("urls") or [])[:25]:
            if isinstance(entry, dict) and entry.get("url"):
                matches.append(str(entry["url"]))
        data_extra = {
            "firstseen": parse_upstream_timestamp(payload.get("firstseen")),
            "url_count": payload.get("url_count"),
        }
    else:
        method = "public text feed (exact host match, performed by this app)"
        try:
            matches = _feed_host_matches(
                ctx, URLHAUS_FEED, targets, max_bytes=SETTINGS.limits.max_feed_bytes,
                cache_key="feed:urlhaus:text_recent", source_label="urlhaus",
            )
        except UpstreamError as exc:
            raise SourceOutcome(
                STATUS_UNAVAILABLE,
                f"URLhaus public feed could not be retrieved ({exc}). The URLhaus query API now requires a free "
                "abuse.ch Auth-Key, which you can add under Settings to query it directly.",
                hint="Settings → abuse.ch Auth-Key (free at https://auth.abuse.ch/)",
                data={"domain": domain, "feed_error": str(exc)},
            ) from exc
        data_extra = {}

    if matches:
        findings = [Finding(
            source_id="urlhaus", source_name="URLhaus malware URL feed", severity="high", category="threat-intel",
            title=f"{len(matches)} URLhaus entry/entries match this host exactly",
            summary=f"URLhaus (abuse.ch/Spamhaus) lists URL(s) on {domain} as associated with malware distribution. "
                    "The matching URLs are shown as plain text on purpose - do not visit them.",
            evidence=[Evidence(f"Match {i+1}", url[:240]) for i, url in enumerate(matches[:5])],
            links=[Evidence("URLhaus host search (safe)", f"https://urlhaus.abuse.ch/browse.php?search={urllib.parse.quote(domain)}")],
            interpretation="Feed entries are community submissions and can include compromised-but-legitimate sites "
                           "(for example a hacked WordPress blog). Verify with the host owner before drawing conclusions.",
        )]
        return {
            "status": STATUS_OK,
            "message": f"{len(matches)} exact host match(es) in URLhaus via {method}.",
            "findings": findings,
            "data": {"domain": domain, "matches": matches[:10], "method": method, **data_extra},
            "upstream_host": "urlhaus-api.abuse.ch" if auth_key else "urlhaus.abuse.ch",
        }
    return {
        "status": STATUS_NO_MATCH,
        "message": f"No exact host match for {domain} in the URLhaus dataset checked via {method}. "
                   "The public feed only covers recent/active entries, so this is not a full historical search.",
        "data": {"domain": domain, "method": method, **data_extra},
        "upstream_host": "urlhaus-api.abuse.ch" if auth_key else "urlhaus.abuse.ch",
    }


# ---------------------------------------------------------------------------
# OpenPhish - phishing feed (exact host match)
# ---------------------------------------------------------------------------

OPENPHISH_FEEDS = (
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
)


@source(
    id="openphish",
    name="OpenPhish community feed",
    category="threat-intel",
    applies_to=("domain",),
    sends="Nothing: the public feed is downloaded and matched locally against your domain.",
    docs="https://openphish.com/",
    description="Exact host match against the free OpenPhish community phishing feed (updated roughly every 12 hours).",
)
def openphish(ctx: SourceContext) -> dict[str, Any]:
    domain = ctx.identifier.value
    targets = _hosts_for(domain)
    last_error = ""
    matches: list[str] = []
    used_feed = ""
    for feed_url in OPENPHISH_FEEDS:
        try:
            matches = _feed_host_matches(
                ctx, feed_url, targets, max_bytes=SETTINGS.limits.max_feed_bytes,
                cache_key=f"feed:openphish:{feed_url}", source_label="openphish",
            )
            used_feed = feed_url
            break
        except UpstreamError as exc:
            last_error = str(exc)
    if not used_feed:
        raise SourceOutcome(
            STATUS_UNAVAILABLE,
            f"OpenPhish feed could not be retrieved ({last_error or 'no response'}).",
            data={"domain": domain, "feed_error": last_error},
        )
    if matches:
        return {
            "status": STATUS_OK,
            "message": f"{len(matches)} exact host match(es) in the OpenPhish community feed.",
            "findings": [Finding(
                source_id="openphish", source_name="OpenPhish community feed", severity="high",
                category="threat-intel",
                title=f"Host appears in the OpenPhish phishing feed ({len(matches)} entr{'y' if len(matches) == 1 else 'ies'})",
                summary=f"OpenPhish currently lists URL(s) on {domain} as phishing. The URLs are shown as plain text - do not open them.",
                evidence=[Evidence(f"Match {i+1}", url[:240]) for i, url in enumerate(matches[:5])],
                links=[Evidence("OpenPhish (safe)", "https://openphish.com/")],
                interpretation="Community feeds contain false positives, especially for compromised legitimate sites and "
                               "for look-alike subdomains of big brands. Treat it as a strong signal to investigate, not as proof.",
            )],
            "data": {"domain": domain, "matches": matches[:10], "feed": used_feed},
            "upstream_host": urllib.parse.urlsplit(used_feed).hostname or "",
        }
    return {
        "status": STATUS_NO_MATCH,
        "message": f"No exact host match for {domain} in the OpenPhish community feed "
                   "(the free feed only contains the most recent ~500 entries, so this is not a historical search).",
        "data": {"domain": domain, "feed": used_feed, "feed_entries_checked": "recent community feed only"},
        "upstream_host": urllib.parse.urlsplit(used_feed).hostname or "",
    }


# ---------------------------------------------------------------------------
# VirusTotal (optional, requires the user's own key)
# ---------------------------------------------------------------------------


@source(
    id="virustotal",
    name="VirusTotal (your key)",
    category="threat-intel",
    applies_to=("domain",),
    sends="The domain name, sent to VirusTotal with YOUR API key.",
    docs="https://docs.virustotal.com/reference/domain-info",
    key_name="virustotal",
    description="Vendor detection counts for the domain. Disabled unless you provide a VirusTotal API key.",
)
def virustotal(ctx: SourceContext) -> dict[str, Any]:
    key = ctx.key("virustotal") or SETTINGS.virustotal_api_key
    if not key:
        raise SourceOutcome(
            STATUS_NOT_CHECKED,
            "Not checked: VirusTotal requires an API key. Add one in Settings to enable this source.",
            hint="https://www.virustotal.com/gui/user/<you>/apikey (free account, rate limited)",
        )
    domain = ctx.identifier.value
    payload = ctx.fetcher.get_json(
        f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}",
        headers={"x-apikey": key}, timeout=SETTINGS.limits.per_source_timeout,
    )
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = malicious + suspicious + harmless + undetected
    registrar = attributes.get("registrar") or ""
    created = attributes.get("creation_date")
    created_iso = None
    if isinstance(created, (int, float)):
        from datetime import datetime, timezone

        created_iso = datetime.fromtimestamp(created, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    data = {
        "domain": domain, "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected, "engines": total,
        "registrar": registrar, "created": created_iso,
        "categories": attributes.get("categories") or {},
        "vt_url": f"https://www.virustotal.com/gui/domain/{domain}",
        "popularity_ranks": attributes.get("popularity_ranks") or {},
    }
    severity = "high" if malicious >= 5 else ("medium" if malicious > 0 else ("low" if suspicious > 0 else "info"))
    title = (f"{malicious} of {total} VirusTotal engines flag this domain" if malicious
             else f"No VirusTotal engine flags this domain (0/{total})")
    findings = [Finding(
        source_id="virustotal", source_name="VirusTotal (your key)", severity=severity, category="threat-intel",
        title=title,
        summary=f"Vendor detections: malicious {malicious}, suspicious {suspicious}, harmless {harmless}, "
                f"undetected {undetected}." + (f" Registrar: {registrar}." if registrar else ""),
        evidence=[Evidence("Malicious", str(malicious)), Evidence("Suspicious", str(suspicious)),
                  Evidence("Harmless", str(harmless)), Evidence("Undetected", str(undetected))],
        links=[Evidence("VirusTotal report", data["vt_url"])], observed_at=created_iso,
        interpretation="Vendor counts disagree often and change over time; a low count is weak evidence in either direction.",
    )]
    return {
        "status": STATUS_OK if (malicious or suspicious) else STATUS_NO_MATCH,
        "message": f"VirusTotal analysed {domain} with {total} engines.",
        "findings": findings, "data": data, "upstream_host": "www.virustotal.com",
    }
