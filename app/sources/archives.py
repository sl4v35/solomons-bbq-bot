"""Web archive sources (Internet Archive / Wayback Machine)."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from ..config import SETTINGS
from .base import (
    Evidence,
    Finding,
    SourceContext,
    SourceOutcome,
    STATUS_NO_MATCH,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    parse_upstream_timestamp,
    source,
)

AVAILABILITY_URL = "https://archive.org/wayback/available"
CDX_URL = "https://web.archive.org/cdx/search/cdx"


def _wayback_timestamp(value: str | None) -> str | None:
    """Wayback timestamps are ``YYYYMMDDhhmmss``."""
    if not value or not str(value).isdigit():
        return parse_upstream_timestamp(value)
    text = str(value)
    iso = f"{text[0:4]}-{text[4:6]}-{text[6:8]}T{text[8:10] or '00'}:{text[10:12] or '00'}:{text[12:14] or '00'}Z"
    return parse_upstream_timestamp(iso)


@source(
    id="wayback",
    name="Internet Archive Wayback Machine",
    category="archives",
    applies_to=("domain", "email"),
    sends="The domain name (bare, without a scheme - the availability API is more reliable that way).",
    docs="https://archive.org/help/wayback_api.php",
    description="Shows whether archived copies of a domain exist and when it was first captured.",
)
def wayback(ctx: SourceContext) -> dict[str, Any]:
    ident = ctx.identifier
    domain = ident.value if ident.kind == "domain" else ident.meta.get("domain", "")
    if not domain:
        raise SourceOutcome(STATUS_NO_MATCH, "No domain to check in the archive.")
    bare = urllib.parse.quote(domain, safe="")

    availability: dict[str, Any] = {}
    availability_error = ""
    try:
        availability = ctx.fetcher.get_json(
            f"{AVAILABILITY_URL}?url={bare}", timeout=SETTINGS.limits.per_source_timeout,
            cache_key=f"wayback:availability:{domain}", cache_ttl=SETTINGS.limits.cache_default_ttl,
        )
    except Exception as exc:  # noqa: BLE001 - degrade to CDX only
        availability_error = str(exc)

    closest = ((availability or {}).get("archived_snapshots") or {}).get("closest") or {}
    first_seen = ""
    captures = 0
    cdx_error = ""
    try:
        raw = ctx.fetcher.get_text(
            f"{CDX_URL}?url={bare}&output=json&limit=2&fl=timestamp,original,statuscode&collapse=timestamp:6",
            timeout=SETTINGS.limits.per_source_timeout,
            cache_key=f"wayback:cdx:{domain}", cache_ttl=SETTINGS.limits.cache_default_ttl,
        )
        rows = json.loads(raw) if raw.strip() else []
        if isinstance(rows, list) and len(rows) > 1:
            first_seen = str(rows[1][0]) if len(rows[1]) > 0 else ""
            captures = len(rows) - 1
    except Exception as exc:  # noqa: BLE001 - optional enrichment
        cdx_error = str(exc)

    if not closest and not first_seen:
        if availability_error and cdx_error:
            return {
                "status": STATUS_UNAVAILABLE,
                "message": f"Wayback Machine could not be reached (availability API: {availability_error}; CDX: {cdx_error}).",
                "data": {"domain": domain},
                "upstream_host": "archive.org",
            }
        return {
            "status": STATUS_NO_MATCH,
            "message": f"No archived snapshots of {domain} were found in the Wayback Machine.",
            "data": {"domain": domain, "first_seen": "", "closest": {}},
            "upstream_host": "archive.org",
        }

    snapshot_url = closest.get("url") or ""
    snapshot_ts = _wayback_timestamp(closest.get("timestamp"))
    first_iso = _wayback_timestamp(first_seen)
    calendar_url = f"https://web.archive.org/web/*/{domain}"

    evidence = [Evidence("Domain", domain)]
    if first_iso:
        evidence.append(Evidence("First archived capture", f"{first_iso} ({first_seen})"))
    if snapshot_ts:
        evidence.append(Evidence("Closest snapshot", f"{snapshot_ts} (HTTP {closest.get('status', '?')})"))
    links = [Evidence("Wayback calendar for this domain", calendar_url)]
    if snapshot_url:
        links.insert(0, Evidence("Closest archived copy", snapshot_url))

    summary_bits = []
    if first_iso:
        summary_bits.append(f"the oldest capture in the index is from {first_seen[:4]}")
    if snapshot_ts:
        summary_bits.append(f"the closest available copy is {closest.get('timestamp')}")
    findings = [Finding(
        source_id="wayback", source_name="Internet Archive Wayback Machine", severity="info",
        category="archives",
        title="Archived copies of this domain exist",
        summary="Public web archives hold captures of this domain: " + "; ".join(summary_bits) + ".",
        evidence=evidence, links=links, observed_at=first_iso or snapshot_ts,
        interpretation="Archived pages are a snapshot of what was publicly reachable at that time. They may contain "
                       "personal content that the owner has since deleted - and archive.org offers a documented "
                       "removal/exclusion process (see the report's action links).",
    )]
    data = {
        "domain": domain, "first_seen": first_seen, "first_seen_iso": first_iso,
        "closest": {"timestamp": closest.get("timestamp"), "url": snapshot_url, "status": closest.get("status")},
        "calendar_url": calendar_url, "errors": {"availability": availability_error, "cdx": cdx_error},
    }
    return {
        "status": STATUS_OK,
        "message": f"Wayback Machine has archived captures of {domain}"
                   + (f" going back to {first_seen[:4]}." if first_seen else "."),
        "findings": findings, "data": data, "upstream_host": "archive.org",
    }
