"""Optional, key-gated breach lookup (Have I Been Pwned).

The *password* exposure check is deliberately NOT here: it lives in
:mod:`app.passwords` and uses HIBP's k-anonymity API, which needs no key and
never sees the full password (only the first five characters of its SHA-1 hash,
computed in your browser).
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from ..config import SETTINGS
from ..http_client import UpstreamHTTPError
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


@source(
    id="hibp_breaches",
    name="Have I Been Pwned (your key)",
    category="breaches",
    applies_to=("email",),
    sends="The full email address, sent to haveibeenpwned.com with YOUR API key.",
    docs="https://haveibeenpwned.com/API/v3",
    key_name="hibp",
    description="Breach and paste appearances for an email address. Requires your own HIBP API key; disabled otherwise.",
)
def hibp_breaches(ctx: SourceContext) -> dict[str, Any]:
    key = ctx.key("hibp") or SETTINGS.hibp_api_key
    if not key:
        raise SourceOutcome(
            STATUS_NOT_CHECKED,
            "Not checked: HIBP's breach-search API requires your own paid API key, and this app does not ship one. "
            "The password-exposure check (k-anonymity) needs no key and is available under 'Password check'.",
            hint="Settings → HIBP API key (https://haveibeenpwned.com/API/Key)",
        )
    email = ctx.identifier.value
    url = (f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
           "?truncateResponse=false&includeUnverified=true")
    try:
        payload = ctx.fetcher.get_json(url, headers={"hibp-api-key": key, "User-Agent": "Verdigris (privacy research)"},
                                       timeout=SETTINGS.limits.per_source_timeout)
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            return {
                "status": STATUS_NO_MATCH,
                "message": f"HIBP found no breaches or pastes for {email} (good news, but not a guarantee).",
                "data": {"email": email, "breaches": [], "pastes": []},
                "upstream_host": "haveibeenpwned.com",
            }
        if exc.status in (401, 403):
            raise SourceOutcome(STATUS_UNAVAILABLE,
                                f"HIBP rejected the API key (HTTP {exc.status}). Check it in Settings.")
        if exc.status == 429:
            raise SourceOutcome(STATUS_UNAVAILABLE, "HIBP rate limit reached (1 request every 1.5s on the free tier).")
        raise

    breaches = payload if isinstance(payload, list) else []
    rows = []
    for breach in breaches:
        if not isinstance(breach, dict):
            continue
        rows.append({
            "name": str(breach.get("Name") or ""),
            "title": str(breach.get("Title") or ""),
            "domain": str(breach.get("Domain") or ""),
            "breach_date": str(breach.get("BreachDate") or ""),
            "added_date": parse_upstream_timestamp(breach.get("AddedDate")),
            "data_classes": [str(d) for d in (breach.get("DataClasses") or [])],
            "is_verified": bool(breach.get("IsVerified")),
            "is_sensitive": bool(breach.get("IsSensitive")),
            "pwn_count": breach.get("PwnCount"),
        })
    data = {"email": email, "breaches": rows, "breach_count": len(rows),
            "hibp_url": "https://haveibeenpwned.com/account/" + urllib.parse.quote(email)}
    if not rows:
        return {"status": STATUS_NO_MATCH, "message": f"HIBP returned no breach entries for {email}.",
                "data": data, "upstream_host": "haveibeenpwned.com"}

    with_passwords = [r for r in rows if "Passwords" in r["data_classes"]]
    verified = [r for r in rows if r["is_verified"]]
    severity = "high" if with_passwords else "medium"
    evidence = [Evidence("Breaches reported", str(len(rows))),
                Evidence("Breaches that included passwords", str(len(with_passwords))),
                Evidence("Verified breaches", str(len(verified)))]
    for row in sorted(rows, key=lambda r: r["added_date"] or "", reverse=True)[:8]:
        evidence.append(Evidence(f"{row['title'] or row['name']} ({row['breach_date'] or 'date unknown'})",
                                 ", ".join(row["data_classes"][:8]) or "unspecified"))
    links = [Evidence("Have I Been Pwned account page", data["hibp_url"])]
    links += [Evidence(row["title"] or row["name"], f"https://haveibeenpwned.com/breach/{urllib.parse.quote(row['name'])}")
              for row in rows[:5] if row["name"]]
    findings = [Finding(
        source_id="hibp_breaches", source_name="Have I Been Pwned (your key)", severity=severity,
        category="breaches",
        title=f"Email address appears in {len(rows)} known breach dataset(s)"
              + (f", {len(with_passwords)} of which included passwords" if with_passwords else ""),
        summary=f"HIBP records {email} in {len(rows)} breach(es). "
                + ("Because some of them exposed passwords, any password reused there should be considered compromised."
                   if with_passwords else
                   "None of the listed breaches exposed passwords, but the address itself is in circulation."),
        evidence=evidence, links=links,
        observed_at=max((r["added_date"] or "") for r in rows) or None,
        interpretation="Breach data is compiled by researchers from leaked datasets; it shows the address was present in "
                       "a compromised dataset, not that an account was accessed. Unverified entries may be fabricated or "
                       "from 'combo lists'.",
    )]
    if with_passwords:
        findings.append(Finding(
            source_id="hibp_breaches", source_name="Have I Been Pwned (your key)", severity="high", category="breaches",
            title="Passwords were exposed in at least one of these breaches",
            summary="Use the password-exposure check in this app to see whether a specific password is in the Pwned "
                    "Passwords corpus, and change any password you have reused.",
            evidence=[Evidence("Breaches with passwords", ", ".join(r["title"] or r["name"] for r in with_passwords[:6]))],
            links=[Evidence("Pwned Passwords (k-anonymity)", "https://haveibeenpwned.com/Passwords")],
            interpretation="Only the first five characters of a SHA-1 hash ever leave your browser during that check - "
                           "the password itself is never transmitted or stored.",
        ))
    return {"status": STATUS_OK, "message": f"{len(rows)} HIBP breach entr{'y' if len(rows) == 1 else 'ies'} for {email}.",
            "findings": findings, "data": data, "upstream_host": "haveibeenpwned.com"}
