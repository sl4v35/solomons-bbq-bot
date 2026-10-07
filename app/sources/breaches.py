"""Optional, key-gated breach lookup (Have I Been Pwned API v3).

The *password* exposure check is deliberately NOT here: it lives in
:mod:`app.passwords` and uses HIBP's k-anonymity range API, which is free, needs
no key and never sees the full password (only the first five characters of its
SHA-1 hash, computed in your browser).

Everything in this module follows HIBP's published API v3 contract:

* both ``hibp-api-key`` **and** a descriptive ``User-Agent`` header are required
  - 401 means the key is missing/malformed/invalid, 403 means no user agent was
  sent, so the two are reported differently instead of both being blamed on the
  key;
* authenticated calls are limited **per API key** (the entry tier allows about
  10 requests/minute), not per source IP;
* 404 means "no breaches for that account", and HIBP's public API never returns
  sensitive or retired breaches, so a 404 is reported as *no matches* with that
  caveat rather than as a clean bill of health;
* breach entries carry ``IsSpamList`` / ``IsFabricated`` / ``IsMalware`` /
  ``IsRetired`` / ``IsStealerLog`` flags. Those are surfaced, and entries HIBP
  itself flags as spam lists or fabricated are not counted as credible breaches;
* ``Name`` is an internal identifier (used for the breach URL) while ``Title`` is
  what HIBP says should be shown to people, so ``Title`` is what we display.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from ..config import SETTINGS
from ..http_client import UpstreamError, UpstreamHTTPError, UpstreamRateLimited
from .base import (
    Evidence,
    Finding,
    SourceContext,
    SourceOutcome,
    STATUS_NOT_CHECKED,
    STATUS_NO_MATCH,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
    parse_upstream_timestamp,
    source,
)

USER_AGENT = "Verdigris (privacy research; user-supplied HIBP key)"

# HIBP's documented integration-test domain, used by tools/live_probe.py to
# exercise the authenticated code path in CI without anybody's paid key.
HIBP_TEST_DOMAIN = "hibp-integration-tests.com"


def _flagged(row: dict[str, Any]) -> bool:
    """True when HIBP itself marks the entry as not a credible breach."""
    return bool(row["is_spam_list"] or row["is_fabricated"] or row["is_malware"])


@source(
    id="hibp_breaches",
    name="Have I Been Pwned (your key)",
    category="breaches",
    applies_to=("email",),
    sends="The full email address, sent to haveibeenpwned.com with YOUR API key "
          "(up to two authenticated calls: breaches, then pastes).",
    docs="https://haveibeenpwned.com/API/v3",
    key_name="hibp",
    description="Breach and paste appearances for an email address via HIBP's paid API v3. "
                "Requires your own HIBP API key; reported as 'not checked' without one.",
)
def hibp_breaches(ctx: SourceContext) -> dict[str, Any]:
    key = ctx.key("hibp") or SETTINGS.hibp_api_key
    if not key:
        raise SourceOutcome(
            STATUS_NOT_CHECKED,
            "Not checked: HIBP's breach-search API requires your own paid API key, and this app does not ship one. "
            "The password-exposure check (k-anonymity) needs no key and is available under 'Password check'.",
            hint="Settings → HIBP API key (https://haveibeenpwned.com/API/Key). The entry tier costs about "
                 "US$3.95/month and allows roughly 10 authenticated requests per minute.",
        )

    email = ctx.identifier.value
    quoted = urllib.parse.quote(email)
    headers = {"hibp-api-key": key, "User-Agent": USER_AGENT}
    timeout = SETTINGS.limits.per_source_timeout
    breach_url = (f"https://haveibeenpwned.com/api/v3/breachedaccount/{quoted}"
                  "?truncateResponse=false&includeUnverified=true")
    hibp_url = "https://haveibeenpwned.com/account/" + quoted

    breach_note = ""
    payload: Any = []
    try:
        payload = ctx.fetcher.get_json(breach_url, headers=headers, timeout=timeout)
    except UpstreamRateLimited:
        # Must be caught before UpstreamHTTPError: it is not a subclass of it.
        raise SourceOutcome(
            STATUS_RATE_LIMITED,
            "HIBP rate-limited your API key. Authenticated calls are limited per key rather than per IP: "
            "the entry tier allows about 10 requests/minute and this source uses up to two per scan.",
            hint="Wait a minute and scan again, or use a higher HIBP tier.",
        )
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            breach_note = ("HIBP returned no breach entries for this address. HIBP's public API does not return "
                           "sensitive or retired breaches, so 'none found' is not a guarantee of no exposure.")
        elif exc.status == 401:
            raise SourceOutcome(
                STATUS_UNAVAILABLE,
                "HIBP rejected the API key (HTTP 401: the hibp-api-key header was missing, malformed or invalid). "
                "Check the key in Settings.",
            )
        elif exc.status == 403:
            raise SourceOutcome(
                STATUS_UNAVAILABLE,
                "HIBP returned HTTP 403, which its API v3 documentation ties to a missing user-agent header "
                "(this app always sends one) or to a subscription tier that does not include this endpoint.",
            )
        else:
            raise

    breaches = payload if isinstance(payload, list) else []
    rows: list[dict[str, Any]] = []
    for breach in breaches:
        if not isinstance(breach, dict):
            continue
        rows.append({
            # ``Name`` is HIBP's stable internal identifier (used for links only);
            # ``Title`` is the value HIBP says should be shown to people.
            "name": str(breach.get("Name") or ""),
            "title": str(breach.get("Title") or ""),
            "domain": str(breach.get("Domain") or ""),
            "breach_date": str(breach.get("BreachDate") or ""),
            "added_date": parse_upstream_timestamp(breach.get("AddedDate")),
            "modified_date": parse_upstream_timestamp(breach.get("ModifiedDate")),
            "data_classes": [str(d) for d in (breach.get("DataClasses") or [])],
            "is_verified": bool(breach.get("IsVerified")),
            "is_sensitive": bool(breach.get("IsSensitive")),
            "is_fabricated": bool(breach.get("IsFabricated")),
            "is_spam_list": bool(breach.get("IsSpamList")),
            "is_malware": bool(breach.get("IsMalware")),
            "is_retired": bool(breach.get("IsRetired")),
            "is_stealer_log": bool(breach.get("IsStealerLog")),
            "pwn_count": breach.get("PwnCount"),
        })

    # -- pastes (second authenticated call; a failure here must not hide breaches)
    pastes: list[dict[str, Any]] = []
    paste_note = ""
    paste_url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{quoted}"
    try:
        paste_payload = ctx.fetcher.get_json(paste_url, headers=headers, timeout=timeout)
        for paste in (paste_payload if isinstance(paste_payload, list) else []):
            if not isinstance(paste, dict):
                continue
            pastes.append({
                "source": str(paste.get("Source") or ""),
                "id": str(paste.get("Id") or ""),
                "title": str(paste.get("Title") or ""),
                "date": parse_upstream_timestamp(paste.get("Date")),
                "email_count": paste.get("EmailCount"),
            })
    except UpstreamHTTPError as exc:
        if exc.status != 404:  # 404 simply means "no pastes"
            paste_note = f"Paste search unavailable (HTTP {exc.status}); breach results are unaffected."
    except UpstreamRateLimited:
        paste_note = "Paste search skipped: HIBP rate-limited the API key after the breach call."
    except UpstreamError as exc:
        paste_note = f"Paste search failed ({exc}); breach results are unaffected."

    data: dict[str, Any] = {
        "email": email, "breaches": rows, "breach_count": len(rows),
        "pastes": pastes, "paste_count": len(pastes),
        "hibp_url": hibp_url, "api_version": "v3",
    }
    if paste_note:
        data["paste_note"] = paste_note

    if not rows and not pastes:
        message = breach_note or f"HIBP returned no breach or paste entries for {email}."
        if paste_note:
            message = f"{message} {paste_note}"
        return {"status": STATUS_NO_MATCH, "message": message, "data": data,
                "upstream_host": "haveibeenpwned.com"}

    credible = [r for r in rows if not _flagged(r)]
    flagged_rows = [r for r in rows if _flagged(r)]
    stealer_rows = [r for r in rows if r["is_stealer_log"]]
    with_passwords = [r for r in credible if "Passwords" in r["data_classes"]]
    verified = [r for r in credible if r["is_verified"]]

    if with_passwords:
        severity = "high"
    elif credible:
        severity = "medium"
    elif pastes:
        severity = "medium"
    else:
        severity = "low"  # only entries HIBP flags as spam lists / fabricated / malware

    evidence = [Evidence("Breach entries returned", str(len(rows)))]
    if flagged_rows:
        evidence.append(Evidence("Entries HIBP flags as spam list, fabricated or malware", str(len(flagged_rows))))
    if stealer_rows:
        evidence.append(Evidence("Entries sourced from stealer logs", str(len(stealer_rows))))
    evidence.append(Evidence("Credible breaches", str(len(credible))))
    evidence.append(Evidence("Credible breaches that included passwords", str(len(with_passwords))))
    evidence.append(Evidence("Verified breaches", str(len(verified))))
    evidence.append(Evidence("Paste appearances", str(len(pastes))))
    for row in sorted(credible or rows, key=lambda r: r["added_date"] or "", reverse=True)[:8]:
        label = f"{row['title'] or row['name']} ({row['breach_date'] or 'date unknown'})"
        if _flagged(row):
            label += " [HIBP-flagged]"
        evidence.append(Evidence(label, ", ".join(row["data_classes"][:8]) or "unspecified"))
    if paste_note:
        evidence.append(Evidence("Paste search", paste_note))

    links = [Evidence("Have I Been Pwned account page", hibp_url)]
    links += [Evidence(row["title"] or row["name"],
                       f"https://haveibeenpwned.com/breach/{urllib.parse.quote(row['name'])}")
              for row in (credible or rows)[:5] if row["name"]]

    findings: list[Finding] = []
    headline_bits = []
    if credible:
        headline_bits.append(f"{len(credible)} breach dataset(s)")
        if with_passwords:
            headline_bits.append(f"{len(with_passwords)} of which included passwords")
    if flagged_rows:
        headline_bits.append(f"{len(flagged_rows)} entr{'y' if len(flagged_rows) == 1 else 'ies'} HIBP flags as "
                             "spam list / fabricated / malware")
    if rows:
        findings.append(Finding(
            source_id="hibp_breaches", source_name="Have I Been Pwned (your key)", severity=severity,
            category="breaches",
            title=f"Email address appears in {', '.join(headline_bits)}",
            summary=(f"HIBP records {email} in {len(rows)} breach entr{'y' if len(rows) == 1 else 'ies'} "
                     f"({len(credible)} credible). ")
                    + ("Because some of them exposed passwords, any password reused there should be considered "
                       "compromised." if with_passwords else
                       "None of the credible breaches exposed passwords, but the address itself is in circulation."),
            evidence=evidence, links=links,
            observed_at=max((r["added_date"] or "") for r in rows) or None,
            interpretation=(
                "Breach data is compiled by researchers from leaked datasets: it shows the address was present in a "
                "compromised dataset, not that an account was accessed. BreachDate is HIBP's own estimate and is "
                "frequently long after the incident, so treat dates as a guide only. Unverified entries may be "
                "fabricated or come from 'combo lists', and HIBP's public API never returns sensitive or retired "
                "breaches."
            ),
        ))

    if with_passwords:
        findings.append(Finding(
            source_id="hibp_breaches", source_name="Have I Been Pwned (your key)", severity="high",
            category="breaches",
            title="Passwords were exposed in at least one of these breaches",
            summary="Use the password-exposure check in this app to see whether a specific password is in the Pwned "
                    "Passwords corpus, and change any password you have reused.",
            evidence=[Evidence("Credible breaches with passwords",
                               ", ".join(r["title"] or r["name"] for r in with_passwords[:6]))],
            links=[Evidence("Pwned Passwords (k-anonymity)", "https://haveibeenpwned.com/Passwords")],
            interpretation="Only the first five characters of a SHA-1 hash ever leave your browser during that check - "
                           "the password itself is never transmitted or stored. Entries HIBP flags as spam lists or "
                           "fabricated are excluded from this count.",
        ))

    if pastes:
        findings.append(Finding(
            source_id="hibp_breaches", source_name="Have I Been Pwned (your key)",
            severity="medium" if not rows else "low", category="breaches",
            title=f"Email address appears in {len(pastes)} indexed paste(s)",
            summary=(f"HIBP indexed {email} in {len(pastes)} paste(s) on public paste sites. "
                     "Pastes are usually removed quickly, so the underlying text is often no longer retrievable."),
            evidence=[Evidence(f"{p['source'] or 'paste'} {p['id']}".strip(),
                               f"{p['email_count'] if p['email_count'] is not None else 'unknown'} address(es) in "
                               f"that paste" + (f" · {p['title']}" if p["title"] else ""))
                      for p in pastes[:8]],
            links=[Evidence("Have I Been Pwned account page", hibp_url)],
            observed_at=max((p["date"] or "") for p in pastes) or None,
            interpretation=("Paste data is unverified and transient: HIBP indexes it while it is public and removes it "
                            "afterwards. Appearing in a paste is not evidence that an account was compromised."),
        ))

    message = (f"{len(rows)} HIBP breach entr{'y' if len(rows) == 1 else 'ies'} "
               f"({len(credible)} credible) and {len(pastes)} paste(s) for {email}.")
    if breach_note:
        message = f"{message} {breach_note}"
    if paste_note:
        message = f"{message} {paste_note}"
    return {"status": STATUS_OK, "message": message, "findings": findings,
            "data": data, "upstream_host": "haveibeenpwned.com"}
