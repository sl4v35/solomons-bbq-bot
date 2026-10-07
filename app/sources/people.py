"""Public-name search and avatar/profile-by-hash sources."""

from __future__ import annotations

import urllib.parse
from typing import Any

from ..config import SETTINGS
from ..crypto import md5_hex
from ..http_client import UpstreamHTTPError
from .base import (
    Evidence,
    clean_html,
    plain_text,
    Finding,
    SourceContext,
    SourceOutcome,
    STATUS_NO_MATCH,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    parse_upstream_timestamp,
    source,
)

_clean = clean_html  # upstream HTML fields (Wikipedia snippets, Gravatar aboutMe)
_plain = plain_text  # plain-text fields: names, URLs, phone numbers, handles


NAME_MATCH_CAVEAT = (
    "A matching name is not proof of the same identity. Names repeat, articles cover many people with the same "
    "name, and search indexes match loosely. Treat every hit as a candidate that needs independent corroboration."
)


@source(
    id="wikipedia_name",
    name="Wikipedia name search",
    category="public-records",
    applies_to=("name",),
    sends="The name you typed (public article-title search on en.wikipedia.org).",
    docs="https://www.mediawiki.org/wiki/API:Opensearch",
    description="Finds public Wikipedia article titles that match the name. Candidates only.",
)
def wikipedia_name(ctx: SourceContext) -> dict[str, Any]:
    name = ctx.identifier.value
    limit = 8
    open_url = ("https://en.wikipedia.org/w/api.php?action=opensearch&namespace=0&limit=%d"
                "&format=json&formatversion=2&search=%s" % (limit, urllib.parse.quote(name)))
    search_url = ("https://en.wikipedia.org/w/api.php?action=query&list=search&srnamespace=0&srlimit=5"
                  "&format=json&formatversion=2&srsearch=%s" % (urllib.parse.quote(f'"{name}"')))
    try:
        open_payload = ctx.fetcher.get_json(open_url, timeout=SETTINGS.limits.per_source_timeout,
                                            cache_key=f"wiki:open:{name.lower()}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    except UpstreamHTTPError as exc:
        raise SourceOutcome(STATUS_UNAVAILABLE, f"Wikipedia opensearch failed: {exc.message}")
    titles: list[str] = []
    urls: list[str] = []
    if isinstance(open_payload, list) and len(open_payload) >= 4:
        raw_titles = open_payload[1] or []
        raw_urls = open_payload[3] or []
        titles = [str(t) for t in raw_titles if t]
        urls = [str(u) for u in raw_urls if u]
    elif isinstance(open_payload, dict):
        titles = [str(t) for t in (open_payload.get("titles") or [])]
        urls = [str(u) for u in (open_payload.get("urls") or [])]

    total_hits = None
    descriptions: list[dict[str, str]] = []
    try:
        search_payload = ctx.fetcher.get_json(search_url, timeout=SETTINGS.limits.per_source_timeout,
                                              cache_key=f"wiki:search:{name.lower()}", cache_ttl=SETTINGS.limits.cache_default_ttl)
        if not isinstance(search_payload, dict):
            raise SourceOutcome(STATUS_UNAVAILABLE,
                                "Wikipedia returned an unexpected response shape for the full-text search.")
        info = (search_payload.get("query") or {}).get("searchinfo") or {}
        total_hits = info.get("totalhits")
        for row in ((search_payload.get("query") or {}).get("search") or [])[:5]:
            descriptions.append({
                "title": str(row.get("title", "")),
                "snippet": _clean(row.get("snippet", ""), 240),
                "url": f"https://en.wikipedia.org/wiki/{urllib.parse.quote(str(row.get('title', '')).replace(' ', '_'))}",
            })
    except UpstreamHTTPError as exc:
        descriptions = []
        total_hits = None

    data = {"name": name, "titles": titles, "urls": urls, "total_hits": total_hits,
            "search_descriptions": descriptions}
    if not titles and not descriptions:
        return {
            "status": STATUS_NO_MATCH,
            "message": f"No English Wikipedia article titles match '{name}'. Wikipedia only covers people it deems "
                       "notable, so this says nothing about whether the person exists.",
            "data": data, "upstream_host": "en.wikipedia.org",
        }

    evidence = [Evidence("Search term", name)]
    if total_hits is not None:
        evidence.append(Evidence("Full-text results for the exact phrase", str(total_hits)))
    for title in titles[:limit]:
        evidence.append(Evidence("Article title", title))
    for row in descriptions[:3]:
        if row["snippet"]:
            evidence.append(Evidence(f"Snippet: {row['title']}", row["snippet"]))
    links = [Evidence(title, url) for title, url in list(zip(titles, urls))[:6]]
    links += [Evidence(row["title"], row["url"]) for row in descriptions[:3] if row["url"] not in {l.url for l in links}]
    exact_title_hit = any(t.lower().strip() == name.lower().strip() for t in titles)
    findings = [Finding(
        source_id="wikipedia_name", source_name="Wikipedia name search",
        severity="medium" if exact_title_hit else "low", category="public-records",
        title=(f"Wikipedia has an article titled '{name}'" if exact_title_hit
               else f"{len(titles)} Wikipedia article title(s) match '{name}'"),
        summary=("An English Wikipedia article title matches the name exactly." if exact_title_hit
                else "Article titles that start with or match the searched name are listed as candidates.")
                + (f" Full-text search for the exact phrase returned {total_hits} result(s)." if total_hits is not None else ""),
        evidence=evidence, links=links or [Evidence("Wikipedia search", f"https://en.wikipedia.org/w/index.php?search={urllib.parse.quote(name)}")],
        interpretation=NAME_MATCH_CAVEAT,
    )]
    return {
        "status": STATUS_OK,
        "message": f"{len(titles)} candidate Wikipedia article(s) for '{name}'.",
        "findings": findings, "data": data, "upstream_host": "en.wikipedia.org",
    }


@source(
    id="gravatar",
    name="Gravatar public profile",
    category="identity",
    applies_to=("email", "username"),
    sends=("An MD5 hash of the email address (Gravatar's lookup key). The address itself is not sent. "
           "Note that MD5 of a known address is reversible by brute force for common providers."),
    docs="https://docs.gravatar.com/api/profiles/",
    description="Public Gravatar profile attached to an email hash (or to a Gravatar profile name).",
)
def gravatar(ctx: SourceContext) -> dict[str, Any]:
    ident = ctx.identifier
    if ident.kind == "email":
        email = ident.value.strip().lower()
        digest = md5_hex(email.encode("utf-8"))
        lookup = digest
        note = "Lookup used the MD5 hash of the email address; the address itself was not transmitted."
    elif ident.kind == "username":
        lookup = urllib.parse.quote(ident.value)
        note = ("Lookup used the Gravatar profile name. Gravatar profile names are chosen by their owners and may not "
                "correspond to the same person as the username you searched elsewhere.")
    else:  # pragma: no cover
        raise SourceOutcome(STATUS_NO_MATCH, "Not applicable.")

    url = f"https://en.gravatar.com/{lookup}.json"
    try:
        payload = ctx.fetcher.get_json(url, timeout=SETTINGS.limits.per_source_timeout,
                                       cache_key=f"gravatar:{lookup}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            subject = "that email hash" if ident.kind == "email" else f"'{ident.value}'"
            return {"status": STATUS_NO_MATCH,
                    "message": f"No public Gravatar profile exists for {subject}. {note}",
                    "data": {"lookup": lookup, "kind": ident.kind}, "upstream_host": "en.gravatar.com"}
        raise

    entries = (payload or {}).get("entry") if isinstance(payload, dict) else None
    if not entries:
        return {"status": STATUS_NO_MATCH, "message": f"Gravatar returned no profile entry. {note}",
                "data": {"lookup": lookup}, "upstream_host": "en.gravatar.com"}
    entry = entries[0] if isinstance(entries, list) else entries
    accounts = []
    for account in (entry.get("accounts") or [])[:12]:
        if isinstance(account, dict):
            accounts.append({"url": _plain(account.get("url"), 200),
                             "username": _plain(account.get("username"), 80),
                             "domain": _plain(account.get("domain"), 80)})
    exposures = {
        "display_name": _plain(entry.get("displayName"), 120),
        "preferred_username": _plain(entry.get("preferredUsername"), 80),
        "profile_url": _plain(entry.get("profileUrl"), 200),
        "current_location": _plain(entry.get("currentLocation"), 160),
        "about": _clean(entry.get("aboutMe"), 400),
        "first_name": _plain((entry.get("name") or {}).get("givenName"), 80) if isinstance(entry.get("name"), dict) else "",
        "last_name": _plain((entry.get("name") or {}).get("familyName"), 80) if isinstance(entry.get("name"), dict) else "",
        "emails_published": [e.get("value") for e in (entry.get("emails") or []) if isinstance(e, dict)][:3],
        "im_accounts": [_plain(i.get("value"), 80) for i in (entry.get("ims") or []) if isinstance(i, dict)][:5],
        "phone_numbers": [_plain(p.get("value"), 40) for p in (entry.get("phoneNumbers") or []) if isinstance(p, dict)][:3],
        "linked_accounts": accounts,
        "avatar": _plain(entry.get("thumbnailUrl"), 240),
    }
    personal = [k for k in ("display_name", "first_name", "last_name", "current_location", "about",
                            "emails_published", "im_accounts", "phone_numbers") if exposures[k]]
    severity = "high" if (exposures["phone_numbers"] or exposures["emails_published"]
                          or (exposures["current_location"] and exposures["display_name"])) else (
        "medium" if personal else "low")
    evidence = [Evidence("Profile name", exposures["preferred_username"] or lookup)]
    for key in ("display_name", "first_name", "last_name", "current_location", "about"):
        if exposures[key]:
            evidence.append(Evidence(key.replace("_", " ").title(), str(exposures[key])[:240]))
    if exposures["emails_published"]:
        evidence.append(Evidence("Additional emails published", ", ".join(exposures["emails_published"])))
    if exposures["phone_numbers"]:
        evidence.append(Evidence("Phone number(s) published", ", ".join(exposures["phone_numbers"])))
    if exposures["im_accounts"]:
        evidence.append(Evidence("IM accounts", ", ".join(exposures["im_accounts"])))
    if accounts:
        evidence.append(Evidence("Linked accounts", "; ".join(
            f"{a['domain'] or a['url']}" + (f" ({a['username']})" if a["username"] else "") for a in accounts[:8])))
    links = [Evidence("Gravatar profile", exposures["profile_url"] or f"https://gravatar.com/{lookup}")]
    links += [Evidence(f"{a['domain'] or 'linked account'}: {a['username']}", a["url"]) for a in accounts[:6] if a["url"]]

    findings = [Finding(
        source_id="gravatar", source_name="Gravatar public profile", severity=severity, category="identity",
        title="Public Gravatar profile exists for this " + ("email hash" if ident.kind == "email" else "profile name"),
        summary=("Gravatar publishes a profile that can be retrieved with this lookup key, including "
                 f"{', '.join(personal) if personal else 'a display name and avatar'}.") ,
        evidence=evidence, links=links,
        interpretation=("Gravatar profiles are created by the account owner and may be stale. "
                        + (note if ident.kind == "username" else
                           "An MD5 hash of an address at a common provider (gmail.com, outlook.com, ...) can be "
                           "brute-forced by anyone, so treat hash-based profile matching as weak-but-real evidence.")),
    )]
    if accounts:
        findings.append(Finding(
            source_id="gravatar", source_name="Gravatar public profile", severity="medium", category="identity",
            title=f"{len(accounts)} other account(s) are linked from this profile",
            summary="The profile owner listed links to other services, which can connect handles across sites.",
            evidence=[Evidence(a["domain"] or a["url"], a["username"] or "") for a in accounts[:8]],
            links=[Evidence(f"{a['domain'] or 'link'}", a["url"]) for a in accounts[:6] if a["url"]],
            interpretation=NAME_MATCH_CAVEAT,
        ))
    return {"status": STATUS_OK,
            "message": f"Gravatar profile found for '{exposures['preferred_username'] or lookup}'. {note}",
            "findings": findings, "data": exposures, "upstream_host": "en.gravatar.com"}
