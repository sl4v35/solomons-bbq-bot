"""Public code-hosting and developer-profile sources."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

from ..config import SETTINGS
from ..http_client import UpstreamError, UpstreamHTTPError, UpstreamRateLimited, parse_sse_events
from ..identifiers import apex_domain
from .base import (
    Evidence,
    clean_html,
    plain_text,
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

GITHUB_ACCEPT = "application/vnd.github+json"
_clean = clean_html  # upstream HTML fields (bios, descriptions)
_plain = plain_text  # plain-text fields: emails, URLs, names, commit subjects, code lines


def _github_headers(ctx: SourceContext) -> dict[str, str]:
    headers = {"Accept": GITHUB_ACCEPT, "X-GitHub-Api-Version": "2022-11-28"}
    token = ctx.key("github") or SETTINGS.github_token
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_rate_limit_message(exc: UpstreamHTTPError) -> str:
    return f"GitHub refused the request ({exc.message}). Unauthenticated GitHub searches are limited to a few requests per minute - add a free GitHub token in Settings to raise the limit."


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


@source(
    id="github_user",
    name="GitHub profile",
    category="code-hosting",
    applies_to=("username",),
    sends="The username (public profile lookup).",
    docs="https://docs.github.com/rest/users/users",
    description="Public GitHub account: display name, company, blog, location, bio and repository counts.",
)
def github_user(ctx: SourceContext) -> dict[str, Any]:
    username = ctx.identifier.value
    url = f"https://api.github.com/users/{urllib.parse.quote(username)}"
    try:
        payload = ctx.fetcher.get_json(url, headers=_github_headers(ctx), timeout=SETTINGS.limits.per_source_timeout,
                                       cache_key=f"github:user:{username}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    except UpstreamRateLimited as exc:
        raise SourceOutcome(STATUS_RATE_LIMITED, _github_rate_limit_message(exc),
                            hint="Settings → GitHub token (free)") from exc
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            raise SourceOutcome(STATUS_NO_MATCH, f"No public GitHub account named '{username}'.") from exc
        if exc.status in (403, 429):
            raise SourceOutcome(STATUS_RATE_LIMITED, _github_rate_limit_message(exc),
                                hint="Settings → GitHub token (free)") from exc
        raise
    if not isinstance(payload, dict) or not payload.get("login"):
        raise SourceOutcome(STATUS_UNAVAILABLE, "GitHub returned an unexpected response shape.")

    account_type = str(payload.get("type") or "User")
    exposures = {
        "name": _plain(payload.get("name"), 120),
        "company": _plain(payload.get("company"), 120),
        "blog": _plain(payload.get("blog"), 200),
        "location": _plain(payload.get("location"), 160),
        "bio": _clean(payload.get("bio"), 300),
        "email": _plain(payload.get("email"), 120),
        "twitter": _plain(payload.get("twitter_username"), 60),
        "public_repos": payload.get("public_repos"),
        "followers": payload.get("followers"),
        "following": payload.get("following"),
        "created_at": parse_upstream_timestamp(payload.get("created_at")),
        "updated_at": parse_upstream_timestamp(payload.get("updated_at")),
        "html_url": payload.get("html_url", f"https://github.com/{username}"),
        "type": account_type,
    }
    personal_fields = [k for k in ("name", "company", "location", "bio", "email", "blog", "twitter") if exposures[k]]
    severity = "medium" if len(personal_fields) >= 2 else ("low" if personal_fields else "info")

    evidence = [Evidence("Account", f"{payload.get('login')} ({account_type})"),
                Evidence("Created", exposures["created_at"] or "unknown"),
                Evidence("Public repositories", str(exposures["public_repos"])),
                Evidence("Followers", str(exposures["followers"]))]
    for key in ("name", "company", "location", "bio", "email", "blog", "twitter"):
        if exposures[key]:
            evidence.append(Evidence(key.replace("_", " ").title(), str(exposures[key])))

    findings = [Finding(
        source_id="github_user", source_name="GitHub profile", severity=severity, category="code-hosting",
        title=f"GitHub account '{payload.get('login')}' exists"
              + (f" and exposes {len(personal_fields)} personal field(s)" if personal_fields else ""),
        summary=(f"Public profile created {exposures['created_at'] or 'unknown'} with "
                 f"{exposures['public_repos']} public repositories."
                 + (f" Self-reported details: {', '.join(personal_fields)}." if personal_fields else "")),
        evidence=evidence,
        links=[Evidence("GitHub profile", exposures["html_url"]),
               Evidence("Public repositories", f"{exposures['html_url']}?tab=repositories")],
        observed_at=exposures["created_at"],
        interpretation="A matching username is not proof of the same person: handles are re-used, squatted and shared. "
                       "Self-reported fields (name, company, location, bio) are whatever the account owner typed.",
    )]

    blog_host = ""
    blog = exposures["blog"]
    if blog:
        candidate = blog if re.match(r"^[a-z][a-z0-9+.-]*://", blog) else "https://" + blog
        try:
            host = (urllib.parse.urlsplit(candidate).hostname or "").lower().strip(".")
        except ValueError:
            host = ""
        if host and re.match(r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$", host):
            blog_host = host
            findings.append(Finding(
                source_id="github_user", source_name="GitHub profile", severity="low", category="code-hosting",
                title=f"Profile links to the site {host}",
                summary=f"The GitHub account '{payload.get('login')}' publishes {host} in its blog field, which "
                        "connects this handle to a domain.",
                evidence=[Evidence("Blog field", blog), Evidence("Registrable domain", apex_domain(host))],
                links=[Evidence("Linked site", blog), Evidence("GitHub profile", exposures["html_url"])],
                interpretation="Anyone can type any domain into that field; verify ownership (DNS, page content, or an "
                               "identity proof) before treating the link as real.",
            ))
    data = {**exposures, "blog_host": blog_host, "personal_fields": personal_fields}
    return {"status": STATUS_OK, "message": f"GitHub account '{payload.get('login')}' found.",
            "findings": findings, "data": data, "upstream_host": "api.github.com"}


@source(
    id="github_commits",
    name="GitHub commit author search",
    category="code-hosting",
    applies_to=("email",),
    sends="The exact email address, inside a GitHub code-search query.",
    docs="https://docs.github.com/rest/search/search#search-commits",
    description="Public commits whose author email matches exactly - a strong link between an address and public code.",
)
def github_commits(ctx: SourceContext) -> dict[str, Any]:
    email = ctx.identifier.value.lower()
    query = urllib.parse.quote(f'author-email:"{email}"', safe=":")
    url = (f"https://api.github.com/search/commits?q={query}"
           f"&sort=committer-date&order=desc&per_page=10")
    try:
        payload = ctx.fetcher.get_json(url, headers=_github_headers(ctx), timeout=SETTINGS.limits.per_source_timeout)
    except UpstreamRateLimited as exc:
        raise SourceOutcome(STATUS_RATE_LIMITED, _github_rate_limit_message(exc),
                            hint="Settings → GitHub token (free)") from exc
    except UpstreamHTTPError as exc:
        if exc.status in (403, 429):
            raise SourceOutcome(STATUS_RATE_LIMITED, _github_rate_limit_message(exc),
                                hint="Settings → GitHub token (free)") from exc
        if exc.status == 422:
            raise SourceOutcome(STATUS_UNAVAILABLE,
                                f"GitHub rejected the commit search query (HTTP 422): {exc.message}") from exc
        raise

    items = payload.get("items") or []
    # GitHub's commit search is not an exact-match index: filter to the exact address.
    exact: list[dict[str, Any]] = []
    for item in items:
        commit = item.get("commit") or {}
        author = commit.get("author") or {}
        committer = commit.get("committer") or {}
        matched_role = ""
        if str(author.get("email", "")).lower() == email:
            matched_role = "author"
        elif str(committer.get("email", "")).lower() == email:
            matched_role = "committer"
        if not matched_role:
            continue
        repo = (item.get("repository") or {})
        exact.append({
            "role": matched_role,
            "sha": item.get("sha", "")[:12],
            "repo": repo.get("full_name", ""),
            "author_name": author.get("name", ""),
            "login": (item.get("author") or {}).get("login", "") if isinstance(item.get("author"), dict) else "",
            "date": parse_upstream_timestamp(author.get("date") or committer.get("date")),
            "message": _plain((commit.get("message") or "").splitlines()[0] if commit.get("message") else "", 160),
            "url": item.get("html_url", ""),
        })

    reported_total = int(payload.get("total_count") or 0)
    incomplete = bool(payload.get("incomplete_results"))
    data = {
        "email": email, "reported_total_count": reported_total,
        "incomplete_results": incomplete,
        "exact_matches": exact, "exact_match_count": len(exact),
        "page_size": len(items),
    }
    partial_note = (
        " GitHub caps this search API, so only the newest page of results was examined; older commits with the same "
        "address may exist." if incomplete else ""
    )
    if not exact:
        return {
            "status": STATUS_NO_MATCH,
            "message": f"No public commits authored with the exact address {email} were returned "
                       f"(GitHub reported {reported_total} loose candidates; none matched exactly)." + partial_note,
            "data": data, "upstream_host": "api.github.com",
        }

    repos = sorted({m["repo"] for m in exact if m["repo"]})
    names = sorted({m["author_name"] for m in exact if m["author_name"]})
    logins = sorted({m["login"] for m in exact if m["login"]})
    severity = "high" if len(repos) >= 2 or names else "medium"
    evidence = [Evidence("Commits found (this page of results)", str(len(exact))),
                Evidence("Public repositories", ", ".join(repos[:8]) or "unknown"),
                Evidence("Name(s) used in commits", ", ".join(names[:6]) or "none")]
    for match in exact[:5]:
        evidence.append(Evidence(f"{match['date'] or 'date unknown'} - {match['repo']}",
                                 f"{match['role']}: {match['author_name']} <{email}> '{match['message']}'"))
    links = [Evidence("GitHub commit search", f"https://github.com/search?q=author-email%3A%22{urllib.parse.quote(email)}%22&type=commits")]
    links += [Evidence(f"Commit {m['sha']}", m["url"]) for m in exact[:3] if m["url"]]

    findings = [Finding(
        source_id="github_commits", source_name="GitHub commit author search", severity=severity,
        category="code-hosting",
        title=f"Email address appears as a commit author in {len(repos)} public repository/repositories",
        summary=f"Public git history on GitHub contains commits authored with {email}"
                + (f", using the name(s) {', '.join(names[:4])}." if names else "."),
        evidence=evidence, links=links,
        observed_at=exact[0]["date"] if exact else None,
        interpretation="Commit emails are self-configured (git config user.email) and are often work or throwaway "
                       "addresses, so this links an address to code activity - not necessarily to the person who owns it."
                       + (partial_note.strip() if partial_note else ""),
    )]
    if logins:
        findings.append(Finding(
            source_id="github_commits", source_name="GitHub commit author search", severity="medium",
            category="code-hosting",
            title=f"Commits link this address to GitHub account(s): {', '.join(logins[:5])}",
            summary="GitHub attributes some of these commits to signed-in accounts, connecting the email address to "
                    "public profile(s).",
            evidence=[Evidence("GitHub account(s)", ", ".join(logins[:8]))],
            links=[Evidence(f"Profile: {login}", f"https://github.com/{login}") for login in logins[:3]],
            interpretation="Verify by opening the profile - account attribution comes from GitHub's own mapping and may "
                           "reflect a shared or organisation mailbox.",
        ))
    return {"status": STATUS_OK,
            "message": f"{len(exact)} exact author-email commit match(es) in {len(repos)} repositories." + partial_note,
            "findings": findings, "data": data, "upstream_host": "api.github.com"}


@source(
    id="github_name",
    name="GitHub people search",
    category="code-hosting",
    applies_to=("name",),
    sends="The name you typed, inside a GitHub user-search query.",
    docs="https://docs.github.com/rest/search/search#search-users",
    description="Public GitHub accounts whose self-reported full name matches. Candidates only - never proof.",
)
def github_name(ctx: SourceContext) -> dict[str, Any]:
    name = ctx.identifier.value
    query = urllib.parse.quote(f'fullname:"{name}"', safe=":")
    url = f"https://api.github.com/search/users?q={query}&per_page=10"
    try:
        payload = ctx.fetcher.get_json(url, headers=_github_headers(ctx), timeout=SETTINGS.limits.per_source_timeout)
    except UpstreamRateLimited as exc:
        raise SourceOutcome(STATUS_RATE_LIMITED, _github_rate_limit_message(exc),
                            hint="Settings → GitHub token (free)") from exc
    except UpstreamHTTPError as exc:
        if exc.status in (403, 429):
            raise SourceOutcome(STATUS_RATE_LIMITED, _github_rate_limit_message(exc),
                                hint="Settings → GitHub token (free)") from exc
        raise
    items = payload.get("items") or []
    total = int(payload.get("total_count") or 0)
    candidates = [{"login": i.get("login"), "url": i.get("html_url"), "type": i.get("type")} for i in items if i.get("login")]
    data = {"name": name, "reported_total_count": total, "candidates": candidates}
    if not candidates:
        return {
            "status": STATUS_NO_MATCH,
            "message": f"No public GitHub accounts list '{name}' as their full name.",
            "data": data, "upstream_host": "api.github.com",
        }
    findings = [Finding(
        source_id="github_name", source_name="GitHub people search", severity="low", category="code-hosting",
        title=f"{total} GitHub account(s) self-report the name '{name}'",
        summary=f"Showing up to {len(candidates)} candidate accounts. These are name matches in a self-reported field, "
                "not identity matches.",
        evidence=[Evidence("Candidate account", c["login"]) for c in candidates[:10]],
        links=[Evidence(f"Profile: {c['login']}", c["url"] or f"https://github.com/{c['login']}") for c in candidates[:6]],
        interpretation="Many unrelated people share a name, and GitHub's 'fullname' search matches loosely (order, "
                       "partial names). Do not treat a candidate as the person you are looking for without corroboration.",
    )]
    return {"status": STATUS_OK, "message": f"{total} candidate GitHub account(s) for the name '{name}'.",
            "findings": findings, "data": data, "upstream_host": "api.github.com"}


# ---------------------------------------------------------------------------
# GitLab / Codeberg / Keybase / Hacker News
# ---------------------------------------------------------------------------


@source(
    id="gitlab_user",
    name="GitLab profile",
    category="code-hosting",
    applies_to=("username",),
    sends="The username (public user lookup).",
    docs="https://docs.gitlab.com/ee/api/users.html",
    description="Public GitLab.com account: display name, state, bio, location and public email if set.",
)
def gitlab_user(ctx: SourceContext) -> dict[str, Any]:
    username = ctx.identifier.value
    url = f"https://gitlab.com/api/v4/users?username={urllib.parse.quote(username)}"
    payload = ctx.fetcher.get_json(url, timeout=SETTINGS.limits.per_source_timeout,
                                   cache_key=f"gitlab:user:{username}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    if not isinstance(payload, list):
        raise SourceOutcome(STATUS_UNAVAILABLE, "GitLab returned an unexpected response shape (expected a list).")
    if not payload:
        return {"status": STATUS_NO_MATCH, "message": f"No public GitLab.com account named '{username}'.",
                "data": {"username": username}, "upstream_host": "gitlab.com"}
    user = payload[0]
    exposures = {
        "name": _plain(user.get("name"), 120),
        "username": user.get("username"),
        "state": user.get("state"),
        "bio": _clean(user.get("bio"), 300),
        "location": _plain(user.get("location"), 160),
        "public_email": _plain(user.get("public_email"), 120),
        "website": _plain(user.get("website_url") or user.get("web_url"), 200),
        "created_at": parse_upstream_timestamp(user.get("created_at")),
        "web_url": user.get("web_url", f"https://gitlab.com/{username}"),
        "followers": user.get("followers"),
    }
    personal = [k for k in ("name", "bio", "location", "public_email") if exposures[k]]
    evidence = [Evidence("Account", f"{exposures['username']} (state: {exposures['state'] or 'unknown'})"),
                Evidence("Created", exposures["created_at"] or "unknown")]
    for key in personal:
        evidence.append(Evidence(key.replace("_", " ").title(), str(exposures[key])))
    findings = [Finding(
        source_id="gitlab_user", source_name="GitLab profile", severity="medium" if len(personal) >= 2 else "low",
        category="code-hosting",
        title=f"GitLab account '{exposures['username']}' exists",
        summary=f"Public GitLab.com profile"
                + (f" exposing {', '.join(personal)}." if personal else " with no personal details published."),
        evidence=evidence,
        links=[Evidence("GitLab profile", exposures["web_url"]),
               Evidence("Public activity", f"{exposures['web_url']}/activity")],
        observed_at=exposures["created_at"],
        interpretation="Username matches across services are not identity matches, and GitLab accounts can be inactive "
                       "or organisation-owned.",
    )]
    if exposures["public_email"]:
        findings.append(Finding(
            source_id="gitlab_user", source_name="GitLab profile", severity="high", category="code-hosting",
            title="Profile publishes an email address",
            summary=f"The GitLab account '{exposures['username']}' shows {exposures['public_email']} publicly.",
            evidence=[Evidence("Public email", exposures["public_email"])],
            links=[Evidence("GitLab profile", exposures["web_url"])],
            interpretation="A published email is a direct identifier, but it may be a role/organisation mailbox rather "
                           "than a personal one.",
        ))
    return {"status": STATUS_OK, "message": f"GitLab account '{exposures['username']}' found.",
            "findings": findings, "data": exposures, "upstream_host": "gitlab.com"}


@source(
    id="codeberg_user",
    name="Codeberg profile",
    category="code-hosting",
    applies_to=("username",),
    sends="The username (public user lookup).",
    docs="https://codeberg.org/api/swagger#/user/userGet",
    description="Public Codeberg (free-software forge) account profile.",
)
def codeberg_user(ctx: SourceContext) -> dict[str, Any]:
    username = ctx.identifier.value
    url = f"https://codeberg.org/api/v1/users/{urllib.parse.quote(username)}"
    try:
        payload = ctx.fetcher.get_json(url, timeout=SETTINGS.limits.per_source_timeout,
                                       cache_key=f"codeberg:user:{username}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            raise SourceOutcome(STATUS_NO_MATCH, f"No public Codeberg account named '{username}'.") from exc
        raise
    if not isinstance(payload, dict) or not payload.get("login"):
        raise SourceOutcome(STATUS_UNAVAILABLE, "Codeberg returned an unexpected response shape.")
    exposures = {
        "login": payload.get("login"),
        "full_name": _plain(payload.get("full_name"), 120),
        "email": _plain(payload.get("email"), 120),
        "location": _plain(payload.get("location"), 160),
        "website": _plain(payload.get("website"), 200),
        "description": _clean(payload.get("description"), 300),
        "pronouns": _plain(payload.get("pronouns"), 60),
        "created": parse_upstream_timestamp(payload.get("created")),
        "last_login": parse_upstream_timestamp(payload.get("last_login")),
        "followers_count": payload.get("followers_count"),
        "html_url": payload.get("html_url", f"https://codeberg.org/{username}"),
    }
    personal = [k for k in ("full_name", "email", "location", "website", "description") if exposures[k]]
    evidence = [Evidence("Account", str(exposures["login"])),
                Evidence("Created", exposures["created"] or "unknown"),
                Evidence("Followers", str(exposures["followers_count"]))]
    for key in personal:
        evidence.append(Evidence(key.replace("_", " ").title(), str(exposures[key])[:200]))
    findings = [Finding(
        source_id="codeberg_user", source_name="Codeberg profile", severity="medium" if len(personal) >= 2 else "low",
        category="code-hosting",
        title=f"Codeberg account '{exposures['login']}' exists",
        summary=f"Public Codeberg profile created {exposures['created'] or 'unknown'}"
                + (f", exposing {', '.join(personal)}." if personal else "."),
        evidence=evidence,
        links=[Evidence("Codeberg profile", exposures["html_url"])],
        observed_at=exposures["created"],
        interpretation="The Codeberg API also returns a noreply email for every user; that address is generated by the "
                       "platform and is not a personal mailbox.",
    )]
    if exposures["email"] and "noreply" not in exposures["email"]:
        findings.append(Finding(
            source_id="codeberg_user", source_name="Codeberg profile", severity="high", category="code-hosting",
            title="Profile publishes an email address",
            summary=f"The Codeberg account '{exposures['login']}' shows {exposures['email']} publicly.",
            evidence=[Evidence("Public email", exposures["email"])],
            links=[Evidence("Codeberg profile", exposures["html_url"])],
            interpretation="Verify before assuming it belongs to the person you are investigating.",
        ))
    return {"status": STATUS_OK, "message": f"Codeberg account '{exposures['login']}' found.",
            "findings": findings, "data": exposures, "upstream_host": "codeberg.org"}


@source(
    id="keybase_user",
    name="Keybase profile & identity proofs",
    category="code-hosting",
    applies_to=("username",),
    sends="The username (public user lookup).",
    # Keybase retired its public API docs site; the client repository is the
    # remaining authoritative reference for the endpoints this source calls.
    docs="https://github.com/keybase/client",
    description="Keybase account, self-reported profile fields and cryptographic proofs of other social/code accounts.",
)
def keybase_user(ctx: SourceContext) -> dict[str, Any]:
    username = ctx.identifier.value
    url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={urllib.parse.quote(username)}"
    payload = ctx.fetcher.get_json(url, timeout=SETTINGS.limits.per_source_timeout,
                                   cache_key=f"keybase:user:{username}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    status = payload.get("status") or {}
    code = status.get("code")
    them = payload.get("them")
    # Pitfall: `them` is usually a list, but some responses return a single object.
    if isinstance(them, dict):
        them = [them]
    if not them:
        message = f"No Keybase account named '{username}'."
        if code not in (0, None):
            message += f" (Keybase status {code}: {_clean(status.get('desc'), 120)})"
        return {"status": STATUS_NO_MATCH, "message": message, "data": {"username": username, "keybase_status": code},
                "upstream_host": "keybase.io"}

    user = them[0]
    basics = user.get("basics") or {}
    profile = user.get("profile") or {}
    public_keys = user.get("public_keys") or {}
    proofs_summary = user.get("proofs_summary") or {}
    all_proofs = proofs_summary.get("all") or []
    proofs = []
    for proof in all_proofs[:12]:
        if isinstance(proof, dict):
            proofs.append({
                "type": str(proof.get("proof_type") or proof.get("key", "")),
                "nametag": _plain(proof.get("nametag"), 80),
                "human_url": _plain(proof.get("human_url"), 240),
                "state": proof.get("state"),
            })
    exposures = {
        "username": basics.get("username_cased") or basics.get("username") or username,
        "full_name": _plain(profile.get("full_name"), 120),
        "location": _plain(profile.get("location"), 160),
        "bio": _clean(profile.get("bio"), 300),
        "key_count": len(public_keys) if isinstance(public_keys, dict) else 0,
        "proofs": proofs,
        "created": parse_upstream_timestamp(basics.get("ctime")),
        "modified": parse_upstream_timestamp(basics.get("mtime")),
        "profile_url": f"https://keybase.io/{basics.get('username') or username}",
    }
    personal = [k for k in ("full_name", "location", "bio") if exposures[k]]
    evidence = [Evidence("Account", str(exposures["username"])),
                Evidence("Account created (ctime)", exposures["created"] or "unknown"),
                Evidence("PGP keys published", str(exposures["key_count"])),
                Evidence("Identity proofs", ", ".join(f"{p['type']}:{p['nametag']}" for p in proofs[:8]) or "none")]
    for key in personal:
        evidence.append(Evidence(key.replace("_", " ").title(), str(exposures[key])))
    links = [Evidence("Keybase profile", exposures["profile_url"])]
    links += [Evidence(f"{p['type']}: {p['nametag']}", p["human_url"]) for p in proofs[:5] if p["human_url"]]

    severity = "high" if proofs else ("medium" if personal else "low")
    findings = [Finding(
        source_id="keybase_user", source_name="Keybase profile & identity proofs", severity=severity,
        category="code-hosting",
        title=f"Keybase account '{exposures['username']}'"
              + (f" with {len(proofs)} identity proof(s)" if proofs else " exists"),
        summary=("Keybase links this username to other accounts using signed proofs, which is stronger evidence than a "
                 "plain username match." if proofs else "Public Keybase profile found.")
                + (f" Self-reported: {', '.join(personal)}." if personal else ""),
        evidence=evidence, links=links, observed_at=exposures["created"],
        interpretation="Keybase proofs are cryptographically signed, but they still only prove control of the linked "
                       "accounts at the time they were made - and Keybase has been in maintenance mode since 2020, so "
                       "data may be stale. Key material is never stored or displayed by this app.",
    )]
    if proofs:
        findings.append(Finding(
            source_id="keybase_user", source_name="Keybase profile & identity proofs", severity="medium",
            category="identity",
            title="Cross-service identity proofs published",
            summary="The account claims and signed for: "
                    + ", ".join("{} ({})".format(p["type"], p["nametag"]) for p in proofs[:6]) + ".",
            evidence=[Evidence(f"{p['type']}", f"{p['nametag']} (state {p.get('state')})") for p in proofs[:8]],
            links=[Evidence(f"{p['type']}: {p['nametag']}", p["human_url"]) for p in proofs[:6] if p["human_url"]],
            interpretation="These are the account owner's own claims, verified by Keybase at proof time. They tie "
                           "handles together, not handles to a legal identity.",
        ))
    return {"status": STATUS_OK, "message": f"Keybase account '{exposures['username']}' found.",
            "findings": findings, "data": exposures, "upstream_host": "keybase.io"}


@source(
    id="hackernews_user",
    name="Hacker News profile",
    category="code-hosting",
    applies_to=("username",),
    sends="The username (public profile lookup via the Algolia-hosted HN API).",
    docs="https://hn.algolia.com/api",
    description="Public Hacker News account: karma, about text and account age.",
)
def hackernews_user(ctx: SourceContext) -> dict[str, Any]:
    username = ctx.identifier.value
    url = f"https://hn.algolia.com/api/v1/users/{urllib.parse.quote(username)}"
    try:
        payload = ctx.fetcher.get_json(url, timeout=SETTINGS.limits.per_source_timeout,
                                       cache_key=f"hn:user:{username}", cache_ttl=SETTINGS.limits.cache_default_ttl)
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            raise SourceOutcome(STATUS_NO_MATCH, f"No public Hacker News account named '{username}'.") from exc
        raise
    if not isinstance(payload, dict) or not payload.get("username"):
        return {"status": STATUS_NO_MATCH, "message": f"No public Hacker News account named '{username}'.",
                "data": {"username": username}, "upstream_host": "hn.algolia.com"}
    about = _clean(payload.get("about"), 400)
    created = parse_upstream_timestamp(payload.get("created_at"))
    karma = payload.get("karma")
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", str(payload.get("about") or ""))
    urls = re.findall(r"https?://[^\s<>\"]{4,120}", str(payload.get("about") or ""))
    data = {"username": payload.get("username"), "karma": karma, "about": about, "created_at": created,
            "emails_in_about": emails[:3], "urls_in_about": urls[:5]}
    evidence = [Evidence("Username", str(payload.get("username"))), Evidence("Karma", str(karma)),
                Evidence("Account created", created or "unknown")]
    if about:
        evidence.append(Evidence("About (self-reported)", about))
    severity = "medium" if (emails or urls or about) else "low"
    findings = [Finding(
        source_id="hackernews_user", source_name="Hacker News profile", severity=severity, category="code-hosting",
        title=f"Hacker News account '{payload.get('username')}' exists"
              + (" and publishes contact details in its bio" if emails else ""),
        summary=f"Public HN profile with {karma} karma, created {created or 'unknown'}."
                + (f" The about field contains: {about[:160]}" if about else ""),
        evidence=evidence,
        links=[Evidence("HN profile", f"https://news.ycombinator.com/user?id={urllib.parse.quote(str(payload.get('username')))}"),
               Evidence("Comments by this user", f"https://hn.algolia.com/?dateRange=all&page=0&prefix=false&query={urllib.parse.quote(str(payload.get('username')))}&sort=byAuthor&type=comment")],
        observed_at=created,
        interpretation="The about text is self-reported and may be empty, outdated, or written by someone else who took "
                       "the handle.",
    )]
    if emails:
        findings.append(Finding(
            source_id="hackernews_user", source_name="Hacker News profile", severity="high", category="identity",
            title="Email address published in the HN bio",
            summary=f"The profile's about field contains {', '.join(emails[:3])}.",
            evidence=[Evidence("Email(s) in bio", ", ".join(emails[:3]))],
            links=[Evidence("HN profile", f"https://news.ycombinator.com/user?id={urllib.parse.quote(str(payload.get('username')))}")],
            interpretation="Publicly posted addresses are frequently harvested for spam; this is exposure, not wrongdoing.",
        ))
    return {"status": STATUS_OK, "message": f"Hacker News account '{payload.get('username')}' found.",
            "findings": findings, "data": data, "upstream_host": "hn.algolia.com"}


# ---------------------------------------------------------------------------
# Sourcegraph public code search (server-sent events)
# ---------------------------------------------------------------------------


@source(
    id="sourcegraph_code",
    name="Sourcegraph public code search",
    category="code-hosting",
    applies_to=("email", "username"),
    sends="The email address or username, as a literal search pattern, to Sourcegraph's public code search.",
    docs="https://sourcegraph.com/docs/api/stream-api",
    description="Looks for the exact string inside public source code indexed by Sourcegraph (streaming SSE API).",
)
def sourcegraph_code(ctx: SourceContext) -> dict[str, Any]:
    ident = ctx.identifier
    if ident.kind == "email":
        pattern = ident.value
        label = "email address"
    elif ident.kind == "username":
        # A bare username is far too noisy on its own; require it to appear as a
        # handle-style token so results stay evidence-grade.
        pattern = ident.value
        label = "username"
        if len(pattern) < 4:
            raise SourceOutcome(STATUS_NOT_CHECKED,
                                "Skipped: usernames shorter than 4 characters produce unusable noise in a global code search.")
    else:  # pragma: no cover - registry guarantees applies_to
        raise SourceOutcome(STATUS_NOT_CHECKED, "Not applicable to this identifier type.")

    query = f"context:global count:20 {pattern}"
    url = f"https://sourcegraph.com/.api/search/stream?q={urllib.parse.quote(query)}&t=literal&display=20"
    try:
        raw = ctx.fetcher.get_text(
            url, headers={"Accept": "text/event-stream"}, timeout=SETTINGS.limits.per_source_timeout + 6,
            max_bytes=2 * 1024 * 1024,
        )
    except UpstreamRateLimited:
        raise SourceOutcome(STATUS_RATE_LIMITED,
                            "Sourcegraph rate-limited the request. Wait a minute and try again.")
    except UpstreamHTTPError as exc:
        raise SourceOutcome(STATUS_UNAVAILABLE, f"Sourcegraph code search failed: {exc.message}")

    matches: list[dict[str, Any]] = []
    error_message = ""
    alert: dict[str, Any] = {}
    for event, data in parse_sse_events(raw):
        if event == "matches":
            try:
                parsed = json.loads(data)
            except ValueError:
                continue
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    repo = str(item.get("repository") or "")
                    path = str(item.get("path") or "")
                    line_matches = item.get("lineMatches") or []
                    lines = []
                    for line_match in line_matches[:3]:
                        if isinstance(line_match, dict):
                            lines.append({
                                "line": _plain(line_match.get("line"), 200),
                                "lineNumber": line_match.get("lineNumber"),
                            })
                    blob_url = f"https://sourcegraph.com/{repo}/-/blob/{path}" if repo and path else ""
                    if lines and lines[0].get("lineNumber") is not None:
                        blob_url += f"#L{int(lines[0]['lineNumber']) + 1}"
                    matches.append({
                        "repository": repo, "path": path, "language": item.get("language"),
                        "commit": str(item.get("commit") or "")[:12], "lines": lines, "url": blob_url,
                        "repo_stars": item.get("repoStars"),
                    })
        elif event == "error":
            error_message = _plain(data, 300)
        elif event == "alert":
            try:
                alert = json.loads(data) if data else {}
            except ValueError:
                alert = {}

    # Post-filter: only keep matches whose line really contains the pattern.
    needle = pattern.lower()
    exact = [m for m in matches if any(needle in (line.get("line") or "").lower() for line in m["lines"])]

    data_out = {"pattern": pattern, "label": label, "match_count": len(exact), "matches": exact[:10],
                "stream_error": error_message, "alert": alert.get("title", "")}
    if not exact:
        if error_message:
            return {"status": STATUS_UNAVAILABLE,
                    "message": f"Sourcegraph returned an error instead of results: {error_message}",
                    "data": data_out, "upstream_host": "sourcegraph.com"}
        return {"status": STATUS_NO_MATCH,
                "message": f"Sourcegraph's public index returned no files containing the exact {label} '{pattern}'. "
                           "Its index is partial, so this is not proof of absence.",
                "data": data_out, "upstream_host": "sourcegraph.com"}

    repos = sorted({m["repository"] for m in exact if m["repository"]})
    findings = [Finding(
        source_id="sourcegraph_code", source_name="Sourcegraph public code search",
        severity="medium" if label == "email address" else "low", category="code-hosting",
        title=f"{label.capitalize()} appears in {len(exact)} public source file(s)",
        summary=f"Sourcegraph's public code index contains the exact string '{pattern}' in "
                f"{len(repos)} repository/repositories.",
        evidence=[Evidence(f"{m['repository']} :: {m['path']}",
                           (m["lines"][0]["line"] if m["lines"] else "")[:180]) for m in exact[:6]],
        links=[Evidence(f"{m['repository']}/{m['path']}", m["url"]) for m in exact[:5] if m["url"]],
        interpretation="Public code often embeds emails in package manifests, sample data, fixtures and documentation. "
                       "A hit shows the string exists in public code - not that it belongs to the person you searched for.",
    )]
    return {"status": STATUS_OK,
            "message": f"{len(exact)} exact match(es) for '{pattern}' in Sourcegraph's public code index.",
            "findings": findings, "data": data_out, "upstream_host": "sourcegraph.com"}
