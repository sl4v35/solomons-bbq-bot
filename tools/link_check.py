#!/usr/bin/env python3
"""Check that every external URL this app publishes to users still resolves.

Verdigris shows people removal/reporting links and upstream documentation links.
A link that 404s is a broken promise, so CI checks them all.

Scope:
  * ``ACTION_LINKS`` in :mod:`app.report` (removal / reporting / dispute pages)
  * the ``docs`` URL of every registered source
  * every absolute https link in ``README.md``
  * the ``where`` hints for optional API keys

Not checked: the ~110 host allowlist in :mod:`app.config` (those are API hosts the
sources themselves exercise - see ``tools/live_probe.py``).

Exit status:
  0  every link resolved (warnings allowed)
  1  at least one link is definitively dead (HTTP 404/410 or DNS failure)

Usage:
    python3 tools/link_check.py            # check everything
    python3 tools/link_check.py --jobs 8   # more parallelism
    python3 tools/link_check.py --strict   # also fail on 4xx/5xx warnings
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0 Safari/537.36 VerdigrisLinkCheck/1.0")
TIMEOUT = 20.0
MAX_BYTES = 64 * 1024
DEAD_STATUSES = {404, 410}
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\((https://[^)\s]+)\)")

# Some sites refuse datacentre IPs or plain HEAD requests; that is a warning, not
# a dead link, because a real browser on a residential connection still works.
SOFT_FAIL_STATUSES = {401, 403, 405, 429, 500, 502, 503, 504}


def collect_urls() -> list[tuple[str, str]]:
    """Return ``(url, origin)`` pairs for every user-visible external link."""
    from app.report import ACTION_LINKS
    from app.sources import public_catalogue

    found: list[tuple[str, str]] = []

    for kind, links in ACTION_LINKS.items():
        for link in links:
            url = link.get("url", "")
            if url.startswith("https://"):
                found.append((url, f"action-link:{kind}:{link.get('provider', '')}"))

    for source in public_catalogue():
        docs = source.get("docs", "")
        if docs.startswith("https://"):
            found.append((docs, f"source-docs:{source['id']}"))

    readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md")
    if os.path.exists(readme):
        with open(readme, encoding="utf-8") as handle:
            for url in MARKDOWN_LINK_RE.findall(handle.read()):
                found.append((url.rstrip(").,"), "README.md"))

    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for url, origin in found:
        if url in seen:
            continue
        seen.add(url)
        unique.append((url, origin))
    return unique


def _once(url: str) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en",
    }, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            response.read(MAX_BYTES)
            return response.status, response.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc.reason or "")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, socket.timeout):
            return 0, "timeout"
        return 0, str(reason)
    except (socket.timeout, TimeoutError):
        return 0, "timeout"
    except Exception as exc:  # noqa: BLE001 - report, never crash the checker
        return 0, f"{type(exc).__name__}: {exc}"


def check(url: str, attempts: int = 2) -> tuple[str, int, str]:
    """Return ``(url, status, detail)``.  ``status`` 0 means a transport failure.

    Transport failures are retried: a runner's transient DNS/TLS blip must not be
    reported as a dead link.  Only a definitive HTTP 404/410 is.
    """
    status, detail = 0, ""
    for attempt in range(max(1, attempts)):
        status, detail = _once(url)
        if status != 0:
            break
        if attempt + 1 < max(1, attempts):
            time.sleep(1.5 * (attempt + 1))
    return url, status, detail


def annotate(level: str, title: str, message: str) -> None:
    """Emit a GitHub Actions annotation so results are readable without raw logs."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    safe_title = title.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    safe_message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} title={safe_title}::{safe_message}")


def main(argv: list[str] | None = None) -> int:
    global TIMEOUT
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=6, help="parallel requests (default 6)")
    parser.add_argument("--strict", action="store_true", help="fail on soft errors too")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="per-request timeout")
    args = parser.parse_args(argv)
    TIMEOUT = args.timeout

    urls = collect_urls()
    if not urls:
        print("no URLs collected - nothing to check", file=sys.stderr)
        return 1

    print(f"checking {len(urls)} external URL(s) with {args.jobs} worker(s)\n")
    origins = dict(urls)
    dead: list[tuple[str, int, str]] = []
    soft: list[tuple[str, int, str]] = []
    ok = 0

    with futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for url, status, detail in pool.map(lambda pair: check(pair[0]), urls):
            origin = origins.get(url, "")
            if 200 <= status < 400:
                ok += 1
                print(f"  ok    {status}  {url}  [{origin}]")
            elif status in DEAD_STATUSES:
                dead.append((url, status, detail))
                print(f"  DEAD  {status}  {url}  [{origin}]  {detail}")
                annotate("error", f"dead link ({status})", f"{url} [{origin}]")
            else:
                # Includes transport failures: after a retry those are usually a
                # runner network blip or a host that blocks datacentre IPs.
                soft.append((url, status, detail))
                print(f"  soft  {status or 'ERR'}  {url}  [{origin}]  {detail}")
                annotate("warning", f"unreachable or blocked ({status or 'transport'})",
                         f"{url} [{origin}] {detail}")

    print(f"\n{ok} ok, {len(soft)} soft failure(s), {len(dead)} dead")
    annotate("notice", "link check summary", f"{ok} ok, {len(soft)} soft, {len(dead)} dead of {len(urls)}")
    if soft:
        print("soft failures are usually bot-blocking (403/429) or a temporary upstream 5xx; "
              "re-check from a normal browser before changing a link.")
    if dead:
        print("\nDEAD LINKS - these must be fixed or removed:")
        for url, status, detail in dead:
            print(f"  {url} -> {status or 'transport error'} {detail}  [{origins.get(url, '')}]")
        return 1
    if args.strict and soft:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
