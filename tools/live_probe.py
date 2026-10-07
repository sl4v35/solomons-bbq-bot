#!/usr/bin/env python3
"""Probe real upstreams (or a deployed instance) and print an honest status table.

Two modes
---------
``sources`` (default)
    Runs every registered source in-process against benign, already-public
    identifiers (example.com, a well-known GitHub account, a public Bitcoin
    address, ...) using the app's own allowlisted fetcher.  This is the check
    that proves each integration still matches the live API - run it in CI
    (which has internet) and after any upstream change.

``deploy`` (``--base-url``)
    Verifies a running deployment over HTTP: ``/health``, every static asset,
    identifier detection, a full scan round-trip and the k-anonymity password
    endpoint.  Use it after Render finishes deploying:

        python3 tools/live_probe.py --base-url https://your-app.onrender.com

Exit status is 1 only for problems this app owns: a source that crashed
(``error``), or a deployment check that failed.  Upstream outages, rate limits
and "needs a key" results are reported but do not fail the run, because they are
not app bugs - and pretending otherwise would make CI useless.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Benign identifiers: all of them are famous, already-public and non-personal.
PROBES = {
    "domain": "example.com",                      # IANA's reserved documentation domain
    "email": "torvalds@linux-foundation.org",     # public commit author address
    "username": "torvalds",                       # public GitHub/GitLab/HN handle
    "name": "Alan Turing",                        # historic public figure
    "phone": "+442071234567",                     # parsed locally, never sent anywhere
    "bitcoin": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # BIP-173 test vector
    "ethereum": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",  # well-known public address
}

WIDTHS = (22, 12, 7, 30)


def row(source_id: str, status: str, elapsed: str, detail: str) -> str:
    return f"  {source_id:<{WIDTHS[0]}} {status:<{WIDTHS[1]}} {elapsed:>{WIDTHS[2]}}  {detail[:WIDTHS[3]]}"


def annotate(level: str, title: str, message: str) -> None:
    """Emit a GitHub Actions annotation (readable through the API without raw logs)."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    safe_title = title.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    safe_message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} title={safe_title}::{safe_message}")


def probe_sources(timeout_per_source: float) -> int:
    from app.config import SETTINGS
    from app.http_client import DEFAULT_FETCHER
    from app.identifiers import detect
    from app.sources import registry
    from app.sources.base import SourceContext, execute

    specs = sorted(registry().values(), key=lambda spec: (spec.category, spec.id))
    print(f"probing {len(specs)} source(s) in-process (per-source timeout "
          f"{SETTINGS.limits.per_source_timeout:.0f}s)\n")
    counts: dict[str, int] = {}
    crashed: list[str] = []
    checked: list[str] = []
    grouped: dict[str, list[str]] = {"answered": [], "not-answered": [], "crashed": []}

    for spec in specs:
        kind = spec.applies_to[0] if spec.applies_to else "domain"
        identifier = detect(PROBES.get(kind, PROBES["domain"]), forced_type=kind)
        context = SourceContext(identifier=identifier, keys={}, mode="osint", fetcher=DEFAULT_FETCHER)
        started = time.monotonic()
        try:
            result = execute(spec, context)
        except Exception as exc:  # noqa: BLE001 - a crash here is exactly what we want to see
            result = None
            print(row(spec.id, "CRASH", f"{(time.monotonic() - started) * 1000:.0f}ms",
                      f"{type(exc).__name__}: {exc}"))
            annotate("error", f"{spec.id} CRASHED", f"{type(exc).__name__}: {exc}")
            crashed.append(spec.id)
            continue
        elapsed = f"{result.elapsed_ms:.0f}ms"
        counts[result.status] = counts.get(result.status, 0) + 1
        detail = result.message.replace("\n", " ")
        if result.status == "error":
            crashed.append(spec.id)
        if result.status in ("ok", "no_match"):
            checked.append(spec.id)
        print(row(spec.id, result.status, elapsed, detail))
        bucket = ("answered" if result.status in ("ok", "no_match")
                  else ("crashed" if result.status == "error" else "not-answered"))
        grouped[bucket].append(f"{spec.id}={result.status}")
        if not timeout_per_source:
            continue

    print("\nstatus counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"sources that really answered (ok/no_match): {len(checked)}/{len(specs)}")
    # GitHub caps annotations per run, so report one aggregated annotation per class.
    annotate("notice", f"answered: {len(grouped['answered'])}/{len(specs)}",
             ", ".join(grouped["answered"]) or "none")
    annotate("warning", f"not answered: {len(grouped['not-answered'])}",
             ", ".join(grouped["not-answered"]) or "none")
    if grouped["crashed"]:
        annotate("error", f"crashed: {len(grouped['crashed'])}", ", ".join(grouped["crashed"]))
    if crashed:
        print(f"\nAPP BUGS - these sources crashed or returned 'error': {', '.join(crashed)}")
        return 1
    unavailable = [s for s in specs if s.id not in checked and s.id not in crashed]
    if unavailable:
        print("\nnot answered this run (upstream outage, rate limit, or needs your own key - "
              "not an app bug): " + ", ".join(s.id for s in unavailable))
    return 0


def _http(base_url: str, path: str, *, method: str = "GET", body: dict | None = None,
          timeout: float = 30.0) -> tuple[int, dict, bytes]:
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json", "User-Agent": "VerdigrisDeployProbe/1.0"}
    if data:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def probe_deployment(base_url: str, scan_identifier: str, wait_seconds: float) -> int:
    failures: list[str] = []
    notes: list[str] = []

    def check(label: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  ok    {label}" + (f" - {detail}" if detail else ""))
        else:
            print(f"  FAIL  {label}" + (f" - {detail}" if detail else ""))
            failures.append(label)

    print(f"probing deployment at {base_url}\n")

    status, headers, payload = _http(base_url, "/health")
    health = {}
    try:
        health = json.loads(payload.decode())
    except (ValueError, UnicodeDecodeError):
        pass
    check("GET /health returns 200 JSON", status == 200 and health.get("status") == "ok",
          f"status={status} app={health.get('app')} sources={health.get('sources_total')}")
    if health.get("auth_required"):
        notes.append("ACCESS_TOKEN is set on this deployment: API calls need the token, "
                     "so the scan round-trip below will fail unless you pass --access-token.")

    for path, fragment in (("/", "Verdigris"), ("/styles.css", "teal"), ("/app.js", "fetch"),
                           ("/favicon.svg", "svg"), ("/manifest.webmanifest", "name"),
                           ("/robots.txt", "User-agent")):
        status, headers, payload = _http(base_url, path)
        text = payload.decode("utf-8", "replace")
        check(f"GET {path}", status == 200 and bool(text.strip()),
              f"{status} {len(payload)} bytes" + ("" if fragment.lower() in text.lower()
                                                  else f" (warning: '{fragment}' not found)"))

    status, _, payload = _http(base_url, "/api/meta")
    meta = json.loads(payload.decode()) if status == 200 else {}
    check("GET /api/meta lists the source catalogue",
          status == 200 and len(meta.get("sources", [])) >= 20, f"{len(meta.get('sources', []))} sources")

    quoted = urllib.parse.quote(scan_identifier)
    status, _, payload = _http(base_url, f"/api/detect?identifier={quoted}")
    detected = json.loads(payload.decode()) if status == 200 else {}
    check(f"GET /api/detect?identifier={scan_identifier}",
          status == 200 and detected.get("ok") is True,
          f"type={detected.get('identifier', {}).get('type')}")

    status, _, payload = _http(base_url, f"/api/detect?identifier={urllib.parse.quote('!!nonsense!!')}")
    check("GET /api/detect rejects garbage", status in (400, 422), f"status={status}")

    if not health.get("auth_required"):
        status, _, payload = _http(base_url, "/api/scan", method="POST",
                                   body={"identifier": scan_identifier, "mode": "report"})
        accepted = json.loads(payload.decode()) if status in (200, 202) else {}
        check("POST /api/scan accepted", status in (200, 202) and accepted.get("scan_id"),
              f"status={status} scan_id={accepted.get('scan_id', '')[:12]}")
        scan_id = accepted.get("scan_id")
        if scan_id:
            deadline = time.time() + wait_seconds
            snapshot: dict = {}
            while time.time() < deadline:
                status, _, payload = _http(base_url, f"/api/scans/{scan_id}")
                snapshot = json.loads(payload.decode()) if status == 200 else {}
                if snapshot.get("state") in ("complete", "failed"):
                    break
                time.sleep(1.0)
            check("scan completed", snapshot.get("state") == "complete",
                  f"state={snapshot.get('state')}")
            sources = snapshot.get("sources", [])
            answered = [s for s in sources if s.get("status") in ("ok", "no_match")]
            statuses = {}
            for source in sources:
                statuses[source.get("status")] = statuses.get(source.get("status"), 0) + 1
            check("sources reported statuses", bool(sources),
                  f"{len(sources)} planned, {len(answered)} answered: "
                  + ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())))
            coverage = snapshot.get("coverage") or {}
            check("coverage block present", bool(coverage),
                  f"with_data={coverage.get('sources_with_data')} not_checked={coverage.get('sources_not_checked')} "
                  f"unavailable={coverage.get('sources_unavailable')}")
            summary = snapshot.get("summary") or {}
            check("report summary present and labelled as rules",
                  summary.get("engine") == "deterministic-rules-v1",
                  f"confidence={summary.get('data_confidence')}")
            if not answered:
                notes.append("No source answered from this deployment. On a free host this usually means "
                             "outbound calls are blocked or every upstream rate-limited the shared IP; "
                             "check the Render logs. The UI must show 'Insufficient data' in that case, "
                             "never a clean bill of health.")

        status, _, payload = _http(base_url, "/api/password-range", method="POST",
                                   body={"prefix": "5BAA6"})
        try:
            ranges = json.loads(payload.decode())
        except ValueError:
            ranges = {}
        check("POST /api/password-range (k-anonymity, no key needed)",
              status == 200 and ranges.get("entry_count", 0) > 0,
              f"status={status} entries={ranges.get('entry_count')}")
        status, _, payload = _http(base_url, "/api/password-range", method="POST",
                                   body={"prefix": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"})
        check("a full SHA-1 hash is refused (only 5-char prefixes are proxied)",
              status == 400, f"status={status}")
    else:
        notes.append("Skipped the scan and password-range checks because ACCESS_TOKEN is set.")

    status, headers, _ = _http(base_url, "/../Dockerfile")
    check("path traversal refused", status in (400, 404), f"status={status}")
    check("security headers present",
          headers.get("X-Content-Type-Options") == "nosniff" or "Content-Security-Policy" in headers,
          f"CSP={'yes' if 'Content-Security-Policy' in headers else 'no'}")

    for failure in failures:
        annotate("error", "deployment check failed", failure)
    if notes:
        print("\nnotes:")
        for note in notes:
            print(f"  - {note}")
    print(f"\n{len(failures)} failure(s)")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", help="probe a deployed instance instead of the upstreams")
    parser.add_argument("--identifier", default=PROBES["domain"],
                        help="identifier for the deployment scan round-trip (default example.com)")
    parser.add_argument("--wait", type=float, default=120.0, help="seconds to wait for a scan")
    parser.add_argument("--per-source-timeout", type=float, default=0.0,
                        help="unused placeholder kept for CI compatibility")
    args = parser.parse_args(argv)

    if args.base_url:
        return probe_deployment(args.base_url, args.identifier, args.wait)
    return probe_sources(args.per_source_timeout)


if __name__ == "__main__":
    raise SystemExit(main())
