"""HTTP server: static UI + JSON API on a single origin.

Standard library only.  Binds ``0.0.0.0``, honours ``$PORT``, exposes
``/health`` and never logs identifiers, query strings, API keys or passwords.
"""

from __future__ import annotations

import json
import math
import os
import re
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from . import APP_NAME, APP_TAGLINE, APP_VERSION
from .config import SETTINGS, Limits
from .http_client import CACHE, UpstreamError
from .identifiers import IDENTIFIER_TYPES, IdentifierError, detect
from .jobs import STORE, CapacityError
from .passwords import PasswordCheckError, fetch_range
from .sources import public_catalogue
from .sources.base import STATUS_LABELS, SEVERITIES, utcnow_iso

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".txt": "text/plain; charset=utf-8",
    ".webmanifest": "application/manifest+json",
}
STATIC_FILES = ("index.html", "styles.css", "app.js", "favicon.svg", "manifest.webmanifest", "robots.txt")
START_TIME = time.time()

# Identifier characters accepted by the API.  Anything else is rejected before
# a request is even parsed as an identifier, which keeps control characters and
# oversized payloads away from upstream queries.
SAFE_IDENTIFIER_RE = re.compile(r"^[\w@.+:/?=&%~,'\- ()]{1,300}$", re.UNICODE)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "manifest-src 'self'"
    ),
}


# ---------------------------------------------------------------------------
# Rate limiting (per client IP, token bucket)
# ---------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, max_buckets: int = 4096) -> None:
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, updated_at)
        self._lock = threading.Lock()
        self.max_buckets = max_buckets

    def reset(self) -> None:
        """Forget every bucket (used by tests and by an operator restarting cleanly)."""
        with self._lock:
            self._buckets.clear()

    def allow(self, key: str, rate_per_min: float, burst: float | None = None) -> tuple[bool, float]:
        capacity = burst if burst is not None else max(1.0, rate_per_min)
        refill = rate_per_min / 60.0
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > self.max_buckets:
                # Drop the oldest half rather than growing without bound.
                for stale in sorted(self._buckets, key=lambda k: self._buckets[k][1])[: self.max_buckets // 2]:
                    self._buckets.pop(stale, None)
            tokens, updated = self._buckets.get(key, (capacity, now))
            tokens = min(capacity, tokens + (now - updated) * refill)
            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[key] = (tokens, now)
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, max(1.0, (1.0 - tokens) / refill)


LIMITER = RateLimiter()


def client_ip(handler: "RequestHandler") -> str:
    peer = handler.client_address[0] if handler.client_address else "unknown"
    if SETTINGS.trust_proxy_headers:
        forwarded = handler.headers.get("X-Forwarded-For")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
        real_ip = handler.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
    return peer


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class RequestHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{APP_VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # A public deployment with no authentication will attract clients that open a
    # connection and then send nothing. Bound how long one request may hold a
    # worker thread; the socket timeout applies to reads and writes alike.
    timeout = 60

    # Refusing a body we are not going to read is only half the job: see
    # _drain_body() below.
    MAX_DRAIN_BYTES = 8 * 1024 * 1024

    def _drain_body(self, length: int) -> None:
        """Read and discard a request body we are about to refuse.

        Replying ``400`` while the client is still writing the body makes
        well-behaved clients die with a broken pipe instead of reading the error
        we sent (this reproduced as a test failure on Python 3.12 and would hit a
        real browser just the same). The declared body is therefore drained
        first, bounded so a hostile Content-Length cannot make us read forever.
        """
        remaining = max(0, min(length, self.MAX_DRAIN_BYTES))
        while remaining > 0:
            try:
                chunk = self.rfile.read(min(65536, remaining))
            except (BrokenPipeError, ConnectionResetError, socket.timeout, TimeoutError, OSError):
                return  # the client gave up; nothing left to drain
            if not chunk:
                return
            remaining -= len(chunk)

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if not SETTINGS.request_log:
            return
        # Never log query strings: identifiers can be personal data.
        path = urlsplit(self.path).path
        sys.stderr.write("%s - %s %s\n" % (self.log_date_time_string(), self.command, path))

    def _safe_path(self) -> str:
        return urlsplit(self.path).path or "/"

    def _send(self, status: int, body: bytes, content_type: str, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):  # pragma: no cover
                pass

    def send_json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8",
                   {**(extra_headers or {}), "Cache-Control": "no-store"})

    def send_error_json(self, status: int, code: str, message: str, **extra: Any) -> None:
        headers: dict[str, str] = {}
        retry_after = extra.get("retry_after_seconds")
        if retry_after and status in (429, 503):
            # Proxies and well-behaved clients read the header, the UI reads the JSON.
            headers["Retry-After"] = str(max(1, int(math.ceil(float(retry_after)))))
        self.send_json(status, {"error": {"code": code, "message": message, **extra}}, headers or None)

    def read_json_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length") or "0"
        try:
            length = int(raw_length)
        except ValueError:
            raise ValueError("Invalid Content-Length header")
        if length <= 0:
            return {}
        if length > SETTINGS.limits.max_body_bytes:
            self._drain_body(length)
            raise ValueError(f"Request body too large (limit {SETTINGS.limits.max_body_bytes} bytes)")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    # -- auth & rate limiting ----------------------------------------------
    def _authorized(self) -> bool:
        if not SETTINGS.access_token:
            return True
        provided = self.headers.get("X-Access-Token") or ""
        if not provided:
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                provided = auth.split(" ", 1)[1].strip()
        if provided and provided == SETTINGS.access_token:
            return True
        self.send_error_json(
            401, "access_token_required",
            "This deployment requires an access token (the operator set ACCESS_TOKEN). "
            "Enter it in Settings and try again.",
        )
        return False

    def _rate_limited(self, bucket: str, rate_per_min: float, burst: float | None = None) -> bool:
        ip = client_ip(self)
        allowed, retry_after = LIMITER.allow(f"{bucket}:{ip}", rate_per_min, burst=burst)
        if allowed:
            return False
        self.send_error_json(
            429, "rate_limited",
            "Too many requests from your address. This limit protects the free upstream APIs this app uses.",
            retry_after_seconds=round(retry_after, 1),
        )
        return True

    # -- routing ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"", "text/plain; charset=utf-8", {"Allow": "GET, POST, HEAD, OPTIONS"})

    def _handle(self, method: str) -> None:
        split = urlsplit(self.path)
        path = split.path or "/"
        query = parse_qs(split.query, keep_blank_values=True)
        try:
            if path in ("/health", "/healthz", "/live"):
                return self.route_health()
            if path.startswith("/api/"):
                if method == "OPTIONS":
                    return self._send(204, b"", "text/plain; charset=utf-8")
                if not self._authorized():
                    return
                return self.route_api(method, path, query)
            if method == "POST":
                return self.send_error_json(405, "method_not_allowed", "Use GET for this path.")
            return self.route_static(path)
        except BrokenPipeError:  # pragma: no cover
            return
        except Exception as exc:  # pragma: no cover - defensive
            sys.stderr.write(f"internal error on {method} {path}: {type(exc).__name__}: {exc}\n")
            try:
                self.send_error_json(500, "internal_error",
                                     "The server hit an unexpected error. Nothing about your query was stored.")
            except Exception:
                pass
        finally:
            if path.startswith("/api/") and SETTINGS.request_log:
                sys.stderr.write(f"api {method} {path} done\n")

    # -- /health ------------------------------------------------------------
    def route_health(self) -> None:
        catalogue = public_catalogue()
        payload = {
            "status": "ok",
            "app": APP_NAME,
            "version": APP_VERSION,
            "uptime_seconds": round(time.time() - START_TIME, 1),
            "time": utcnow_iso(),
            "sources_total": len(catalogue),
            "sources_disabled": sorted(SETTINGS.disabled_sources),
            "cache": CACHE.stats(),
            "jobs": STORE.stats(),
            "auth_required": bool(SETTINGS.access_token),
            "optional_keys_configured": {
                "hibp": bool(SETTINGS.hibp_api_key),
                "virustotal": bool(SETTINGS.virustotal_api_key),
                "abusech": bool(SETTINGS.abusech_auth_key),
                "github": bool(SETTINGS.github_token),
            },
        }
        self.send_json(200, payload)

    # -- API ----------------------------------------------------------------
    def route_api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        limits = SETTINGS.limits

        if path == "/api/meta":
            return self.send_json(200, {
                "app": APP_NAME, "tagline": APP_TAGLINE, "version": APP_VERSION,
                "identifier_types": list(IDENTIFIER_TYPES),
                "status_labels": STATUS_LABELS, "severities": list(SEVERITIES),
                "sources": public_catalogue(),
                "limits": {
                    "scan_rate_per_minute": limits.rate_scan_per_min,
                    "api_rate_per_minute": limits.rate_api_per_min,
                    "password_checks_per_minute": limits.rate_password_per_min,
                    "scan_deadline_seconds": limits.scan_total_timeout,
                    "max_identifier_length": limits.max_identifier_len,
                },
                "auth_required": bool(SETTINGS.access_token),
                "optional_keys": [
                    {"key": "hibp", "label": "Have I Been Pwned API key (paid)",
                     "unlocks": "Email breach and paste lookups via HIBP API v3. The entry tier is about "
                                "US$3.95/month and allows ~10 authenticated requests per minute; the "
                                "password-exposure check stays free and keyless either way.",
                     "where": "https://haveibeenpwned.com/API/Key"},
                    {"key": "virustotal", "label": "VirusTotal API key", "unlocks": "Vendor detection counts for domains",
                     "where": "https://www.virustotal.com/gui/user/<you>/apikey"},
                    {"key": "abusech", "label": "abuse.ch Auth-Key", "unlocks": "URLhaus host API (full history, not just the recent feed)",
                     "where": "https://auth.abuse.ch/"},
                    {"key": "github", "label": "GitHub token (optional)", "unlocks": "Higher GitHub API rate limits",
                     "where": "https://github.com/settings/tokens"},
                    {"key": "urlscan", "label": "urlscan.io API key (optional)", "unlocks": "Search works without it; a key only raises limits",
                     "where": "https://urlscan.io/user/profile/"},
                    {"key": "otx", "label": "AlienVault OTX key (optional)", "unlocks": "Search works without it",
                     "where": "https://otx.alienvault.com/settings"},
                ],
                "disclaimer": (
                    f"{APP_NAME} is an independent, unofficial project. It is not affiliated with, endorsed by, or "
                    "connected to Serus (serus.ai) or its operators."
                ),
                "no_authentication_warning": (
                    "This deployment has no user authentication: anyone who knows the URL can run scans through it. "
                    "Scans are performed from the server's IP address, so third-party APIs see the server, not you."
                ),
            })

        if path == "/api/sources":
            return self.send_json(200, {"sources": public_catalogue()})

        if path == "/api/detect":
            if self._rate_limited("api", limits.rate_api_per_min):
                return
            identifier_text = (query.get("identifier") or [""])[0]
            forced = (query.get("type") or ["auto"])[0]
            try:
                identifier = detect(identifier_text, forced_type=forced)
            except IdentifierError as exc:
                return self.send_json(422, {"ok": False, "error": str(exc)})
            return self.send_json(200, {"ok": True, "identifier": identifier.as_dict()})

        if path == "/api/scan":
            if self._rate_limited("scan", limits.rate_scan_per_min, burst=max(2.0, limits.rate_scan_per_min / 3)):
                return
            if method == "POST":
                try:
                    body = self.read_json_body()
                except json.JSONDecodeError:  # subclass of ValueError - must come first
                    return self.send_error_json(400, "bad_json", "Request body must be valid JSON.")
                except ValueError as exc:
                    return self.send_error_json(400, "bad_request", str(exc))
                identifier_text = str(body.get("identifier") or "")
                forced = str(body.get("type") or "auto")
                mode = str(body.get("mode") or "osint")
                keys = body.get("keys") if isinstance(body.get("keys"), dict) else {}
            else:
                identifier_text = (query.get("identifier") or [""])[0]
                forced = (query.get("type") or ["auto"])[0]
                mode = (query.get("mode") or ["osint"])[0]
                keys = {}
            mode = mode.strip().lower()
            if mode not in ("osint", "report"):
                return self.send_error_json(400, "bad_mode", "Mode must be 'osint' or 'report'.")
            if not identifier_text or not SAFE_IDENTIFIER_RE.match(identifier_text):
                return self.send_error_json(
                    400, "bad_identifier",
                    "Enter an identifier of up to 300 characters using letters, digits and common punctuation.",
                )
            try:
                identifier = detect(identifier_text, forced_type=forced)
            except IdentifierError as exc:
                return self.send_json(422, {"ok": False, "error": str(exc),
                                            "hint": "Pick the identifier type manually if auto-detection disagrees."})
            keys = _sanitise_keys(keys)
            try:
                job = STORE.create(identifier, mode, keys)
            except CapacityError as exc:
                return self.send_error_json(503, "server_busy", str(exc), retry_after_seconds=10)
            return self.send_json(202, {
                "scan_id": job.id, "state": job.state, "mode": job.mode,
                "identifier": job.identifier.as_dict(), "poll": f"/api/scans/{job.id}",
            })

        match = re.fullmatch(r"/api/scans/([a-f0-9]{8,32})", path)
        if match:
            if self._rate_limited("api", limits.rate_api_per_min * 4):
                return
            job = STORE.get(match.group(1))
            if job is None:
                return self.send_error_json(
                    404, "scan_not_found",
                    "This scan is no longer in memory. Results are kept for "
                    f"{SETTINGS.limits.job_ttl_seconds // 60} minutes after they finish; re-run the lookup.",
                )
            since = (query.get("since") or [""])[0]
            snapshot = STORE.snapshot(job)
            if since.isdigit() and int(since) == snapshot["version"]:
                return self.send_json(200, {"scan_id": job.id, "state": job.state,
                                            "version": snapshot["version"], "unchanged": True})
            return self.send_json(200, snapshot)

        if path == "/api/password-range":
            if self._rate_limited("password", limits.rate_password_per_min, burst=3.0):
                return
            if method == "POST":
                try:
                    body = self.read_json_body()
                except json.JSONDecodeError:  # subclass of ValueError - must come first
                    return self.send_error_json(400, "bad_json", "Request body must be valid JSON.")
                except ValueError as exc:
                    return self.send_error_json(400, "bad_request", str(exc))
                prefix = str(body.get("prefix") or "")
            else:
                prefix = (query.get("prefix") or [""])[0]
            try:
                result = fetch_range(prefix, STORE.fetcher)
            except PasswordCheckError as exc:
                return self.send_error_json(400, "bad_prefix", str(exc))
            except UpstreamError as exc:
                return self.send_error_json(
                    502, "upstream_unavailable",
                    f"Could not reach the HIBP k-anonymity API ({exc.message}). Nothing was stored.",
                )
            return self.send_json(200, result)

        return self.send_error_json(404, "not_found", f"No API route at {path}.")

    # -- static -------------------------------------------------------------
    def route_static(self, path: str) -> None:
        if path in ("/", "/index.html"):
            name = "index.html"
        else:
            name = path.lstrip("/")
            if name.endswith("/"):
                name += "index.html"
        if name not in STATIC_FILES:
            return self.send_error_json(404, "not_found", f"No route at {path}.")
        full_path = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(full_path):
            return self.send_error_json(500, "asset_missing", f"Bundled asset '{name}' is missing from the image.")
        try:
            stat = os.stat(full_path)
            if stat.st_size > SETTINGS.limits.max_static_bytes:
                return self.send_error_json(500, "asset_too_large", "Bundled asset is too large to serve.")
            with open(full_path, "rb") as handle:
                body = handle.read()
        except OSError:
            return self.send_error_json(500, "asset_unreadable", f"Could not read '{name}'.")
        content_type = CONTENT_TYPES.get(os.path.splitext(name)[1], "application/octet-stream")
        etag = 'W/"%d-%d"' % (stat.st_size, int(stat.st_mtime))
        if self.headers.get("If-None-Match") == etag:
            self._send(304, b"", content_type, {"ETag": etag})
            return
        cache_control = "no-cache" if name == "index.html" else "public, max-age=300"
        self._send(200, body, content_type, {"ETag": etag, "Cache-Control": cache_control})


def _sanitise_keys(raw: Any) -> dict[str, str]:
    """Keep only known key names, trimmed and length-capped.  Never logged."""
    allowed = {"hibp", "virustotal", "abusech", "github", "urlscan", "otx"}
    out: dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        name = str(key).strip().lower()
        if name not in allowed or not isinstance(value, str):
            continue
        value = value.strip()
        if value and len(value) <= 200:
            out[name] = value
    return out


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def handle_error(self, request, client_address):  # pragma: no cover
        exc_type = sys.exc_info()[0]
        if exc_type in (BrokenPipeError, ConnectionResetError, socket.timeout, TimeoutError):
            return
        sys.stderr.write(
            f"error handling request from {client_address[0] if client_address else '?'}: "
            f"{getattr(exc_type, '__name__', exc_type)}\n"
        )


def serve(host: str | None = None, port: int | None = None) -> Server:
    host = host or SETTINGS.host
    port = port if port is not None else SETTINGS.port
    httpd = Server((host, port), RequestHandler)
    return httpd


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    host = SETTINGS.host
    port = SETTINGS.port
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    if "--host" in argv:
        host = argv[argv.index("--host") + 1]
    httpd = serve(host, port)

    def shutdown(signum: int, _frame: Any) -> None:
        sys.stderr.write(f"received signal {signum}, shutting down\n")
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, shutdown)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            pass

    sys.stderr.write(
        f"{APP_NAME} {APP_VERSION} listening on http://{host}:{port} "
        f"(health: /health, API: /api/meta, auth: {'required' if SETTINGS.access_token else 'none'})\n"
    )
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
