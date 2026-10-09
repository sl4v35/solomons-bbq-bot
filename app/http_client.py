"""Safe outbound HTTP client.

Design rules enforced here (and nowhere else, so they cannot be bypassed):

* every URL must use ``https`` and its host must appear in the fixed allowlist
  in :mod:`app.config` -- there is no way for a request to name an arbitrary
  host, and the app exposes no "fetch this URL" endpoint;
* the resolved IP addresses must be public (no loopback / private / link-local /
  reserved ranges), which blocks SSRF and metadata-endpoint tricks;
* redirects are only followed to allowlisted hosts, except for the RDAP
  bootstrap where an explicit, documented exception follows https redirects
  after the same public-IP check;
* every request has a timeout and a hard response-size cap;
* responses may be cached in a bounded TTL cache; authenticated responses are
  never cached.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .config import (
    ALLOWED_HOSTS,
    RDAP_BOOTSTRAP_ANY_HTTPS,
    SETTINGS,
    USER_AGENT,
)


class UpstreamError(Exception):
    """Base class for upstream failures. ``kind`` is shown to the user."""

    kind = "unavailable"

    def __init__(self, message: str, *, kind: str | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind or self.__class__.kind
        self.status = status


class UpstreamBlocked(UpstreamError):
    kind = "blocked"


class UpstreamTimeout(UpstreamError):
    kind = "timeout"


class UpstreamHTTPError(UpstreamError):
    kind = "http-error"


class UpstreamRateLimited(UpstreamError):
    kind = "rate-limited"


class UpstreamTooLarge(UpstreamError):
    kind = "too-large"


class UpstreamParseError(UpstreamError):
    kind = "parse-error"


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    final_url: str
    elapsed_ms: int
    content_type: str = ""

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError) as exc:  # pragma: no cover - defensive
            raise UpstreamParseError(f"upstream returned invalid JSON ({exc})") from exc

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Bounded TTL cache
# ---------------------------------------------------------------------------


class TTLCache:
    """Thread-safe, insertion-ordered TTL cache with a hard entry cap."""

    def __init__(self, max_entries: int = 400, default_ttl: float = 600.0) -> None:
        self.max_entries = max(1, max_entries)
        self.default_ttl = default_ttl
        self._data: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                self.misses += 1
                return None
            expires_at, value = item
            if expires_at < now:
                self._data.pop(key, None)
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        ttl = self.default_ttl if ttl is None else ttl
        with self._lock:
            self._data[key] = (time.time() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"entries": len(self._data), "hits": self.hits, "misses": self.misses}


CACHE = TTLCache(SETTINGS.limits.cache_max_entries, SETTINGS.limits.cache_default_ttl)


# ---------------------------------------------------------------------------
# Host / IP validation
# ---------------------------------------------------------------------------


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
        return False
    if ip.is_multicast or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and (ip.is_site_local or ip.ipv4_mapped is not None):
        # Reject IPv6 that maps onto an IPv4 private/loopback address.
        mapped = ip.ipv4_mapped
        if mapped is not None and not _is_public_ip(str(mapped)):
            return False
    return getattr(ip, "is_global", True)


def validate_url(url: str, *, bootstrap_redirect: bool = False) -> urllib.parse.ParseResult:
    """Validate an outbound URL against the fixed allowlist."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise UpstreamBlocked(f"refusing non-https URL ({parsed.scheme or 'none'})")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise UpstreamBlocked("URL has no host")
    if parsed.port not in (None, 443):
        raise UpstreamBlocked(f"refusing port {parsed.port}")
    if host not in ALLOWED_HOSTS:
        if not (bootstrap_redirect and RDAP_BOOTSTRAP_ANY_HTTPS):
            raise UpstreamBlocked(f"host '{host}' is not in the upstream allowlist")
    return parsed


def assert_public_resolution(host: str, port: int = 443) -> list[str]:
    """Resolve ``host`` and require at least one public IP (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UpstreamBlocked(f"cannot resolve upstream host ({exc.strerror or 'nxdomain'})") from exc
    ips: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        if ip_str and _is_public_ip(ip_str.split("%")[0]):
            ips.append(ip_str)
    if not ips:
        raise UpstreamBlocked("upstream host resolves only to private/reserved addresses")
    return ips


# ---------------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------------


class _RedirectPolicy(urllib.request.HTTPRedirectHandler):
    def __init__(self, *, bootstrap_redirect: bool, max_redirects: int) -> None:
        self.bootstrap_redirect = bootstrap_redirect
        self.max_redirects = max_redirects
        self.hops = 0
        self.final_hosts: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        self.hops += 1
        if self.hops > self.max_redirects:
            raise UpstreamBlocked("too many redirects from upstream")
        newurl = urllib.parse.urljoin(req.full_url, newurl)
        parsed = urllib.parse.urlsplit(newurl)
        host = (parsed.hostname or "").lower()
        self.final_hosts.append(host)
        if parsed.scheme != "https":
            raise UpstreamBlocked(f"upstream redirected to non-https URL ({parsed.scheme})")
        if host not in ALLOWED_HOSTS:
            if not (self.bootstrap_redirect and RDAP_BOOTSTRAP_ANY_HTTPS):
                raise UpstreamBlocked(f"upstream redirected to non-allowlisted host '{host}'")
            assert_public_resolution(host, parsed.port or 443)
        return urllib.request.Request(
            newurl,
            data=req.data,
            headers=dict(req.header_items()),
            method=req.get_method(),
        )


# ---------------------------------------------------------------------------
# Transport (swappable for tests)
# ---------------------------------------------------------------------------

Transport = Callable[..., Response]


class Fetcher:
    """Thin wrapper around urllib with allowlist, size and timeout enforcement."""

    def __init__(self, transport: Transport | None = None, cache: TTLCache | None = None) -> None:
        self._transport = transport
        self.cache = cache if cache is not None else CACHE
        self._ssl = ssl.create_default_context()

    # -- public API ---------------------------------------------------------
    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        bootstrap_redirect: bool = False,
        cache_key: str | None = None,
        cache_ttl: float | None = None,
    ) -> Response:
        limits = SETTINGS.limits
        timeout = limits.default_timeout if timeout is None else timeout
        max_bytes = limits.max_response_bytes if max_bytes is None else max_bytes
        authed = bool(headers and any(k.lower().startswith(("authorization", "x-api-key", "auth-key", "hibp-api-key", "x-key")) for k in headers))

        if cache_key and not authed:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        parsed = validate_url(url, bootstrap_redirect=bootstrap_redirect)
        if self._transport is not None:
            response = self._transport(
                url=url,
                method=method,
                headers=headers or {},
                body=body,
                timeout=timeout,
                max_bytes=max_bytes,
            )
        else:
            assert_public_resolution(parsed.hostname or "", parsed.port or 443)
            response = self._urlopen(
                url,
                method=method,
                headers=headers or {},
                body=body,
                timeout=timeout,
                max_bytes=max_bytes,
                bootstrap_redirect=bootstrap_redirect,
            )

        if cache_key and not authed and 200 <= response.status < 300:
            self.cache.set(cache_key, response, cache_ttl if cache_ttl is not None else limits.cache_default_ttl)
        return response

    # -- retry wrapper ------------------------------------------------------
    RETRYABLE_KINDS = frozenset({"unreachable", "network-error", "tls-error", "timeout"})

    def request_with_retry(
        self,
        url: str,
        *,
        attempts: int = 2,
        backoff: float = 0.4,
        **kwargs: Any,
    ) -> Response:
        """GET requests are idempotent here, so a single retry on transport-level
        failures is safe and materially improves results on flaky networks.

        HTTP status errors (4xx/5xx) are never retried: they are real answers.
        """
        last_error: UpstreamError | None = None
        for attempt in range(1, max(1, attempts) + 1):
            try:
                return self.request(url, **kwargs)
            except UpstreamError as exc:
                if exc.kind not in self.RETRYABLE_KINDS or attempt >= attempts:
                    raise
                last_error = exc
                time.sleep(backoff * attempt)
        raise last_error or UpstreamError("request failed")  # pragma: no cover

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        bootstrap_redirect: bool = False,
        cache_key: str | None = None,
        cache_ttl: float | None = None,
    ) -> Any:
        response = self.request_with_retry(
            url,
            headers={"Accept": "application/json", **(headers or {})},
            timeout=timeout,
            max_bytes=max_bytes,
            bootstrap_redirect=bootstrap_redirect,
            cache_key=cache_key,
            cache_ttl=cache_ttl,
        )
        if response.status == 429:
            raise UpstreamRateLimited("upstream rate limit reached")
        if response.status >= 400:
            raise UpstreamHTTPError(
                f"upstream returned HTTP {response.status}", status=response.status
            )
        return response.json()

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> Any:
        body = json.dumps(payload).encode("utf-8")
        response = self.request(
            url,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json", **(headers or {})},
            body=body,
            timeout=timeout,
            max_bytes=max_bytes,
        )
        if response.status == 429:
            raise UpstreamRateLimited("upstream rate limit reached")
        if response.status >= 400:
            raise UpstreamHTTPError(
                f"upstream returned HTTP {response.status}", status=response.status
            )
        return response.json()

    def post_form(
        self,
        url: str,
        fields: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
    ) -> Any:
        body = urllib.parse.urlencode(fields).encode("utf-8")
        response = self.request(
            url,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                **(headers or {}),
            },
            body=body,
            timeout=timeout,
            max_bytes=max_bytes,
        )
        if response.status == 429:
            raise UpstreamRateLimited("upstream rate limit reached (HTTP 429)")
        if response.status >= 400:
            raise UpstreamHTTPError(
                f"upstream returned HTTP {response.status}", status=response.status
            )
        return response.json()

    def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        bootstrap_redirect: bool = False,
        cache_key: str | None = None,
        cache_ttl: float | None = None,
    ) -> str:
        response = self.request_with_retry(
            url,
            headers=headers,
            timeout=timeout,
            max_bytes=max_bytes,
            bootstrap_redirect=bootstrap_redirect,
            cache_key=cache_key,
            cache_ttl=cache_ttl,
        )
        if response.status == 429:
            raise UpstreamRateLimited("upstream rate limit reached")
        if response.status >= 400:
            raise UpstreamHTTPError(
                f"upstream returned HTTP {response.status}", status=response.status
            )
        return response.text()

    # -- internals ----------------------------------------------------------
    def _urlopen(
        self,
        url: str,
        *,
        method: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        max_bytes: int,
        bootstrap_redirect: bool,
    ) -> Response:
        policy = _RedirectPolicy(
            bootstrap_redirect=bootstrap_redirect, max_redirects=SETTINGS.limits.max_redirects
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),  # deterministic: never inherit env proxies
            urllib.request.HTTPSHandler(context=self._ssl),
            policy,
        )
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en",
            "Connection": "close",
        }
        request_headers.update({k: v for k, v in headers.items() if v is not None})
        request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        started = time.monotonic()
        try:
            with opener.open(request, timeout=timeout) as raw:
                payload = _read_capped(raw, max_bytes)
                status = getattr(raw, "status", raw.getcode())
                content_type = raw.headers.get("Content-Type", "") if raw.headers else ""
                final_url = raw.geturl()
        except UpstreamError:
            raise
        except urllib.error.HTTPError as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            if exc.code == 429:
                raise UpstreamRateLimited(
                    "upstream rate limit reached (HTTP 429)", status=429
                ) from exc
            detail = ""
            try:
                detail = _read_capped(exc, 512).decode("utf-8", "replace").strip().replace("\n", " ")[:200]
            except Exception:  # pragma: no cover - best effort
                detail = ""
            raise UpstreamHTTPError(
                f"upstream returned HTTP {exc.code}" + (f": {detail}" if detail else ""),
                status=exc.code,
            ) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise UpstreamTimeout(f"upstream timed out after {timeout:g}s") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise UpstreamTimeout(f"upstream timed out after {timeout:g}s") from exc
            if isinstance(reason, ssl.SSLError):
                raise UpstreamError(f"TLS error contacting upstream: {reason}", kind="tls-error") from exc
            raise UpstreamError(
                f"cannot reach upstream ({getattr(reason, 'strerror', None) or reason})", kind="unreachable"
            ) from exc
        except (ssl.SSLError, OSError) as exc:
            raise UpstreamError(f"network error contacting upstream ({exc})", kind="network-error") from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return Response(
            status=int(status),
            body=payload,
            final_url=final_url,
            elapsed_ms=elapsed_ms,
            content_type=content_type,
        )


def _read_capped(stream: Any, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise UpstreamTooLarge(f"upstream response exceeded {max_bytes} bytes")
    return b"".join(chunks)


DEFAULT_FETCHER = Fetcher()


# ---------------------------------------------------------------------------
# Server-sent events helper (Sourcegraph public code search)
# ---------------------------------------------------------------------------


def parse_sse_events(text: str) -> Iterable[tuple[str, str]]:
    """Yield ``(event, data)`` pairs from a text/event-stream body.

    Handles multi-line ``data:`` fields and CRLF line endings.
    """
    event = "message"
    data_lines: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line
        if line == "":
            if data_lines:
                yield event, "\n".join(data_lines)
            event = "message"
            data_lines = []
            continue
        if line.startswith(":"):
            continue  # comment / keep-alive
        if ":" in line:
            field, _, value = line.partition(":")
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = line, ""
        if field == "event":
            event = value
        elif field == "data":
            data_lines.append(value)
    if data_lines:
        yield event, "\n".join(data_lines)
