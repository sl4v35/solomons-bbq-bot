"""Source framework: statuses, findings, registry and error mapping.

Every source returns one of five explicit statuses so the UI can always tell
the difference between *"we looked and found nothing"*, *"we deliberately did
not look"* and *"we tried and the source failed"*:

``ok``            the source answered and produced data/findings
``no_match``      the source answered successfully but had nothing on this identifier
``not_checked``   skipped on purpose (not applicable, or needs a key the user did not supply)
``unavailable``   the source could not be reached / refused / returned something unusable
``rate_limited``  the source told us to slow down (a specific flavour of "unavailable")
"""

from __future__ import annotations

import html
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..http_client import (
    UpstreamBlocked,
    UpstreamError,
    UpstreamHTTPError,
    UpstreamParseError,
    UpstreamRateLimited,
    UpstreamTimeout,
    UpstreamTooLarge,
)

STATUS_OK = "ok"
STATUS_NO_MATCH = "no_match"
STATUS_NOT_CHECKED = "not_checked"
STATUS_UNAVAILABLE = "unavailable"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_ERROR = "error"
STATUS_PENDING = "pending"  # in-flight placeholder used while a scan runs

ALL_STATUSES = (
    STATUS_OK,
    STATUS_NO_MATCH,
    STATUS_NOT_CHECKED,
    STATUS_UNAVAILABLE,
    STATUS_RATE_LIMITED,
    STATUS_ERROR,
)

STATUS_LABELS = {
    STATUS_OK: "Data returned",
    STATUS_NO_MATCH: "No matches",
    STATUS_NOT_CHECKED: "Not checked",
    STATUS_UNAVAILABLE: "Source unavailable",
    STATUS_RATE_LIMITED: "Rate limited",
    STATUS_ERROR: "Source error",
    STATUS_PENDING: "Checking…",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITIES = tuple(SEVERITY_ORDER)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# Only real HTML markup is stripped: a tag name must start with an ASCII letter and
# any attributes must follow whitespace.  "<torvalds@linux-foundation.org>", "vector<T>"
# and source-code lines therefore survive, which matters because findings quote them.
_HTML_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9]*(?:\s[^<>]*)?/?>")


def clean_html(value: Any, limit: int = 400) -> str:
    """Strip markup from an upstream HTML field (bios, search snippets, descriptions)."""
    if value is None:
        return ""
    text = _HTML_TAG_RE.sub(" ", str(value))
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def plain_text(value: Any, limit: int = 400) -> str:
    """Normalise a plain-text upstream field WITHOUT touching angle brackets.

    Email display names, URLs, code lines and commit subjects frequently contain
    "<" and ">"; stripping them silently destroys evidence (and once produced a
    false "no matches" for an email address quoted as <a@b.c> in source code).
    """
    if value is None:
        return ""
    text = html.unescape(str(value))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _from_epoch(seconds: float) -> str | None:
    try:
        parsed = datetime.fromtimestamp(float(seconds), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_upstream_timestamp(value: Any) -> str | None:
    """Normalise a timestamp coming from an upstream API (best effort, honest)."""
    if value is None or value is False or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):  # epoch seconds (Keybase ctime, VirusTotal dates)
        return _from_epoch(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if re.fullmatch(r"-?\d{1,12}", text):  # epoch seconds delivered as a string
        return _from_epoch(int(text))
    if re.fullmatch(r"-?\d{13}", text):  # epoch milliseconds
        return _from_epoch(int(text) / 1000.0)
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y%m%d%H%M%S", "%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
            try:
                parsed = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Evidence:
    label: str
    value: str
    url: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"label": self.label, "value": self.value}
        if self.url:
            data["url"] = self.url
        return data


def Link(label: str, url: str) -> Evidence:  # noqa: N802 - reads like a constructor
    """Build a clickable source reference (label + absolute URL)."""
    return Evidence(label=label, value=url, url=url)


def normalise_link(item: Evidence) -> Evidence:
    """Guarantee the frontend contract: every link carries an absolute http(s) URL.

    Sources frequently build links as ``Evidence(label, url)``.  Promoting the value
    here keeps findings clickable without letting a non-URL string (or a hostile
    scheme such as ``javascript:``) become an href.
    """
    url = str(item.url or "").strip()
    value = str(item.value or "").strip()
    if not url.startswith(("https://", "http://")) and value.startswith(("https://", "http://")):
        url = value
    if not url.startswith(("https://", "http://")):
        url = ""
    return Evidence(label=item.label, value=item.value, url=url or None)


@dataclass
class Finding:
    source_id: str
    source_name: str
    title: str
    severity: str
    category: str
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    links: list[Evidence] = field(default_factory=list)
    observed_at: str | None = None
    interpretation: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    recorded_at: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            self.severity = "info"
        self.links = [normalise_link(link) for link in self.links if link]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "source_name": self.source_name,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "summary": self.summary,
            "evidence": [e.as_dict() for e in self.evidence],
            "links": [link.as_dict() for link in self.links],
            "observed_at": self.observed_at,
            "recorded_at": self.recorded_at,
            "interpretation": self.interpretation,
        }


@dataclass
class SourceResult:
    source_id: str
    source_name: str
    status: str
    message: str
    category: str = ""
    elapsed_ms: int = 0
    checked_at: str = field(default_factory=utcnow_iso)
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    sends: str = ""
    upstream_host: str = ""
    applies: bool = True
    hint: str = ""  # optional actionable hint (e.g. "add a key in Settings")

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "category": self.category,
            "status": self.status,
            "status_label": STATUS_LABELS.get(self.status, self.status),
            "message": self.message,
            "elapsed_ms": self.elapsed_ms,
            "checked_at": self.checked_at,
            "finding_count": len(self.findings),
            "findings": [f.as_dict() for f in self.findings],
            "data": self.data,
            "sends": self.sends,
            "upstream_host": self.upstream_host,
            "applies": self.applies,
            "hint": self.hint,
        }


@dataclass
class SourceContext:
    identifier: Any  # app.identifiers.Identifier
    keys: dict[str, str] = field(default_factory=dict)
    mode: str = "osint"
    fetcher: Any = None
    now: str = field(default_factory=utcnow_iso)

    def key(self, name: str) -> str:
        return (self.keys.get(name) or "").strip()


class SourceOutcome(Exception):
    """Raised by a source to finish with an explicit non-``ok`` status."""

    def __init__(self, status: str, message: str, *, data: dict[str, Any] | None = None,
                 hint: str = "", findings: list[Finding] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.data = data or {}
        self.hint = hint
        self.findings = findings or []


@dataclass(frozen=True)
class SourceSpec:
    id: str
    name: str
    category: str
    applies_to: tuple[str, ...]
    sends: str
    docs: str = ""
    key_name: str = ""  # settings key that unlocks this source (optional)
    runner: Callable[[SourceContext], dict[str, Any]] | None = None
    description: str = ""

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "applies_to": list(self.applies_to),
            "sends": self.sends,
            "docs": self.docs,
            "requires_key": self.key_name,
            "description": self.description,
        }


_REGISTRY: dict[str, SourceSpec] = {}
_ORDER: list[str] = []


def source(
    *,
    id: str,  # noqa: A002 - matches the JSON field name used by the UI
    name: str,
    category: str,
    applies_to: tuple[str, ...],
    sends: str,
    docs: str = "",
    key_name: str = "",
    description: str = "",
) -> Callable[[Callable[[SourceContext], dict[str, Any]]], Callable[[SourceContext], dict[str, Any]]]:
    """Register a source function.

    The wrapped function returns ``{"status": ..., "message": ..., "findings": [...], "data": {...}}``.
    Exceptions are mapped to honest, non-fake statuses by :func:`execute`.
    """

    def decorator(func: Callable[[SourceContext], dict[str, Any]]):
        spec = SourceSpec(
            id=id, name=name, category=category, applies_to=applies_to, sends=sends,
            docs=docs, key_name=key_name, runner=func, description=description,
        )
        if id in _REGISTRY:
            raise ValueError(f"duplicate source id {id}")
        _REGISTRY[id] = spec
        _ORDER.append(id)
        func.source_id = id  # type: ignore[attr-defined]
        return func

    return decorator


def registry() -> dict[str, SourceSpec]:
    return dict(_REGISTRY)


def source_order() -> list[str]:
    return list(_ORDER)


def specs_for(kind: str) -> list[SourceSpec]:
    return [_REGISTRY[sid] for sid in _ORDER if kind in _REGISTRY[sid].applies_to]


def execute(spec: SourceSpec, ctx: SourceContext) -> SourceResult:
    """Run one source and always return a :class:`SourceResult` (never raise)."""
    started = time.monotonic()
    host = ""
    try:
        outcome = (spec.runner or (lambda _ctx: {}))(ctx)
    except SourceOutcome as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=exc.status, message=exc.message, data=exc.data, hint=exc.hint,
            findings=exc.findings, elapsed_ms=int((time.monotonic() - started) * 1000),
            sends=spec.sends, upstream_host=host,
        )
    except UpstreamRateLimited as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_RATE_LIMITED, message=f"{exc.message}. Try again in a minute.",
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
            hint="This source is rate limiting the app's shared IP address.",
        )
    except UpstreamTimeout as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_UNAVAILABLE, message=str(exc),
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )
    except UpstreamHTTPError as exc:
        message = str(exc)
        if exc.status in (401, 403):
            message = (
                f"Upstream refused the request (HTTP {exc.status})."
                + (" Check the API key in Settings." if spec.key_name else
                   " This source may now require authentication.")
            )
        elif exc.status == 404:
            message = "Upstream returned HTTP 404 (no record / endpoint not found)."
        elif exc.status and exc.status >= 500:
            message = f"Upstream server error (HTTP {exc.status})."
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_UNAVAILABLE, message=message,
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )
    except UpstreamTooLarge as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_UNAVAILABLE, message=f"Upstream response was too large and was cut off ({exc}).",
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )
    except UpstreamParseError as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_UNAVAILABLE, message=f"Could not parse the response ({exc}).",
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )
    except UpstreamBlocked as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_UNAVAILABLE, message=f"Request blocked by the app's own safety rules: {exc}",
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )
    except UpstreamError as exc:
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_UNAVAILABLE, message=str(exc),
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )
    except Exception as exc:  # pragma: no cover - defensive
        detail = ""
        if os.environ.get("SOURCE_DEBUG", "").strip().lower() in {"1", "true", "yes"}:
            # Opt-in only: exception text can contain the identifier being looked up,
            # and this app deliberately keeps identifiers out of server-side logs.
            detail = f": {str(exc)[:200]}"
        return SourceResult(
            source_id=spec.id, source_name=spec.name, category=spec.category,
            status=STATUS_ERROR,
            message=f"Unexpected error while processing this source ({type(exc).__name__}{detail}).",
            elapsed_ms=int((time.monotonic() - started) * 1000), sends=spec.sends,
        )

    elapsed = int((time.monotonic() - started) * 1000)
    status = outcome.get("status") or STATUS_OK
    if status not in ALL_STATUSES:
        status = STATUS_ERROR
    findings = outcome.get("findings") or []
    for finding in findings:
        if not finding.source_id:
            finding.source_id = spec.id
        if not finding.source_name:
            finding.source_name = spec.name
    return SourceResult(
        source_id=spec.id, source_name=spec.name, category=spec.category,
        status=status, message=outcome.get("message", ""), data=outcome.get("data") or {},
        findings=findings, elapsed_ms=elapsed, sends=spec.sends,
        upstream_host=outcome.get("upstream_host", ""), hint=outcome.get("hint", ""),
    )


def skip(spec: SourceSpec, message: str, *, hint: str = "") -> SourceResult:
    """Build a ``not_checked`` result without running the source."""
    return SourceResult(
        source_id=spec.id, source_name=spec.name, category=spec.category,
        status=STATUS_NOT_CHECKED, message=message, hint=hint, sends=spec.sends, applies=False,
    )
