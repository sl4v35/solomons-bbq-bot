"""Source registry.

Importing this package registers every source with the framework.  Add a new
module to the import list below and it becomes available to the scanner, the
``/api/sources`` endpoint and the UI's coverage panel.
"""

from __future__ import annotations

from typing import Any

from ..config import SETTINGS
from . import archives, blockchain, breaches, code_hosts, dns_registry, people, phone, threat_intel  # noqa: F401
from .base import (
    ALL_STATUSES,
    SEVERITIES,
    SEVERITY_ORDER,
    STATUS_LABELS,
    STATUS_NOT_CHECKED,
    SourceContext,
    SourceResult,
    SourceSpec,
    execute,
    registry,
    skip,
    source_order,
    specs_for,
)

__all__ = [
    "ALL_STATUSES", "SEVERITIES", "SEVERITY_ORDER", "STATUS_LABELS", "STATUS_NOT_CHECKED",
    "SourceContext", "SourceResult", "SourceSpec", "execute", "registry", "skip",
    "source_order", "specs_for", "plan_for", "public_catalogue",
]


def plan_for(kind: str, keys: dict[str, str] | None = None) -> list[tuple[SourceSpec, SourceResult | None]]:
    """Return ``(spec, pre-computed result or None)`` pairs for an identifier type.

    A non-``None`` result means the source is not going to run and the reason is
    already known (missing key, disabled by the operator).  Those are reported as
    ``not_checked`` -- never silently dropped.
    """
    keys = keys or {}
    plan: list[tuple[SourceSpec, SourceResult | None]] = []
    for spec in specs_for(kind):
        if spec.id in SETTINGS.disabled_sources:
            plan.append((spec, skip(spec, "Disabled by the operator of this deployment (DISABLED_SOURCES).")))
            continue
        if spec.key_name and not (keys.get(spec.key_name) or "").strip() and not _server_key(spec.key_name):
            plan.append((spec, skip(
                spec,
                f"Not checked: this source needs your own {spec.key_name} API key, which was not supplied.",
                hint=f"Settings → {_key_label(spec.key_name)}",
            )))
            continue
        plan.append((spec, None))
    return plan


def _server_key(name: str) -> str:
    return {
        "hibp": SETTINGS.hibp_api_key,
        "virustotal": SETTINGS.virustotal_api_key,
        "abusech": SETTINGS.abusech_auth_key,
        "github": SETTINGS.github_token,
    }.get(name, "")


def _key_label(name: str) -> str:
    return {
        "hibp": "HIBP API key",
        "virustotal": "VirusTotal API key",
        "abusech": "abuse.ch Auth-Key",
        "github": "GitHub token",
        "urlscan": "urlscan.io API key (optional)",
        "otx": "OTX API key (optional)",
    }.get(name, name)


def public_catalogue() -> list[dict[str, Any]]:
    """The source list as published to the UI (no keys, no internals)."""
    return [registry()[sid].public_dict() for sid in source_order()]
