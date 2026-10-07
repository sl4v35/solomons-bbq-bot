"""Password exposure check via HIBP's k-anonymity API.

Privacy contract (enforced in code, not just in documentation):

* there is **no** endpoint in this app that accepts a password;
* the browser hashes the password with SHA-1 (Web Crypto) and keeps the digest;
* only the first five hexadecimal characters of that digest are sent - first to
  this server, then to ``api.pwnedpasswords.com``;
* this server returns the public range list and the browser compares the
  remaining 35 characters locally, so the full hash never reaches us either;
* nothing about the check is written to logs, to scan history or to disk.
"""

from __future__ import annotations

import re
from typing import Any

from .config import SETTINGS
from .http_client import UpstreamError
from .sources.base import utcnow_iso

RANGE_URL = "https://api.pwnedpasswords.com/range/"
PREFIX_RE = re.compile(r"^[0-9a-fA-F]{5}$")


class PasswordCheckError(ValueError):
    pass


def fetch_range(prefix: str, fetcher: Any) -> dict[str, Any]:
    """Return the public hash-suffix/count list for a 5-character SHA-1 prefix."""
    candidate = (prefix or "").strip()
    if not PREFIX_RE.match(candidate):
        raise PasswordCheckError(
            "Expected exactly five hexadecimal characters (the first five of a SHA-1 hash). "
            "Nothing else is accepted by this endpoint."
        )
    upper = candidate.upper()
    url = RANGE_URL + upper
    text = fetcher.get_text(
        url,
        headers={"User-Agent": "Verdigris (k-anonymity password check)", "Add-Padding": "true"},
        timeout=min(10.0, SETTINGS.limits.per_source_timeout),
        max_bytes=SETTINGS.limits.max_response_bytes,
        cache_key=f"hibp-range:{upper}",
        cache_ttl=SETTINGS.limits.cache_feed_ttl,
    )
    parsed: list[dict[str, Any]] = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count = line.partition(":")
        suffix = suffix.strip().upper()
        if len(suffix) != 35 or not re.fullmatch(r"[0-9A-F]{35}", suffix):
            continue
        try:
            parsed.append({"suffix": suffix, "count": int(count.strip())})
        except ValueError:
            continue
    if not parsed:
        raise UpstreamError("HIBP returned an empty or unparsable range response", kind="parse-error")
    # We ask HIBP for padding (``Add-Padding: true``) so the response size does not
    # reveal how common the queried prefix is. HIBP documents that padded entries
    # always carry a count of 0 and should be discarded, so they are dropped here
    # rather than being handed to the browser. An empty ``entries`` list with a
    # non-empty ``parsed`` list is a legitimate "not in the corpus" answer, not an
    # error.
    entries = [entry for entry in parsed if entry["count"] > 0]
    return {
        "prefix": upper,
        "entries": entries,
        "entry_count": len(entries),
        "returned_count": len(parsed),
        "padding_discarded": len(parsed) - len(entries),
        "upstream_host": "api.pwnedpasswords.com",
        "checked_at": utcnow_iso(),
        "note": (
            "Only the five-character prefix above was sent to HIBP. The remaining 35 hash characters "
            "stay in your browser, where the comparison happens. Padding was requested (Add-Padding: true) "
            "so the response size does not reveal how common the prefix is; HIBP's padded entries always "
            "have a count of 0 and were discarded here."
        ),
    }
