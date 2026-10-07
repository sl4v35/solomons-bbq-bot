"""Runtime configuration, upstream allowlists and hard limits.

Everything here is deliberately conservative: fixed allowlists (no user-supplied
URLs are ever fetched), short timeouts, response-size caps, bounded caches and
rate limits.  Values can be overridden with environment variables so a hosting
provider (Render) can tune them without a code change.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

APP_NAME = "Verdigris"
APP_VERSION = "1.0.0"
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (+https://github.com/sl4v35/solomons-bbq-bot; public-source-intel research tool)"


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# ---------------------------------------------------------------------------
# Fixed upstream allowlist.  Hosts must match exactly (no wildcards) and the
# only scheme ever used is https.  Nothing in this list is reachable through a
# user-controlled URL parameter: the app has no "fetch this URL" endpoint.
# ---------------------------------------------------------------------------

ALLOWED_HOSTS: dict[str, str] = {
    # DNS over HTTPS (Google public resolver, JSON API)
    "dns.google": "DNS-over-HTTPS lookups (A/AAAA/MX/NS/TXT/DMARC)",
    # Domain registration data
    "rdap.org": "RDAP bootstrap / redirector",
    "data.iana.org": "IANA RDAP bootstrap table",
    # Registry + registrar RDAP servers (fixed list; redirects outside it are refused)
    "rdap.verisign.com": "RDAP for .com/.net",
    "rdap.nic.google": "RDAP for Google-run TLDs",
    "rdap.identitydigital.services": "RDAP for Identity Digital TLDs",
    "rdap.publicinterestregistry.org": "RDAP for .org",
    "rdap.nominet.uk": "RDAP for .uk",
    "rdap.nic.fr": "RDAP for .fr",
    "rdap.denic.de": "RDAP for .de",
    "rdap.nic.ch": "RDAP for .ch",
    "rdap.nic.it": "RDAP for .it",
    "rdap.nic.es": "RDAP for .es",
    "rdap.nic.pl": "RDAP for .pl",
    "rdap.nic.se": "RDAP for .se",
    "rdap.nic.no": "RDAP for .no",
    "rdap.nic.fi": "RDAP for .fi",
    "rdap.nic.dk": "RDAP for .dk",
    "rdap.nic.nl": "RDAP for .nl",
    "rdap.nic.be": "RDAP for .be",
    "rdap.nic.at": "RDAP for .at",
    "rdap.nic.cz": "RDAP for .cz",
    "rdap.nic.pt": "RDAP for .pt",
    "rdap.nic.gr": "RDAP for .gr",
    "rdap.nic.hu": "RDAP for .hu",
    "rdap.nic.ro": "RDAP for .ro",
    "rdap.nic.tr": "RDAP for .tr",
    "rdap.nic.ru": "RDAP for .ru",
    "rdap.nic.io": "RDAP for .io",
    "rdap.nic.co": "RDAP for .co",
    "rdap.nic.me": "RDAP for .me",
    "rdap.nic.tv": "RDAP for .tv",
    "rdap.nic.cc": "RDAP for .cc",
    "rdap.nic.info": "RDAP for .info",
    "rdap.nic.biz": "RDAP for .biz",
    "rdap.nic.xyz": "RDAP for .xyz",
    "rdap.nic.online": "RDAP for .online",
    "rdap.nic.site": "RDAP for .site",
    "rdap.nic.store": "RDAP for .store",
    "rdap.nic.tech": "RDAP for .tech",
    "rdap.nic.app": "RDAP for .app",
    "rdap.nic.dev": "RDAP for .dev",
    "rdap.nic.cloud": "RDAP for .cloud",
    "rdap.nic.email": "RDAP for .email",
    "rdap.nic.network": "RDAP for .network",
    "rdap.nic.solutions": "RDAP for .solutions",
    "rdap.nic.services": "RDAP for .services",
    "rdap.nic.digital": "RDAP for .digital",
    "rdap.nic.media": "RDAP for .media",
    "rdap.nic.news": "RDAP for .news",
    "rdap.nic.blog": "RDAP for .blog",
    "rdap.nic.shop": "RDAP for .shop",
    "rdap.nic.club": "RDAP for .club",
    "rdap.nic.life": "RDAP for .life",
    "rdap.nic.world": "RDAP for .world",
    "rdap.nic.space": "RDAP for .space",
    "rdap.nic.website": "RDAP for .website",
    "rdap.nic.fun": "RDAP for .fun",
    "rdap.nic.live": "RDAP for .live",
    "rdap.nic.rocks": "RDAP for .rocks",
    "rdap.nic.guru": "RDAP for .guru",
    "rdap.nic.ninja": "RDAP for .ninja",
    "rdap.nic.today": "RDAP for .today",
    "rdap.centralnic.com": "RDAP for CentralNic/Teads TLDs",
    "rdap.godaddy.com": "RDAP for Go Daddy Registry TLDs",
    "rdap.nic.us": "RDAP for .us",
    "rdap.nic.ca": "RDAP for .ca",
    "rdap.nic.au": "RDAP for .au",
    "rdap.nic.jp": "RDAP for .jp",
    "rdap.nic.br": "RDAP for .br",
    "rdap.nic.in": "RDAP for .in",
    "rdap.nic.za": "RDAP for .za",
    "rdap.nic.mx": "RDAP for .mx",
    "rdap.nic.ar": "RDAP for .ar",
    "rdap.nic.cl": "RDAP for .cl",
    "rdap.nic.il": "RDAP for .il",
    "rdap.nic.kr": "RDAP for .kr",
    "rdap.nic.cn": "RDAP for .cn",
    "rdap.nic.sg": "RDAP for .sg",
    "rdap.nic.hk": "RDAP for .hk",
    "rdap.nic.tw": "RDAP for .tw",
    "rdap.nic.nz": "RDAP for .nz",
    "rdap.nic.eu": "RDAP for .eu",
    "rdap.nic.asia": "RDAP for .asia",
    "rdap.nic.mobi": "RDAP for .mobi",
    "rdap.nic.name": "RDAP for .name",
    "rdap.nic.pro": "RDAP for .pro",
    "rdap.nic.tel": "RDAP for .tel",
    "rdap.nic.travel": "RDAP for .travel",
    "rdap.nic.jobs": "RDAP for .jobs",
    "rdap.nic.museum": "RDAP for .museum",
    "rdap.nic.int": "RDAP for .int",
    "rdap.nic.mil": "RDAP for .mil",
    "rdap.nic.gov": "RDAP for .gov",
    "rdap.nic.edu": "RDAP for .edu",
    # Public URL scan records
    "urlscan.io": "Existing public urlscan.io scan records (search only)",
    # Community threat-intel references
    "otx.alienvault.com": "AlienVault OTX indicator references",
    "urlhaus.abuse.ch": "URLhaus public feed (exact host match)",
    "urlhaus-api.abuse.ch": "URLhaus API (only with a user-supplied free Auth-Key)",
    "openphish.com": "OpenPhish community phishing feed",
    "raw.githubusercontent.com": "OpenPhish public feed mirror",
    # Web archives
    "archive.org": "Wayback Machine availability API",
    "web.archive.org": "Wayback Machine CDX index (first snapshot) and links",
    # Code hosting / public profiles
    "api.github.com": "GitHub public profiles and commit author-email search",
    "gitlab.com": "GitLab public user lookup",
    "codeberg.org": "Codeberg public user lookup",
    "keybase.io": "Keybase public user lookup",
    "hn.algolia.com": "Hacker News public user lookup (Algolia API)",
    "sourcegraph.com": "Sourcegraph public code search (server-sent events)",
    # Public name search
    "en.wikipedia.org": "Wikipedia public title/name search",
    # Avatars / public profile by email hash
    "en.gravatar.com": "Gravatar public profile lookup (MD5 of the email)",
    "gravatar.com": "Gravatar public profile lookup (MD5 of the email)",
    "api.gravatar.com": "Gravatar profile API",
    # Blockchain
    "blockstream.info": "Bitcoin address statistics (public blockchain data)",
    "mempool.space": "Bitcoin address statistics (fallback public explorer)",
    "ethereum-rpc.publicnode.com": "Ethereum JSON-RPC (public)",
    "eth.llamarpc.com": "Ethereum JSON-RPC (public)",
    "cloudflare-eth.com": "Ethereum JSON-RPC (public)",
    "rpc.nodeflare.app": "Ethereum JSON-RPC (public)",
    "1rpc.io": "Ethereum JSON-RPC (public)",
    "eth.drpc.org": "Ethereum JSON-RPC (public)",
    # Optional, key-gated
    "haveibeenpwned.com": "HIBP breached-account search (requires the user's API key)",
    "www.virustotal.com": "VirusTotal domain report (requires the user's API key)",
    # Password exposure (k-anonymity: only 5 hex characters leave the browser)
    "api.pwnedpasswords.com": "HIBP Pwned Passwords k-anonymity range API (no key needed)",
}

# Hosts allowed for RDAP bootstrap redirects (rdap.org answers with a 302 to the
# registry's own RDAP server).  Redirects are only followed over https and only
# after the target IP is verified to be a public (non-private/reserved) address.
RDAP_REDIRECT_HOSTS = frozenset(
    host for host in ALLOWED_HOSTS if host.startswith("rdap.") or host in {"rdap.org"}
)

# Hosts we allow a redirect to *outside* the fixed list, limited to the RDAP
# bootstrap only.  Kept as an explicit, documented exception rather than a
# general "follow any redirect" behaviour.
RDAP_BOOTSTRAP_ANY_HTTPS = True

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Limits:
    # Request handling
    max_body_bytes: int = 32 * 1024  # 32 KiB for every inbound API body
    max_identifier_len: int = 254  # RFC 5321 address / DNS name limit
    max_static_bytes: int = 2 * 1024 * 1024

    # Outbound
    default_timeout: float = 8.0
    feed_timeout: float = 12.0
    max_response_bytes: int = 512 * 1024  # 512 KiB per upstream response
    max_feed_bytes: int = 6 * 1024 * 1024  # community feeds are larger
    max_redirects: int = 3
    per_source_timeout: float = 12.0
    scan_total_timeout: float = 45.0

    # Concurrency / jobs
    scan_worker_threads: int = 8
    max_concurrent_scans: int = 4
    max_queued_scans: int = 8
    job_ttl_seconds: int = 900
    max_jobs: int = 200

    # Cache
    cache_max_entries: int = 400
    cache_default_ttl: float = 600.0  # 10 min for DNS/RDAP/profile lookups
    cache_feed_ttl: float = 1800.0  # 30 min for community feeds

    # Rate limits (per client IP, token bucket).  Operators can raise/lower them
    # with environment variables, which is also how the test-suite relaxes them.
    rate_scan_per_min: float = field(default_factory=lambda: _float_env("RATE_SCAN_PER_MIN", 12.0))
    rate_api_per_min: float = field(default_factory=lambda: _float_env("RATE_API_PER_MIN", 60.0))
    rate_password_per_min: float = field(default_factory=lambda: _float_env("RATE_PASSWORD_PER_MIN", 10.0))


@dataclass
class Settings:
    host: str = "0.0.0.0"
    port: int = field(default_factory=lambda: _int_env("PORT", 8080))
    limits: Limits = field(default_factory=Limits)
    # Optional operator-protection token.  When set, /api/* requires it.
    access_token: str = field(default_factory=lambda: os.environ.get("ACCESS_TOKEN", "").strip())
    # Optional server-side keys (never required; users may also send their own per request)
    hibp_api_key: str = field(default_factory=lambda: os.environ.get("HIBP_API_KEY", "").strip())
    virustotal_api_key: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", "").strip())
    abusech_auth_key: str = field(default_factory=lambda: os.environ.get("ABUSECH_AUTH_KEY", "").strip())
    github_token: str = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN", "").strip())
    # Source toggles (set to "0" to disable an integration honestly at deploy time)
    disabled_sources: frozenset[str] = field(default_factory=lambda: frozenset(
        s.strip() for s in os.environ.get("DISABLED_SOURCES", "").split(",") if s.strip()
    ))
    # Trust the first X-Forwarded-For hop for rate limiting behind a proxy.
    trust_proxy_headers: bool = field(
        default_factory=lambda: os.environ.get("TRUST_PROXY_HEADERS", "1").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    request_log: bool = field(
        default_factory=lambda: os.environ.get("REQUEST_LOG", "1").strip().lower()
        in {"1", "true", "yes", "on"}
    )


SETTINGS = Settings()


def ethereum_rpc_endpoints() -> list[str]:
    """Public, keyless Ethereum JSON-RPC endpoints, tried in order."""
    override = os.environ.get("ETH_RPC_URLS", "").strip()
    if override:
        return [u.strip() for u in override.split(",") if u.strip().startswith("https://")]
    return [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://cloudflare-eth.com",
        "https://rpc.nodeflare.app/eth/public",
        "https://1rpc.io/eth",
        "https://eth.drpc.org",
    ]
