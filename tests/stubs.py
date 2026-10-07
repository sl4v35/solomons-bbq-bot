"""Test doubles: a programmable transport that mimics the real HTTP client.

Every canned body in here was captured from the live upstream API on
2026-10-07 and trimmed to the fields the app reads, so the parser tests run
against real response shapes rather than invented ones.
"""

from __future__ import annotations

import json
import re
import sys
import os
from typing import Any, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.http_client import (  # noqa: E402
    Response,
    TTLCache,
    Fetcher,
    UpstreamError,
    UpstreamHTTPError,
    UpstreamRateLimited,
    UpstreamTimeout,
)

# --------------------------------------------------------------------------
# Captured upstream shapes
# --------------------------------------------------------------------------

DOH_A = {
    "Status": 0, "TC": False, "RD": True, "RA": True, "AD": True, "CD": False,
    "Question": [{"name": "example.com.", "type": 1}],
    "Answer": [{"name": "example.com.", "type": 1, "TTL": 27, "data": "93.184.216.34"}],
}
DOH_AAAA = {
    "Status": 0, "Question": [{"name": "example.com.", "type": 28}],
    "Answer": [{"name": "example.com.", "type": 28, "TTL": 27, "data": "2606:2800:220:1:248:1893:25c8:1946"}],
}
DOH_MX = {
    "Status": 0, "TC": False, "RD": True, "RA": True, "AD": True, "CD": False,
    "Question": [{"name": "example.com.", "type": 15}],
    "Answer": [{"name": "example.com.", "type": 15, "TTL": 27, "data": "0 ."}],
}
DOH_NS = {
    "Status": 0,
    "Question": [{"name": "example.com.", "type": 2}],
    "Answer": [
        {"name": "example.com.", "type": 2, "TTL": 100, "data": "a.iana-servers.net."},
        {"name": "example.com.", "type": 2, "TTL": 100, "data": "b.iana-servers.net."},
    ],
}
DOH_TXT_SPF = {
    "Status": 0,
    "Question": [{"name": "example.com.", "type": 16}],
    "Answer": [{"name": "example.com.", "type": 16, "TTL": 60,
                "data": "\"v=spf1 -all\""}],
}
DOH_TXT_DMARC = {
    "Status": 0,
    "Question": [{"name": "_dmarc.example.com.", "type": 16}],
    "Answer": [{"name": "_dmarc.example.com.", "type": 16, "TTL": 60,
                "data": "\"v=DMARC1;p=reject;sp=reject;rua=mailto:dmarc@example.com\""}],
}
DOH_NXDOMAIN = {"Status": 3, "Question": [{"name": "nope.invalid.", "type": 1}], "Answer": []}

# RDAP for example.com - captured 2026-10-07 from rdap.verisign.com (trimmed).
# Note the `eventAction` / `eventDate` field names (a known integration pitfall).
RDAP_EXAMPLE = {
    "objectClassName": "domain",
    "handle": "2336799_DOMAIN_COM-VRSN",
    "ldhName": "EXAMPLE.COM",
    "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
    "entities": [
        {
            "objectClassName": "entity", "handle": "376", "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                     ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
            "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                          "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                   ["fn", {}, "text", ""],
                                                   ["tel", {"type": "voice"}, "uri", ""],
                                                   ["email", {}, "text", ""]]]}],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2099-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-08-14T08:01:43Z"},
        {"eventAction": "last update of RDAP database", "eventDate": "2026-10-07T08:11:33Z"},
    ],
    "secureDNS": {"delegationSigned": True,
                  "dsData": [{"keyTag": 2371, "algorithm": 13, "digestType": 2, "digest": "C988EC42..."}]},
    "nameservers": [{"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
                    {"objectClassName": "nameserver", "ldhName": "B.IANA-SERVERS.NET"}],
    "rdapConformance": ["rdap_level_0"],
}

RDAP_RECENT = {
    "objectClassName": "domain", "ldhName": "NEWISH.EXAMPLE",
    "status": ["ok"], "entities": [],
    "events": [{"eventAction": "registration", "eventDate": "2026-09-01T00:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-09-01T00:00:00Z"}],
    "secureDNS": {"delegationSigned": False}, "nameservers": [],
}

RDAP_EXPIRED = {
    "objectClassName": "domain", "ldhName": "LAPSED.EXAMPLE",
    "status": ["clientHold"], "entities": [],
    "events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2020-01-01T00:00:00Z"}],
    "secureDNS": {"delegationSigned": False}, "nameservers": [],
}

# urlscan.io search - captured 2026-10-07 (trimmed to one result).
URLSCAN_RESULTS = {
    "results": [{
        "task": {"visibility": "public", "method": "api", "domain": "example.com",
                 "apexDomain": "example.com", "time": "2026-10-07T08:07:38.254Z",
                 "uuid": "01a11567-46a0-71bb-837e-e91fc420856b", "url": "https://example.com/"},
        "page": {"server": "cloudflare", "ip": "172.66.147.243", "mimeType": "text/html",
                 "title": "Example Domain", "url": "https://example.com/", "domain": "example.com",
                 "apexDomain": "example.com", "asnname": "CLOUDFLARENET - Cloudflare, Inc., US",
                 "asn": "AS13335", "status": "200"},
        "_id": "01a11567-46a0-71bb-837e-e91fc420856b",
        "result": "https://urlscan.io/api/v1/result/01a11567-46a0-71bb-837e-e91fc420856b/",
    }],
    "total": 6212, "took": 10, "has_more": False, "search_date_limit_days": 30,
}
URLSCAN_EMPTY = {"results": [], "total": 0, "took": 4, "has_more": False, "search_date_limit_days": 30}

OTX_POPULAR = {
    "indicator": "example.org", "type": "domain",
    "validation": [{"source": "akamai", "message": "Akamai rank: #2138", "name": "Akamai Popular Domain"},
                   {"source": "whitelist", "message": "Whitelisted domain example.org", "name": "Whitelisted domain"}],
    "pulse_info": {"count": 2, "pulses": [
        {"id": "6abb55898b66dfc1e9c35ff4", "name": "Some bulk indicator dump",
         "created": "2026-09-29T06:07:05.387000", "tags": ["malware", "trojan"],
         "author": {"username": "Q.Vashti", "id": "337399"}, "indicator_count": 4996},
        {"id": "6aa8d07dd09b074cfef8b8bd", "name": "Another pulse", "created": "2026-09-15T04:36:16.000000",
         "tags": ["phishing"], "author": {"username": "someone"}, "indicator_count": 12},
    ]},
}
OTX_EMPTY = {"indicator": "clean.example", "type": "domain", "validation": [], "pulse_info": {"count": 0, "pulses": []}}

WAYBACK_AVAILABLE = {
    "url": "example.com",
    "archived_snapshots": {"closest": {"status": "200", "available": True,
                                       "url": "http://web.archive.org/web/20261007031409/https://example.com/",
                                       "timestamp": "20261007031409"}},
}
WAYBACK_NONE = {"url": "nothing.example", "archived_snapshots": {}}
WAYBACK_CDX = json.dumps([["timestamp", "original", "statuscode"],
                          ["19960110230000", "http://example.com/", "200"]])

GITHUB_USER = {
    "login": "torvalds", "id": 1024025, "avatar_url": "https://avatars.githubusercontent.com/u/1024025?v=4",
    "html_url": "https://github.com/torvalds", "type": "User", "name": "Linus Torvalds",
    "company": "Linux Foundation", "blog": "", "location": "Portland, OR", "email": None,
    "hireable": None, "bio": None, "twitter_username": None, "public_repos": 15,
    "public_gists": 0, "followers": 200000, "following": 0,
    "created_at": "2011-08-25T20:52:45Z", "updated_at": "2026-09-30T10:00:00Z",
}

GITHUB_COMMITS = {
    "total_count": 8, "incomplete_results": False,
    "items": [
        {"sha": "f1cbd03f5eabb75ea8ace23b47d2209f10871c16",
         "html_url": "https://github.com/torvalds/linux/commit/f1cbd03f5eabb75ea8ace23b47d2209f10871c16",
         "commit": {"message": "Merge branch 'for-linus'\n\nMore of the same.",
                    "author": {"name": "Linus Torvalds", "email": "torvalds@linux-foundation.org",
                               "date": "2012-03-14T17:16:45.000-07:00"},
                    "committer": {"name": "Linus Torvalds", "email": "torvalds@linux-foundation.org",
                                  "date": "2012-03-14T17:16:45.000-07:00"}},
         "author": {"login": "torvalds", "id": 1024025},
         "repository": {"full_name": "torvalds/linux"}},
        # Decoy: GitHub's search is not an exact-match index, so this must be filtered out.
        {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "html_url": "https://github.com/someone/repo/commit/aaaa",
         "commit": {"message": "unrelated",
                    "author": {"name": "Other Person", "email": "somebody-else@example.org",
                               "date": "2020-01-01T00:00:00Z"},
                    "committer": {"name": "Other Person", "email": "somebody-else@example.org",
                                  "date": "2020-01-01T00:00:00Z"}},
         "author": None, "repository": {"full_name": "someone/repo"}},
    ],
}

GITHUB_NAME_SEARCH = {
    "total_count": 42, "incomplete_results": False,
    "items": [{"login": "alan-turing-fan", "html_url": "https://github.com/alan-turing-fan", "type": "User"},
              {"login": "aturing", "html_url": "https://github.com/aturing", "type": "User"}],
}

GITLAB_EMPTY: list = []
GITLAB_USER = [{
    "id": 1234, "name": "Some Person", "username": "someperson", "state": "active",
    "avatar_url": "https://gitlab.com/uploads/-/system/user/avatar/1234/avatar.png",
    "web_url": "https://gitlab.com/someperson", "bio": "Building things", "location": "Berlin",
    "public_email": "some.person@example.org", "created_at": "2016-03-01T10:00:00.000Z",
}]

CODEBERG_USER = {
    "id": 2628, "login": "6543", "full_name": "", "email": "6543@noreply.codeberg.org",
    "avatar_url": "https://codeberg.org/avatars/09a2", "html_url": "https://codeberg.org/6543",
    "created": "2019-10-12T05:05:49+02:00", "last_login": "0001-01-01T00:00:00Z",
    "location": "", "pronouns": "", "website": "https://mh.obermui.de",
    "description": "<a href=\"https://chaos.social/@6543\">Mastodon</a>",
    "followers_count": 52, "following_count": 34, "starred_repos_count": 95, "username": "6543",
}

# Keybase normally returns `them` as a list ...
KEYBASE_LIST = {
    "status": {"code": 0, "name": "OK"},
    "them": [{
        "id": "23260c2ce19420f97b58d7d95b68ca00",
        "basics": {"username": "chris", "username_cased": "chris", "ctime": 1391653108, "mtime": 1624468589},
        "profile": {"full_name": "Chris Coyne", "location": "Maine", "bio": "Previously worked on Keybase."},
        "public_keys": {"primary": {"kid": "0101d492...", "key_type": 1}},
        "proofs_summary": {"all": [
            {"proof_type": "twitter", "nametag": "malgorithms", "human_url": "https://twitter.com/malgorithms",
             "state": 1},
            {"proof_type": "dns", "nametag": "chriscoyne.com", "human_url": "https://chriscoyne.com/", "state": 1},
        ]},
    }],
}
# ... but some responses return a single object - the app must handle both.
KEYBASE_OBJECT = {
    "status": {"code": 0, "name": "OK"},
    "them": {
        "id": "abc123", "basics": {"username": "solo", "username_cased": "solo", "ctime": 1500000000},
        "profile": {"full_name": "Solo Object", "location": "", "bio": ""},
        "public_keys": {"primary": {"kid": "0101ff", "key_type": 1}},
    },
}
KEYBASE_MISSING = {"status": {"code": 100, "name": "INPUT_ERROR", "desc": "user not found"}, "them": None}

HN_USER = {"about": "Bug fixer.", "karma": 157316, "username": "pg", "created_at": "2008-02-27T17:14:00.000Z"}
HN_USER_EMAIL = {"about": "Me &lt;me@example.org&gt; https://example.org", "karma": 10,
                 "username": "someone", "created_at": "2015-01-01T00:00:00.000Z"}

WIKI_OPENSEARCH = ["Alan Turing", ["Alan Turing", "Alan Turing Institute", "Alan Turing law"],
                   ["", "", ""],
                   ["https://en.wikipedia.org/wiki/Alan_Turing",
                    "https://en.wikipedia.org/wiki/Alan_Turing_Institute",
                    "https://en.wikipedia.org/wiki/Alan_Turing_law"]]
WIKI_OPENSEARCH_NONE = ["Nobody By This Name", [], [], []]
WIKI_SEARCH = {"query": {"searchinfo": {"totalhits": 512},
                         "search": [{"title": "Alan Turing",
                                     "snippet": "<span class=\"searchmatch\">Alan</span> <span class=\"searchmatch\">Turing</span> was ..."}]}}

GRAVATAR_PROFILE = {"entry": [{
    "hash": "e61fdf64734cbc0690d2492e67efe216df0559e5afabb57c5322b8b687ef5d30",
    "requestHash": "chris", "profileUrl": "https://gravatar.com/chris", "preferredUsername": "chris",
    "thumbnailUrl": "https://2.gravatar.com/avatar/e61f", "displayName": "Chris",
    "currentLocation": "Maine, USA", "aboutMe": "<p>Hello <b>world</b></p>",
    "name": {"givenName": "Chris", "familyName": "C"},
    "accounts": [{"url": "https://twitter.com/chris", "username": "chris", "domain": "twitter.com"},
                 {"url": "https://github.com/chris", "username": "chris", "domain": "github.com"}],
    "phoneNumbers": [{"type": "work", "value": "+1-555-0100"}],
}]}

BLOCKSTREAM_ACTIVE = {
    "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "chain_stats": {"funded_txo_count": 117, "funded_txo_sum": 17997427,
                    "spent_txo_count": 1, "spent_txo_sum": 14293, "tx_count": 118},
    "mempool_stats": {"funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0,
                      "spent_txo_sum": 0, "tx_count": 0},
}
BLOCKSTREAM_UNUSED = {
    "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "chain_stats": {"funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0,
                    "spent_txo_sum": 0, "tx_count": 0},
    "mempool_stats": {"funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0,
                      "spent_txo_sum": 0, "tx_count": 0},
}

ETH_BALANCE = {"jsonrpc": "2.0", "id": 1, "result": "0x1bc16d674ec80000"}  # 2 ETH
ETH_NONCE = {"jsonrpc": "2.0", "id": 2, "result": "0x2a"}  # 42
ETH_NO_CODE = {"jsonrpc": "2.0", "id": 3, "result": "0x"}
ETH_WITH_CODE = {"jsonrpc": "2.0", "id": 3, "result": "0x6080604052"}

# Sourcegraph public code search streams server-sent events; `event: matches`
# carries a JSON array (verified 2026-10-07).
SOURCEGRAPH_SSE = """event: filters
data: [{"value":"type:file","label":"Code","count":2,"exhaustive":false,"kind":"type"}]

event: matches
data: [{"type":"content","path":"package.json","repositoryID":1,"repository":"github.com/someone/project","repoStars":10,"commit":"8863d9f6d76d0ad55a27bd0d6f05d6476937f0e8","lineMatches":[{"line":"  \\"author\\": \\"Linus Torvalds <torvalds@linux-foundation.org>\\",","lineNumber":4,"offsetAndLengths":[[26,34]]}],"language":"JSON"}]

event: matches
data: [{"type":"content","path":"README.md","repositoryID":2,"repository":"github.com/other/notes","commit":"abc","lineMatches":[{"line":"contact: unrelated@example.org","lineNumber":9}],"language":"Markdown"}]

event: progress
data: {"done":true,"matchCount":2,"durationMs":1152}

event: done
data: {}
"""

URLHAUS_FEED = """#
# URLhaus recent malware URLs (plain text)
#
https://malware-host.example/payload.exe
http://example.com/bad/path
https://totally-unrelated.example/x
"""

URLHAUS_API_OK = {
    "query_status": "ok", "host": "example.com", "firstseen": "2021-04-01 12:00:00 UTC", "url_count": 3,
    "urls": [{"url": "http://example.com/bad/path", "url_status": "offline", "dateadded": "2021-04-01 12:00:00 UTC",
              "threat": "malware_download", "tags": ["exe"]}],
}
URLHAUS_API_EMPTY = {"query_status": "no_results", "host": "example.org"}

OPENPHISH_FEED = """https://phishing-host.example/login
http://example.com/secure/verify
https://other.example/x
"""

HIBP_RANGE = """1E4C9B93F3F0682250B6CF8331B7EE68FD8:3735919
593BA639E0E2F6CAE5D16F8B4E0B3AC0DA2:1
0018B52A0B5739BCC905BB28E231EF9B11C:3
"""

HIBP_BREACHES = [{
    "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
    "AddedDate": "2013-12-04T00:00:00Z", "PwnCount": 152445165, "IsVerified": True,
    "IsSensitive": False, "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
}]

VIRUSTOTAL_DOMAIN = {"data": {"id": "example.com", "type": "domain", "attributes": {
    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 89, "undetected": 3},
    "registrar": "RESERVED-Internet Assigned Numbers Authority", "creation_date": -2209075200,
    "categories": {"Dr.Web": "known infection source"}, "popularity_ranks": {"Alexa": {"rank": 100, "ingestion_time": "2026-09-01"}},
}}}

MALICIOUS_HOST = "malware-host.example"


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


class StubTransport:
    """Route table of ``(pattern, response)`` pairs.

    ``response`` may be a dict/list (JSON body), a :class:`Response`, a string
    (text body), an exception instance/class, or a callable receiving the
    request kwargs.
    """

    def __init__(self, routes: list[tuple[str, Any]] | None = None, default: Any = None) -> None:
        self.routes: list[tuple[re.Pattern[str], Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.default = default
        for pattern, response in routes or []:
            self.add(pattern, response)

    def add(self, pattern: str, response: Any) -> "StubTransport":
        self.routes.append((re.compile(pattern), response))
        return self

    def __call__(self, **kwargs: Any) -> Response:
        url = kwargs["url"]
        self.calls.append({"url": url, "method": kwargs.get("method", "GET"),
                           "headers": dict(kwargs.get("headers") or {}),
                           "body": kwargs.get("body"),
                           "timeout": kwargs.get("timeout"),
                           "max_bytes": kwargs.get("max_bytes")})
        for pattern, response in self.routes:
            if pattern.search(url):
                return self._materialise(url, response, kwargs)
        if self.default is not None:
            return self._materialise(url, self.default, kwargs)
        raise AssertionError(f"StubTransport has no route for {url}")

    def _materialise(self, url: str, response: Any, kwargs: dict[str, Any]) -> Response:
        if isinstance(response, Exception):
            raise response
        if isinstance(response, type) and issubclass(response, Exception):
            raise response()
        if callable(response):
            response = response(**kwargs)
            if response is None:
                raise AssertionError(f"route for {url} returned None")
        if isinstance(response, Response):
            return response
        if isinstance(response, tuple) and len(response) == 2 and isinstance(response[0], int):
            status, payload = response
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            if status == 429:
                raise UpstreamRateLimited("upstream rate limit reached (HTTP 429)", status=429)
            if status >= 400:
                raise UpstreamHTTPError(f"upstream returned HTTP {status}", status=status)
            return Response(status=status, body=body, final_url=url, elapsed_ms=1)
        if isinstance(response, str):
            return Response(status=200, body=response.encode(), final_url=url, elapsed_ms=1,
                            content_type="text/plain")
        if isinstance(response, bytes):
            return Response(status=200, body=response, final_url=url, elapsed_ms=1,
                            content_type="text/plain")
        return Response(status=200, body=json.dumps(response).encode(), final_url=url, elapsed_ms=1,
                        content_type="application/json")

    def urls(self) -> list[str]:
        return [call["url"] for call in self.calls]


def make_fetcher(routes: list[tuple[str, Any]] | None = None, default: Any = None) -> tuple[Fetcher, StubTransport]:
    transport = StubTransport(routes, default=default)
    fetcher = Fetcher(transport=transport, cache=TTLCache(max_entries=32, default_ttl=60))
    return fetcher, transport


def dns_routes(domain: str = "example.com", *, fail_types: tuple[str, ...] = ()) -> list[tuple[str, Any]]:
    """Standard DoH routes, optionally failing selected record types."""
    mapping = {
        "A": DOH_A, "AAAA": DOH_AAAA, "MX": DOH_MX, "NS": DOH_NS, "TXT": DOH_TXT_SPF,
    }
    routes: list[tuple[str, Any]] = []
    for rtype, payload in mapping.items():
        response: Any = payload
        if rtype in fail_types:
            response = UpstreamTimeout("upstream timed out after 8s")
        routes.append((rf"dns\.google/resolve\?name={re.escape(domain)}&type={rtype}$", response))
    dmarc_response: Any = DOH_TXT_DMARC if "DMARC" not in fail_types else UpstreamTimeout("timed out")
    routes.append((r"dns\.google/resolve\?name=_dmarc\.", dmarc_response))
    return routes


def context_for(value: str, *, fetcher: Fetcher, forced: str = "auto", keys: dict[str, str] | None = None,
                mode: str = "osint") -> Any:
    from app.identifiers import detect
    from app.sources.base import SourceContext

    return SourceContext(identifier=detect(value, forced_type=forced), keys=keys or {}, mode=mode, fetcher=fetcher)


def run_source(source_id: str, ctx: Any) -> Any:
    from app.sources import registry
    from app.sources.base import execute

    return execute(registry()[source_id], ctx)


__all__ = [name for name in dir() if not name.startswith("__")] + [
    "StubTransport", "make_fetcher", "dns_routes", "context_for", "run_source",
    "UpstreamError", "UpstreamHTTPError", "UpstreamRateLimited", "UpstreamTimeout", "Response",
]
