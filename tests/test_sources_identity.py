"""Source tests for identity-oriented integrations (code hosts, people, blockchain, breaches)."""

from __future__ import annotations

import json
import unittest

from stubs import *  # noqa: F401,F403
from stubs import (
    BLOCKSTREAM_ACTIVE,
    BLOCKSTREAM_UNUSED,
    CODEBERG_USER,
    ETH_BALANCE,
    ETH_NONCE,
    ETH_NO_CODE,
    ETH_WITH_CODE,
    GITHUB_COMMITS,
    GITHUB_NAME_SEARCH,
    GITHUB_USER,
    GITLAB_EMPTY,
    GITLAB_USER,
    GRAVATAR_PROFILE,
    HIBP_BREACHES,
    HIBP_PASTES,
    HIBP_SPAMMY_BREACHES,
    HIBP_STEALER_LOG_BREACHES,
    HN_USER,
    HN_USER_EMAIL,
    KEYBASE_LIST,
    KEYBASE_MISSING,
    KEYBASE_OBJECT,
    SOURCEGRAPH_SSE,
    UpstreamTimeout,
    WIKI_OPENSEARCH,
    WIKI_OPENSEARCH_NONE,
    WIKI_SEARCH,
    context_for,
    hibp_routes,
    make_fetcher,
    run_source,
)

from app.sources.base import (
    STATUS_ERROR,
    STATUS_NO_MATCH,
    STATUS_NOT_CHECKED,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
)

ETH_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
EMAIL = "torvalds@linux-foundation.org"


def eth_route(balance=ETH_BALANCE, nonce=ETH_NONCE, code=ETH_NO_CODE):
    """Route that answers JSON-RPC calls by method name (id echoed back)."""

    def route(**kwargs):
        body = json.loads(kwargs.get("body") or b"{}")
        method = body.get("method", "")
        payload = {"eth_getBalance": balance, "eth_getTransactionCount": nonce, "eth_getCode": code}.get(method)
        if payload is None:
            return (400, {"error": {"code": -32601, "message": "method not found"}})
        out = dict(payload)
        out["id"] = body.get("id", 1)
        return out

    return route


class GitHubTests(unittest.TestCase):
    def test_profile_lookup(self):
        fetcher, transport = make_fetcher([(r"api\.github\.com/users/", GITHUB_USER)])
        result = run_source("github_user", context_for("torvalds", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["name"], "Linus Torvalds")
        self.assertEqual(result.data["location"], "Portland, OR")
        self.assertEqual(len(result.data["personal_fields"]), 3)
        self.assertEqual(result.findings[0].severity, "medium")
        self.assertIn("not proof of the same person", result.findings[0].interpretation)
        self.assertEqual(transport.calls[0]["headers"]["Accept"], "application/vnd.github+json")
        self.assertEqual(transport.calls[0]["headers"]["X-GitHub-Api-Version"], "2022-11-28")
        self.assertNotIn("Authorization", transport.calls[0]["headers"])

    def test_token_is_used_when_supplied(self):
        fetcher, transport = make_fetcher([(r"api\.github\.com/users/", GITHUB_USER)])
        run_source("github_user", context_for("torvalds", fetcher=fetcher, keys={"github": "ghp_TEST"}))
        self.assertEqual(transport.calls[0]["headers"]["Authorization"], "Bearer ghp_TEST")

    def test_missing_account_is_no_match(self):
        fetcher, _ = make_fetcher([(r"api\.github\.com/users/", (404, {}))])
        result = run_source("github_user", context_for("nosuchuser12345", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertEqual(result.findings, [])

    def test_rate_limit_is_explained_with_a_hint(self):
        for status_code in (403, 429):
            fetcher, _ = make_fetcher([(r"api\.github\.com/users/", (status_code, {}))])
            result = run_source("github_user", context_for("torvalds", fetcher=fetcher))
            self.assertEqual(result.status, STATUS_RATE_LIMITED, status_code)
            self.assertIn("GitHub token", result.hint)

    def test_commit_search_filters_to_the_exact_email(self):
        fetcher, transport = make_fetcher([(r"api\.github\.com/search/commits", GITHUB_COMMITS)])
        result = run_source("github_commits", context_for(EMAIL, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["exact_match_count"], 1)
        self.assertEqual(result.data["reported_total_count"], 8)  # GitHub's loose count is kept separate
        blob = json.dumps(result.as_dict())
        self.assertIn(EMAIL, blob)
        self.assertNotIn("somebody-else@example.org", blob)
        self.assertNotIn("someone/repo", blob)
        query = transport.calls[0]["url"]
        self.assertIn("search/commits?q=author-email", query)
        self.assertIn("torvalds%40linux-foundation.org", query)  # the address is URL-encoded, never split

    def test_loose_only_results_are_reported_as_no_match(self):
        decoy_only = {"total_count": 3, "incomplete_results": False, "items": [GITHUB_COMMITS["items"][1]]}
        fetcher, _ = make_fetcher([(r"api\.github\.com/search/commits", decoy_only)])
        result = run_source("github_commits", context_for(EMAIL, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("exact", result.message)

    def test_incomplete_results_are_disclosed(self):
        incomplete = json.loads(json.dumps(GITHUB_COMMITS))
        incomplete["incomplete_results"] = True
        fetcher, _ = make_fetcher([(r"api\.github\.com/search/commits", incomplete)])
        result = run_source("github_commits", context_for(EMAIL, fetcher=fetcher))
        self.assertTrue(result.data["incomplete_results"])
        self.assertIn("incomplete", json.dumps(result.as_dict()).lower())

    def test_name_search_reports_candidates_only(self):
        fetcher, _ = make_fetcher([(r"api\.github\.com/search/users", GITHUB_NAME_SEARCH)])
        result = run_source("github_name", context_for("Linus Torvalds", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.findings[0].severity, "low")
        self.assertEqual(result.data["reported_total_count"], 42)
        self.assertIn("candidate", result.findings[0].interpretation.lower())
        self.assertIn("loosely", result.findings[0].interpretation.lower())


class GitLabCodebergTests(unittest.TestCase):
    def test_empty_list_is_no_match(self):
        fetcher, _ = make_fetcher([(r"gitlab\.com/api/v4/users", GITLAB_EMPTY)])
        result = run_source("gitlab_user", context_for("torvalds", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)

    def test_public_email_is_called_out(self):
        fetcher, _ = make_fetcher([(r"gitlab\.com/api/v4/users", GITLAB_USER)])
        result = run_source("gitlab_user", context_for("someperson", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        titles = [f.title for f in result.findings]
        self.assertTrue(any("publishes an email" in t for t in titles), titles)
        self.assertEqual([f for f in result.findings if "email" in f.title][0].severity, "high")

    def test_unexpected_shape_is_unavailable(self):
        fetcher, _ = make_fetcher([(r"gitlab\.com/api/v4/users", {"message": "404"})])
        result = run_source("gitlab_user", context_for("someperson", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)

    def test_codeberg_noreply_email_is_not_an_exposure(self):
        fetcher, _ = make_fetcher([(r"codeberg\.org/api/v1/users", CODEBERG_USER)])
        result = run_source("codeberg_user", context_for("6543", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        titles = [f.title for f in result.findings]
        self.assertFalse(any("publishes an email" in t for t in titles), titles)
        self.assertFalse(any("noreply" in e.value for f in result.findings for e in f.evidence
                             if "email" in f.title.lower()))

    def test_codeberg_missing_account(self):
        fetcher, _ = make_fetcher([(r"codeberg\.org/api/v1/users", (404, {}))])
        result = run_source("codeberg_user", context_for("torvalds", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)


class KeybaseTests(unittest.TestCase):
    def test_list_shaped_response(self):
        fetcher, _ = make_fetcher([(r"keybase\.io/_/api/1\.0/user/lookup", KEYBASE_LIST)])
        result = run_source("keybase_user", context_for("chris", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["created"], "2014-02-06T02:18:28Z")  # epoch ctime
        self.assertEqual(len(result.data["proofs"]), 2)
        self.assertTrue(any("identity proof" in f.title.lower() for f in result.findings))

    def test_object_shaped_response_is_handled(self):
        # Pitfall: `them` may be a single object rather than a list.
        fetcher, _ = make_fetcher([(r"keybase\.io/_/api/1\.0/user/lookup", KEYBASE_OBJECT)])
        result = run_source("keybase_user", context_for("solo", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["username"], "solo")

    def test_missing_user(self):
        fetcher, _ = make_fetcher([(r"keybase\.io/_/api/1\.0/user/lookup", KEYBASE_MISSING)])
        result = run_source("keybase_user", context_for("nosuchuser", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertEqual(result.data["keybase_status"], 100)

    def test_key_material_is_never_stored(self):
        payload = json.loads(json.dumps(KEYBASE_LIST))
        payload["them"][0]["public_keys"]["primary"]["key"] = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxsBNBFakeKeyMaterialAAAA\n-----END PGP PUBLIC KEY BLOCK-----")
        fetcher, _ = make_fetcher([(r"keybase\.io/_/api/1\.0/user/lookup", payload)])
        result = run_source("keybase_user", context_for("chris", fetcher=fetcher))
        blob = json.dumps(result.as_dict())
        self.assertNotIn("BEGIN PGP", blob)
        self.assertNotIn("FakeKeyMaterial", blob)


class HackerNewsTests(unittest.TestCase):
    def test_profile(self):
        fetcher, _ = make_fetcher([(r"hn\.algolia\.com/api/v1/users", HN_USER)])
        result = run_source("hackernews_user", context_for("pg", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["karma"], 157316)
        self.assertIn("self-reported", result.findings[0].summary.lower() + json.dumps(result.as_dict()).lower())

    def test_email_in_bio_is_flagged(self):
        fetcher, _ = make_fetcher([(r"hn\.algolia\.com/api/v1/users", HN_USER_EMAIL)])
        result = run_source("hackernews_user", context_for("someone", fetcher=fetcher))
        emails = [f for f in result.findings if "Email" in f.title]
        self.assertTrue(emails)
        self.assertEqual(emails[0].severity, "high")
        self.assertEqual(result.data["emails_in_about"], ["me@example.org"])

    def test_missing_user(self):
        fetcher, _ = make_fetcher([(r"hn\.algolia\.com/api/v1/users", (404, {}))])
        result = run_source("hackernews_user", context_for("nosuchuser", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)


class SourcegraphTests(unittest.TestCase):
    def test_sse_stream_is_parsed_and_filtered(self):
        fetcher, transport = make_fetcher([(r"sourcegraph\.com/\.api/search/stream", SOURCEGRAPH_SSE)])
        result = run_source("sourcegraph_code", context_for(EMAIL, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["match_count"], 1)
        self.assertEqual(result.data["matches"][0]["repository"], "github.com/someone/project")
        self.assertEqual(result.data["matches"][0]["url"],
                         "https://sourcegraph.com/github.com/someone/project/-/blob/package.json#L5")
        # Angle brackets inside code lines must survive cleaning.
        self.assertIn("<torvalds@linux-foundation.org>", json.dumps(result.as_dict()))
        self.assertNotIn("unrelated@example.org", json.dumps(result.as_dict()))
        self.assertEqual(transport.calls[0]["headers"]["Accept"], "text/event-stream")

    def test_stream_error_is_unavailable_not_no_match(self):
        stream = "event: error\ndata: stream disconnected before completion: eof\n\nevent: done\ndata: {}\n\n"
        fetcher, _ = make_fetcher([(r"sourcegraph\.com/\.api/search/stream", stream)])
        result = run_source("sourcegraph_code", context_for(EMAIL, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("error", result.message.lower())

    def test_no_matches(self):
        stream = "event: matches\ndata: []\n\nevent: done\ndata: {}\n\n"
        fetcher, _ = make_fetcher([(r"sourcegraph\.com/\.api/search/stream", stream)])
        result = run_source("sourcegraph_code", context_for(EMAIL, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("not proof of absence", result.message)

    def test_short_usernames_are_skipped(self):
        fetcher, transport = make_fetcher([])
        result = run_source("sourcegraph_code", context_for("abc", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NOT_CHECKED)
        self.assertEqual(transport.calls, [])

    def test_rate_limit(self):
        fetcher, _ = make_fetcher([(r"sourcegraph\.com/\.api/search/stream", (429, {}))])
        result = run_source("sourcegraph_code", context_for(EMAIL, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_RATE_LIMITED)


class WikipediaTests(unittest.TestCase):
    def test_candidates_are_reported_as_candidates(self):
        fetcher, _ = make_fetcher([
            (r"action=opensearch", WIKI_OPENSEARCH),
            (r"action=query&list=search", WIKI_SEARCH),
        ])
        result = run_source("wikipedia_name", context_for("Alan Turing", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["total_hits"], 512)
        self.assertEqual(result.findings[0].severity, "medium")  # exact title hit
        self.assertIn("not proof", result.findings[0].interpretation.lower())
        self.assertTrue(all(link.url for link in result.findings[0].links))

    def test_no_titles_is_no_match_with_honest_scope(self):
        fetcher, _ = make_fetcher([
            (r"action=opensearch", WIKI_OPENSEARCH_NONE),
            (r"action=query&list=search", {"query": {"searchinfo": {"totalhits": 0}, "search": []}}),
        ])
        result = run_source("wikipedia_name", context_for("Nobody By This Name", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("notable", result.message)

    def test_unexpected_shape_is_unavailable_not_error(self):
        fetcher, _ = make_fetcher([
            (r"action=opensearch", WIKI_OPENSEARCH),
            (r"action=query&list=search", ["not", "a", "dict"]),
        ])
        result = run_source("wikipedia_name", context_for("Alan Turing", fetcher=fetcher))
        self.assertNotEqual(result.status, STATUS_ERROR)
        self.assertIn(result.status, (STATUS_OK, STATUS_UNAVAILABLE))


class GravatarTests(unittest.TestCase):
    def test_email_lookup_sends_only_the_md5(self):
        fetcher, transport = make_fetcher([(r"gravatar\.com/", GRAVATAR_PROFILE)])
        result = run_source("gravatar", context_for("person@example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(len(transport.calls), 1)
        url = transport.calls[0]["url"]
        self.assertIn("7de8517bce4457e8390aa4006a1880fb", url)  # md5 of the address
        self.assertNotIn("person@example.com", url)
        self.assertNotIn("person%40example.com", url)
        self.assertTrue(any("linked" in f.title.lower() for f in result.findings))

    def test_username_lookup_sends_the_username(self):
        fetcher, transport = make_fetcher([(r"gravatar\.com/", GRAVATAR_PROFILE)])
        result = run_source("gravatar", context_for("chris", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertIn("gravatar.com/chris.json", transport.calls[0]["url"])

    def test_unknown_hash_is_no_match_and_explains_the_hash(self):
        fetcher, _ = make_fetcher([(r"gravatar\.com/", (404, {}))])
        result = run_source("gravatar", context_for("person@example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("MD5", result.message)

    def test_html_in_about_is_stripped_but_content_kept(self):
        fetcher, _ = make_fetcher([(r"gravatar\.com/", GRAVATAR_PROFILE)])
        result = run_source("gravatar", context_for("chris", fetcher=fetcher))
        self.assertEqual(result.data["about"], "Hello world")


class PhoneTests(unittest.TestCase):
    def test_nothing_is_sent_to_a_third_party(self):
        fetcher, transport = make_fetcher([])
        result = run_source("phone_local", context_for("+442071234567", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(transport.calls, [])
        self.assertEqual(result.data["third_party_queries"], 0)
        self.assertEqual(result.sends.lower()[:8], "nothing.")
        self.assertIn("No third-party service was queried", result.message)
        self.assertEqual(result.findings[0].severity, "info")

    def test_country_is_a_hint_not_an_owner(self):
        fetcher, _ = make_fetcher([])
        result = run_source("phone_local", context_for("+442071234567", fetcher=fetcher))
        blob = json.dumps(result.as_dict())
        self.assertIn("cannot tell you who owns the number", blob)
        self.assertIn("dark web", blob)  # explicit disclaimer that no such source is used


class BitcoinTests(unittest.TestCase):
    def test_active_address(self):
        fetcher, _ = make_fetcher([(r"blockstream\.info/api/address/", BLOCKSTREAM_ACTIVE)])
        result = run_source("blockstream_btc",
                            context_for("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["tx_count"], 118)
        self.assertEqual(result.data["balance_btc"], "0.17983134 BTC")
        self.assertEqual(result.findings[0].severity, "high")
        self.assertIn("no removal", json.dumps(result.as_dict()).lower())

    def test_unused_address_is_no_match_but_still_reported(self):
        fetcher, _ = make_fetcher([(r"blockstream\.info/api/address/", BLOCKSTREAM_UNUSED)])
        result = run_source("blockstream_btc",
                            context_for("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertTrue(result.findings)  # an info finding so the UI can show what was checked
        self.assertEqual(result.findings[0].severity, "info")

    def test_falls_back_to_the_second_explorer(self):
        fetcher, transport = make_fetcher([
            (r"blockstream\.info/api/address/", UpstreamTimeout("timed out")),
            (r"mempool\.space/api/address/", BLOCKSTREAM_ACTIVE),
        ])
        result = run_source("blockstream_btc",
                            context_for("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.upstream_host, "mempool.space")
        # The first host is retried once at the transport layer before failing over.
        self.assertGreaterEqual(len(transport.calls), 2)
        self.assertIn("mempool.space", transport.calls[-1]["url"])

    def test_both_explorers_failing_is_unavailable(self):
        fetcher, _ = make_fetcher([
            (r"blockstream\.info/api/address/", UpstreamTimeout("timed out")),
            (r"mempool\.space/api/address/", (503, {})),
        ])
        result = run_source("blockstream_btc",
                            context_for("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)


class EthereumTests(unittest.TestCase):
    def test_eoa_balance_and_nonce(self):
        fetcher, transport = make_fetcher([(r"https://(ethereum-rpc|eth|cloudflare|1rpc|rpc)\S*", eth_route())])
        result = run_source("ethereum_rpc", context_for(ETH_ADDRESS, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["balance_eth"], "2 ETH")
        self.assertEqual(result.data["outbound_tx_count"], 42)
        self.assertFalse(result.data["is_contract"])
        self.assertEqual(len(transport.calls), 3)  # balance, nonce, code
        bodies = [json.loads(c["body"]) for c in transport.calls]
        self.assertEqual([b["params"] for b in bodies], [[ETH_ADDRESS, "latest"]] * 3)

    def test_contract_detection(self):
        fetcher, _ = make_fetcher([(r"https://\S*", eth_route(code=ETH_WITH_CODE))])
        result = run_source("ethereum_rpc", context_for(ETH_ADDRESS, fetcher=fetcher))
        self.assertTrue(result.data["is_contract"])
        self.assertEqual(result.data["code_size_bytes"], 5)
        self.assertTrue(any("smart contract" in f.title for f in result.findings))

    def test_endpoint_failover(self):
        def route(**kwargs):
            if "publicnode" in kwargs["url"]:
                raise UpstreamTimeout("timed out")
            return eth_route()(**kwargs)

        fetcher, transport = make_fetcher([(r"https://\S*", route)])
        result = run_source("ethereum_rpc", context_for(ETH_ADDRESS, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_OK)
        self.assertNotEqual(result.data["rpc_endpoint"], "ethereum-rpc.publicnode.com")
        self.assertTrue(result.data["errors"])
        self.assertGreater(len(transport.calls), 3)

    def test_all_endpoints_failing_is_unavailable_and_lists_them(self):
        fetcher, _ = make_fetcher([(r"https://\S*", UpstreamTimeout("timed out"))])
        result = run_source("ethereum_rpc", context_for(ETH_ADDRESS, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("publicnode.com", result.message)
        self.assertTrue(result.data["errors"])

    def test_rpc_error_object_is_not_treated_as_zero_balance(self):
        def route(**kwargs):
            return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "limit exceeded"}}

        fetcher, _ = make_fetcher([(r"https://\S*", route)])
        result = run_source("ethereum_rpc", context_for(ETH_ADDRESS, fetcher=fetcher))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("limit exceeded", json.dumps(result.data["errors"]))


class HibpTests(unittest.TestCase):
    """HIBP API v3: key-gated, two authenticated calls, documented status codes."""

    def test_without_key_nothing_is_sent(self):
        fetcher, transport = make_fetcher(hibp_routes())
        result = run_source("hibp_breaches", context_for("person@example.com", fetcher=fetcher))
        self.assertEqual(result.status, STATUS_NOT_CHECKED)
        self.assertEqual(transport.calls, [])
        self.assertIn("API key", result.message)
        self.assertIn("Settings", result.hint)
        # The k-anonymity password check must still be advertised as keyless.
        self.assertIn("k-anonymity", result.message)
        # The hint tells the truth about what a key costs and how fast it is.
        self.assertIn("3.95", result.hint)
        self.assertIn("10 authenticated requests per minute", result.hint)

    def test_with_key_the_email_is_sent_with_a_disclosure(self):
        fetcher, transport = make_fetcher(hibp_routes())
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["breach_count"], 1)
        self.assertEqual(result.data["api_version"], "v3")
        self.assertEqual(transport.calls[0]["headers"]["hibp-api-key"], "HIBPKEY")
        self.assertIn("person%40example.com", transport.calls[0]["url"])
        self.assertIn("full email address", result.sends)  # disclosed to the user up front
        self.assertTrue(any(f.severity == "high" and "Passwords were exposed" in f.title for f in result.findings))

    def test_both_calls_send_the_key_and_a_descriptive_user_agent(self):
        # HIBP returns 401 without the key and 403 without a user-agent header.
        fetcher, transport = make_fetcher(hibp_routes(pastes=HIBP_PASTES))
        run_source("hibp_breaches", context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(len(transport.calls), 2)
        for call in transport.calls:
            self.assertEqual(call["headers"]["hibp-api-key"], "HIBPKEY")
            self.assertTrue(call["headers"]["User-Agent"].strip(), "HIBP requires a descriptive user agent")
            self.assertIn("Verdigris", call["headers"]["User-Agent"])
        self.assertIn("/api/v3/breachedaccount/", transport.calls[0]["url"])
        self.assertIn("/api/v3/pasteaccount/", transport.calls[1]["url"])
        # Full breach model, unverified entries included - both documented defaults
        # are made explicit rather than left to change underneath us.
        self.assertIn("truncateResponse=false", transport.calls[0]["url"])
        self.assertIn("includeUnverified=true", transport.calls[0]["url"])

    def test_paste_appearances_are_reported_as_their_own_finding(self):
        fetcher, _ = make_fetcher(hibp_routes(pastes=HIBP_PASTES))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["paste_count"], 2)
        paste_findings = [f for f in result.findings if "paste" in f.title.lower()]
        self.assertEqual(len(paste_findings), 1)
        self.assertIn("Pastebin", paste_findings[0].evidence[0].label)
        # Pastes are unverified and transient; the report must say so.
        self.assertIn("transient", paste_findings[0].interpretation.lower())

    def test_entries_hibp_flags_are_not_counted_as_credible_breaches(self):
        fetcher, _ = make_fetcher(hibp_routes(breaches=HIBP_SPAMMY_BREACHES))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["breach_count"], 2)
        finding = result.findings[0]
        self.assertEqual(finding.severity, "low")  # no credible breach, no password exposure claim
        self.assertIn("spam list", finding.title.lower())
        labels = " ".join(e.label for e in finding.evidence)
        self.assertIn("Entries HIBP flags as spam list, fabricated or malware", labels)
        self.assertIn("Credible breaches", labels)
        credible = [e for e in finding.evidence if e.label == "Credible breaches"][0]
        self.assertEqual(credible.value, "0")

    def test_stealer_log_entries_are_labelled_as_such(self):
        fetcher, _ = make_fetcher(hibp_routes(breaches=HIBP_STEALER_LOG_BREACHES))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        labels = " ".join(e.label for e in result.findings[0].evidence)
        self.assertIn("Entries sourced from stealer logs", labels)

    def test_display_uses_the_title_and_the_link_uses_the_internal_name(self):
        fetcher, _ = make_fetcher(hibp_routes())
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        links = {e.label: e.value for e in result.findings[0].links}
        self.assertIn("Adobe", links)  # Title is what HIBP says to show people
        self.assertEqual(links["Adobe"], "https://haveibeenpwned.com/breach/Adobe")

    def test_no_breaches_is_no_match_and_says_what_the_api_hides(self):
        fetcher, _ = make_fetcher(hibp_routes(breaches=(404, {})))
        result = run_source("hibp_breaches",
                            context_for("clean@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("sensitive or retired breaches", result.message)
        self.assertNotIn("guarantee", result.message.replace("not a guarantee", ""))

    def test_no_breaches_but_pastes_found_is_a_real_result(self):
        fetcher, _ = make_fetcher(hibp_routes(breaches=(404, {}), pastes=HIBP_PASTES))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["breach_count"], 0)
        self.assertEqual(result.data["paste_count"], 2)

    def test_bad_key_is_unavailable_and_blames_the_key(self):
        fetcher, _ = make_fetcher(hibp_routes(breaches=(401, {})))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "BAD"}))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("key", result.message.lower())
        self.assertIn("401", result.message)

    def test_403_is_not_blamed_on_the_key(self):
        # Per HIBP's docs, 403 means "no user agent was specified", not a bad key.
        fetcher, _ = make_fetcher(hibp_routes(breaches=(403, {})))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_UNAVAILABLE)
        self.assertIn("user-agent", result.message.lower())
        self.assertNotIn("rejected the api key", result.message.lower())

    def test_rate_limit_explains_that_hibp_limits_per_key(self):
        fetcher, _ = make_fetcher(hibp_routes(breaches=(429, {})))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_RATE_LIMITED)
        self.assertIn("per key", result.message)
        self.assertNotIn("shared IP", result.message)  # that would be wrong for HIBP
        self.assertNotIn("1.5s", result.message)       # the retired v2-era limit

    def test_paste_failure_does_not_hide_the_breach_result(self):
        fetcher, _ = make_fetcher(hibp_routes(pastes=UpstreamTimeout("timed out")))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["breach_count"], 1)
        self.assertEqual(result.data["paste_count"], 0)
        self.assertIn("Paste search failed", result.data["paste_note"])
        self.assertIn("breach results are unaffected", result.data["paste_note"])

    def test_paste_401_suggests_the_key_may_not_cover_pastes(self):
        # Observed against HIBP's own integration-test domain: the documented test
        # key is accepted by breachedaccount but refused by pasteaccount.
        fetcher, _ = make_fetcher(hibp_routes(pastes=(401, {})))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertEqual(result.data["breach_count"], 1)
        self.assertIn("may not include paste access", result.data["paste_note"])

    def test_paste_rate_limit_is_reported_but_not_fatal(self):
        fetcher, _ = make_fetcher(hibp_routes(pastes=(429, {})))
        result = run_source("hibp_breaches",
                            context_for("person@example.com", fetcher=fetcher, keys={"hibp": "HIBPKEY"}))
        self.assertEqual(result.status, STATUS_OK)
        self.assertIn("rate-limited", result.data["paste_note"])


if __name__ == "__main__":
    unittest.main()
