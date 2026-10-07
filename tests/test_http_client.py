"""Unit tests for the safe outbound HTTP client (allowlist, SSRF guard, limits)."""

from __future__ import annotations

import io
import socket
import unittest
import urllib.request

from stubs import *  # noqa: F401,F403
from stubs import Response, StubTransport, UpstreamHTTPError, UpstreamRateLimited, UpstreamTimeout, make_fetcher

import app.http_client as hc
from app.http_client import (
    CACHE,
    TTLCache,
    UpstreamBlocked,
    UpstreamTooLarge,
    _is_public_ip,
    _read_capped,
    assert_public_resolution,
    parse_sse_events,
    validate_url,
)


class AllowlistTests(unittest.TestCase):
    def test_allowlisted_host_is_accepted(self):
        parsed = validate_url("https://api.github.com/users/torvalds")
        self.assertEqual(parsed.hostname, "api.github.com")

    def test_unknown_host_is_blocked(self):
        with self.assertRaises(UpstreamBlocked):
            validate_url("https://evil.example/steal?token=1")

    def test_subdomain_is_not_implicitly_allowed(self):
        with self.assertRaises(UpstreamBlocked):
            validate_url("https://evil.api.github.com/")

    def test_plain_http_is_blocked(self):
        with self.assertRaises(UpstreamBlocked):
            validate_url("http://api.github.com/users/torvalds")

    def test_non_standard_port_is_blocked(self):
        with self.assertRaises(UpstreamBlocked):
            validate_url("https://api.github.com:8443/users/torvalds")

    def test_bootstrap_redirect_exception_is_scoped(self):
        # The RDAP bootstrap exception allows an unknown https host...
        validate_url("https://rdap.some-registry.example/domain/example.com", bootstrap_redirect=True)
        # ...but only when the caller explicitly asks for it.
        with self.assertRaises(UpstreamBlocked):
            validate_url("https://rdap.some-registry.example/domain/example.com")

    def test_fetcher_refuses_to_reach_unknown_hosts(self):
        fetcher, transport = make_fetcher([])
        with self.assertRaises(UpstreamBlocked):
            fetcher.request("https://attacker.example/")
        self.assertEqual(transport.calls, [])  # never even attempted


class SsrfGuardTests(unittest.TestCase):
    def test_private_ranges_are_rejected(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.5.5", "169.254.169.254",
                   "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1"):
            self.assertFalse(_is_public_ip(ip), ip)

    def test_public_ranges_are_accepted(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"):
            self.assertTrue(_is_public_ip(ip), ip)

    def test_ipv4_mapped_private_ipv6_is_rejected(self):
        self.assertFalse(_is_public_ip("::ffff:127.0.0.1"))
        self.assertFalse(_is_public_ip("::ffff:169.254.169.254"))

    def test_garbage_ip_is_rejected(self):
        self.assertFalse(_is_public_ip("not-an-ip"))

    def test_resolution_to_private_address_is_blocked(self):
        original = socket.getaddrinfo

        def fake(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        hc.socket.getaddrinfo = fake
        try:
            with self.assertRaises(UpstreamBlocked):
                assert_public_resolution("api.github.com")
        finally:
            hc.socket.getaddrinfo = original

    def test_unresolvable_host_is_blocked(self):
        original = socket.getaddrinfo

        def fake(host, port, *args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        hc.socket.getaddrinfo = fake
        try:
            with self.assertRaises(UpstreamBlocked):
                assert_public_resolution("api.github.com")
        finally:
            hc.socket.getaddrinfo = original


class RedirectPolicyTests(unittest.TestCase):
    def _policy(self, bootstrap=False, max_redirects=3):
        return hc._RedirectPolicy(bootstrap_redirect=bootstrap, max_redirects=max_redirects)

    def _request(self, url="https://rdap.org/domain/example.com"):
        return urllib.request.Request(url, headers={"Accept": "application/rdap+json"})

    def test_redirect_to_allowlisted_host_is_followed(self):
        policy = self._policy()
        new = policy.redirect_request(self._request(), None, 302, "Found", {},
                                      "https://rdap.verisign.com/com/v1/domain/example.com")
        self.assertEqual(new.full_url, "https://rdap.verisign.com/com/v1/domain/example.com")

    def test_redirect_to_unknown_host_is_blocked(self):
        policy = self._policy()
        with self.assertRaises(UpstreamBlocked):
            policy.redirect_request(self._request(), None, 302, "Found", {}, "https://evil.example/x")

    def test_bootstrap_redirect_checks_public_ip(self):
        original = socket.getaddrinfo
        hc.socket.getaddrinfo = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        try:
            policy = self._policy(bootstrap=True)
            with self.assertRaises(UpstreamBlocked):
                policy.redirect_request(self._request(), None, 302, "Found", {},
                                        "https://registry-rdap.example/domain/example.com")
        finally:
            hc.socket.getaddrinfo = original

    def test_downgrade_to_http_is_blocked(self):
        policy = self._policy()
        with self.assertRaises(UpstreamBlocked):
            policy.redirect_request(self._request(), None, 302, "Found", {},
                                    "http://rdap.verisign.com/com/v1/domain/example.com")

    def test_redirect_loop_is_blocked(self):
        policy = self._policy(max_redirects=1)
        policy.redirect_request(self._request(), None, 302, "Found", {},
                                "https://rdap.verisign.com/com/v1/domain/example.com")
        with self.assertRaises(UpstreamBlocked):
            policy.redirect_request(self._request(), None, 302, "Found", {},
                                    "https://rdap.nic.google/domains/example.com")


class SizeAndTimeoutTests(unittest.TestCase):
    def test_response_size_cap(self):
        stream = io.BytesIO(b"x" * 5000)
        with self.assertRaises(UpstreamTooLarge):
            _read_capped(stream, 1024)

    def test_under_cap_is_returned_whole(self):
        stream = io.BytesIO(b"x" * 512)
        self.assertEqual(len(_read_capped(stream, 1024)), 512)

    def test_timeout_maps_to_upstream_timeout(self):
        fetcher, _ = make_fetcher([("dns.google", UpstreamTimeout("timed out"))])
        with self.assertRaises(UpstreamTimeout):
            fetcher.get_json("https://dns.google/resolve?name=example.com&type=A")

    def test_http_error_status_is_reported(self):
        fetcher, _ = make_fetcher([("urlscan.io", (500, {"error": "boom"}))])
        with self.assertRaises(UpstreamHTTPError) as ctx:
            fetcher.get_json("https://urlscan.io/api/v1/search/?q=domain:example.com")
        self.assertEqual(ctx.exception.status, 500)

    def test_429_maps_to_rate_limited(self):
        fetcher, _ = make_fetcher([("hn.algolia.com", (429, {}))])
        with self.assertRaises(UpstreamRateLimited):
            fetcher.get_json("https://hn.algolia.com/api/v1/users/pg")


class RetryTests(unittest.TestCase):
    def test_retries_transport_errors_then_succeeds(self):
        attempts = {"n": 0}

        def route(**kwargs):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise UpstreamTimeout("timed out")
            return Response(status=200, body=b'{"ok": true}', final_url=kwargs["url"], elapsed_ms=1)

        fetcher, _ = make_fetcher([("dns.google", route)])
        payload = fetcher.get_json("https://dns.google/resolve?name=example.com&type=A")
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(attempts["n"], 2)

    def test_does_not_retry_http_status_errors(self):
        attempts = {"n": 0}

        def route(**kwargs):
            attempts["n"] += 1
            raise UpstreamHTTPError("upstream returned HTTP 503", status=503)

        fetcher, _ = make_fetcher([("archive.org", route)])
        with self.assertRaises(UpstreamHTTPError):
            fetcher.get_json("https://archive.org/wayback/available?url=example.com")
        self.assertEqual(attempts["n"], 1)

    def test_gives_up_after_configured_attempts(self):
        fetcher, transport = make_fetcher([("dns.google", UpstreamTimeout("timed out"))])
        with self.assertRaises(UpstreamTimeout):
            fetcher.request_with_retry("https://dns.google/resolve?name=example.com&type=A", attempts=3)
        self.assertEqual(len(transport.calls), 3)


class CacheTests(unittest.TestCase):
    def test_ttl_cache_expiry_and_eviction(self):
        cache = TTLCache(max_entries=2, default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        self.assertEqual(cache.get("a"), 1)
        cache.set("c", 3)  # evicts the least recently used ("b")
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("c"), 3)
        cache.set("d", 4, ttl=-1)  # already expired
        self.assertIsNone(cache.get("d"))

    def test_identical_get_json_is_served_from_cache(self):
        fetcher, transport = make_fetcher([("dns.google", {"Status": 0, "Answer": []})])
        url = "https://dns.google/resolve?name=example.com&type=A"
        fetcher.get_json(url, cache_key="k1")
        fetcher.get_json(url, cache_key="k1")
        self.assertEqual(len(transport.calls), 1)

    def test_authenticated_responses_are_not_cached(self):
        fetcher, transport = make_fetcher([("haveibeenpwned.com", [{"Name": "Adobe"}])])
        url = "https://haveibeenpwned.com/api/v3/breachedaccount/a@b.c"
        fetcher.get_json(url, headers={"hibp-api-key": "secret"}, cache_key="k2")
        fetcher.get_json(url, headers={"hibp-api-key": "secret"}, cache_key="k2")
        self.assertEqual(len(transport.calls), 2)

    def test_error_responses_are_not_cached(self):
        fetcher, transport = make_fetcher([("archive.org", (500, {"error": "boom"}))])
        for _ in range(2):
            with self.assertRaises(UpstreamHTTPError):
                fetcher.get_json("https://archive.org/wayback/available?url=x", cache_key="k3")
        self.assertEqual(len(transport.calls), 2)

    def test_global_cache_is_bounded(self):
        self.assertLessEqual(CACHE.max_entries, 400)
        self.assertLessEqual(CACHE.default_ttl, 3600)


class SseParsingTests(unittest.TestCase):
    def test_parses_event_and_data(self):
        events = list(parse_sse_events("event: matches\ndata: [{\"a\":1}]\n\nevent: done\ndata: {}\n\n"))
        self.assertEqual(events, [("matches", '[{"a":1}]'), ("done", "{}")])

    def test_handles_crlf_and_multiline_data(self):
        events = list(parse_sse_events("event: x\r\ndata: line1\r\ndata: line2\r\n\r\n"))
        self.assertEqual(events, [("x", "line1\nline2")])

    def test_ignores_comments_and_defaults_event_name(self):
        events = list(parse_sse_events(": keep-alive\n\ndata: hello\n\n"))
        self.assertEqual(events, [("message", "hello")])

    def test_flushes_trailing_event_without_blank_line(self):
        events = list(parse_sse_events("event: matches\ndata: [1]"))
        self.assertEqual(events, [("matches", "[1]")])

    def test_strips_single_leading_space(self):
        events = list(parse_sse_events("data:nospace\n\ndata: withspace\n\n"))
        self.assertEqual(events, [("message", "nospace"), ("message", "withspace")])


class PostBodyTests(unittest.TestCase):
    def test_post_json_sends_json_body(self):
        fetcher, transport = make_fetcher([("ethereum-rpc.publicnode.com", {"jsonrpc": "2.0", "id": 1, "result": "0x0"})])
        fetcher.post_json("https://ethereum-rpc.publicnode.com", {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber"})
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertIn(b'"method"', call["body"])
        self.assertEqual(call["headers"]["Content-Type"], "application/json")

    def test_post_form_urlencodes_fields(self):
        fetcher, transport = make_fetcher([("urlhaus-api.abuse.ch", {"query_status": "no_results"})])
        fetcher.post_form("https://urlhaus-api.abuse.ch/v1/host/", {"host": "example.com"})
        call = transport.calls[0]
        self.assertEqual(call["body"], b"host=example.com")
        self.assertEqual(call["headers"]["Content-Type"], "application/x-www-form-urlencoded")


if __name__ == "__main__":
    unittest.main()
