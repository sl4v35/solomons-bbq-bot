"""End-to-end HTTP tests: a real server on an ephemeral port, stubbed upstreams.

These cover the deployment acceptance criteria: /health, static assets, unknown
routes, path traversal, security headers, rate limits, optional access token,
identifier validation and one full scan round-trip.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

from stubs import *  # noqa: F401,F403
from stubs import HIBP_RANGE, UpstreamTimeout, make_fetcher

import app.server as server
from app.config import SETTINGS
from app.jobs import STORE
from app.server import SECURITY_HEADERS, _sanitise_keys

BASE_HOST = "127.0.0.1"


def request(port, path, method="GET", body=None, headers=None, timeout=20):
    url = f"http://{BASE_HOST}:{port}{path}"
    data = None
    hdrs = {"Accept": "application/json"}
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = response.read()
            return response.status, dict(response.headers), payload
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, dict(exc.headers), payload


def as_json(payload):
    return json.loads(payload.decode("utf-8"))


class ServerUnderTest(unittest.TestCase):
    """Base class that boots the app once per test class."""

    routes: list = []

    @classmethod
    def setUpClass(cls):
        fetcher, cls.transport = make_fetcher(cls.routes, default=UpstreamTimeout("no route"))
        cls.saved_fetcher = STORE.fetcher
        STORE.fetcher = fetcher
        cls.httpd = server.serve(BASE_HOST, 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.thread.join(timeout=5)
        cls.httpd.server_close()
        STORE.fetcher = cls.saved_fetcher

    def setUp(self):
        server.LIMITER.reset()
        self.saved_token = SETTINGS.access_token
        self.saved_log = SETTINGS.request_log
        self.saved_limits = SETTINGS.limits
        # Generous limits by default so unrelated tests never trip the buckets;
        # RateLimitTests installs tight ones of its own.
        SETTINGS.limits = dataclasses.replace(
            self.saved_limits, rate_scan_per_min=100000, rate_api_per_min=100000,
            rate_password_per_min=100000,
        )

    def tearDown(self):
        SETTINGS.access_token = self.saved_token
        SETTINGS.request_log = self.saved_log
        SETTINGS.limits = self.saved_limits

    def get(self, path, **kwargs):
        return request(self.port, path, **kwargs)


class HealthTests(ServerUnderTest):
    def test_health_is_json_and_reports_boolean_key_state_only(self):
        status, headers, payload = self.get("/health")
        self.assertEqual(status, 200)
        data = as_json(payload)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["app"], "Verdigris")
        self.assertGreaterEqual(data["sources_total"], 20)
        self.assertIn("cache", data)
        self.assertIn("jobs", data)
        self.assertIsInstance(data["auth_required"], bool)
        for name, configured in data["optional_keys_configured"].items():
            self.assertIsInstance(configured, bool, name)
        blob = payload.decode()
        # No secret material, ever - only booleans.
        for token in (SETTINGS.hibp_api_key, SETTINGS.virustotal_api_key, SETTINGS.github_token,
                      SETTINGS.abusech_auth_key, SETTINGS.access_token):
            if token:
                self.assertNotIn(token, blob)
        self.assertIn("application/json", headers["Content-Type"])

    def test_health_aliases(self):
        for path in ("/health", "/healthz", "/live"):
            self.assertEqual(self.get(path)[0], 200, path)

    def test_health_needs_no_access_token(self):
        SETTINGS.access_token = "s3cret"
        self.assertEqual(self.get("/health")[0], 200)


class StaticTests(ServerUnderTest):
    def test_index_and_assets(self):
        expected = {
            "/": "text/html",
            "/index.html": "text/html",
            "/styles.css": "text/css",
            "/app.js": "javascript",
            "/favicon.svg": "svg",
            "/manifest.webmanifest": "manifest",
            "/robots.txt": "text/plain",
        }
        for path, fragment in expected.items():
            status, headers, payload = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(fragment, headers["Content-Type"], path)
            self.assertTrue(payload, path)

    def test_index_mentions_the_product_and_the_no_affiliation_note(self):
        _, _, payload = self.get("/")
        html = payload.decode()
        self.assertIn("Verdigris", html)
        self.assertIn("not affiliated", html.lower())

    def test_head_requests_work_without_a_body(self):
        status, headers, payload = self.get("/index.html", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(payload, b"")
        self.assertGreater(int(headers["Content-Length"]), 0)

    def test_options_is_allowed(self):
        status, headers, _ = self.get("/api/meta", method="OPTIONS")
        self.assertEqual(status, 204)

    def test_post_to_a_static_path_is_405(self):
        status, _, payload = self.get("/styles.css", method="POST", body={})
        self.assertEqual(status, 405)
        self.assertEqual(as_json(payload)["error"]["code"], "method_not_allowed")

    def test_unknown_path_is_404(self):
        status, _, payload = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertEqual(as_json(payload)["error"]["code"], "not_found")

    def test_unknown_api_path_is_404_json(self):
        status, headers, payload = self.get("/api/nope")
        self.assertEqual(status, 404)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertEqual(as_json(payload)["error"]["code"], "not_found")

    def test_path_traversal_is_refused(self):
        for path in ("/../Dockerfile", "/..%2fDockerfile", "/%2e%2e/Dockerfile",
                     "/static/../../etc/passwd", "/styles.css/../../Dockerfile",
                     "/....//....//Dockerfile"):
            status, _, payload = self.get(path)
            self.assertIn(status, (400, 404), path)
            self.assertNotIn(b"FROM python", payload, path)

    def test_security_headers_on_every_response(self):
        for path in ("/", "/health", "/api/meta", "/nope"):
            _, headers, _ = self.get(path)
            for name, value in SECURITY_HEADERS.items():
                self.assertEqual(headers.get(name), value, f"{path} {name}")
            cache_control = headers.get("Cache-Control", "")
            self.assertTrue(cache_control.startswith(("no-store", "no-cache")), (path, cache_control))

    def test_csp_forbids_inline_script_and_third_party_connects(self):
        _, headers, _ = self.get("/")
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)


class MetaAndDetectTests(ServerUnderTest):
    def test_meta_describes_the_source_catalogue(self):
        status, _, payload = self.get("/api/meta")
        self.assertEqual(status, 200)
        data = as_json(payload)
        self.assertEqual(data["version"], "1.0.0")
        self.assertIn("domain", data["identifier_types"])
        self.assertEqual(len(data["sources"]), data.get("sources_total", len(data["sources"])))
        self.assertGreaterEqual(len(data["sources"]), 20)
        self.assertEqual(sorted(data["status_labels"]),
                         ["error", "no_match", "not_checked", "ok", "pending", "rate_limited", "unavailable"])
        for source in data["sources"]:
            self.assertTrue(source["sends"], source)  # every source discloses what it sends
            self.assertTrue(source["description"], source)
        self.assertIn("scan_rate_per_minute", data["limits"])

    def test_sources_endpoint(self):
        status, _, payload = self.get("/api/sources")
        self.assertEqual(status, 200)
        self.assertTrue(as_json(payload)["sources"])

    def test_detect_happy_paths(self):
        cases = {
            "example.com": "domain",
            "person@example.com": "email",
            "torvalds": "username",
            "Alan Turing": "name",
            "+442071234567": "phone",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": "bitcoin",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed": "ethereum",
        }
        for value, kind in cases.items():
            status, _, payload = self.get("/api/detect?identifier=" + urllib.parse.quote(value))
            self.assertEqual(status, 200, value)
            data = as_json(payload)
            self.assertTrue(data["ok"], value)
            self.assertEqual(data["identifier"]["type"], kind, value)

    def test_detect_rejects_garbage_with_422(self):
        for value in ("", "1.2.3.4", "not an identifier!!", "http://10.0.0.1/x"):
            status, _, payload = self.get("/api/detect?identifier=" + urllib.parse.quote(value))
            self.assertEqual(status, 422, value)
            self.assertFalse(as_json(payload)["ok"], value)

    def test_detect_rejects_oversized_input(self):
        status, _, _ = self.get("/api/detect?identifier=" + "a" * 5000)
        self.assertIn(status, (400, 414, 422))


class ScanRoundTripTests(ServerUnderTest):
    def test_phone_scan_completes_without_touching_the_network(self):
        status, _, payload = self.get("/api/scan", method="POST",
                                      body={"identifier": "+442071234567", "mode": "report"})
        self.assertEqual(status, 202)
        data = as_json(payload)
        scan_id = data["scan_id"]
        self.assertEqual(data["state"], "queued")
        self.assertEqual(data["poll"], f"/api/scans/{scan_id}")

        snapshot = None
        deadline = time.monotonic() + 20
        version = ""
        while time.monotonic() < deadline:
            status, _, payload = self.get(f"/api/scans/{scan_id}?since={version}")
            self.assertEqual(status, 200)
            body = as_json(payload)
            if body.get("unchanged"):
                time.sleep(0.05)
                continue
            snapshot = body
            version = str(body["version"])
            if body["state"] in ("complete", "failed"):
                break
            time.sleep(0.05)

        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["state"], "complete")
        self.assertEqual(snapshot["identifier"]["value"], "+442071234567")
        self.assertEqual([s["source_id"] for s in snapshot["sources"]], ["phone_local"])
        self.assertEqual(snapshot["sources"][0]["status"], "ok")
        self.assertTrue(snapshot["findings"])
        self.assertTrue(snapshot["privacy"])
        self.assertEqual(snapshot["coverage"]["third_party_queries"], 0)
        self.assertEqual(snapshot["summary"]["engine"], "deterministic-rules-v1")
        self.assertEqual(self.transport.calls, [])  # nothing left the process

    def test_incremental_polling_reports_unchanged(self):
        _, _, payload = self.get("/api/scan", method="POST", body={"identifier": "+15551234567"})
        scan_id = as_json(payload)["scan_id"]
        deadline = time.monotonic() + 20
        version = None
        while time.monotonic() < deadline:
            body = as_json(self.get(f"/api/scans/{scan_id}?since={version or ''}")[2])
            if body.get("unchanged"):
                return  # the contract we wanted
            version = str(body["version"])
            if body["state"] == "complete" and version is not None:
                body2 = as_json(self.get(f"/api/scans/{scan_id}?since={version}")[2])
                self.assertTrue(body2.get("unchanged"))
                return
            time.sleep(0.05)
        self.fail("scan never reported unchanged")

    def test_get_scan_is_supported_for_link_previews(self):
        status, _, payload = self.get("/api/scan?identifier=" + urllib.parse.quote("+15551234567"))
        self.assertEqual(status, 202)
        self.assertIn("scan_id", as_json(payload))

    def test_unknown_scan_explains_the_ttl(self):
        status, _, payload = self.get("/api/scans/abcdef0123456789")
        self.assertEqual(status, 404)
        data = as_json(payload)
        self.assertEqual(data["error"]["code"], "scan_not_found")
        self.assertIn("minutes", data["error"]["message"])

    def test_malformed_scan_ids_are_rejected(self):
        for scan_id in ("../health", "zzzz", "abc", "0" * 40):
            status, _, _ = self.get(f"/api/scans/{scan_id}")
            self.assertEqual(status, 404, scan_id)

    def test_invalid_requests_are_refused(self):
        cases = [
            ({"identifier": ""}, 400, "bad_identifier"),
            ({"identifier": "example.com", "mode": "turbo"}, 400, "bad_mode"),
            ({"identifier": "\x00\x01evil"}, 400, "bad_identifier"),
            ({"identifier": "a" * 400}, 400, "bad_identifier"),
            ({"identifier": "1.2.3.4"}, 422, None),
            ({"identifier": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"}, 422, None),
            ({"identifier": "example.com", "type": "passport"}, 422, None),
        ]
        for body, expected_status, expected_code in cases:
            status, _, payload = self.get("/api/scan", method="POST", body=body)
            self.assertEqual(status, expected_status, body)
            if expected_code:
                self.assertEqual(as_json(payload)["error"]["code"], expected_code, body)

    def test_malformed_json_body_is_400(self):
        status, _, payload = self.get("/api/scan", method="POST", body=b"{not json",
                                      headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertEqual(as_json(payload)["error"]["code"], "bad_json")

    def test_oversized_body_is_refused(self):
        status, _, _ = self.get("/api/scan", method="POST", body=b"x" * (1024 * 1024),
                                headers={"Content-Type": "application/json"})
        self.assertIn(status, (400, 413))


class PasswordRangeTests(ServerUnderTest):
    routes = [(r"api\.pwnedpasswords\.com/range/", HIBP_RANGE)]

    def test_prefix_lookup_proxies_only_the_prefix(self):
        status, _, payload = self.get("/api/password-range", method="POST", body={"prefix": "5baa6"})
        self.assertEqual(status, 200)
        data = as_json(payload)
        self.assertEqual(data["prefix"], "5BAA6")
        self.assertEqual(data["entry_count"], 3)
        self.assertEqual(self.transport.calls[-1]["url"], "https://api.pwnedpasswords.com/range/5BAA6")

    def test_bad_prefixes_are_refused(self):
        for prefix in ("", "12", "1234567", "ZZZZZ", "my-password", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"):
            status, _, payload = self.get("/api/password-range", method="POST", body={"prefix": prefix})
            self.assertEqual(status, 400, prefix)
            self.assertEqual(as_json(payload)["error"]["code"], "bad_prefix", prefix)
        self.assertEqual(self.transport.calls, [])

    def test_get_form_is_supported(self):
        status, _, payload = self.get("/api/password-range?prefix=5BAA6")
        self.assertEqual(status, 200)
        self.assertEqual(as_json(payload)["entry_count"], 3)


class PasswordRangeUpstreamDownTests(ServerUnderTest):
    routes = [(r"api\.pwnedpasswords\.com/range/", UpstreamTimeout("timed out"))]

    def test_upstream_failure_is_502_and_says_nothing_was_stored(self):
        status, _, payload = self.get("/api/password-range", method="POST", body={"prefix": "5BAA6"})
        self.assertEqual(status, 502)
        data = as_json(payload)
        self.assertEqual(data["error"]["code"], "upstream_unavailable")
        self.assertIn("Nothing was stored", data["error"]["message"])


class RateLimitTests(ServerUnderTest):
    def test_scan_rate_limit_returns_429_with_retry_after(self):
        original = self.saved_limits
        SETTINGS.limits = dataclasses.replace(original, rate_scan_per_min=1)
        try:
            statuses = []
            for _ in range(6):
                status, _, payload = self.get("/api/scan", method="POST", body={"identifier": "+15551234567"})
                statuses.append(status)
                if status == 429:
                    data = as_json(payload)
                    self.assertEqual(data["error"]["code"], "rate_limited")
                    self.assertGreater(data["error"]["retry_after_seconds"], 0)
                    self.assertIn("Retry-After", self.get("/api/scan", method="POST",
                                                           body={"identifier": "+15551234567"})[1])
                    break
            self.assertIn(429, statuses)
        finally:
            SETTINGS.limits = original

    def test_api_rate_limit_is_separate_from_the_scan_bucket(self):
        original = self.saved_limits
        SETTINGS.limits = dataclasses.replace(original, rate_api_per_min=2, rate_scan_per_min=100)
        try:
            detect_statuses = [self.get("/api/detect?identifier=example.com")[0] for _ in range(6)]
            self.assertIn(429, detect_statuses)
            # The scan bucket still has capacity.
            self.assertEqual(self.get("/api/scan", method="POST",
                                      body={"identifier": "+15551234567"})[0], 202)
        finally:
            SETTINGS.limits = original

    def test_limiter_is_bounded_in_memory(self):
        limiter = server.RateLimiter(max_buckets=8)
        for index in range(50):
            limiter.allow(f"ip-{index}", 60)
        self.assertLessEqual(len(limiter._buckets), 9)  # bounded, oldest half dropped
        limiter.reset()
        self.assertEqual(len(limiter._buckets), 0)


class AccessTokenTests(ServerUnderTest):
    def test_api_requires_the_token_when_configured(self):
        SETTINGS.access_token = "s3cret-token"
        status, _, payload = self.get("/api/meta")
        self.assertEqual(status, 401)
        self.assertEqual(as_json(payload)["error"]["code"], "access_token_required")

        status, _, _ = self.get("/api/meta", headers={"X-Access-Token": "s3cret-token"})
        self.assertEqual(status, 200)
        status, _, _ = self.get("/api/meta", headers={"Authorization": "Bearer s3cret-token"})
        self.assertEqual(status, 200)
        status, _, _ = self.get("/api/meta", headers={"X-Access-Token": "wrong"})
        self.assertEqual(status, 401)
        # Static UI stays reachable so the user can enter the token in Settings.
        self.assertEqual(self.get("/")[0], 200)
        self.assertEqual(self.get("/health")[0], 200)


class LoggingTests(ServerUnderTest):
    def test_access_log_has_no_query_string_or_identifier(self):
        SETTINGS.request_log = True
        captured = io.StringIO()
        saved = sys.stderr
        sys.stderr = captured
        try:
            self.get("/api/detect?identifier=" + urllib.parse.quote("person@example.com"))
            self.get("/api/scan?identifier=" + urllib.parse.quote("+442071234567"))
        finally:
            sys.stderr = saved
        log = captured.getvalue()
        self.assertTrue(log.strip())
        self.assertNotIn("person@example.com", log)
        self.assertNotIn("person%40example.com", log)
        self.assertNotIn("+442071234567", log)
        self.assertNotIn("identifier=", log)
        self.assertIn("/api/detect", log)

    def test_logging_can_be_switched_off(self):
        SETTINGS.request_log = False
        captured = io.StringIO()
        saved = sys.stderr
        sys.stderr = captured
        try:
            self.get("/health")
        finally:
            sys.stderr = saved
        self.assertNotIn("/health", captured.getvalue())


class SanitiseKeysTests(unittest.TestCase):
    def test_only_known_keys_survive(self):
        cleaned = _sanitise_keys({"HIBP": " abc ", "virustotal": "VT", "evil": "x", "github": 5,
                                  "abusech": "", "urlscan": "y" * 500, "otx": "z"})
        self.assertEqual(cleaned, {"hibp": "abc", "virustotal": "VT", "otx": "z"})

    def test_non_dict_input(self):
        self.assertEqual(_sanitise_keys(None), {})
        self.assertEqual(_sanitise_keys("hibp=abc"), {})
        self.assertEqual(_sanitise_keys([1, 2]), {})


class PortBindingTests(unittest.TestCase):
    def test_server_honours_an_explicit_port_and_binds_all_interfaces(self):
        # Render supplies PORT; the app must bind 0.0.0.0 and use it.
        fetcher, _ = make_fetcher([])
        saved = STORE.fetcher
        STORE.fetcher = fetcher
        original_host, original_port = SETTINGS.host, SETTINGS.port
        SETTINGS.host, SETTINGS.port = "0.0.0.0", 0
        httpd = server.serve()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            self.assertGreater(port, 0)
            status, _, _ = request(port, "/health")
            self.assertEqual(status, 200)
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
            httpd.server_close()
            STORE.fetcher = saved
            SETTINGS.host, SETTINGS.port = original_host, original_port

    def test_settings_read_port_from_the_environment(self):
        from app import config

        os.environ["PORT"] = "8123"
        try:
            reloaded = config.Settings()  # re-reads the environment
            self.assertEqual(reloaded.port, 8123)
            self.assertEqual(reloaded.host, "0.0.0.0")
        finally:
            del os.environ["PORT"]


if __name__ == "__main__":
    unittest.main()
