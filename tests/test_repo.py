"""Repository hygiene, packaging and deployment-artifact tests.

These run offline and guard the things that silently break a deployment or leak
something: the Dockerfile contract, the Render Blueprint, ignore files, the
no-dependency rule, the outbound-host allowlist, secret-shaped strings in tracked
files, and the frontend's CSP-compatible rendering rules.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import unittest

from stubs import *  # noqa: F401,F403

from app.config import ALLOWED_HOSTS, SETTINGS
from app.server import SECURITY_HEADERS, STATIC_FILES
from app.sources import public_catalogue, registry

REPO = pathlib.Path(__file__).resolve().parent.parent

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{36}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"sk-[A-Za-z0-9]{32,}",
]

# Hosts that appear in the code only as documentation or as links shown to the
# user - the backend never fetches them, so they are (correctly) not allowlisted.
LINK_ONLY_HOSTS = {
    "about.sourcegraph.com", "auth.abuse.ch", "blockchair.com", "developers.google.com",
    "docs.alienvault.com", "docs.github.com", "docs.gitlab.com", "docs.gravatar.com",
    "docs.virustotal.com", "eth.blockscout.com", "ethereum.org", "etherscan.io",
    "about.rdap.org", "github.com", "news.ycombinator.com",
    "safebrowsing.google.com", "support.github.com", "support.google.com", "www.bing.com",
    "www.fcc.gov", "www.iana.org", "www.icann.org", "www.mediawiki.org",
}


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True,
                             timeout=30, check=True)
        files = [line for line in out.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError):
        files = []
    if files:
        return files
    # Fallback for environments without git metadata (e.g. an exported archive).
    skip = {".git", "__pycache__", "node_modules", ".venv"}
    found = []
    for root, dirs, names in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in names:
            found.append(str(pathlib.Path(root, name).relative_to(REPO)))
    return sorted(found)


class DockerfileTests(unittest.TestCase):
    def setUp(self):
        self.text = (REPO / "Dockerfile").read_text()

    def test_slim_base_and_no_runtime_dependencies(self):
        self.assertIn("FROM python:3.12-slim", self.text)
        self.assertNotIn("pip install", self.text)  # stdlib only: nothing to install
        self.assertNotIn("requirements.txt", self.text)

    def test_runs_as_non_root(self):
        self.assertRegex(self.text, r"USER\s+\S+")
        self.assertIn("useradd", self.text)
        user_line = [line for line in self.text.splitlines() if line.strip().startswith("USER")][-1]
        self.assertNotEqual(user_line.split()[-1], "root")

    def test_honours_port_and_has_a_healthcheck(self):
        self.assertIn("EXPOSE 8080", self.text)
        self.assertIn("PORT", self.text)
        self.assertIn("HEALTHCHECK", self.text)
        self.assertIn("/health", self.text)

    def test_entrypoint_is_the_app(self):
        self.assertIn('CMD ["python", "-m", "app.server"]', self.text)
        self.assertIn("COPY app ./app", self.text)

    def test_dockerignore_keeps_the_image_small_and_clean(self):
        ignore = (REPO / ".dockerignore").read_text()
        for entry in (".git", "tests", "tools", "docs", ".env", "*.md"):
            self.assertIn(entry, ignore, entry)


class RenderBlueprintTests(unittest.TestCase):
    def setUp(self):
        self.text = (REPO / "render.yaml").read_text()

    def test_web_service_on_the_free_plan_with_docker(self):
        self.assertIn("type: web", self.text)
        self.assertIn("plan: free", self.text)
        self.assertIn("runtime: docker", self.text)
        self.assertNotIn("type: static", self.text)  # must be a Web Service, not a Static Site
        for paid in ("plan: starter", "plan: standard", "plan: pro", "plan: enterprise"):
            self.assertNotIn(paid, self.text)

    def test_health_check_and_dockerfile_paths(self):
        self.assertIn("healthCheckPath: /health", self.text)
        self.assertIn("dockerfilePath: ./Dockerfile", self.text)

    def test_optional_keys_are_declared_empty(self):
        for key in ("ACCESS_TOKEN", "HIBP_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSECH_AUTH_KEY",
                    "GITHUB_TOKEN", "DISABLED_SOURCES"):
            self.assertRegex(self.text, rf"- key: {key}\n\s+value: \"\"", key)

    def test_no_secret_values_are_committed(self):
        for pattern in SECRET_PATTERNS:
            self.assertIsNone(re.search(pattern, self.text), pattern)


class IgnoreFileTests(unittest.TestCase):
    def test_env_keys_and_scan_artifacts_are_ignored(self):
        ignore = (REPO / ".gitignore").read_text()
        for entry in (".env", "*.key", "*.pem", "scan-history*.json", "*-export.json",
                      "__pycache__/", "node_modules/"):
            self.assertIn(entry, ignore, entry)
        self.assertIn("!.env.example", ignore)  # the template stays tracked

    def test_example_env_file_exists_and_is_safe(self):
        example = (REPO / ".env.example").read_text()
        for pattern in SECRET_PATTERNS:
            self.assertIsNone(re.search(pattern, example), pattern)
        secrets = ("ACCESS_TOKEN", "HIBP_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSECH_AUTH_KEY",
                   "GITHUB_TOKEN")
        for line in example.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            value = value.split("#", 1)[0].strip()  # inline comments are documentation
            if key.strip() in secrets:
                self.assertEqual(value, "", f"{key} has a real value in .env.example")
        for documented in ("PORT", "ACCESS_TOKEN", "HIBP_API_KEY", "VIRUSTOTAL_API_KEY",
                           "ABUSECH_AUTH_KEY", "GITHUB_TOKEN", "DISABLED_SOURCES", "ETH_RPC_URLS",
                           "REQUEST_LOG", "TRUST_PROXY_HEADERS", "SOURCE_DEBUG",
                           "RATE_SCAN_PER_MIN", "RATE_API_PER_MIN", "RATE_PASSWORD_PER_MIN"):
            self.assertIn(documented + "=", example, documented)


class ReadmeTests(unittest.TestCase):
    def setUp(self):
        self.text = (REPO / "README.md").read_text()

    def test_states_non_affiliation_with_serus(self):
        self.assertIn("not affiliated with", self.text.lower())
        self.assertIn("serus", self.text.lower())

    def test_documents_deployment_and_free_tier_limits(self):
        for phrase in ("render.com/deploy", "Free plan", "Cold starts", "onrender.com",
                       "No authentication by default", "/health", "PORT"):
            self.assertIn(phrase, self.text, phrase)

    def test_documents_local_run_and_tests(self):
        self.assertIn("python3 -m app.server", self.text)
        self.assertIn("python3 -m unittest discover", self.text)
        self.assertIn("docker build", self.text)

    def test_documents_honesty_rules(self):
        lowered = self.text.lower()
        for phrase in ("insufficient data", "not checked", "deterministic-rules-v1",
                       "no numeric", "dark web", "k-anonymity", "source unavailable",
                       "no simulated"):
            self.assertIn(phrase, lowered, phrase)

    def test_legacy_readme_is_preserved_not_deleted(self):
        legacy = REPO / "docs" / "legacy" / "README-solomons-bbq-bot-twilio.md"
        self.assertTrue(legacy.exists())
        self.assertTrue(legacy.read_text().strip())


class DependencyFreeTests(unittest.TestCase):
    def test_backend_imports_only_the_standard_library(self):
        allowed = set(sys.stdlib_module_names) | {"app", "tests", "tools", "stubs"}
        offenders = []
        for path in sorted((REPO / "app").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [] if node.level else [(node.module or "").split(".")[0]]
                else:
                    continue
                for name in names:
                    if name and name not in allowed:
                        offenders.append(f"{path.relative_to(REPO)}: {name}")
        self.assertEqual(offenders, [])

    def test_no_requirements_or_lockfile_is_needed(self):
        for name in ("requirements.txt", "Pipfile", "pyproject.toml", "poetry.lock"):
            self.assertFalse((REPO / name).exists(), name)


class AllowlistTests(unittest.TestCase):
    def test_every_host_in_the_code_is_allowlisted_or_link_only(self):
        hosts: set[str] = set()
        for path in list((REPO / "app").rglob("*.py")):
            for match in re.finditer(r"https://([a-zA-Z0-9.\-]+)", path.read_text(encoding="utf-8")):
                hosts.add(match.group(1).lower())
        unknown = sorted(hosts - set(ALLOWED_HOSTS) - LINK_ONLY_HOSTS)
        self.assertEqual(unknown, [], "hosts referenced in code but neither allowlisted nor link-only")

    def test_allowlist_entries_have_a_purpose(self):
        self.assertGreaterEqual(len(ALLOWED_HOSTS), 50)
        for host, purpose in ALLOWED_HOSTS.items():
            self.assertTrue(purpose.strip(), host)
            self.assertNotIn("*", host, host)  # no wildcards: exact hosts only

    def test_ethereum_endpoints_are_all_allowlisted(self):
        from app.config import ethereum_rpc_endpoints

        for endpoint in ethereum_rpc_endpoints():
            host = re.sub(r"^https://", "", endpoint).split("/")[0]
            self.assertIn(host, ALLOWED_HOSTS, endpoint)

    def test_fetcher_rejects_an_unlisted_host(self):
        from app.http_client import UpstreamBlocked, validate_url

        with self.assertRaises(UpstreamBlocked):
            validate_url("https://definitely-not-allowlisted.example/")


class SourceCatalogueTests(unittest.TestCase):
    def test_ids_are_unique_and_well_described(self):
        specs = registry()
        self.assertEqual(len(specs), len(public_catalogue()))
        self.assertGreaterEqual(len(specs), 20)
        for source_id, spec in specs.items():
            self.assertEqual(spec.id, source_id)
            self.assertTrue(spec.name.strip(), source_id)
            self.assertTrue(spec.category.strip(), source_id)
            self.assertTrue(spec.applies_to, source_id)
            self.assertTrue(spec.sends.strip(), source_id)  # privacy disclosure is mandatory
            self.assertTrue(spec.description.strip(), source_id)
            self.assertTrue(spec.docs.startswith("https://"), source_id)
            for kind in spec.applies_to:
                self.assertIn(kind, ("domain", "email", "username", "name", "phone",
                                     "bitcoin", "ethereum"), source_id)

    def test_key_gated_sources_declare_their_key(self):
        keyed = {spec.id: spec.key_name for spec in registry().values() if spec.key_name}
        self.assertIn("hibp_breaches", keyed)
        self.assertIn("virustotal", keyed)
        self.assertEqual(keyed["hibp_breaches"], "hibp")
        self.assertEqual(keyed["virustotal"], "virustotal")

    def test_disabled_sources_are_reported_not_hidden(self):
        for source in public_catalogue():
            self.assertIn("requires_key", source)
        self.assertIsInstance(SETTINGS.disabled_sources, frozenset)


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.static = REPO / "app" / "static"
        self.html = (self.static / "index.html").read_text()
        self.js = (self.static / "app.js").read_text()

    def test_all_declared_static_files_exist(self):
        for name in STATIC_FILES:
            path = self.static / name
            self.assertTrue(path.exists(), name)
            self.assertTrue(path.stat().st_size > 0, name)

    def test_no_inline_script_or_style_so_the_strict_csp_holds(self):
        self.assertNotRegex(self.html, r"<script(?![^>]*\ssrc=)")
        self.assertNotIn("<style", self.html)
        self.assertNotIn("onclick=", self.html)
        self.assertNotIn("javascript:", self.html)

    def test_assets_are_same_origin(self):
        for match in re.finditer(r'(?:src|href)="([^"]+)"', self.html):
            target = match.group(1)
            if target.startswith("#"):
                continue
            self.assertTrue(target.startswith("/"), target)  # no cross-origin loads
            self.assertFalse(target.startswith("//"), target)

    def test_js_never_renders_upstream_text_as_markup(self):
        for token in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(token, self.js, token)

    def test_js_uses_relative_api_urls_only(self):
        for match in re.finditer(r'fetch\("([^"]+)"', self.js):
            self.assertTrue(match.group(1).startswith("/api/"), match.group(1))
        self.assertNotIn("localhost", self.js)
        self.assertNotIn("127.0.0.1", self.js)

    def test_csp_has_no_escape_hatches(self):
        csp = SECURITY_HEADERS["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(SECURITY_HEADERS["X-Frame-Options"], "DENY")

    def test_manifest_is_valid_json_and_names_the_product(self):
        manifest = json.loads((self.static / "manifest.webmanifest").read_text())
        self.assertIn("Verdigris", manifest["name"])
        self.assertTrue(manifest["icons"])

    def test_ui_states_the_serus_disclaimer_and_the_no_auth_notice(self):
        self.assertIn("not affiliated with", self.html.lower())
        self.assertIn("Serus", self.html)
        self.assertIn("serus.ai", self.html)
        # The About view is rendered from app.js; it must disclose the open deployment.
        self.assertIn("No authentication by default", self.js)
        self.assertIn("anyone with the URL can run scans", self.js)
        self.assertIn("ACCESS_TOKEN", self.js)
        self.assertIn("no simulated results", (self.html + self.js).lower())


class NoSecretsTests(unittest.TestCase):
    def test_tracked_files_contain_no_secret_shaped_strings(self):
        offenders = []
        for relative in tracked_files():
            path = REPO / relative
            if not path.is_file() or path.stat().st_size > 2_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pattern in SECRET_PATTERNS:
                if re.search(pattern, text):
                    offenders.append(f"{relative}: {pattern}")
        self.assertEqual(offenders, [])

    def test_env_and_history_artifacts_are_not_tracked(self):
        tracked = tracked_files()
        self.assertNotIn(".env", tracked)
        for relative in tracked:
            self.assertFalse(relative.endswith("-export.json"), relative)
            self.assertFalse(relative.startswith("scan-history"), relative)
            self.assertFalse(re.search(r"(secret|credential|token)s?\.(json|txt|env)$", relative),
                             relative)

    def test_legacy_work_is_preserved(self):
        self.assertIn("docs/legacy/README-solomons-bbq-bot-twilio.md", tracked_files())


if __name__ == "__main__":
    unittest.main()
