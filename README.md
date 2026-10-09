# Verdigris

**Evidence-first public-source intelligence & privacy checks.**
Type one identifier — a domain, email address, username, person's name, phone number, or a
Bitcoin/Ethereum address — and Verdigris queries real public sources in parallel, then shows you
exactly what each one said, what it refused to say, and what it could not reach.

> Verdigris is an independent, unofficial project. It is **not affiliated with, endorsed by, or
> derived from Serus (serus.ai)** or any other commercial OSINT product. It shares no data with them.

No accounts. No credits. No paywall. No simulated or "demo" results: every row in the UI comes from
a live upstream call or is explicitly labelled as not checked / unavailable.

---

## Deploy it free on Render

The repository ships a Blueprint ([`render.yaml`](render.yaml)) that creates a **Free plan Web
Service** running the included [`Dockerfile`](Dockerfile).

**From a phone (Chrome/Android) or desktop:**

1. Open the deploy button:
   <https://render.com/deploy?repo=https://github.com/sl4v35/solomons-bbq-bot&branch=arena/6d72ca39-solomons-bbq-bot>
2. Sign in with GitHub (or create a free Render account) and authorise Render to reach the repository.
3. Press **Apply**. Render builds the Docker image and starts the service (usually 3–5 minutes).
4. Open the `https://<your-service>.onrender.com` URL Render shows you. That is the app.
5. Optional but recommended: open `https://<your-service>.onrender.com/health` — it should return
   JSON with `"status": "ok"`.

No credit card is needed for a Free Web Service, and nothing in this repository requests a paid
resource.

**Free-tier realities you should know before publishing the URL:**

- **Cold starts.** A free instance is spun down after ~15 minutes idle; the first request afterwards
  can take 30–60 seconds. This is normal, not a crash.
- **One instance, shared IP.** Every visitor's scans leave from the same IP, so free upstream APIs
  (GitHub search in particular) rate-limit the *deployment*, not just you. Verdigris reports that
  honestly as `Rate limited` with a hint, never as "no matches".
- **No authentication by default.** Anyone with the URL can use it, and their scans consume the same
  shared upstream quota. If that bothers you, set `ACCESS_TOKEN` (see below) — the API then requires
  a token, which the UI asks for in **Settings**.
- **Memory only.** Scan results live in RAM for 15 minutes and are never written to disk. Your
  browser keeps your own history in `localStorage`.

---

## What it does

| Feature | How it behaves |
| --- | --- |
| Auto-detection | Paste anything; the backend classifies it as domain / email / username / name / phone / bitcoin / ethereum, tells you what it decided and why, and lets you override the type. IP addresses and garbage are rejected with an explanation instead of a fake result. |
| Two modes | **OSINT lookup** (per-source results + findings) and **Evidence-based report** (adds a written summary, coverage gaps and removal/reporting links). |
| Per-source progress | Each source has its own row with a live status: `Checking…`, `Data returned`, `No match`, `Not checked`, `Unavailable`, `Rate limited`. |
| Findings | Severity (`critical`/`high`/`medium`/`low`/`info`), filters by severity and status, evidence rows, clickable source links, and two timestamps: when the scan ran and when the upstream data was recorded. |
| Honest absence | The UI legend keeps four states apart and never collapses them: **Data returned**, **No matches** (we looked, nothing there), **Not checked** (we deliberately did not look — not applicable, or it needs an API key you did not supply) and **Source unavailable** / **Rate limited** (we tried and it failed, which is *not* a clean result). |
| Coverage block | Every report states how many sources answered, how many found nothing, how many were skipped and how many failed, plus the exact list of upstream hosts contacted. |
| History | Stored in your browser only (`localStorage`), with per-entry delete, delete-all, and JSON export. Password checks are never added to history. |
| Optional keys | HIBP, VirusTotal, abuse.ch, GitHub, urlscan.io and OTX keys can be added in Settings. They stay in your browser and are sent per request; the server never logs or stores them. HIBP's API v3 is **paid**: the entry tier is about US$3.95/month and allows roughly 10 authenticated requests per minute, limited **per key** rather than per IP (this source spends up to two of those per scan: breaches, then pastes). |
| Password exposure check | Uses HIBP's **free, keyless** k-anonymity API. Your password is hashed **in the browser** (SHA-1), only the first 5 hex characters are sent to this server, and only those 5 characters are forwarded to `api.pwnedpasswords.com`. The full password and full hash never leave your device, and no endpoint in this app accepts a password. The request sends `Add-Padding: true`, so HIBP pads the response and its size does not reveal how common your prefix is; HIBP documents padded entries as always having a count of `0`, and this server discards them before the browser compares suffixes locally. |
| Removal links | Real removal/reporting/dispute pages per identifier type. Verdigris only opens them in a new tab — it never fills in or submits anything, and it never claims a request was made. |

### What it deliberately does not do

- No numeric "privacy score" or "risk score". When every source fails the report says
  **Insufficient data** rather than implying safety.
- No claims about paid people-search, credit-header, court, carrier/HLA or "full dark web" databases.
- No Tor or dark-web crawling, no login attempts, no access-control bypass, no non-public data.
- No AI/LLM in the summary. The report text is produced by a fixed rule engine
  (`deterministic-rules-v1`) and says so on every report.
- No artificial credits, no simulated data, no upsell.

### Interpretation rules baked into the findings

- A matching username or name is **not** proof of the same person — handles are re-used, squatted and shared.
- A threat-intel pulse, public scan archive or phishing-feed hit is a **third-party claim, not a verdict**.
- Phone analysis gives **format and country calling code only** — never the owner, carrier, active status or location.
- Blockchain data is public and permanent; an address is not a person (it may be an exchange or custodian).
- Gravatar lookups use an MD5 hash of the address; for common providers such hashes can be brute-forced by anyone.

---

## Sources

All 22 sources are real, public and keyless unless noted. Every one of them is listed in the UI with
what it sends, and the same list is served at `/api/meta`.

| ID | Name | Category | Applies to | Needs your key |
| --- | --- | --- | --- | --- |
| `wayback` | Internet Archive Wayback Machine | archives | domain, email | - |
| `blockstream_btc` | Bitcoin address (Blockstream) | blockchain | bitcoin | - |
| `ethereum_rpc` | Ethereum address (public JSON-RPC) | blockchain | ethereum | - |
| `hibp_breaches` | Have I Been Pwned (your key) — API v3 breaches *and* pastes | breaches | email | hibp |
| `codeberg_user` | Codeberg profile | code-hosting | username | - |
| `github_commits` | GitHub commit author search | code-hosting | email | - |
| `github_name` | GitHub people search | code-hosting | name | - |
| `github_user` | GitHub profile | code-hosting | username | - |
| `gitlab_user` | GitLab profile | code-hosting | username | - |
| `hackernews_user` | Hacker News profile | code-hosting | username | - |
| `keybase_user` | Keybase profile & identity proofs | code-hosting | username | - |
| `sourcegraph_code` | Sourcegraph public code search | code-hosting | email, username | - |
| `gravatar` | Gravatar public profile | identity | email, username | - |
| `phone_local` | Phone number analysis (local, nothing sent) | identity | phone | - |
| `dns_doh` | Google DNS-over-HTTPS | infrastructure | domain, email | - |
| `wikipedia_name` | Wikipedia name search | public-records | name | - |
| `rdap` | RDAP registration data | registry | domain, email | - |
| `openphish` | OpenPhish community feed | threat-intel | domain | - |
| `otx` | AlienVault OTX | threat-intel | domain | - |
| `urlhaus` | URLhaus malware URL feed | threat-intel | domain | abusech (optional) |
| `urlscan` | urlscan.io public scans | threat-intel | domain | - |
| `virustotal` | VirusTotal (your key) | threat-intel | domain | virustotal |

Notes that matter for honesty:

- URLhaus's **host API** now requires a free `Auth-Key` from <https://auth.abuse.ch>; without one
  Verdigris falls back to the public recent-URL feed and says which it used. Its bulk download
  endpoint is occasionally 503, so it is treated as best-effort, never as a hard dependency.
- urlscan.io is queried with `q=domain:<host>` only. The `verdict:` filter is a paid feature and is
  never used, so no result is presented as a verdict.
- Ethereum uses keyless public JSON-RPC endpoints (publicnode, llamarpc, Cloudflare, 1rpc, drpc,
  nodeflare), tried in order. They come and go; if none answer, the row says `Unavailable` and lists
  what was tried. Override with `ETH_RPC_URLS`.
- The Wayback availability API is called with a **bare domain** (no scheme), which is measurably more
  reliable.
- GitHub commit search returns a loose `total_count` and `incomplete_results`; Verdigris filters to
  the **exact** author/committer email and discloses when GitHub truncated the search.

---

## Privacy architecture

- **Same origin.** The UI and API are served by one process; the browser only ever talks to the host
  it loaded the page from (`connect-src 'self'` is enforced by CSP). There is no arbitrary-URL proxy
  anywhere in the codebase.
- **Fixed allowlist.** Outbound requests go to ~110 pinned hosts (`app/config.py`) over HTTPS/443
  only, with a DNS-resolution guard that refuses private/link-local/metadata addresses (SSRF
  protection), a redirect cap, per-request timeouts and response-size caps.
- **What leaves the server is disclosed per source**, both in the UI (`sends`) and in every report's
  privacy block. Sources that were not checked are recorded as "nothing - not checked".
- **Nothing is persisted server-side.** No database, no disk writes, no analytics. Scan jobs live in
  memory for 15 minutes. Access logs print the HTTP method and path only — never a query string,
  because identifiers are personal data (`REQUEST_LOG=0` disables even that).
- **Keys are never logged.** Optional API keys are held in your browser's `localStorage` and sent per
  request; on the server they exist only for the duration of that scan.

---

## Run it locally

Requires Python 3.11+ (3.12 in Docker). **There are no dependencies to install** — the backend is
standard library only, and the frontend is vanilla HTML/CSS/JS.

```bash
git clone https://github.com/sl4v35/solomons-bbq-bot.git
cd solomons-bbq-bot
python3 -m app.server                      # http://127.0.0.1:8080
PORT=9000 python3 -m app.server            # honour a hosting-provided port
python3 -m app.server --host 0.0.0.0 --port 8080
```

Docker (the same image Render builds):

```bash
docker build -t verdigris .
docker run --rm -p 8080:8080 -e PORT=8080 verdigris
curl -s localhost:8080/health
```

### Environment variables

All optional. See [`.env.example`](.env.example).

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | Port to bind. Render injects this. The bind address is always `0.0.0.0` (containers require it); use `python3 -m app.server --host 127.0.0.1` to change it locally. |
| `ACCESS_TOKEN` | empty | If set, every `/api/*` call needs `X-Access-Token: <token>` (or `Authorization: Bearer <token>`). `/health` and the static UI stay open so the token can be entered in Settings. |
| `HIBP_API_KEY` | empty | Server-side HIBP API v3 key for email breach + paste lookups (users can also supply their own per request). Paid: entry tier ≈ US$3.95/month, ~10 authenticated requests/minute per key. |
| `VIRUSTOTAL_API_KEY` | empty | Server-side VirusTotal key for domain reports. |
| `ABUSECH_AUTH_KEY` | empty | Free abuse.ch `Auth-Key` enabling the full URLhaus host history. |
| `GITHUB_TOKEN` | empty | Raises GitHub API rate limits (shared-IP deployments benefit most). |
| `DISABLED_SOURCES` | empty | Comma-separated source ids to turn off; the UI then reports them as disabled rather than pretending they ran. |
| `ETH_RPC_URLS` | built-in list | Comma-separated `https://` JSON-RPC endpoints, tried in order. |
| `TRUST_PROXY_HEADERS` | `1` | Trust the first `X-Forwarded-For` hop for per-IP rate limiting (correct behind Render's proxy). |
| `REQUEST_LOG` | `1` | Print `METHOD /path` per request. Never logs query strings. |
| `SOURCE_DEBUG` | `0` | Include exception detail in `Unavailable` messages. Leave off in public deployments. |
| `RATE_SCAN_PER_MIN` | `12` | Scans per minute per IP (burst = max(2, rate/3)). |
| `RATE_API_PER_MIN` | `60` | Other API calls per minute per IP (polling gets 4×). |
| `RATE_PASSWORD_PER_MIN` | `10` | k-anonymity prefix lookups per minute per IP. |

Rate limits return `429` with `Retry-After` and a JSON `retry_after_seconds`, and the UI shows the
wait instead of retrying in a loop.

---

## HTTP API

| Method & path | Purpose |
| --- | --- |
| `GET /health` | Liveness + JSON booleans describing configured keys, cache and job counts. No secrets. |
| `GET /api/meta` | App metadata, identifier types, status/severity vocabularies, full source catalogue, rate limits. |
| `GET /api/sources` | Just the source catalogue. |
| `GET /api/detect?identifier=<value>&type=auto` | Classification only (no upstream calls). `422` for input it refuses. |
| `POST /api/scan` | Body `{"identifier", "type", "mode", "keys"}` → `202 {"scan_id", "poll"}`. `503` when the queue is full. |
| `GET /api/scan?identifier=…` | Same, for convenience/link previews. |
| `GET /api/scans/{scan_id}?since={version}` | Poll. Returns `{"unchanged": true}` when nothing changed since `version`. |
| `POST /api/password-range` | Body `{"prefix": "5BAA6"}` → HIBP k-anonymity range. A full hash or a password is refused with `400`. |
| `GET /`, `/styles.css`, `/app.js`, … | The UI. |

Errors are JSON: `{"error": {"code": "…", "message": "…"}}`.

---

## Testing

```bash
python3 -m unittest discover -s tests -t tests      # 292 tests, no network needed
node --check app/static/app.js                      # frontend syntax
python3 tools/link_check.py                         # every user-facing external URL
python3 tools/live_probe.py                         # every source against the live upstreams
python3 tools/live_probe.py --base-url https://<your-app>.onrender.com   # post-deploy verification
```

The unit/integration suite runs fully offline: a programmable transport
([`tests/stubs.py`](tests/stubs.py)) replays response bodies captured from the real APIs, so parser
regressions (RDAP `eventAction`, Keybase `them` as object vs list, Sourcegraph SSE, GitHub's
incomplete search results, …) are caught without touching the network. `tools/live_probe.py` is the
complement: it hits the real upstreams and prints a status table, failing only when a source crashes
(an app bug) rather than when an upstream is down (not an app bug).

The live probe also verifies HIBP's **paid** API v3 path without anybody's key: HIBP documents that
any 32-character hexadecimal value may be used as a test key against accounts on its own
`hibp-integration-tests.com` domain, so CI runs the real `hibp_breaches` source against that address
(no personal data involved). On the last run it returned `ok`: one breach entry parsed into two
findings, and `pasteaccount` refusing the test key with HTTP 401 - which is exactly the
degradation path the source is written for, so the breach result is still reported with a note.

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the suite, the frontend
syntax check, a Docker build + container smoke test, the link check, and the live upstream probe on
every push. A failing test suite, a dead link or a crashed source is published as a check
annotation, so results are readable without opening the raw job logs.

To verify a **deployment** from outside the host, run the **Verify deployment** workflow manually
(**Actions → Verify deployment → Run workflow**) with the service's base URL — it wraps
`tools/live_probe.py --base-url …` and checks health, static assets, the API, a full scan
round-trip, the password-range endpoint, path-traversal refusal and security headers.

---

## Repository layout

```
app/
  server.py        HTTP server, routing, security headers, rate limits, static files
  jobs.py          scan orchestration, bounded in-memory job store
  sources/         22 real integrations + the status/finding framework
  http_client.py   the only outbound path: allowlist, SSRF guard, limits, cache, retries
  identifiers.py   detection, validation, local phone parsing
  crypto.py        keccak-256, EIP-55, base58check, bech32/bech32m (dependency-free)
  passwords.py     HIBP k-anonymity range fetch
  report.py        coverage maths, deterministic summary engine, removal links
  config.py        settings, host allowlist, limits
  static/          vanilla HTML/CSS/JS UI (dark, teal, mobile-first)
tests/             offline unit + integration tests and captured upstream fixtures
tools/             link checker and live/deployment probe
Dockerfile         python:3.12-slim, non-root, HEALTHCHECK, honours $PORT
render.yaml        Free-plan Web Service blueprint
docs/legacy/       the previous, unrelated project README (preserved)
```

---

## Responsible use

Verdigris only shows what is already public, and it is easy to misuse. Do not use it to surveil,
harass, dox, stalk, discriminate against, or build dossiers on people. A finding is a snapshot of
what one public source returned at one moment — it is not an accusation, and it is frequently about
somebody else with the same handle. Nothing here is legal advice.

If you find your own data in a source, the report's **removal and reporting links** point at the
correct provider process. Verdigris will not submit anything for you.

## Licence

Released under the [MIT License](LICENSE): free to use, modify and redistribute, with no
warranty of any kind. The name "Verdigris" was chosen for this project; it is not a trademark of
anyone else's product, and no affiliation with Serus is implied or claimed.
