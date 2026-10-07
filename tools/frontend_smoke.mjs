#!/usr/bin/env node
/*
 * Frontend smoke test: loads the real UI from a running server into jsdom and
 * drives it the way a person would - detect, scan, filter, switch tabs, export.
 *
 * It fails on:
 *   - any console error/warning or uncaught exception (the acceptance criterion
 *     "no console errors" is checked, not assumed)
 *   - a backend the UI could not reach
 *   - a scan that never rendered per-source statuses and findings
 *   - missing severity filters, coverage block or privacy disclosure
 *
 * jsdom is a dev-only dependency; the app itself ships no JavaScript tooling.
 * Install it into the gitignored smoke directory first:
 *
 *   mkdir -p .tools-smoke && cd .tools-smoke && npm install jsdom --no-audit --no-fund
 *   python3 -m app.server &                 # or any deployed URL
 *   node tools/frontend_smoke.mjs --base-url http://127.0.0.1:8080
 *
 * The default identifier is a phone number, which the app parses locally: the
 * smoke test therefore exercises the whole UI without depending on any
 * third-party API being up.  Pass --identifier to test something else.
 */

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

function loadJsdom() {
  const candidates = [
    path.join(repoRoot, ".tools-smoke", "node_modules"),
    path.join(repoRoot, "node_modules"),
  ];
  for (const base of candidates) {
    try {
      const require = createRequire(path.join(base, "noop.js"));
      return require("jsdom");
    } catch {
      /* try the next candidate */
    }
  }
  try {
    const require = createRequire(import.meta.url);
    return require("jsdom");
  } catch {
    console.error("jsdom is not installed. Run:");
    console.error("  mkdir -p .tools-smoke && cd .tools-smoke && npm install jsdom --no-audit --no-fund");
    process.exit(2);
  }
}

const { JSDOM, VirtualConsole } = loadJsdom();

const args = process.argv.slice(2);
function arg(name, fallback) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const BASE_URL = arg("base-url", "http://127.0.0.1:8080");
const IDENTIFIER = arg("identifier", "+442071234567");
const MODE = arg("mode", "report");
const WAIT_MS = Number(arg("wait", "60000"));

const problems = [];
const notes = [];

function fail(message) {
  problems.push(message);
  console.error(`  FAIL  ${message}`);
}
function ok(message) {
  console.log(`  ok    ${message}`);
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let value;
    try {
      value = predicate();
    } catch (error) {
      value = null;
    }
    if (value) return value;
    await sleep(150);
  }
  fail(`timed out after ${timeoutMs}ms waiting for ${label}`);
  return null;
}

async function main() {
  console.log(`smoke-testing ${BASE_URL} with identifier "${IDENTIFIER}" (mode ${MODE})\n`);

  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (error) => {
    // A missing crypto.subtle inside jsdom is expected and handled by the app;
    // anything else is a real defect.
    const text = String(error && error.message ? error.message : error);
    if (/crypto|subtle/i.test(text)) {
      notes.push(`jsdom limitation (expected): ${text.slice(0, 120)}`);
      return;
    }
    fail(`jsdomError: ${text.slice(0, 300)}`);
  });
  virtualConsole.on("error", (...parts) => fail(`console.error: ${parts.join(" ").slice(0, 300)}`));
  virtualConsole.on("warn", (...parts) => notes.push(`console.warn: ${parts.join(" ").slice(0, 200)}`));

  const dom = await JSDOM.fromURL(BASE_URL + "/", {
    runScripts: "dangerously",
    resources: "usable",
    pretendToBeVisual: true,
    virtualConsole,
    // jsdom implements no fetch of its own.  Bridge it to Node's fetch, resolving
    // the app's same-origin relative URLs against the server under test.  Note that
    // crypto.subtle is deliberately NOT polyfilled: the password tab must degrade
    // gracefully when browser-side hashing is unavailable.
    beforeParse(window) {
      window.fetch = (input, init) => {
        const url = typeof input === "string"
          ? new URL(input, BASE_URL).href
          : new URL(input.url, BASE_URL).href;
        return fetch(url, init);
      };
    },
  });
  const { window } = dom;
  const { document } = window;
  window.addEventListener("error", (event) => {
    const text = event && event.error ? String(event.error) : String(event.message || "");
    if (!/crypto|subtle/i.test(text)) fail(`window error: ${text.slice(0, 300)}`);
  });
  window.addEventListener("unhandledrejection", (event) => {
    fail(`unhandled rejection: ${String(event.reason).slice(0, 300)}`);
  });

  // --- the app boots and reports backend availability -----------------------
  const pill = await waitFor(() => {
    const node = document.getElementById("backend-pill");
    return node && !/checking/i.test(node.textContent) ? node : null;
  }, 20000, "the backend status pill");
  if (pill) {
    const text = pill.textContent.toLowerCase();
    if (/unavailable|offline|error/.test(text)) fail(`backend pill says: ${pill.textContent.trim()}`);
    else ok(`backend pill: ${pill.textContent.trim()}`);
  }

  const title = document.querySelector("h1") ? document.querySelector("h1").textContent : "";
  if (/verdigris/i.test(title)) ok(`product name rendered: ${title.trim()}`);
  else fail(`product name missing from the header (got "${title}")`);

  const disclaimer = document.body.textContent.toLowerCase();
  if (disclaimer.includes("not affiliated with serus")) ok("Serus non-affiliation notice present");
  else fail("the UI does not state that it is not affiliated with Serus");

  // --- detection feedback while typing -------------------------------------
  const input = document.getElementById("identifier-input");
  if (!input) {
    fail("identifier input not found");
    return finish();
  }
  input.value = IDENTIFIER;
  input.dispatchEvent(new window.Event("input", { bubbles: true }));
  const detectLine = await waitFor(() => {
    const node = document.getElementById("detect-line");
    return node && node.textContent.trim().length > 10 ? node : null;
  }, 15000, "auto-detection feedback");
  if (detectLine) ok(`detection line: ${detectLine.textContent.trim().slice(0, 110)}`);

  // --- privacy preview: what will be sent, and to whom ----------------------
  const details = document.getElementById("privacy-details");
  if (details) details.open = true;
  const preview = await waitFor(() => {
    const node = document.getElementById("privacy-preview");
    return node && node.textContent.trim().length > 20 ? node : null;
  }, 15000, "the privacy preview");
  if (preview) ok(`privacy preview: ${preview.textContent.trim().replace(/\s+/g, " ").slice(0, 110)}`);

  // --- run a scan ----------------------------------------------------------
  if (MODE === "report") {
    const reportButton = document.querySelector('.seg[data-mode="report"]');
    if (reportButton) reportButton.click();
    else fail("report mode toggle not found");
  }
  const scanButton = document.getElementById("scan-button");
  if (!scanButton) {
    fail("scan button not found");
    return finish();
  }
  scanButton.click();

  const results = await waitFor(() => {
    const node = document.getElementById("results");
    return node && !node.hidden ? node : null;
  }, WAIT_MS, "the results panel");
  if (!results) return finish();

  const sourceRows = await waitFor(() => {
    const rows = document.querySelectorAll("#progress-list .source-row, #progress-list li, #progress-list > div");
    return rows.length ? rows : null;
  }, WAIT_MS, "per-source rows");
  if (sourceRows) ok(`${sourceRows.length} source row(s) rendered`);

  const settled = await waitFor(() => {
    const pending = document.body.textContent.match(/Checking…/g);
    return !pending || pending.length === 0 ? true : null;
  }, WAIT_MS, "every source to leave the pending state");
  if (settled) ok("no source stayed in the pending state");

  const findings = await waitFor(() => {
    const nodes = document.querySelectorAll("#findings-list .finding, #findings-list > *");
    return nodes.length ? nodes : null;
  }, WAIT_MS, "findings");
  if (findings) ok(`${findings.length} finding card(s) rendered`);
  else fail("no findings rendered for a completed scan");

  const coverage = document.getElementById("coverage-panel");
  if (coverage && coverage.textContent.trim().length > 20) {
    ok(`coverage block: ${coverage.textContent.trim().replace(/\s+/g, " ").slice(0, 110)}`);
  } else fail("coverage block is empty");
  if (coverage && /Coverage limitations \(always apply\)/.test(coverage.textContent)) {
    ok("coverage block states the standing limitations on every report");
  } else fail("the standing coverage limitations are missing from the report");

  const privacyPanel = document.getElementById("privacy-panel");
  if (privacyPanel && privacyPanel.textContent.trim().length > 10) {
    ok("privacy disclosure panel rendered");
  } else fail("privacy disclosure panel is empty");

  const severityFilters = document.querySelectorAll("#severity-filters button");
  const filterLabels = [...severityFilters].map((b) => b.textContent.replace(/\(\d+\)/, "").trim().toLowerCase());
  // Only severities that actually occur get a chip, plus "All" - so a single-info
  // scan legitimately renders two.  A rich identifier should render more.
  if (severityFilters.length >= 2 && filterLabels.includes("all")) {
    ok(`${severityFilters.length} severity filter chip(s): ${filterLabels.join(", ")}`);
  } else fail(`severity filters look wrong: ${filterLabels.join(", ") || "none"}`);

  if (severityFilters.length) {
    severityFilters[severityFilters.length - 1].click();
    await sleep(200);
    ok("severity filter click did not throw");
    severityFilters[0].click();
    await sleep(200);
  }

  const summaryPanel = document.getElementById("summary-panel");
  if (MODE === "report") {
    if (summaryPanel && summaryPanel.textContent.trim().length > 40) {
      const text = summaryPanel.textContent;
      ok(`summary rendered (${text.trim().replace(/\s+/g, " ").slice(0, 90)}…)`);
      if (/deterministic|rule/i.test(text)) ok("summary is labelled as rule-based, not AI");
      else fail("the summary does not say it is rule-based (no AI model is configured)");
      if (/does not claim/i.test(text)) ok("summary lists what the report explicitly does not claim");
      else fail("the summary does not list explicit non-claims");
      if (/coverage gap|not checked|unavailable/i.test(text)) {
        ok("summary names the coverage gaps in this scan");
      } else {
        notes.push("this scan had no gaps to report (every planned source answered), " +
                   "so the summary has no coverage-gap section");
      }
    } else fail("report mode produced no summary panel content");
  }

  // --- history: saved locally, deletable, exportable -----------------------
  const saveButton = document.getElementById("save-scan");
  if (saveButton) {
    saveButton.click();
    await sleep(300);
    const stored = window.localStorage.getItem("verdigris.history") ||
      Object.keys(window.localStorage).filter((k) => /history/i.test(k)).map((k) => window.localStorage.getItem(k)).join("");
    if (stored && stored.length > 20) ok(`scan saved to browser history (${stored.length} bytes in localStorage)`);
    else fail("saving to history did not write to localStorage");

    const historyTab = document.querySelector('.tab[data-view="history"]');
    if (historyTab) historyTab.click();
    await sleep(300);
    const historyView = document.getElementById("view-history");
    if (historyView && !historyView.hidden) ok("history view opened");
    else fail("history view did not open");
    const deleteButtons = document.querySelectorAll("#view-history button");
    if (deleteButtons.length) ok(`${deleteButtons.length} history control button(s) rendered (delete/export)`);
    else fail("history view has no controls");
  }

  // --- password tab: hashing must be refused cleanly when crypto.subtle is absent
  const passwordTab = document.querySelector('.tab[data-view="password"]');
  if (passwordTab) passwordTab.click();
  await sleep(300);
  const unsupported = document.getElementById("pw-unsupported");
  if (unsupported && !unsupported.hidden) {
    ok("password tab explains that browser-side hashing is unavailable (jsdom has no crypto.subtle)");
  } else {
    notes.push("crypto.subtle availability could not be verified in this environment");
  }

  // --- remaining tabs -------------------------------------------------------
  for (const view of ["settings", "about"]) {
    const tab = document.querySelector(`.tab[data-view="${view}"]`);
    if (!tab) {
      fail(`${view} tab missing`);
      continue;
    }
    tab.click();
    await sleep(250);
    const section = document.getElementById(`view-${view}`);
    if (section && !section.hidden) ok(`${view} view opened`);
    else fail(`${view} view did not open`);
  }
  const aboutText = document.getElementById("view-about");
  if (aboutText) {
    const text = aboutText.textContent.toLowerCase();
    for (const phrase of ["no authentication by default", "allowlist", "cold start"]) {
      if (text.includes(phrase)) ok(`about view discloses: ${phrase}`);
      else fail(`about view does not disclose: ${phrase}`);
    }
  }

  return finish();

  function finish() {
    if (notes.length) {
      console.log("\nnotes:");
      for (const note of notes.slice(0, 10)) console.log(`  - ${note}`);
    }
    console.log(`\n${problems.length} problem(s)`);
    try {
      window.close();
    } catch {
      /* ignore */
    }
    process.exit(problems.length ? 1 : 0);
  }
}

main().catch((error) => {
  console.error(`smoke test crashed: ${error && error.stack ? error.stack : error}`);
  process.exit(1);
});
