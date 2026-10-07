/* Verdigris front-end - vanilla JS, no dependencies, no external requests.
 *
 * Everything the UI needs comes from this origin (/api/*).  Scan results are
 * kept in memory while you look at them and only persisted to this browser's
 * localStorage when you explicitly save them.
 */
(function () {
  "use strict";

  var HISTORY_KEY = "verdigris.history.v1";
  var SETTINGS_KEY = "verdigris.settings.v1";
  var MAX_HISTORY = 25;
  var POLL_INTERVAL_MS = 500;

  var state = {
    meta: null,
    health: null,
    backendOnline: false,
    view: "scan",
    mode: "osint",
    detected: null,
    scan: null,
    pollTimer: null,
    pollVersion: -1,
    polling: false,
    history: [],
    settings: { keys: {}, accessToken: "" },
    severityFilter: "all",
    lastSnapshot: null
  };

  /* ---------------------------------------------------------------- utils */
  function $(id) { return document.getElementById(id); }

  // Every string the UI renders goes through textContent/createTextNode: upstream
  // data (bios, snippets, commit messages) is never interpreted as markup.  There
  // is deliberately no raw-HTML path here, which also keeps the strict CSP honest.
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined || value === false) { return; }
        if (key === "class") { node.className = value; }
        else if (key === "text") { node.textContent = String(value); }
        else if (key.slice(0, 2) === "on" && typeof value === "function") { node.addEventListener(key.slice(2), value); }
        else if (value === true) { node.setAttribute(key, ""); }
        else { node.setAttribute(key, String(value)); }
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined || child === false) { return; }
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }

  function fmtTime(iso) {
    if (!iso) { return "unknown"; }
    try {
      var date = new Date(iso);
      if (isNaN(date.getTime())) { return String(iso); }
      return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    } catch (err) { return String(iso); }
  }

  function timeAgo(iso) {
    if (!iso) { return ""; }
    var then = new Date(iso).getTime();
    if (isNaN(then)) { return ""; }
    var seconds = Math.round((Date.now() - then) / 1000);
    if (seconds < 60) { return seconds + "s ago"; }
    if (seconds < 3600) { return Math.round(seconds / 60) + " min ago"; }
    if (seconds < 86400) { return Math.round(seconds / 3600) + " h ago"; }
    return Math.round(seconds / 86400) + " d ago";
  }

  function flash(message, isError) {
    var box = $("flash");
    box.textContent = message;
    box.className = "flash" + (isError ? " is-error" : "");
    box.hidden = false;
    window.clearTimeout(flash._t);
    flash._t = window.setTimeout(function () { box.hidden = true; }, isError ? 12000 : 6000);
  }

  function apiError(message, status) {
    var err = new Error(message);
    err.status = status;
    return err;
  }

  function api(path, options) {
    var opts = options || {};
    var headers = { "Accept": "application/json" };
    if (opts.body) { headers["Content-Type"] = "application/json"; }
    if (state.settings.accessToken) { headers["X-Access-Token"] = state.settings.accessToken; }
    return fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      cache: "no-store",
      credentials: "same-origin"
    }).then(function (response) {
      return response.text().then(function (text) {
        var payload = null;
        if (text) {
          try { payload = JSON.parse(text); }
          catch (err) { payload = null; }
        }
        if (!response.ok) {
          var message = (payload && payload.error && payload.error.message) ||
            ("Request failed with HTTP " + response.status);
          throw apiError(message, response.status);
        }
        return payload;
      });
    });
  }

  /* ------------------------------------------------------------ storage */
  function loadSettings() {
    try {
      var raw = window.localStorage.getItem(SETTINGS_KEY);
      if (!raw) { return; }
      var parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        state.settings.keys = (parsed.keys && typeof parsed.keys === "object") ? parsed.keys : {};
        state.settings.accessToken = typeof parsed.accessToken === "string" ? parsed.accessToken : "";
      }
    } catch (err) { state.settings = { keys: {}, accessToken: "" }; }
  }

  function saveSettings() {
    try { window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(state.settings)); }
    catch (err) { flash("Could not save settings in this browser (storage may be blocked).", true); }
  }

  function loadHistory() {
    try {
      var raw = window.localStorage.getItem(HISTORY_KEY);
      var parsed = raw ? JSON.parse(raw) : [];
      state.history = Array.isArray(parsed) ? parsed : [];
    } catch (err) { state.history = []; }
  }

  function persistHistory() {
    while (state.history.length) {
      try {
        window.localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
        return true;
      } catch (err) {
        if (state.history.length > 1) {
          state.history.pop(); // drop the oldest until it fits
          continue;
        }
        try { window.localStorage.removeItem(HISTORY_KEY); } catch (e2) { /* ignore */ }
        flash("Browser storage is full - this scan could not be saved locally.", true);
        return false;
      }
    }
    return false;
  }

  function downloadJson(filename, data) {
    try {
      var blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var link = el("a", { href: url, download: filename });
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
      flash("Exported " + filename);
    } catch (err) {
      flash("Export failed in this browser: " + err.message, true);
    }
  }

  /* ------------------------------------------------------- backend health */
  function checkBackend() {
    return api("/health").then(function (payload) {
      state.health = payload;
      state.backendOnline = true;
      setBackendUi(true, "backend online · v" + (payload.version || "?"));
      return payload;
    }).catch(function (err) {
      state.backendOnline = false;
      state.health = null;
      setBackendUi(false, "backend unreachable");
      var banner = $("offline-banner");
      banner.hidden = false;
      $("offline-banner-detail").textContent =
        "The API at this origin did not answer (" + err.message + "). No scan can be started and nothing is " +
        "simulated in its place. On a free host the first request after idle can take 30-60 seconds to wake the " +
        "container - press Retry.";
      return null;
    });
  }

  function setBackendUi(online, label) {
    var pill = $("backend-pill");
    pill.textContent = label;
    pill.className = "pill " + (online ? "pill-ok" : "pill-bad");
    $("offline-banner").hidden = online;
    $("scan-button").disabled = !online;
    $("pw-check").disabled = !online || !window.crypto || !window.crypto.subtle || !window.isSecureContext;
  }

  /* ------------------------------------------------------------ detection */
  var detectTimer = null;

  function currentInput() { return ($("identifier-input").value || "").trim(); }

  function requestDetect() {
    var text = currentInput();
    var type = $("type-select").value;
    var line = $("detect-line");
    if (!text) {
      state.detected = null;
      line.className = "detect-line";
      clear(line);
      renderPrivacyPreview(null);
      $("scan-button").textContent = "Run scan";
      return;
    }
    window.clearTimeout(detectTimer);
    detectTimer = window.setTimeout(function () {
      api("/api/detect?identifier=" + encodeURIComponent(text) + "&type=" + encodeURIComponent(type))
        .then(function (payload) {
          if (payload && payload.ok) {
            state.detected = payload.identifier;
            line.className = "detect-line is-ok";
            clear(line);
            line.appendChild(el("span", { text: "Detected: " + payload.identifier.type_label + " → " }));
            line.appendChild(el("code", { text: payload.identifier.value }));
            (payload.identifier.notes || []).forEach(function (note) {
              line.appendChild(el("div", { class: "small muted", text: note }));
            });
            renderPrivacyPreview(payload.identifier);
          } else {
            state.detected = null;
            line.className = "detect-line is-error";
            line.textContent = (payload && payload.error) || "That input could not be interpreted.";
            renderPrivacyPreview(null);
          }
        })
        .catch(function (err) {
          state.detected = null;
          line.className = "detect-line is-error";
          line.textContent = err.message || "Detection failed.";
          renderPrivacyPreview(null);
        });
    }, 260);
  }

  function sourcesForType(type) {
    if (!state.meta || !type) { return []; }
    return (state.meta.sources || []).filter(function (source) {
      return (source.applies_to || []).indexOf(type) !== -1;
    });
  }

  function renderPrivacyPreview(identifier) {
    var box = $("privacy-preview");
    clear(box);
    if (!identifier) {
      box.appendChild(el("p", { class: "muted small", text: "Enter an identifier to see exactly which fields leave this server and for which sources." }));
      return;
    }
    var sources = sourcesForType(identifier.type);
    if (!sources.length) {
      box.appendChild(el("p", { class: "muted small", text: "No sources are registered for this identifier type." }));
      return;
    }
    box.appendChild(el("p", {
      class: "small muted",
      text: "For a " + identifier.type_label.toLowerCase() + ", this app will contact the following public services. " +
        "Scans run from the server, so these services see the server's IP address, not yours."
    }));
    var list = el("ul", { class: "tight-list" });
    sources.forEach(function (source) {
      var label = source.requires_key
        ? source.name + " (only if you supplied a key - otherwise it is reported as “Not checked”)"
        : source.name;
      list.appendChild(el("li", {}, [
        el("strong", { text: label }),
        el("div", { class: "small", text: "Sends: " + source.sends })
      ]));
    });
    box.appendChild(list);
  }

  /* ---------------------------------------------------------------- scan */
  function startScan() {
    if (!state.backendOnline) {
      flash("Backend unavailable - start it before scanning. Nothing is simulated.", true);
      return;
    }
    var text = currentInput();
    if (!text) { flash("Enter an identifier first.", true); return; }
    $("scan-button").disabled = true;
    $("scan-meta").textContent = "starting…";
    api("/api/scan", {
      method: "POST",
      body: {
        identifier: text,
        type: $("type-select").value,
        mode: state.mode,
        keys: state.settings.keys || {}
      }
    }).then(function (payload) {
      state.scan = payload;
      state.pollVersion = -1;
      state.lastSnapshot = null;
      $("results").hidden = false;
      $("results-title").textContent = "Scan · " + payload.identifier.type_label;
      $("scan-meta").textContent = "scan " + payload.scan_id.slice(0, 8) + " running";
      $("cancel-button").hidden = false;
      $("save-scan").disabled = true;
      $("export-scan").disabled = true;
      renderScanShell(payload.identifier);
      startPolling(payload.scan_id);
      $("results").scrollIntoView({ behavior: "smooth", block: "start" });
    }).catch(function (err) {
      $("scan-meta").textContent = "";
      flash(err.message, true);
    }).then(function () {
      $("scan-button").disabled = !state.backendOnline;
    });
  }

  function renderScanShell(identifier) {
    state.severityFilter = "all";
    clear($("findings-list"));
    clear($("severity-filters"));
    clear($("summary-panel"));
    $("findings-list").appendChild(el("p", { class: "empty", text: "Waiting for sources…" }));
    $("coverage-panel").textContent = "";
    $("privacy-panel").textContent = "";
    var head = $("results-title");
    head.textContent = (identifier.type_label || "Scan") + " · " + (identifier.display || identifier.value || "");
  }

  function startPolling(scanId) {
    stopPolling();
    state.polling = true;
    var tick = function () {
      if (!state.polling) { return; }
      if (document.hidden) { state.pollTimer = window.setTimeout(tick, POLL_INTERVAL_MS * 3); return; }
      api("/api/scans/" + scanId + (state.pollVersion >= 0 ? "?since=" + state.pollVersion : ""))
        .then(function (payload) {
          if (!state.polling) { return; }
          if (!payload.unchanged) {
            state.pollVersion = payload.version;
            state.lastSnapshot = payload;
            renderSnapshot(payload);
          }
          if (payload.state === "complete" || payload.state === "failed") {
            state.polling = false;
            $("cancel-button").hidden = true;
            $("save-scan").disabled = false;
            $("export-scan").disabled = false;
            $("scan-meta").textContent = payload.state === "complete"
              ? "finished in " + payload.duration_ms + " ms"
              : "failed";
            if (payload.state === "failed") {
              flash("Scan failed: " + (payload.error || "unknown error"), true);
            }
            return;
          }
          state.pollTimer = window.setTimeout(tick, POLL_INTERVAL_MS);
        })
        .catch(function (err) {
          state.polling = false;
          $("cancel-button").hidden = true;
          $("scan-meta").textContent = "";
          if (err.status === 404) {
            flash("That scan expired on the server (results are kept briefly in memory). Re-run it, or save scans to history.", true);
          } else {
            flash("Lost contact with the backend while polling: " + err.message, true);
            checkBackend();
          }
        });
    };
    tick();
  }

  function stopPolling() {
    state.polling = false;
    if (state.pollTimer) { window.clearTimeout(state.pollTimer); state.pollTimer = null; }
  }

  var STATUS_DOT = {
    ok: "dot-ok", no_match: "dot-nomatch", not_checked: "dot-notchecked",
    unavailable: "dot-unavailable", rate_limited: "dot-rate", error: "dot-error", pending: "dot-pending"
  };

  function renderSnapshot(snapshot) {
    renderProgress(snapshot.sources || []);
    renderFindings(snapshot.findings || []);
    if (snapshot.coverage) { renderCoverage(snapshot.coverage, snapshot.identifier, snapshot.summary); }
    if (snapshot.privacy && snapshot.privacy.length) { renderPrivacy(snapshot.privacy); }
    renderSummary(snapshot);
  }

  function renderProgress(sources) {
    var list = $("progress-list");
    clear(list);
    var done = 0;
    sources.forEach(function (source) {
      if (source.status !== "pending") { done += 1; }
      var row = el("div", { class: "source-row" + (source.status === "pending" ? " is-pending" : "") });
      row.appendChild(el("span", { class: "dot " + (STATUS_DOT[source.status] || "dot-notchecked") }));
      var main = el("div", {}, [
        el("div", { class: "source-name", text: source.source_name }),
        el("div", { class: "source-cat", text: source.category || "" }),
        el("div", { class: "source-msg", text: source.message || "" })
      ]);
      if (source.hint) { main.appendChild(el("div", { class: "source-hint", text: source.hint })); }
      if (source.sends) { main.appendChild(el("div", { class: "source-sends", text: "Sends: " + source.sends })); }
      row.appendChild(main);
      var side = el("div", { class: "source-side" }, [
        el("div", { class: "source-status st-" + source.status, text: source.status_label || source.status }),
        el("div", { text: source.elapsed_ms ? source.elapsed_ms + " ms" : "" }),
        el("div", { text: source.finding_count ? source.finding_count + " finding(s)" : "" })
      ]);
      row.appendChild(side);
      list.appendChild(row);
    });
    $("progress-count").textContent = done + " / " + sources.length;
  }

  function renderFindings(findings) {
    var listBox = $("findings-list");
    var filterBox = $("severity-filters");
    clear(listBox);
    clear(filterBox);

    if (!findings.length) {
      listBox.appendChild(el("p", {
        class: "empty",
        text: "No findings yet. If every source ends as “No matches” that is a real result; if sources end as " +
          "“Source unavailable” or “Not checked”, it is not - see Coverage below."
      }));
      return;
    }

    var counts = { all: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (finding) { counts[finding.severity] = (counts[finding.severity] || 0) + 1; });
    ["all", "critical", "high", "medium", "low", "info"].forEach(function (severity) {
      if (severity !== "all" && !counts[severity]) { return; }
      var chip = el("button", {
        type: "button",
        class: "chip" + (state.severityFilter === severity ? " is-active" : ""),
        onclick: function () { state.severityFilter = severity; renderFindings(findings); }
      }, [
        document.createTextNode(severity === "all" ? "All" : severity),
        el("span", { class: "chip-count", text: "(" + counts[severity] + ")" })
      ]);
      filterBox.appendChild(chip);
    });

    var visible = findings.filter(function (finding) {
      return state.severityFilter === "all" || finding.severity === state.severityFilter;
    });
    if (!visible.length) {
      listBox.appendChild(el("p", { class: "empty", text: "No findings at that severity." }));
      return;
    }
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    visible.sort(function (a, b) { return (order[a.severity] || 9) - (order[b.severity] || 9); });
    visible.forEach(function (finding) { listBox.appendChild(findingCard(finding)); });
  }

  function findingCard(finding) {
    var card = el("article", { class: "finding sev-" + (finding.severity || "info") });
    card.appendChild(el("div", { class: "finding-head" }, [
      el("span", { class: "sev-badge sev-" + finding.severity, text: finding.severity }),
      el("span", { class: "finding-title", text: finding.title }),
      el("span", { class: "finding-meta", text: finding.source_name + " · " + (finding.category || "") })
    ]));
    if (finding.summary) { card.appendChild(el("p", { class: "finding-summary", text: finding.summary })); }

    if (finding.evidence && finding.evidence.length) {
      var evidence = el("dl", { class: "evidence" });
      finding.evidence.forEach(function (item) {
        var valueNode = item.url
          ? el("dd", {}, [el("a", { href: item.url, target: "_blank", rel: "noopener noreferrer nofollow", text: item.value })])
          : el("dd", { text: item.value });
        evidence.appendChild(el("div", { class: "evidence-row" }, [
          el("dt", { text: item.label }), valueNode
        ]));
      });
      card.appendChild(evidence);
    }

    if (finding.links && finding.links.length) {
      var links = el("div", { class: "link-list" });
      finding.links.forEach(function (link) {
        var href = link.url || link.value;
        var row = [el("span", { class: "link-label", text: link.label + ": " })];
        // Only absolute http(s) URLs become clickable; anything else stays plain text.
        if (/^https?:\/\//i.test(href || "")) {
          row.push(el("a", { href: href, target: "_blank", rel: "noopener noreferrer nofollow", text: href }));
        } else {
          row.push(el("span", { class: "link-plain", text: href || link.label }));
        }
        links.appendChild(el("div", {}, row));
      });
      card.appendChild(links);
    }

    var stamp = el("div", { class: "finding-meta" }, [
      document.createTextNode("recorded " + fmtTime(finding.recorded_at) +
        (finding.observed_at ? " · source data from " + fmtTime(finding.observed_at) : " · no timestamp in source data"))
    ]);
    card.appendChild(stamp);

    if (finding.interpretation) {
      card.appendChild(el("div", { class: "interpretation" }, [
        el("strong", { text: "How to read this: " }),
        document.createTextNode(finding.interpretation)
      ]));
    }
    return card;
  }

  function renderCoverage(coverage, identifier, summary) {
    var box = $("coverage-panel");
    clear(box);
    var stats = el("div", { class: "coverage-stats" }, [
      stat(coverage.sources_with_data, "sources with data"),
      stat(coverage.sources_no_match, "no match"),
      stat(coverage.sources_not_checked, "not checked"),
      stat(coverage.sources_unavailable, "unavailable")
    ]);
    box.appendChild(stats);

    var list = el("ul", { class: "coverage-list" });
    list.appendChild(el("li", { class: "good", text: "Identifier: " + (identifier ? identifier.type_label + " · " + identifier.display : "?") }));
    list.appendChild(el("li", { class: "good", text: "Findings: " + coverage.findings_total + " (critical " + coverage.findings_by_severity.critical + ", high " + coverage.findings_by_severity.high + ", medium " + coverage.findings_by_severity.medium + ", low " + coverage.findings_by_severity.low + ", info " + coverage.findings_by_severity.info + ")" }));
    list.appendChild(el("li", { text: "Third-party services actually contacted: " + (coverage.queried_upstreams || []).join(", ") || "none" }));
    list.appendChild(el("li", { text: "Scan window: " + fmtTime(coverage.started_at) + " → " + fmtTime(coverage.finished_at) + " (" + coverage.duration_ms + " ms)" }));

    (coverage.not_checked_sources || []).forEach(function (row) {
      list.appendChild(el("li", { class: "mute", text: "NOT CHECKED — " + row.source + ": " + row.reason }));
    });
    (coverage.unavailable_sources || []).forEach(function (row) {
      list.appendChild(el("li", { class: "bad", text: "SOURCE UNAVAILABLE — " + row.source + ": " + row.reason }));
    });
    box.appendChild(list);

    // Prefer the limitations the backend attached to this report, so there is one
    // source of truth; fall back to the bundled list in OSINT mode.
    var limitations = (summary && summary.limitations && summary.limitations.length)
      ? summary.limitations
      : STANDING_LIMITS;
    var limits = el("div", { class: "notice notice-warn" }, [
      el("strong", { text: "Coverage limitations (always apply): " }),
      el("ul", { class: "tight-list", style: "margin-top:6px" }, limitations.map(function (text) {
        return el("li", { text: text });
      }))
    ]);
    box.appendChild(limits);
  }

  function stat(value, label) {
    return el("div", { class: "stat" }, [
      el("div", { class: "stat-value", text: String(value === undefined || value === null ? 0 : value) }),
      el("div", { class: "stat-label", text: label })
    ]);
  }

  function renderPrivacy(rows) {
    var box = $("privacy-panel");
    clear(box);
    box.appendChild(el("p", {
      class: "small muted",
      text: "Every outbound request this scan made (or deliberately did not make). Keys you added in Settings are sent " +
        "only to the service that issued them and are never stored here."
    }));
    var list = el("ul", { class: "tight-list" });
    rows.forEach(function (row) {
      list.appendChild(el("li", {}, [
        el("strong", { text: row.source }),
        el("div", { class: "small", text: row.sent }),
        el("div", { class: "small muted", text: "Upstream host: " + row.upstream + " · status: " + row.status })
      ]));
    });
    box.appendChild(list);
  }

  function renderSummary(snapshot) {
    var box = $("summary-panel");
    clear(box);
    if (snapshot.mode !== "report") { return; }
    var summary = snapshot.summary;
    if (!summary) {
      if (snapshot.state !== "complete") {
        box.appendChild(el("p", { class: "muted small", text: "The evidence summary appears when the scan finishes." }));
      }
      return;
    }

    var card = el("div", { class: "card" });
    card.appendChild(el("div", { class: "summary-headline" }, [
      el("h3", { text: "Evidence summary" }),
      el("p", { text: summary.headline }),
      el("p", { class: "engine-note" }, [
        el("strong", { text: "Engine: " + summary.engine + " (rule-based). " }),
        document.createTextNode(summary.engine_note)
      ]),
      el("p", { class: "engine-note" }, [
        el("strong", { text: "Data confidence: " + summary.data_confidence + ". " }),
        document.createTextNode(summary.data_confidence_note)
      ])
    ]));

    (summary.sections || []).forEach(function (section) {
      var block = el("div", { class: "summary-section" });
      block.appendChild(el("h4", { text: section.title }));
      (section.points || []).forEach(function (point) {
        block.appendChild(el("div", { class: "summary-point" }, [
          el("span", { class: "dot dot-" + (point.severity === "high" || point.severity === "critical" ? "unavailable" : (point.severity === "medium" ? "rate" : "nomatch")) }),
          el("span", { text: point.text })
        ]));
      });
      card.appendChild(block);
    });

    if (summary.actions && (summary.actions.links || []).length) {
      var actionBlock = el("div", { class: "summary-section" });
      actionBlock.appendChild(el("h4", { text: "Removal, opt-out and reporting entry points" }));
      actionBlock.appendChild(el("p", { class: "small muted", text: summary.actions.note }));
      var actions = el("ul", { class: "actions-list" });
      summary.actions.links.forEach(function (action) {
        actions.appendChild(el("li", {}, [
          el("div", { class: "action-provider", text: action.provider }),
          el("a", { href: action.url, target: "_blank", rel: "noopener noreferrer nofollow", text: action.label }),
          el("div", { class: "action-does", text: action.does })
        ]));
      });
      actionBlock.appendChild(actions);
      card.appendChild(actionBlock);
    }

    var claims = el("div", { class: "notice notice-info" });
    claims.appendChild(el("strong", { text: "This report explicitly does not claim:" }));
    var claimList = el("ul", { class: "tight-list", style: "margin-top:6px" });
    (summary.not_claims || []).forEach(function (text) { claimList.appendChild(el("li", { text: text })); });
    claims.appendChild(claimList);
    card.appendChild(claims);

    box.appendChild(card);
  }

  var STANDING_LIMITS = [
    "Absence of a finding is not evidence of absence - several sources only cover recent or partial data.",
    "A matching username, handle or name is never proof of the same person.",
    "Threat-intel pulses, public scans and feed listings are third-party claims, not verdicts.",
    "Phone analysis gives format and country calling code only - never an owner, a carrier or a location.",
    "No paid people-search, credit, court or carrier database is queried, and no Tor/dark-web crawling happens.",
    "Blockchain history is public and permanent; there is no removal process.",
    "Free-tier upstreams rate-limit by IP: “source unavailable” means “could not check”, never “nothing found”.",
    "No privacy score or risk score is produced. When sources fail, the report says “insufficient data”."
  ];

  /* --------------------------------------------------------------- export */
  function exportSnapshot(snapshot, filename) {
    if (!snapshot) { flash("Nothing to export yet.", true); return; }
    var payload = {
      exported_at: new Date().toISOString(),
      exported_by: "Verdigris browser history",
      notice: "Real results from public sources at scan time. No simulated data. Includes only what the sources returned.",
      scan: snapshot
    };
    downloadJson(filename || ("verdigris-scan-" + (snapshot.scan_id || "result") + ".json"), payload);
  }

  function saveCurrentScan() {
    var snapshot = state.lastSnapshot;
    if (!snapshot) { flash("No finished scan to save.", true); return; }
    var entry = {
      saved_at: new Date().toISOString(),
      scan_id: snapshot.scan_id,
      identifier: snapshot.identifier,
      mode: snapshot.mode,
      state: snapshot.state,
      duration_ms: snapshot.duration_ms,
      finished_at: snapshot.finished_at,
      coverage: snapshot.coverage,
      sources: snapshot.sources,
      findings: snapshot.findings,
      summary: snapshot.summary,
      privacy: snapshot.privacy
    };
    state.history.unshift(entry);
    if (state.history.length > MAX_HISTORY) { state.history = state.history.slice(0, MAX_HISTORY); }
    if (persistHistory()) {
      flash("Saved to this browser's history (" + state.history.length + " stored).");
      renderHistory();
    }
  }

  /* -------------------------------------------------------------- history */
  function renderHistory() {
    var box = $("history-list");
    clear(box);
    if (!state.history.length) {
      box.appendChild(el("p", { class: "empty", text: "Nothing saved yet. Saved scans stay in this browser only - the server keeps results in memory for a few minutes and never writes them to disk." }));
      return;
    }
    state.history.forEach(function (entry, index) {
      var coverage = entry.coverage || {};
      var row = el("div", { class: "history-row" });
      var info = el("div", {}, [
        el("div", { class: "history-id", text: (entry.identifier && (entry.identifier.display || entry.identifier.value)) || "(unknown)" }),
        el("div", { class: "history-meta", text: ((entry.identifier && entry.identifier.type_label) || "?") + " · " + (entry.mode === "report" ? "evidence report" : "OSINT lookup") + " · " + fmtTime(entry.saved_at) + " (" + timeAgo(entry.saved_at) + ")" }),
        el("div", { class: "history-meta", text: "findings " + (coverage.findings_total || 0) +
          " · data " + (coverage.sources_with_data || 0) +
          " · no match " + (coverage.sources_no_match || 0) +
          " · not checked " + (coverage.sources_not_checked || 0) +
          " · unavailable " + (coverage.sources_unavailable || 0) })
      ]);
      var actions = el("div", { class: "history-actions" }, [
        el("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Open", onclick: function () { openHistoryEntry(index); } }),
        el("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Export", onclick: function () { exportSnapshot(entry, "verdigris-scan-" + (entry.scan_id || index) + ".json"); } }),
        el("button", { class: "btn btn-danger btn-sm", type: "button", text: "Delete", onclick: function () { deleteHistoryEntry(index); } })
      ]);
      row.appendChild(info);
      row.appendChild(actions);
      box.appendChild(row);
    });
  }

  function openHistoryEntry(index) {
    var entry = state.history[index];
    if (!entry) { return; }
    stopPolling();
    setView("scan");
    $("results").hidden = false;
    $("results-title").textContent = "Saved scan · " + (entry.identifier ? entry.identifier.type_label : "?");
    $("scan-meta").textContent = "opened from history (" + fmtTime(entry.saved_at) + ")";
    $("cancel-button").hidden = true;
    $("save-scan").disabled = true;
    $("export-scan").disabled = false;
    state.lastSnapshot = entry;
    state.severityFilter = "all";
    renderSnapshot(entry);
    renderSummary(entry);
    $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function deleteHistoryEntry(index) {
    var entry = state.history[index];
    state.history.splice(index, 1);
    persistHistory();
    renderHistory();
    flash("Deleted the saved scan for " + ((entry && entry.identifier && entry.identifier.display) || "that entry") + " from this device.");
  }

  /* ------------------------------------------------------------- password */
  function bytesToHex(buffer) {
    var view = new Uint8Array(buffer);
    var out = "";
    for (var i = 0; i < view.length; i += 1) { out += view[i].toString(16).padStart(2, "0"); }
    return out.toUpperCase();
  }

  function sha1Hex(text) {
    var data = new TextEncoder().encode(text);
    return window.crypto.subtle.digest("SHA-1", data).then(bytesToHex);
  }

  function checkPassword() {
    var input = $("pw-input");
    var password = input.value;
    var statusBox = $("pw-status");
    var resultBox = $("pw-result");
    clear(resultBox);
    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
      $("pw-unsupported").hidden = false;
      statusBox.className = "detect-line is-error";
      statusBox.textContent = "Browser-side hashing is unavailable on this origin, so the check is disabled.";
      return;
    }
    if (!password) { statusBox.className = "detect-line is-error"; statusBox.textContent = "Enter a password to check."; return; }
    if (!state.backendOnline) { statusBox.className = "detect-line is-error"; statusBox.textContent = "Backend unavailable - cannot reach the HIBP range API."; return; }

    $("pw-check").disabled = true;
    statusBox.className = "detect-line";
    statusBox.textContent = "Hashing locally…";

    sha1Hex(password).then(function (hex) {
      var prefix = hex.slice(0, 5);
      var suffix = hex.slice(5);
      statusBox.textContent = "Requesting the public range for prefix " + prefix + "… (only these five characters are sent)";
      return api("/api/password-range", { method: "POST", body: { prefix: prefix } }).then(function (payload) {
        var match = null;
        (payload.entries || []).forEach(function (entry) {
          // A count of 0 would be one of HIBP's padding entries, not a real match.
          if (entry.suffix === suffix && entry.count > 0) { match = entry; }
        });
        renderPasswordResult(match, payload, prefix);
        input.value = "";
        statusBox.textContent = "Done. The input field was cleared; nothing was stored.";
      });
    }).catch(function (err) {
      statusBox.className = "detect-line is-error";
      statusBox.textContent = err.message || "Password check failed.";
      clear(resultBox);
    }).then(function () {
      $("pw-check").disabled = !state.backendOnline;
    });
  }

  function renderPasswordResult(match, payload, prefix) {
    var box = $("pw-result");
    clear(box);
    if (match) {
      box.appendChild(el("div", { class: "notice notice-bad" }, [
        el("strong", { text: "This password appears in the Pwned Passwords corpus " + match.count.toLocaleString() + " time(s)." }),
        el("p", { class: "small", text: "It has been exposed in known breaches and must be treated as compromised. Do not use it anywhere, and change it anywhere it was reused. Count comes from HIBP's k-anonymity range API." }),
        el("p", { class: "small muted", text: "Sent to HIBP: the prefix " + prefix + " only. Compared locally: the remaining 35 hash characters. Real entries in that range: " + payload.entry_count + (payload.padding_discarded ? " (" + payload.padding_discarded + " padding entries discarded)" : "") + "." })
      ]));
    } else {
      box.appendChild(el("div", { class: "notice notice-ok" }, [
        el("strong", { text: "Not found in the Pwned Passwords corpus." }),
        el("p", { class: "small", text: "The hash suffix was not present among the " + (payload.returned_count || payload.entry_count) + " entries HIBP returned for prefix " + prefix + ". That means it is not in HIBP's corpus - it does not mean the password is strong, and it may still appear in breaches HIBP has not received." }),
        el("p", { class: "small muted", text: "Sent to HIBP: the prefix " + prefix + " only. The full hash never left your browser." })
      ]));
    }
  }

  /* ------------------------------------------------------------- settings */
  function renderKeysForm() {
    var box = $("keys-form");
    clear(box);
    var keys = (state.meta && state.meta.optional_keys) || [];
    keys.forEach(function (spec) {
      var row = el("div", { class: "key-row" });
      var inputId = "key-" + spec.key;
      row.appendChild(el("label", { for: inputId, text: spec.label }));
      var input = el("input", {
        id: inputId, type: "password", autocomplete: "off", spellcheck: "false",
        placeholder: state.settings.keys[spec.key] ? "(saved - hidden)" : "leave empty to keep this source disabled",
        value: ""
      });
      row.appendChild(input);
      row.appendChild(el("div", { class: "key-help", text: "Unlocks: " + spec.unlocks + " · get one: " + spec.where }));
      if (state.settings.keys[spec.key]) {
        row.appendChild(el("div", { class: "key-help" }, [
          el("span", { text: "Stored in this browser: " + maskKey(state.settings.keys[spec.key]) + " " }),
          el("button", {
            class: "btn btn-ghost btn-sm", type: "button", text: "Remove", onclick: function () {
              delete state.settings.keys[spec.key];
              saveSettings();
              renderKeysForm();
              flash(spec.label + " removed from this browser.");
            }
          })
        ]));
      }
      row.appendChild(el("div", { class: "key-help" }, [
        el("button", {
          class: "btn btn-ghost btn-sm", type: "button", text: "Save this key", onclick: function () {
            var value = (input.value || "").trim();
            if (!value) { flash("Enter a key value first.", true); return; }
            state.settings.keys[spec.key] = value;
            saveSettings();
            input.value = "";
            renderKeysForm();
            flash(spec.label + " saved in this browser.");
          }
        })
      ]));
      box.appendChild(row);
    });

    var tokenRow = el("div", { class: "key-row" });
    tokenRow.appendChild(el("label", { for: "key-access", text: "Server access token (only if the operator set ACCESS_TOKEN)" }));
    var tokenInput = el("input", {
      id: "key-access", type: "password", autocomplete: "off", spellcheck: "false",
      placeholder: state.settings.accessToken ? "(saved - hidden)" : "leave empty",
      value: ""
    });
    tokenRow.appendChild(tokenInput);
    tokenRow.appendChild(el("div", { class: "key-help", text: "Sent as the X-Access-Token header with every API call from this browser." }));
    tokenRow.appendChild(el("div", { class: "key-help" }, [
      el("button", {
        class: "btn btn-ghost btn-sm", type: "button", text: "Save token", onclick: function () {
          state.settings.accessToken = (tokenInput.value || "").trim();
          saveSettings();
          tokenInput.value = "";
          renderKeysForm();
          checkBackend();
          flash("Access token saved in this browser.");
        }
      })
    ]));
    box.appendChild(tokenRow);
  }

  function maskKey(value) {
    if (!value) { return ""; }
    if (value.length <= 6) { return "••••"; }
    return value.slice(0, 3) + "…" + value.slice(-3) + " (" + value.length + " chars)";
  }

  function renderServerPanel() {
    var box = $("server-panel");
    clear(box);
    var health = state.health || {};
    var rows = [
      ["Origin", window.location.origin],
      ["App", (state.meta && state.meta.app) + " " + (state.meta && state.meta.version)],
      ["Backend health", state.backendOnline ? ("ok · uptime " + Math.round(health.uptime_seconds || 0) + "s") : "unreachable"],
      ["Authentication", health.auth_required ? "access token required by the operator" : "NONE - this prototype is publicly usable by anyone with the URL"],
      ["Sources registered", String((state.meta && state.meta.sources || []).length)],
      ["Sources disabled by operator", (health.sources_disabled || []).length ? (health.sources_disabled || []).join(", ") : "none"],
      ["Server-side keys configured", Object.keys(health.optional_keys_configured || {}).filter(function (k) { return health.optional_keys_configured[k]; }).join(", ") || "none"],
      ["Scan rate limit", (state.meta && state.meta.limits.scan_rate_per_minute) + " scans/min per IP"],
      ["Scan deadline", (state.meta && state.meta.limits.scan_deadline_seconds) + "s per scan"],
      ["Upstream response cap", "512 KiB per response (6 MiB for community feeds)"],
      ["Result retention", "in memory only, ~15 minutes; never written to disk"],
      ["Your keys stored here", Object.keys(state.settings.keys || {}).join(", ") || "none"]
    ];
    var dl = el("dl", { class: "kv" });
    rows.forEach(function (row) {
      dl.appendChild(el("div", { class: "kv-row" }, [el("dt", { text: row[0] }), el("dd", { text: row[1] })]));
    });
    box.appendChild(dl);

    var catalogue = $("source-catalogue");
    clear(catalogue);
    ((state.meta && state.meta.sources) || []).forEach(function (source) {
      catalogue.appendChild(el("div", { class: "catalogue-row" }, [
        el("div", { class: "cat-name", text: source.name + (source.requires_key ? " (needs your key)" : "") }),
        el("div", { class: "cat-meta", text: source.category + " · applies to: " + (source.applies_to || []).join(", ") }),
        el("div", { class: "cat-sends", text: "Sends: " + source.sends }),
        source.docs ? el("div", { class: "cat-meta" }, [
          el("a", { href: source.docs, target: "_blank", rel: "noopener noreferrer", text: "source documentation" })
        ]) : null
      ]));
    });
  }

  /* ---------------------------------------------------------------- about */
  function renderAbout() {
    var notList = $("not-list");
    clear(notList);
    [
      "It does not query paid people-search, credit-header, court-record or carrier databases - those need contracts and money, and pretending otherwise would be a lie.",
      "It does not crawl Tor, .onion services or any 'dark web' marketplace.",
      "It does not bypass a login, a paywall, a rate limit or any other access control. Public endpoints only.",
      "It does not fabricate, simulate or 'demo' scan results. If a source fails, the row says 'source unavailable'.",
      "It does not produce a numeric privacy or risk score. If no source succeeds, the report says 'Insufficient data'.",
      "It does not claim that a removal, takedown or abuse request was submitted - it only links to the provider's own form.",
      "It does not use an AI model for its summaries; they are produced by fixed rules and are labelled as such.",
      "It does not run scans in your browser against third-party sites (that would be blocked by CORS and would expose your IP)."
    ].forEach(function (text) { notList.appendChild(el("li", { text: text })); });

    var interp = $("interpretation-list");
    clear(interp);
    [
      "Username or name matches are not identity matches. Handles are re-used, squatted, shared and re-registered.",
      "Presence in a threat-intel pulse, a public scan archive or a community feed is a third-party claim, not a verdict. Many pulses are bulk indicator dumps; many archived sites are harmless.",
      "Phone parsing establishes format and country calling code only - never the owner, the carrier, whether the line is active, or a location.",
      "Blockchain lookups show public ledger facts about an address, which is often an exchange or custodian wallet rather than an individual.",
      "Commit-email and Gravatar matches link an identifier to content that someone chose to publish; they can be stale, shared or deliberately misleading.",
      "Severity describes how much exposure the evidence shows, not the likelihood that it refers to the person you have in mind.",
      "Strong conclusions need several independent sources agreeing - ideally with a signed proof (Keybase) or a controlled asset (a domain's DNS, a mailbox)."
    ].forEach(function (text) { interp.appendChild(el("li", { text: text })); });

    var privacy = $("privacy-list");
    clear(privacy);
    [
      "Scans run on this server, so the third-party APIs see the server's IP address, not yours. Your browser only talks to this origin.",
      "Your identifier is sent to the specific public sources listed for its type - the 'What will be sent, and to whom' panel shows them before you scan, and the 'What was actually sent' panel shows what really happened afterwards.",
      "Access logs contain the request path only: no query strings, no identifiers, no keys, no passwords.",
      "Results are held in memory for about 15 minutes and are never written to disk. Scan history lives in your browser's localStorage and can be deleted there at any time.",
      "Optional API keys are stored in your browser, sent to this server once per request, and used only to call the service that issued them. They are never logged, cached or persisted server-side.",
      "Password checks hash in the browser (Web Crypto SHA-1) and send only the first five hex characters of the digest. This app has no endpoint that accepts a password.",
      "There is no analytics, no tracking, no advertising and no third-party script or font on this page."
    ].forEach(function (text) { privacy.appendChild(el("li", { text: text })); });

    var hosting = $("hosting-list");
    clear(hosting);
    [
      "This app is designed for a free-tier container host (Render Free). Free containers are spun down after roughly 15 minutes without traffic.",
      "A cold start means the first request after idle can take 30-60 seconds. If you see 'backend unavailable', press Retry rather than assuming it is broken.",
      "Free plans have a fixed 512 MB RAM instance, no persistent disk and a monthly instance-hour allowance - so caches are in-memory and bounded, and nothing is written to disk.",
      "Upstream free APIs rate-limit by source IP. Because every user of this deployment shares one IP, limits can be reached during busy periods; affected sources are reported as 'rate limited' or 'source unavailable'.",
      "A public Render URL is unauthenticated by design in this prototype. If you need to restrict it, set the ACCESS_TOKEN environment variable and enter the token under Settings."
    ].forEach(function (text) { hosting.appendChild(el("li", { text: text })); });

    var security = $("security-list");
    clear(security);
    [
      "No authentication by default: anyone with the URL can run scans. That is disclosed here and in the README.",
      "Outbound requests are restricted to a fixed allowlist of hosts, HTTPS only, with private/reserved IP ranges blocked (SSRF protection), hard timeouts and response-size caps.",
      "There is no 'fetch this URL' endpoint, so arbitrary proxying is impossible.",
      "Redirects are only followed to allowlisted hosts; the single documented exception is the RDAP bootstrap (rdap.org → the registry's own RDAP server), which is re-validated against the public-IP rule.",
      "Strict Content-Security-Policy: scripts, styles and connections come from this origin only; no inline scripts; frames are refused.",
      "Rate limits: scans, API polling and password-range lookups are limited per client IP with token buckets.",
      "Input is validated and length-capped before anything is forwarded upstream."
    ].forEach(function (text) { security.appendChild(el("li", { text: text })); });
  }

  /* ----------------------------------------------------------------- views */
  function setView(name) {
    state.view = name;
    ["scan", "password", "history", "settings", "about"].forEach(function (view) {
      var section = $("view-" + view);
      var tab = document.querySelector('.tab[data-view="' + view + '"]');
      if (section) {
        section.hidden = view !== name;
        section.className = "view" + (view === name ? " is-active" : "");
      }
      if (tab) {
        tab.className = "tab" + (view === name ? " is-active" : "");
        tab.setAttribute("aria-selected", view === name ? "true" : "false");
      }
    });
    if (name === "history") { renderHistory(); }
    if (name === "settings") { renderKeysForm(); renderServerPanel(); }
    if (name === "about") { renderAbout(); }
  }

  /* ------------------------------------------------------------------ init */
  function wireEvents() {
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (tab) {
      tab.addEventListener("click", function () { setView(tab.getAttribute("data-view")); });
    });

    $("identifier-input").addEventListener("input", requestDetect);
    $("identifier-input").addEventListener("keydown", function (event) {
      if (event.key === "Enter") { event.preventDefault(); startScan(); }
    });
    $("type-select").addEventListener("change", requestDetect);

    Array.prototype.forEach.call(document.querySelectorAll(".seg"), function (button) {
      button.addEventListener("click", function () {
        state.mode = button.getAttribute("data-mode");
        Array.prototype.forEach.call(document.querySelectorAll(".seg"), function (other) {
          var active = other === button;
          other.className = "seg" + (active ? " is-active" : "");
          other.setAttribute("aria-pressed", active ? "true" : "false");
        });
        $("mode-hint").textContent = state.mode === "report"
          ? "Evidence report: every applicable source, plus a rule-based summary, coverage gaps, interpretation caveats and provider removal/opt-out links. No AI model is used."
          : "OSINT lookup: every applicable source, findings only. Evidence report adds the rule-based summary and action links.";
      });
    });

    $("scan-button").addEventListener("click", startScan);
    $("cancel-button").addEventListener("click", function () {
      stopPolling();
      $("cancel-button").hidden = true;
      $("scan-meta").textContent = "stopped watching this scan (it may still be finishing on the server)";
    });
    $("new-scan").addEventListener("click", function () {
      stopPolling();
      $("results").hidden = true;
      $("identifier-input").value = "";
      $("detect-line").textContent = "";
      state.lastSnapshot = null;
      $("identifier-input").focus();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    $("export-scan").addEventListener("click", function () { exportSnapshot(state.lastSnapshot); });
    $("save-scan").addEventListener("click", saveCurrentScan);
    $("retry-backend").addEventListener("click", function () { checkBackend(); });

    $("history-export-all").addEventListener("click", function () {
      if (!state.history.length) { flash("No saved scans to export.", true); return; }
      downloadJson("verdigris-history-" + new Date().toISOString().slice(0, 10) + ".json", {
        exported_at: new Date().toISOString(),
        count: state.history.length,
        notice: "Browser-local scan history exported by Verdigris. Contains only what public sources returned.",
        scans: state.history
      });
    });
    $("history-delete-all").addEventListener("click", function () {
      if (!state.history.length) { flash("History is already empty.", true); return; }
      var count = state.history.length;
      state.history = [];
      try { window.localStorage.removeItem(HISTORY_KEY); } catch (err) { /* ignore */ }
      renderHistory();
      flash("Deleted " + count + " saved scan(s) from this device.");
    });

    $("pw-check").addEventListener("click", checkPassword);
    $("pw-input").addEventListener("keydown", function (event) {
      if (event.key === "Enter") { event.preventDefault(); checkPassword(); }
    });
    $("pw-toggle").addEventListener("click", function () {
      var input = $("pw-input");
      var showing = input.type === "text";
      input.type = showing ? "password" : "text";
      $("pw-toggle").textContent = showing ? "Show" : "Hide";
    });

    $("keys-save").addEventListener("click", function () {
      saveSettings();
      renderKeysForm();
      renderServerPanel();
      flash("Settings saved in this browser.");
    });
    $("keys-clear").addEventListener("click", function () {
      state.settings.keys = {};
      saveSettings();
      renderKeysForm();
      renderServerPanel();
      flash("All stored keys deleted from this browser.");
    });

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden && state.polling) { startPolling(state.scan.scan_id); }
    });
  }

  function init() {
    loadSettings();
    loadHistory();
    wireEvents();
    renderAbout();
    renderHistory();
    $("footer-version").textContent = "loading…";

    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
      $("pw-unsupported").hidden = false;
    }

    api("/api/meta").then(function (meta) {
      state.meta = meta;
      $("footer-version").textContent = "v" + meta.version;
      renderKeysForm();
      renderServerPanel();
      renderPrivacyPreview(state.detected);
      document.title = meta.app + " · " + meta.tagline;
    }).catch(function (err) {
      $("footer-version").textContent = "meta unavailable";
      flash("Could not load app metadata: " + err.message, true);
    }).then(function () {
      return checkBackend();
    }).then(function () {
      renderServerPanel();
      window.setInterval(function () { checkBackend().then(renderServerPanel); }, 60000);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
