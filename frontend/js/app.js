/* ==========================================================
   CYBERMIND — application logic
   Uses only DOM APIs and textContent for user-provided data.
   ========================================================== */

(function (global) {
  "use strict";

  var API = global.CyberMindAPI;
  var History = global.CyberMindHistory;
  var document = global.document;

  var THEME_KEY = "cybermind:theme:v1";
  var DEFAULT_MAX_CHARS = 5000;

  var maxChars = DEFAULT_MAX_CHARS;
  var isAnalyzing = false;
  var elements = {};

  var THREAT_LABELS = {
    benign: "Benign",
    phishing: "Phishing",
    scam: "Scam",
    social_engineering: "Social Engineering"
  };

  var THREAT_HEADLINES = {
    benign: "No strong threat signals detected",
    phishing: "Possible phishing attempt",
    scam: "Likely scam or prize fraud",
    social_engineering: "Possible social-engineering attempt"
  };

  var RISK_LABELS = {
    low: "Low",
    medium: "Medium",
    high: "High",
    critical: "Critical"
  };

  /* ------------------------------------------------------
     Small helpers
     ------------------------------------------------------ */

  function byId(id) {
    return document.getElementById(id);
  }

  function el(tagName, className, text) {
    var node = document.createElement(tagName);

    if (className) {
      node.className = className;
    }

    if (typeof text === "string") {
      node.textContent = text;
    }

    return node;
  }

  function isNonEmptyString(value) {
    return typeof value === "string" && value.trim() !== "";
  }

  function asArray(value) {
    if (Array.isArray(value)) {
      return value;
    }

    // NodeList / HTMLCollection / other array-likes returned by the
    // DOM (e.g. querySelectorAll) are converted to real arrays.
    if (
      value &&
      typeof value !== "string" &&
      typeof value.length === "number"
    ) {
      return Array.prototype.slice.call(value);
    }

    return [];
  }

  function toNumber(value) {
    var number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function clampScore(value) {
    var number = toNumber(value);

    if (number === null) {
      return null;
    }

    return Math.max(0, Math.min(100, Math.round(number)));
  }

  function normalizeThreat(value) {
    var threat = isNonEmptyString(value)
      ? value.trim().toLowerCase().replace(/[\s-]+/g, "_")
      : "";

    if (threat === "socialengineering") {
      threat = "social_engineering";
    }

    return Object.prototype.hasOwnProperty.call(THREAT_LABELS, threat)
      ? threat
      : "unknown";
  }

  function normalizeRisk(value) {
    var level = isNonEmptyString(value) ? value.trim().toLowerCase() : "";
    return Object.prototype.hasOwnProperty.call(RISK_LABELS, level)
      ? level
      : "unknown";
  }

  var ACRONYMS = {
    https: "HTTPS",
    http: "HTTP",
    url: "URL",
    urls: "URLs",
    ml: "ML",
    nlp: "NLP",
    pos: "POS",
    ip: "IP",
    otp: "OTP",
    sms: "SMS"
  };

  function humanize(value) {
    return String(value)
      .replace(/_/g, " ")
      .split(" ")
      .filter(function (word) {
        return word !== "";
      })
      .map(function (word) {
        var lower = word.toLowerCase();

        if (Object.prototype.hasOwnProperty.call(ACRONYMS, lower)) {
          return ACRONYMS[lower];
        }

        return lower.charAt(0).toUpperCase() + lower.slice(1);
      })
      .join(" ");
  }

  function formatTimestamp(value) {
    var date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "Unknown time";
    }

    try {
      return date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short"
      });
    } catch (error) {
      return date.toLocaleString();
    }
  }

  function formatPercent(value) {
    var number = toNumber(value);

    if (number === null) {
      return null;
    }

    var percent = number <= 1 ? number * 100 : number;
    var rounded = Math.round(percent * 10) / 10;

    return (Number.isInteger(rounded) ? rounded : rounded.toFixed(1)) + "%";
  }

  function threatLabel(threat) {
    return THREAT_LABELS[threat] || "Unavailable";
  }

  function riskLabel(level) {
    return RISK_LABELS[level] || "Unavailable";
  }

  /* ------------------------------------------------------
     Theme
     ------------------------------------------------------ */

  function storedTheme() {
    try {
      var value = global.localStorage.getItem(THEME_KEY);
      return value === "light" || value === "dark" ? value : null;
    } catch (error) {
      return null;
    }
  }

  function applyTheme(theme) {
    var dark = theme === "dark";

    document.documentElement.setAttribute(
      "data-theme",
      dark ? "dark" : "light"
    );

    if (elements.themeToggle) {
      elements.themeToggle.setAttribute(
        "aria-pressed",
        dark ? "true" : "false"
      );
      elements.themeToggle.setAttribute(
        "aria-label",
        dark ? "Switch to light mode" : "Switch to dark mode"
      );
    }

    if (elements.themeToggleText) {
      elements.themeToggleText.textContent = dark ? "Light" : "Dark";
    }

    if (elements.themeColorMeta) {
      elements.themeColorMeta.setAttribute(
        "content",
        dark ? "#070b16" : "#f5f7fb"
      );
    }
  }

  function initTheme() {
    var theme =
      document.documentElement.getAttribute("data-theme") === "dark"
        ? "dark"
        : "light";

    applyTheme(theme);

    elements.themeToggle.addEventListener("click", function () {
      var next =
        document.documentElement.getAttribute("data-theme") === "dark"
          ? "light"
          : "dark";

      applyTheme(next);

      try {
        global.localStorage.setItem(THEME_KEY, next);
      } catch (error) {
        /* Theme still applies for this page view. */
      }
    });

    if (
      global.matchMedia &&
      typeof global.matchMedia === "function"
    ) {
      var query = global.matchMedia("(prefers-color-scheme: dark)");

      var onChange = function (event) {
        if (storedTheme() === null) {
          applyTheme(event.matches ? "dark" : "light");
        }
      };

      if (typeof query.addEventListener === "function") {
        query.addEventListener("change", onChange);
      } else if (typeof query.addListener === "function") {
        query.addListener(onChange);
      }
    }
  }

  /* ------------------------------------------------------
     Navigation
     ------------------------------------------------------ */

  function closeNavigation() {
    if (!elements.navMenu) {
      return;
    }

    elements.navMenu.classList.remove("is-open");
    elements.navToggle.setAttribute("aria-expanded", "false");
    elements.navToggle.setAttribute(
      "aria-label",
      "Open navigation menu"
    );
    document.body.classList.remove("nav-open");
  }

  function initNavigation() {
    elements.navToggle.addEventListener("click", function () {
      var open = elements.navMenu.classList.toggle("is-open");

      elements.navToggle.setAttribute(
        "aria-expanded",
        open ? "true" : "false"
      );
      elements.navToggle.setAttribute(
        "aria-label",
        open ? "Close navigation menu" : "Open navigation menu"
      );
      document.body.classList.toggle("nav-open", open);
    });

    asArray(
      elements.navMenu.querySelectorAll(".nav-link")
    ).forEach(function (link) {
      link.addEventListener("click", closeNavigation);
    });

    asArray(
      elements.navMenu.querySelectorAll('a[href^="#"]')
    ).forEach(function (link) {
      link.addEventListener("click", closeNavigation);
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        closeNavigation();
      }
    });

    global.addEventListener("resize", function () {
      if (global.innerWidth >= 900) {
        closeNavigation();
      }
    });
  }

  /* ------------------------------------------------------
     Character counter
     ------------------------------------------------------ */

  function updateCharCount() {
    if (!elements.messageInput || !elements.charCount) {
      return;
    }

    var length = elements.messageInput.value.length;

    elements.charCount.textContent = length + " / " + maxChars;
    elements.charCount.classList.toggle(
      "is-near-limit",
      length > maxChars * 0.9
    );
  }

  function setMaxChars(value) {
    var number = toNumber(value);

    if (number !== null && number >= 1) {
      maxChars = Math.round(number);
      elements.messageInput.setAttribute(
        "maxlength",
        String(maxChars)
      );
      updateCharCount();
    }
  }

  /* ------------------------------------------------------
     Form helpers
     ------------------------------------------------------ */

  function showFormError(message) {
    elements.formError.textContent = message;
    elements.formError.hidden = false;
  }

  function clearFormError() {
    elements.formError.textContent = "";
    elements.formError.hidden = true;
  }

  function setLoading(loading) {
    isAnalyzing = loading;

    elements.analyzeBtn.disabled = loading;
    elements.analyzeBtn.classList.toggle("is-loading", loading);
    elements.analyzeBtn.setAttribute(
      "aria-busy",
      loading ? "true" : "false"
    );
    elements.analyzeBtnText.textContent = loading
      ? "Analyzing\u2026"
      : "Analyze Message";
    elements.clearBtn.disabled = loading;
    elements.messageInput.setAttribute(
      "aria-busy",
      loading ? "true" : "false"
    );
  }

  function announce(message) {
    if (elements.resultStatus) {
      elements.resultStatus.textContent = message;
    }
  }

  function showResultsSection() {
    elements.resultsSection.hidden = false;
    elements.resultsTitle.setAttribute("tabindex", "-1");
    elements.resultsTitle.focus({ preventScroll: true });
    elements.resultsSection.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  }

  /* ------------------------------------------------------
     Samples
     ------------------------------------------------------ */

  function initSamples() {
    asArray(
      document.querySelectorAll("[data-sample-text]")
    ).forEach(function (button) {
      button.addEventListener("click", function () {
        var text = button.getAttribute("data-sample-text") || "";

        elements.messageInput.value = text;
        elements.messageInput.dispatchEvent(
          new global.Event("input", { bubbles: true })
        );
        clearFormError();
        elements.messageInput.focus();
      });
    });
  }

  /* ------------------------------------------------------
     Backend status
     ------------------------------------------------------ */

  function setBackendStatus(state, text, title) {
    var pill = elements.backendStatus;

    pill.classList.remove(
      "status-checking",
      "status-online",
      "status-offline"
    );
    pill.classList.add("status-" + state);

    if (title) {
      pill.setAttribute("title", title);
    } else {
      pill.removeAttribute("title");
    }

    elements.backendStatusText.textContent = text;
  }

  async function checkBackend() {
    setBackendStatus("checking", "Checking backend\u2026");

    try {
      var data = await API.health();

      if (data && data.status === "healthy") {
        setBackendStatus(
          "online",
          "Backend online \u00b7 model ready",
          "Connected to " + API.getBaseUrl()
        );

        if (data.max_message_length) {
          setMaxChars(data.max_message_length);
        }
      } else {
        setBackendStatus(
          "offline",
          "Backend degraded",
          "The analysis engine is not ready."
        );
      }
    } catch (error) {
      setBackendStatus(
        "offline",
        "Backend offline",
        error && error.message ? error.message : ""
      );
      setMaxChars(DEFAULT_MAX_CHARS);
    }
  }

  /* ------------------------------------------------------
     Icons (constant markup only)
     ------------------------------------------------------ */

  var ICONS = {
    signals:
      '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><path d="M4 6h16M4 12h10M4 18h7" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/><circle cx="18" cy="12" r="2.2" fill="none" stroke="currentColor" stroke-width="1.9"/></svg>',
    url:
      '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><path d="M10.5 13.5a3.5 3.5 0 0 0 5 0l2.6-2.6a3.5 3.5 0 0 0-5-5l-1.4 1.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M13.5 10.5a3.5 3.5 0 0 0-5 0l-2.6 2.6a3.5 3.5 0 0 0 5 5l1.4-1.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    brain:
      '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><circle cx="6" cy="6" r="2.2" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="18" cy="7" r="2.2" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="12" cy="18" r="2.2" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M8 7l2.5 8.6M16 8.6l-2.9 7M8.2 6.3l7.6.5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>',
    gauge:
      '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><path d="M4 16a8 8 0 1 1 16 0" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="m12 16 4-4" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>',
    nlp:
      '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><path d="M5 5h14M5 12h9M5 19h11" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/><path d="M17 16.5h4M19 14.5v4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    shield:
      '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false"><path d="M12 3.5 19 6v5.4c0 4.3-2.7 7.6-7 9.1-4.3-1.5-7-4.8-7-9.1V6l7-2.5Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9.3 12.1 11.1 14l3.7-4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>'
  };

  function icon(name) {
    var holder = el("span", "detail-icon");

    holder.setAttribute("aria-hidden", "true");
    holder.innerHTML = ICONS[name] || "";

    return holder;
  }

  function detailCard(iconName, title) {
    var card = el("article", "card detail-card");
    var heading = el("h3");

    heading.appendChild(icon(iconName));
    heading.appendChild(document.createTextNode(title));
    card.appendChild(heading);

    return card;
  }

  function addEmpty(card, message) {
    card.appendChild(el("p", "detail-empty", message));
  }

  function addNote(card, message) {
    card.appendChild(el("p", "detail-note", message));
  }

  /* ------------------------------------------------------
     Result rendering
     ------------------------------------------------------ */

  function buildGauge(score, level) {
    var wrap = el("div", "gauge-wrap");
    var gauge = el("div", "risk-gauge risk-" + level);

    gauge.style.setProperty("--score", String(score === null ? 0 : score));

    if (score === null) {
      gauge.setAttribute("role", "img");
      gauge.setAttribute(
        "aria-label",
        "Risk score unavailable from the backend"
      );
    } else {
      gauge.setAttribute("role", "img");
      gauge.setAttribute(
        "aria-label",
        "Risk score " +
          score +
          " out of 100, " +
          riskLabel(level).toLowerCase() +
          " risk"
      );
    }

    var inner = el("div", "gauge-inner");
    inner.appendChild(
      el("span", "gauge-value", score === null ? "\u2014" : String(score))
    );
    inner.appendChild(el("span", "gauge-unit", "/ 100"));

    gauge.appendChild(inner);
    wrap.appendChild(gauge);

    return wrap;
  }

  function buildSummary(result, meta) {
    var final = result.final_assessment || {};
    var threat = normalizeThreat(final.final_threat);
    var score = clampScore(final.risk_score);
    var level = normalizeRisk(final.risk_level);
    var reasons = asArray(final.reasons).filter(isNonEmptyString);
    var ml = result.machine_learning || {};
    var mlConfidence = formatPercent(ml.confidence);

    var summary = el("article", "result-summary");

    summary.appendChild(buildGauge(score, level));

    var main = el("div", "summary-main");
    var badges = el("div", "summary-badges");

    if (threat === "unknown") {
      badges.appendChild(
        el("span", "threat-badge", "Threat unavailable")
      );
    } else {
      badges.appendChild(
        el("span", "threat-badge threat-" + threat, threatLabel(threat))
      );
    }

    badges.appendChild(
      el(
        "span",
        "risk-pill risk-" + level,
        level === "unknown"
          ? "Risk level unavailable"
          : riskLabel(level) + " risk"
      )
    );

    main.appendChild(badges);

    main.appendChild(
      el(
        "h3",
        "summary-headline",
        THREAT_HEADLINES[threat] || "Assessment available"
      )
    );

    var subText;

    if (score === null) {
      subText =
        "The backend did not return a numeric risk score for this message.";
    } else {
      subText =
        "Combined risk score: " +
        score +
        " out of 100. " +
        (mlConfidence
          ? "The classifier's top-class confidence is " + mlConfidence + "."
          : "No machine-learning confidence was returned.");
    }

    main.appendChild(el("p", "summary-sub", subText));

    if (reasons.length > 0) {
      var reasonList = el("ul", "reason-list");

      reasons.forEach(function (reason) {
        reasonList.appendChild(el("li", null, reason));
      });

      main.appendChild(reasonList);
    }

    var scanned = el("div", "scanned-message");
    scanned.appendChild(el("span", "label", "Scanned message"));
    scanned.appendChild(el("p", null, meta.text || ""));
    main.appendChild(scanned);

    main.appendChild(
      el(
        "p",
        "result-meta",
        "Analysed " + formatTimestamp(meta.timestamp)
      )
    );

    summary.appendChild(main);

    return summary;
  }

  function buildSignalsCard(result) {
    var card = detailCard("signals", "Detection signals");
    var keywords = result.keywords || {};
    var keywordList = asArray(keywords.keywords).filter(isNonEmptyString);
    var indicators =
      keywords.security_indicators &&
      typeof keywords.security_indicators === "object"
        ? keywords.security_indicators
        : {};

    var hasIndicators = Object.keys(indicators).some(function (key) {
      return asArray(indicators[key]).length > 0;
    });

    if (keywordList.length === 0 && !hasIndicators) {
      addEmpty(
        card,
        "No suspicious keywords or security indicators were detected."
      );
      return card;
    }

    if (keywordList.length > 0) {
      card.appendChild(
        el("h4", "mini-heading", "Important keywords")
      );

      var chipList = el("div", "chip-list");

      keywordList.forEach(function (keyword) {
        chipList.appendChild(el("span", "chip", keyword));
      });

      card.appendChild(chipList);
    }

    if (hasIndicators) {
      card.appendChild(
        el("h4", "mini-heading", "Security indicator groups")
      );

      var groups = el("div", "indicator-groups");

      Object.keys(indicators).forEach(function (category) {
        var matches = asArray(indicators[category]).filter(
          isNonEmptyString
        );

        if (matches.length === 0) {
          return;
        }

        var group = el("div", "indicator-group");
        var head = el("div", "indicator-group-head");

        head.appendChild(
          el("span", "indicator-name", humanize(category))
        );
        head.appendChild(
          el("span", "indicator-count", matches.length + " match(es)")
        );

        group.appendChild(head);
        group.appendChild(
          el("p", "indicator-matches", matches.join(", "))
        );

        groups.appendChild(group);
      });

      card.appendChild(groups);
    }

    addNote(
      card,
      "Keyword scores come from the backend's TF-IDF extractor; indicator groups come from its rule-based pattern list."
    );

    return card;
  }

  function buildUrlsCard(result) {
    var card = detailCard("url", "Suspicious URLs");
    var urls = result.urls || {};
    var analyses = asArray(urls.analyses).filter(function (item) {
      return item && typeof item === "object";
    });

    if (analyses.length === 0) {
      addEmpty(card, "No URLs were detected in this message.");
      addNote(
        card,
        "URL analysis runs only when the text contains an explicit http(s):// or www. link."
      );
      return card;
    }

    var list = el("div", "url-list");

    analyses.forEach(function (analysis) {
      var item = el("div", "url-item");
      var url = isNonEmptyString(analysis.url)
        ? analysis.url
        : "URL unavailable";

      item.appendChild(el("span", "url-value", url));

      var meta = el("div", "url-meta");
      var indicators = asArray(analysis.indicators).filter(
        isNonEmptyString
      );
      var terms = asArray(analysis.suspicious_terms).filter(
        isNonEmptyString
      );

      if (isNonEmptyString(analysis.hostname)) {
        meta.appendChild(
          el("span", "tag", "Host: " + analysis.hostname)
        );
      }

      if (isNonEmptyString(analysis.scheme)) {
        meta.appendChild(
          el("span", "tag", "Scheme: " + analysis.scheme)
        );
      }

      if (indicators.length > 0) {
        indicators.forEach(function (indicator) {
          meta.appendChild(
            el("span", "tag tag-warn", humanize(indicator))
          );
        });
      } else {
        meta.appendChild(
          el("span", "tag", "No URL heuristics triggered")
        );
      }

      if (terms.length > 0) {
        meta.appendChild(
          el("span", "tag", "Suspicious terms: " + terms.join(", "))
        );
      }

      item.appendChild(meta);
      list.appendChild(item);
    });

    card.appendChild(list);
    addNote(
      card,
      "URL checks are local heuristics only. No external reputation or blocklist service is queried."
    );

    return card;
  }

  function buildMachineLearningCard(result) {
    var card = detailCard("brain", "Machine-learning classification");
    var ml = result.machine_learning || {};
    var prediction = normalizeThreat(ml.prediction);
    var probabilities =
      ml.probabilities && typeof ml.probabilities === "object"
        ? ml.probabilities
        : {};
    var rows = Object.keys(probabilities)
      .map(function (label) {
        return {
          label: label,
          value: toNumber(probabilities[label])
        };
      })
      .filter(function (row) {
        return row.value !== null;
      })
      .sort(function (a, b) {
        return b.value - a.value;
      });

    var meta = el("div", "chip-list");
    meta.appendChild(
      el(
        "span",
        "chip chip-accent",
        "Prediction: " +
          (prediction === "unknown"
            ? "unavailable"
            : threatLabel(prediction))
      )
    );

    var confidence = formatPercent(ml.confidence);

    if (confidence) {
      meta.appendChild(
        el("span", "chip", "Confidence: " + confidence)
      );
    }

    card.appendChild(meta);

    if (rows.length === 0) {
      addEmpty(
        card,
        "Class probabilities were not returned by the backend."
      );
      return card;
    }

    var list = el("div", "prob-list");

    rows.forEach(function (row, index) {
      var percent = Math.max(0, Math.min(100, row.value * 100));
      var wrapper = el(
        "div",
        "prob-row" + (index === 0 ? " is-top" : "")
      );
      var head = el("div", "prob-head");

      head.appendChild(
        el("span", null, humanize(row.label))
      );
      head.appendChild(
        el(
          "strong",
          null,
          formatPercent(row.value) || "0%"
        )
      );

      var track = el("div", "prob-track");
      var fill = el("div", "prob-fill");

      fill.style.width = percent.toFixed(2) + "%";
      track.appendChild(fill);

      wrapper.appendChild(head);
      wrapper.appendChild(track);
      list.appendChild(wrapper);
    });

    card.appendChild(list);
    addNote(
      card,
      "Probabilities are model estimates, not certainty. The final assessment also considers heuristic and URL evidence."
    );

    return card;
  }

  function buildComponentsCard(result) {
    var card = detailCard("gauge", "Risk components");
    var final = result.final_assessment || {};
    var components =
      final.component_scores &&
      typeof final.component_scores === "object"
        ? final.component_scores
        : {};
    var heuristic = result.heuristic || {};
    var entries = [
      {
        label: "Heuristic score",
        value: components.heuristic,
        suffix: "/100"
      },
      {
        label: "ML confidence",
        value: components.machine_learning,
        suffix: "/100"
      },
      {
        label: "URL indicators",
        value: components.url_indicators,
        suffix: ""
      },
      {
        label: "Security indicators",
        value: components.security_indicators,
        suffix: ""
      }
    ].filter(function (entry) {
      return toNumber(entry.value) !== null;
    });

    if (entries.length === 0) {
      addEmpty(
        card,
        "Component scores were not returned by the backend."
      );
      return card;
    }

    var grid = el("div", "metric-grid");

    entries.forEach(function (entry) {
      var box = el("div", "metric-box");
      var number = toNumber(entry.value);
      var display = Number.isInteger(number)
        ? String(number)
        : String(Math.round(number * 100) / 100);

      box.appendChild(el("span", "metric-label", entry.label));
      box.appendChild(
        el("span", "metric-figure", display + entry.suffix)
      );
      grid.appendChild(box);
    });

    card.appendChild(grid);

    var heuristicCategory = isNonEmptyString(
      heuristic.threat_category
    )
      ? heuristic.threat_category
      : null;
    var heuristicRisk = clampScore(heuristic.risk_score);

    if (heuristicCategory || heuristicRisk !== null) {
      var parts = [];

      if (heuristicCategory) {
        parts.push("Heuristic category: " + humanize(heuristicCategory));
      }

      if (heuristicRisk !== null) {
        parts.push("heuristic risk " + heuristicRisk + "/100");
      }

      addNote(card, parts.join(" \u00b7 "));
    } else {
      addNote(
        card,
        "The backend did not provide heuristic category details."
      );
    }

    return card;
  }

  function buildNlpCard(result) {
    var card = detailCard("nlp", "NLP preprocessing");
    var nlp = result.nlp || {};
    var tokens = asArray(nlp.tokens);
    var filtered = asArray(nlp.filtered_tokens);
    var posTags = asArray(nlp.pos_tags);
    var entities = asArray(nlp.named_entities);

    if (
      tokens.length === 0 &&
      filtered.length === 0 &&
      posTags.length === 0 &&
      entities.length === 0
    ) {
      addEmpty(
        card,
        "NLP preprocessing details were not returned by the backend."
      );
      return card;
    }

    var grid = el("div", "metric-grid metric-grid-4");
    var metrics = [
      { label: "Tokens", value: tokens.length },
      { label: "Filtered", value: filtered.length },
      { label: "POS tags", value: posTags.length },
      { label: "Entities", value: entities.length }
    ];

    metrics.forEach(function (metric) {
      var box = el("div", "metric-box");

      box.appendChild(
        el("span", "metric-label", metric.label)
      );
      box.appendChild(
        el("span", "metric-figure", String(metric.value))
      );
      grid.appendChild(box);
    });

    card.appendChild(grid);

    if (entities.length > 0) {
      card.appendChild(
        el("h4", "mini-heading", "Named entities")
      );

      var chips = el("div", "chip-list");

      entities.forEach(function (entity) {
        if (!Array.isArray(entity) || entity.length === 0) {
          return;
        }

        var name = isNonEmptyString(entity[0])
          ? entity[0]
          : "Unnamed";

        var type = isNonEmptyString(entity[1])
          ? entity[1]
          : "ENTITY";

        chips.appendChild(
          el("span", "chip", name + " (" + type + ")")
        );
      });

      card.appendChild(chips);
    } else {
      addNote(card, "No named entities were detected.");
    }

    addNote(
      card,
      "Preprocessing uses NLTK tokenisation, stop-word removal, stemming, lemmatisation, POS tagging, and named-entity recognition."
    );

    return card;
  }

  function buildRecommendations(threat, level) {
    var recommendations = [
      "Verify the sender through an official phone number or website that you find independently \u2014 not contact details taken from the message."
    ];

    if (threat === "benign") {
      recommendations.push(
        "No strong threat signals were found, but automated analysis can still be wrong. Stay cautious with unexpected requests."
      );
    } else {
      recommendations.push(
        "Do not click links, call numbers, or download attachments until the message is confirmed as genuine."
      );
      recommendations.push(
        "Never share passwords, OTPs, PINs, or banking credentials."
      );

      if (threat === "phishing") {
        recommendations.push(
          "If you entered credentials on a linked page, change that password now and enable multi-factor authentication."
        );
      } else if (threat === "scam") {
        recommendations.push(
          "Do not pay any fee or send money to claim a prize, reward, or refund."
        );
      } else if (threat === "social_engineering") {
        recommendations.push(
          "Confirm unusual requests through a separate, trusted channel before acting."
        );
      }

      if (level === "high" || level === "critical") {
        recommendations.push(
          "If you already interacted with the message, contact your bank or service provider immediately and report the incident."
        );
      }

      recommendations.push(
        "Report the message to your email provider, mobile carrier, or the organisation being impersonated."
      );
    }

    return recommendations;
  }

  function buildRecommendationsCard(result) {
    var card = detailCard("shield", "Safety recommendations");
    var final = result.final_assessment || {};
    var threat = normalizeThreat(final.final_threat);
    var level = normalizeRisk(final.risk_level);
    var list = el("ul", "recommendation-list");

    buildRecommendations(threat, level).forEach(function (text) {
      list.appendChild(el("li", null, text));
    });

    card.appendChild(list);
    addNote(
      card,
      "These are general safety steps based on the detected threat and risk level, not a guarantee that the message is safe or malicious."
    );

    return card;
  }

  function buildResultFooter() {
    var footer = el("div", "result-footer");
    var text = el(
      "p",
      null,
      "Automated results may be incorrect. Always verify suspicious communications independently."
    );
    var button = el("button", "btn btn-ghost btn-sm", "Scan another message");

    button.type = "button";
    button.addEventListener("click", function () {
      elements.messageInput.focus();
      elements.messageInput.select();
      elements.scannerSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });
    });

    footer.appendChild(text);
    footer.appendChild(button);

    return footer;
  }

  function renderResult(result, meta) {
    var container = elements.resultContent;

    container.textContent = "";

    var final = result.final_assessment || {};

    container.appendChild(buildSummary(result, meta));

    var grid = el("div", "result-grid");

    grid.appendChild(buildSignalsCard(result));
    grid.appendChild(buildUrlsCard(result));
    grid.appendChild(buildMachineLearningCard(result));
    grid.appendChild(buildComponentsCard(result));
    grid.appendChild(buildNlpCard(result));
    grid.appendChild(buildRecommendationsCard(result));

    container.appendChild(grid);
    container.appendChild(buildResultFooter());

    var threat = normalizeThreat(final.final_threat);
    var score = clampScore(final.risk_score);
    var level = normalizeRisk(final.risk_level);
    var announcement =
      "Analysis complete. Threat: " +
      threatLabel(threat) +
      ". Risk score " +
      (score === null ? "unavailable" : score + " out of 100") +
      ". Risk level " +
      riskLabel(level) +
      ".";

    announce(announcement);
  }

  function renderError(message, status) {
    var container = elements.resultContent;

    container.textContent = "";

    var card = el("div", "error-card");
    card.appendChild(el("h3", null, "Analysis could not be completed"));
    card.appendChild(el("p", null, message));

    if (status === 503) {
      card.appendChild(
        el(
          "p",
          null,
          "The backend is reachable but its analysis engine is not ready. Check the server console for details."
        )
      );
    } else if (status === 0) {
      card.appendChild(
        el(
          "p",
          null,
          "Start the backend (start.bat or uvicorn) and make sure the API base URL is correct. API base: " +
            API.getBaseUrl()
        )
      );
    }

    var actions = el("div", "scanner-actions");
    var retry = el("button", "btn btn-primary btn-sm", "Try again");

    retry.type = "button";
    retry.addEventListener("click", function () {
      elements.scanForm.requestSubmit();
    });

    actions.appendChild(retry);
    card.appendChild(actions);
    container.appendChild(card);

    announce("Analysis failed. " + message);
  }

  /* ------------------------------------------------------
     History rendering
     ------------------------------------------------------ */

  function renderHistory() {
    var list = elements.historyList;
    var entries = History.load();

    list.textContent = "";
    elements.clearHistoryBtn.disabled = entries.length === 0;

    if (!History.isAvailable()) {
      list.appendChild(
        el(
          "div",
          "history-empty",
          "Browser storage is unavailable, so scan history cannot be saved. Analysis still works."
        )
      );
      elements.clearHistoryBtn.disabled = true;
      return;
    }

    if (entries.length === 0) {
      list.appendChild(
        el(
          "div",
          "history-empty",
          "No scans saved yet. Analyse a message and the result will appear here \u2014 in this browser only."
        )
      );
      return;
    }

    entries.forEach(function (entry) {
      var final = entry.result.final_assessment || {};
      var threat = normalizeThreat(final.final_threat);
      var level = normalizeRisk(final.risk_level);
      var score = clampScore(final.risk_score);
      var button = el("button", "history-item");

      button.type = "button";
      button.setAttribute(
        "aria-label",
        "Open scan from " +
          formatTimestamp(entry.timestamp) +
          ", " +
          threatLabel(threat) +
          ", risk " +
          (score === null ? "unavailable" : score + " out of 100")
      );

      var top = el("div", "history-top");
      top.appendChild(
        el(
          "span",
          "threat-badge threat-" + threat,
          threat === "unknown" ? "Unavailable" : threatLabel(threat)
        )
      );
      top.appendChild(
        el(
          "span",
          "risk-pill risk-" + level,
          level === "unknown" ? "No level" : riskLabel(level)
        )
      );
      top.appendChild(
        el("span", "history-time", formatTimestamp(entry.timestamp))
      );

      button.appendChild(top);
      button.appendChild(el("span", "history-text", entry.text));
      button.appendChild(
        el(
          "span",
          "history-score",
          "Risk score: " +
            (score === null ? "unavailable" : score + "/100") +
            " \u00b7 " +
            riskLabel(level) +
            " risk"
        )
      );

      button.addEventListener("click", function () {
        renderResult(entry.result, {
          text: entry.text,
          timestamp: entry.timestamp
        });
        showResultsSection();
      });

      list.appendChild(button);
    });
  }

  /* ------------------------------------------------------
     Form submission
     ------------------------------------------------------ */

  async function handleSubmit(event) {
    event.preventDefault();

    if (isAnalyzing) {
      return;
    }

    clearFormError();

    var text = elements.messageInput.value.trim();

    if (text === "") {
      showFormError(
        "Enter a message to analyse. You can paste an SMS, email, or chat message."
      );
      elements.messageInput.focus();
      return;
    }

    if (text.length > maxChars) {
      showFormError(
        "This message is too long. The maximum is " +
          maxChars +
          " characters."
      );
      elements.messageInput.focus();
      return;
    }

    setLoading(true);
    announce("Analysing message\u2026");

    try {
      var result = await API.analyze(text);
      var timestamp = new Date().toISOString();

      renderResult(result, { text: text, timestamp: timestamp });

      var stored = History.add(text, result);

      renderHistory();

      if (!stored.saved) {
        announce(
          "Analysis complete, but browser storage is full, so this scan was not saved to history."
        );
      }

      showResultsSection();
    } catch (error) {
      var message =
        error && error.message
          ? error.message
          : "An unexpected error occurred. Please try again.";

      renderError(message, error && error.status ? error.status : 0);
      showResultsSection();
    } finally {
      setLoading(false);
    }
  }

  /* ------------------------------------------------------
     Service worker
     ------------------------------------------------------ */

  function initServiceWorker() {
    if (!("serviceWorker" in global.navigator)) {
      return;
    }

    if (
      global.location.protocol !== "http:" &&
      global.location.protocol !== "https:"
    ) {
      return;
    }

    global.addEventListener("load", function () {
      global.navigator.serviceWorker
        .register("service-worker.js")
        .catch(function () {
          /* Offline support is optional; ignore registration errors. */
        });
    });
  }

  /* ------------------------------------------------------
     Initialisation
     ------------------------------------------------------ */

  function cacheElements() {
    elements = {
      navToggle: byId("navToggle"),
      navMenu: byId("navMenu"),
      themeToggle: byId("themeToggle"),
      themeToggleText: byId("themeToggleText"),
      themeColorMeta: byId("themeColorMeta"),
      backendStatus: byId("backendStatus"),
      backendStatusText: byId("backendStatusText"),
      scanForm: byId("scanForm"),
      messageInput: byId("messageInput"),
      charCount: byId("charCount"),
      formError: byId("formError"),
      analyzeBtn: byId("analyzeBtn"),
      analyzeBtnText: byId("analyzeBtnText"),
      clearBtn: byId("clearBtn"),
      scannerSection: byId("scanner"),
      resultsSection: byId("results"),
      resultsTitle: byId("resultsTitle"),
      resultStatus: byId("resultStatus"),
      resultContent: byId("resultContent"),
      historyList: byId("historyList"),
      clearHistoryBtn: byId("clearHistoryBtn")
    };
  }

  function init() {
    cacheElements();

    if (
      !API ||
      typeof API.analyze !== "function" ||
      !History ||
      typeof History.load !== "function"
    ) {
      return;
    }

    initTheme();
    initNavigation();
    initSamples();
    initServiceWorker();

    elements.messageInput.addEventListener("input", updateCharCount);
    elements.scanForm.addEventListener("submit", handleSubmit);

    elements.clearBtn.addEventListener("click", function () {
      elements.messageInput.value = "";
      updateCharCount();
      clearFormError();
      elements.messageInput.focus();
    });

    elements.clearHistoryBtn.addEventListener("click", function () {
      if (History.load().length === 0) {
        return;
      }

      var confirmed = global.confirm(
        "Clear all locally stored scan history? This cannot be undone."
      );

      if (!confirmed) {
        return;
      }

      History.clear();
      renderHistory();
      announce("Scan history cleared.");
    });

    updateCharCount();
    renderHistory();
    checkBackend();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})(window);
