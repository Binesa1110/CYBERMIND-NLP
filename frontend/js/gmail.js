/* ==========================================================
   CYBERMIND — opt-in Gmail monitor dashboard
   Gmail data is fetched same-origin and is never service-worker cached.
   ========================================================== */

(function (global) {
  "use strict";

  var elements = {};
  var currentStatus = null;

  function endpoint(path) {
    return new URL(path, global.CyberMindAPI.getBaseUrl()).toString();
  }

  async function request(path, method, body) {
    var options = {
      method: method || "GET",
      cache: "no-store",
      credentials: "include",
      headers: { Accept: "application/json" }
    };

    if (body !== undefined) {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }

    var response;
    try {
      response = await global.fetch(endpoint(path), options);
    } catch (error) {
      throw new Error(
        "Could not reach the Gmail API. Open CYBERMIND from " +
          "http://127.0.0.1:8000/ui/ and try again."
      );
    }

    var payload = null;
    if (response.status !== 204) {
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
    }

    if (!response.ok) {
      throw new Error(
        payload && typeof payload.detail === "string"
          ? payload.detail
          : "Gmail request failed (HTTP " + response.status + ")."
      );
    }
    return payload;
  }

  function setStatus(message, kind) {
    elements.status.textContent = message;
    elements.status.className = "gmail-status" + (kind ? " is-" + kind : "");
  }

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function setVisible(element, visible) {
    element.hidden = !visible;
  }

  function updateConsentButton() {
    elements.enable.disabled = !elements.consent.checked;
  }

  function friendlyMonitoringError(code) {
    var messages = {
      gmail_api_error:
        "Google reported an API error. Monitoring will retry; check Google Cloud and OAuth setup.",
      gmail_reauthorization_required:
        "Gmail authorization expired. Disconnect and connect the account again.",
      gmail_history_recovery_limit_exceeded:
        "The missed-message recovery limit was exceeded. Review setup and reconnect monitoring.",
      gmail_reconciliation_error:
        "Inbox reconciliation failed. The worker will retry; check its terminal logs.",
      gmail_processing_error:
        "A message could not be processed. The worker will retry it.",
      pubsub_not_configured:
        "Google Cloud Pub/Sub is not configured."
    };
    return messages[code] || "Monitoring needs attention (" + code + ").";
  }

  function renderStatus(status) {
    currentStatus = status;
    var connected = status.connected === true;
    var monitoringEnabled = status.monitoring_enabled === true;
    var pubsubReady = status.pubsub_configured === true;
    var localOrigin = global.location.origin;
    var apiOrigin = new URL(global.CyberMindAPI.getBaseUrl()).origin;

    setVisible(elements.connect, !connected && status.oauth_configured);
    setVisible(
      elements.consentWrap,
      connected && !monitoringEnabled && pubsubReady
    );
    setVisible(
      elements.enable,
      connected && !monitoringEnabled && pubsubReady
    );
    setVisible(elements.pause, connected && monitoringEnabled);
    setVisible(elements.refresh, connected);
    setVisible(elements.clear, connected);
    setVisible(elements.disconnect, connected);
    setVisible(elements.statistics, connected);

    if (localOrigin !== apiOrigin) {
      setVisible(elements.connect, false);
      setStatus(
        "For Gmail sign-in, open the same-origin app at " +
          apiOrigin +
          "/ui/. Gmail browser sessions are not shared across origins.",
        "warning"
      );
      return;
    }

    if (
      !connected &&
      status.oauth_configured &&
      status.redirect_uri_matches_origin !== true
    ) {
      setVisible(elements.connect, false);
      setStatus(
        "Open CYBERMIND using the host configured in GOOGLE_REDIRECT_URI. Use localhost consistently instead of switching between localhost and 127.0.0.1.",
        "warning"
      );
      return;
    }

    if (connected) {
      var state = monitoringEnabled
        ? "Monitoring is ON"
        : "Gmail is connected; monitoring is OFF.";
      var message = state + " Account: " + status.email + ".";
      if (!monitoringEnabled && !pubsubReady) {
        message +=
          " Pub/Sub is not configured; missing settings: " +
          (status.missing_pubsub_settings || []).join(", ") +
          ".";
      }
      if (status.watch_expiration && monitoringEnabled) {
        message += " Watch expires " + status.watch_expiration + ".";
      }
      if (status.monitoring_error) {
        message += " " + friendlyMonitoringError(status.monitoring_error);
      }
      setStatus(message, status.monitoring_error ? "warning" : "success");
      refreshAlerts();
      return;
    }

    elements.alerts.replaceChildren();
    elements.statistics.replaceChildren();
    if (status.oauth_configured) {
      setStatus(
        "No Gmail account is connected. Connect read-only access first; monitoring remains off until you enable it.",
        ""
      );
    } else {
      setVisible(elements.connect, false);
      setStatus(
        "Gmail setup is incomplete. Missing settings: " +
          (status.missing_oauth_settings || []).join(", ") +
          ". See GMAIL_SETUP_GUIDE.md.",
        "warning"
      );
    }
  }

  function renderStatistics(statistics) {
    var stats = statistics || {};
    var entries = [
      ["Analyzed", stats.total_analysed || 0],
      ["Phishing", stats.phishing || 0],
      ["Scams", stats.scam || 0],
      ["Benign", stats.benign || 0]
    ];
    elements.statistics.replaceChildren();
    entries.forEach(function (entry) {
      var card = make("div", "gmail-stat");
      card.appendChild(make("span", "gmail-stat-label", entry[0]));
      card.appendChild(make("strong", "gmail-stat-value", entry[1]));
      elements.statistics.appendChild(card);
    });
  }

  function renderAlerts(alerts) {
    elements.alerts.replaceChildren();
    if (!alerts.length) {
      elements.alerts.appendChild(
        make(
          "p",
          "gmail-empty",
          currentStatus && currentStatus.monitoring_enabled
            ? "Monitoring is active. No new Inbox messages have been analyzed yet."
            : "No Gmail analysis records are saved."
        )
      );
      return;
    }

    alerts.forEach(function (alert) {
      var card = make("article", "gmail-alert");
      var heading = make("div", "gmail-alert-heading");
      heading.appendChild(
        make(
          "span",
          "gmail-threat gmail-threat-" + alert.threat_category,
          alert.threat_category
        )
      );
      heading.appendChild(
        make(
          "span",
          "gmail-risk",
          alert.risk_level + " risk · " + alert.risk_score + "/100"
        )
      );
      card.appendChild(heading);
      card.appendChild(
        make("h3", "gmail-alert-subject", alert.subject || "(No subject)")
      );
      card.appendChild(make("p", "gmail-alert-sender", alert.sender));
      if (alert.received_at) {
        var date = new Date(alert.received_at);
        card.appendChild(
          make(
            "time",
            "gmail-alert-time",
            isNaN(date.getTime()) ? alert.received_at : date.toLocaleString()
          )
        );
      }

      var details = make("details", "gmail-alert-details");
      details.appendChild(make("summary", "", "Analysis details"));
      var list = make("ul", "gmail-reasons");
      (alert.reasons || []).forEach(function (reason) {
        list.appendChild(make("li", "", reason));
      });
      if ((alert.urls || []).length) {
        list.appendChild(
          make(
            "li",
            "",
            "URLs: " + alert.urls.join(", ")
          )
        );
      }
      if ((alert.attachment_metadata || []).length) {
        var descriptions = alert.attachment_metadata.map(function (item) {
          return (
            (item.mime_type || "unknown file type") +
            " (" +
            (item.size || 0) +
            " bytes)"
          );
        });
        list.appendChild(
          make("li", "", "Attachments not downloaded: " + descriptions.join(", "))
        );
      }
      if (alert.content_truncated) {
        list.appendChild(
          make("li", "", "Some message content was truncated before analysis.")
        );
      }
      details.appendChild(list);
      card.appendChild(details);
      elements.alerts.appendChild(card);
    });
  }

  async function refreshAlerts() {
    try {
      var payload = await request("/gmail/alerts?limit=100");
      renderStatistics(payload.statistics);
      renderAlerts(payload.alerts || []);
    } catch (error) {
      setStatus(error.message, "error");
    }
  }

  async function refreshStatus() {
    try {
      var status = await request("/gmail/status");
      renderStatus(status);
    } catch (error) {
      setStatus(error.message, "error");
    }
  }

  async function connect() {
    elements.connect.disabled = true;
    try {
      var payload = await request("/gmail/connect", "POST");
      var authorizationUrl = new URL(payload.authorization_url);
      if (authorizationUrl.origin !== "https://accounts.google.com") {
        throw new Error("The server returned an invalid Google authorization URL.");
      }
      global.location.assign(authorizationUrl.toString());
    } catch (error) {
      setStatus(error.message, "error");
      elements.connect.disabled = false;
    }
  }

  async function updateMonitoring(enabled) {
    try {
      await request("/gmail/monitoring", "POST", { enabled: enabled });
      elements.consent.checked = false;
      setStatus(
        enabled ? "Monitoring enabled." : "Monitoring paused.",
        "success"
      );
      await refreshStatus();
    } catch (error) {
      setStatus(error.message, "error");
    }
  }

  async function pauseMonitoring() {
    try {
      var payload = await request("/gmail/monitoring", "POST", {
        enabled: false
      });
      elements.consent.checked = false;
      await refreshStatus();
      if (!payload.watch_stopped) {
        setStatus(
          "Monitoring is disabled locally. Google could not stop the existing watch immediately; notifications will be ignored and the watch will expire.",
          "warning"
        );
      }
    } catch (error) {
      setStatus(error.message, "error");
    }
  }

  async function disconnect() {
    if (
      !global.confirm(
        "Disconnect Gmail and remove saved alerts from this server?"
      )
    ) {
      return;
    }
    try {
      var payload = await request("/gmail/disconnect", "POST");
      await refreshStatus();
      if (payload.remote_revocation !== "revoked") {
        setStatus(
          "Local Gmail data was removed, but Google could not confirm token revocation. Revoke CYBERMIND access in your Google Account.",
          "warning"
        );
      }
    } catch (error) {
      setStatus(error.message, "error");
    }
  }

  async function clearAlerts() {
    if (!global.confirm("Delete all saved Gmail analysis records?")) {
      return;
    }
    try {
      await request("/gmail/alerts", "DELETE");
      await refreshAlerts();
    } catch (error) {
      setStatus(error.message, "error");
    }
  }

  function init() {
    elements = {
      status: document.getElementById("gmailStatus"),
      connect: document.getElementById("gmailConnectBtn"),
      consentWrap: document.getElementById("gmailConsentWrap"),
      consent: document.getElementById("gmailConsent"),
      enable: document.getElementById("gmailEnableBtn"),
      pause: document.getElementById("gmailPauseBtn"),
      refresh: document.getElementById("gmailRefreshBtn"),
      clear: document.getElementById("gmailClearBtn"),
      disconnect: document.getElementById("gmailDisconnectBtn"),
      statistics: document.getElementById("gmailStatistics"),
      alerts: document.getElementById("gmailAlerts")
    };

    elements.consent.addEventListener("change", updateConsentButton);
    elements.connect.addEventListener("click", connect);
    elements.enable.addEventListener("click", function () {
      if (elements.consent.checked) {
        updateMonitoring(true);
      }
    });
    elements.pause.addEventListener("click", pauseMonitoring);
    elements.refresh.addEventListener("click", refreshStatus);
    elements.clear.addEventListener("click", clearAlerts);
    elements.disconnect.addEventListener("click", disconnect);
    updateConsentButton();
    refreshStatus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})(window);
