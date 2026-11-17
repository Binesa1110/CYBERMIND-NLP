/* ==========================================================
   CYBERMIND — API client
   The backend base URL is configured in ONE place below.
   ========================================================== */

(function (global) {
  "use strict";

  /* --------------------------------------------------------
     Configuration
     --------------------------------------------------------
     To point the frontend at a different backend, define this
     before loading app.js / api.js:

       <script>
         window.CYBERMIND_CONFIG = {
           API_BASE_URL: "https://api.example.com"
         };
       </script>

     When the frontend is served by FastAPI at /ui/, the API is
     same-origin and relative URLs are used automatically.
     -------------------------------------------------------- */

  var DEFAULT_CONFIG = {
    API_BASE_URL: null,
    REQUEST_TIMEOUT_MS: 25000
  };

  var CONFIG = Object.assign(
    {},
    DEFAULT_CONFIG,
    global.CYBERMIND_CONFIG || {}
  );

  function resolveBaseUrl() {
    if (
      typeof CONFIG.API_BASE_URL === "string" &&
      CONFIG.API_BASE_URL.trim() !== ""
    ) {
      return CONFIG.API_BASE_URL.trim().replace(/\/+$/, "");
    }

    var protocol = global.location.protocol;
    var hostname = global.location.hostname;
    var port = global.location.port;
    var isHttp = protocol === "http:" || protocol === "https:";

    // Opened directly from disk: browsers block cross-origin API
    // calls from file://. Point at the local backend anyway so the
    // error message can explain what to do.
    if (!isHttp) {
      return "http://127.0.0.1:8000";
    }

    var pathname = global.location.pathname || "";

    // The backend mounts the UI at /ui/. If the page is being served
    // from that path, the API is same-origin regardless of port
    // (8000 in normal use, any port for tests or custom setups).
    if (/\/ui(\/|$)/.test(pathname)) {
      return "";
    }

    var isLocal =
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      hostname === "[::1]";

    // A separate local static server (e.g. VS Code Live Server on
    // :5500, http-server on :8080, or CRA on :3000) talks to the
    // backend on its default port.
    var staticDevPorts = ["5500", "8080", "3000"];

    if (isLocal && staticDevPorts.indexOf(port) !== -1) {
      return "http://127.0.0.1:8000";
    }

    // Everything else (localhost:8000, a LAN address, or a public
    // deployment) is served same-origin.
    return "";
  }

  var BASE_URL = resolveBaseUrl();

  function apiOrigin() {
    return BASE_URL === "" ? global.location.origin : BASE_URL;
  }

  function networkErrorMessage() {
    if (global.location.protocol === "file:") {
      return (
        "This page was opened directly from disk, so the browser blocks " +
        "API requests. Start the backend and open " +
        "http://127.0.0.1:8000/ui/ instead."
      );
    }

    return (
      "Could not reach the CYBERMIND backend at " +
      apiOrigin() +
      ". Make sure the server is running, then try again."
    );
  }

  function formatHttpError(status, detail) {
    var cleanDetail = typeof detail === "string" ? detail.trim() : "";

    if (status === 422) {
      return (
        cleanDetail ||
        "The message could not be validated. Check it is not empty and " +
          "is within the length limit."
      );
    }

    if (status === 413) {
      return "The message is too long for the server to analyse.";
    }

    if (status === 429) {
      return "Too many requests. Please wait a moment and try again.";
    }

    if (status === 503) {
      return (
        cleanDetail ||
        "The analysis engine is not available right now. " +
          "Please try again later."
      );
    }

    if (status >= 500) {
      return (
        "The backend could not analyse this message. " +
        "Please try again in a moment."
      );
    }

    return cleanDetail || "Request failed (HTTP " + status + ").";
  }

  function ApiError(message, status, payload) {
    this.name = "ApiError";
    this.message = message;
    this.status = status || 0;
    this.payload = payload || null;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiError);
    } else {
      this.stack = new Error(message).stack;
    }
  }

  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;

  async function request(path, options) {
    var controller = new global.AbortController();
    var timer = global.setTimeout(function () {
      controller.abort();
    }, CONFIG.REQUEST_TIMEOUT_MS);

    var response;

    try {
      response = await global.fetch(BASE_URL + path, {
        method: (options && options.method) || "GET",
        headers: (options && options.headers) || {},
        body: options && options.body,
        cache: "no-store",
        credentials: "omit",
        mode: "cors",
        signal: controller.signal
      });
    } catch (error) {
      global.clearTimeout(timer);

      if (error && error.name === "AbortError") {
        throw new ApiError(
          "The request timed out. The backend may be busy or unreachable.",
          0
        );
      }

      throw new ApiError(networkErrorMessage(), 0, error);
    }

    global.clearTimeout(timer);

    var raw = "";
    var payload = null;

    try {
      raw = await response.text();
    } catch (error) {
      raw = "";
    }

    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch (error) {
        payload = null;
      }
    }

    if (!response.ok) {
      var detail =
        payload && typeof payload.detail === "string"
          ? payload.detail
          : "";

      throw new ApiError(
        formatHttpError(response.status, detail),
        response.status,
        payload
      );
    }

    return payload;
  }

  async function analyze(text) {
    var payload = await request("/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({ text: text })
    });

    if (
      !payload ||
      payload.status !== "success" ||
      typeof payload.result !== "object" ||
      payload.result === null
    ) {
      throw new ApiError(
        "The backend returned an unexpected response. Please try again.",
        0,
        payload
      );
    }

    return payload.result;
  }

  async function health() {
    return request("/health", {
      method: "GET",
      headers: { Accept: "application/json" }
    });
  }

  global.CyberMindAPI = {
    analyze: analyze,
    health: health,
    getBaseUrl: apiOrigin,
    getMaxLength: function () {
      return 5000;
    },
    ApiError: ApiError,
    DEFAULT_CONFIG: DEFAULT_CONFIG
  };
})(window);
