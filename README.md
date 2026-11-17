# CYBERMIND-NLP

**AI-Powered Cyber Threat Detection**

CYBERMIND is a cybersecurity text-analysis web application built on the
existing CYBERMIND-NLP Python project. It combines NLTK preprocessing,
rule-based keyword and URL analysis, a locally trained scikit-learn model,
and a decision engine that produces a final threat, risk score, and risk
level.

The web UI is plain HTML5, CSS3, and vanilla JavaScript. It is served by the
FastAPI backend at `/ui/`, so the browser and API are same-origin by default.
An optional Gmail monitor uses read-only OAuth access and remains disabled
until a user explicitly connects an account and enables monitoring. Setup
requires Google Cloud OAuth and Pub/Sub configuration; see
[`GMAIL_SETUP_GUIDE.md`](./GMAIL_SETUP_GUIDE.md).

## Screenshots

Screenshots can be added here after capturing the running app. Redact email
addresses, OAuth details, and any personal information before publishing.

- Dashboard: `docs/screenshots/dashboard.png` (placeholder)
- Threat analysis result: `docs/screenshots/analysis-result.png` (placeholder)
- Email security panel: `docs/screenshots/email-security.png` (placeholder;
  use mock/demo data only)

---

## 1. What was verified

These are the **actual outputs** of the bundled model (they were not edited
or forced):

| Sample message | Final threat | Risk score | Risk level | ML top confidence |
| --- | --- | --- | --- | --- |
| "Your bank account will be blocked. Click here to verify your password immediately." | `phishing` | 73 / 100 | CRITICAL | 78.43% |
| "Congratulations! You won a lottery. Pay a processing fee to receive your prize." | `scam` | 74 / 100 | CRITICAL | 80.39% |
| "Hi, are we meeting for lunch tomorrow?" | `benign` | 0 / 100 | LOW | 69.89% |

Automated test results on this machine:

- **Backend tests:** 48 passed (`unittest`), including mocked Gmail OAuth,
  parsing, storage, opt-in and Pub/Sub checks.
- **Browser end-to-end tests:** 21 checks passed (Playwright + installed
  Microsoft Edge), covering desktop features, history, theme persistence,
  XSS safety, offline behaviour, and the 360 / 390 / 768 / 1024 / 1440 px
  layouts. The Gmail dashboard loads and private Gmail status is not served
  from the offline cache.
- **Live Gmail / Google Cloud:** not configured or tested; real monitoring
  requires the setup in `GMAIL_SETUP_GUIDE.md`.

> These results describe this specific bundled model and sample set. No
> general accuracy percentage is claimed.

---

## 2. Project structure

```
CYBERMIND-NLP-main/
├── api.py                          FastAPI app, validation, CORS, static hosting
├── main.py                         Original interactive CLI (unchanged)
├── start.bat                       Windows launcher (server + opens browser)
├── run_gmail_worker.bat            Optional Gmail Pub/Sub worker
├── run_tests.bat                   Windows test launcher
├── requirements.txt                Runtime and Gmail integration dependencies
├── requirements-dev.txt            Test-only dependencies (httpx, playwright)
├── .env.example                    Optional environment variables
├── README.md                       This file
├── .gitignore
│
├── data/
│   ├── raw/cybersecurity_messages.csv
│   └── test/unseen_messages.csv
│
├── models/
│   └── cybermind_threat_classifier.joblib   Existing trained model (unchanged)
│
├── src/
│   ├── analyzer.py
│   ├── preprocessing.py
│   ├── sentiment.py
│   ├── keyword_analyzer.py
│   ├── url_analyzer.py
│   ├── threat_analyzer.py
│   ├── ml_classifier.py
│   ├── decision_engine.py
│   └── gmail_security/             OAuth, encrypted store, Gmail API and worker
│       ├── config.py
│       ├── store.py
│       ├── sessions.py
│       ├── gmail_client.py
│       ├── monitor.py
│       ├── router.py
│       └── worker.py
│
├── tests/
│   ├── __init__.py
│   ├── test_api.py                 Backend / API tests
│   ├── test_gmail_security.py      Mocked Gmail OAuth, storage and sync tests
│   ├── test_preprocessing.py       NLP preprocessing tests
│   └── browser_e2e.py              Optional Playwright browser tests
│
└── frontend/
    ├── index.html                  Single-page app
    ├── manifest.json               PWA manifest
    ├── service-worker.js           App-shell cache + offline fallback
    ├── offline.html                Offline page
    ├── css/
    │   ├── style.css               Themes, layout, components
    │   ├── responsive.css          Responsive breakpoints
    │   └── gmail.css               Gmail dashboard
    ├── js/
    │   ├── api.js                  Single API base-URL configuration + fetch
    │   ├── history.js              localStorage scan history (max 20)
    │   ├── app.js                  UI logic, result rendering, theme, nav
    │   └── gmail.js                Gmail dashboard and API calls
    └── assets/
        ├── logo.svg
        └── icons/
            ├── favicon-32.png
            ├── apple-touch-icon-180.png
            ├── icon-192.png
            ├── icon-512.png
            └── icon-maskable-512.png
```

In this workspace the virtual environment is **one folder above** the project
root:

```
C:\Users\ASUS\Downloads\CYBERMIND-NLP-main\
├── .venv\                          Python 3.13 virtual environment
└── CYBERMIND-NLP-main\             Project root (run commands here)
```

---

## 3. Start the app (Windows, beginner steps)

1. Open **File Explorer** and go to the project root:
   `C:\Users\ASUS\Downloads\CYBERMIND-NLP-main\CYBERMIND-NLP-main`
2. Double-click **`start.bat`**.
3. A console window opens. Wait a few seconds; the default browser opens
   `http://localhost:8000/ui/` automatically.
4. To stop the server, click the console window and press **Ctrl+C**.

`start.bat` checks that Python packages, the model file, and NLTK data are
present. If something is missing it prints the exact command to fix it.

### Start manually in PowerShell

```powershell
cd C:\Users\ASUS\Downloads\CYBERMIND-NLP-main\CYBERMIND-NLP-main
$env:PYTHONUTF8 = "1"
..\.venv\Scripts\python.exe -m uvicorn api:app --host 0.0.0.0 --port 8000
```

Then open:

- Website: <http://localhost:8000/ui/>
- API documentation (Swagger): <http://localhost:8000/docs>
- Health check: <http://localhost:8000/health>
- API status JSON: <http://localhost:8000/>

`/app` redirects to `/ui/`. The root `/` intentionally remains a JSON status
endpoint so existing API clients keep working.

### First-time setup on a new machine

```powershell
cd C:\Users\ASUS\Downloads\CYBERMIND-NLP-main\CYBERMIND-NLP-main

# Create and activate a virtual environment (skip if you already have one)
python -m venv ..\.venv
..\.venv\Scripts\Activate.ps1

# Install runtime dependencies
..\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Download the NLTK data used by src/preprocessing.py
..\.venv\Scripts\python.exe -m nltk.downloader stopwords punkt punkt_tab wordnet omw-1.4 averaged_perceptron_tagger averaged_perceptron_tagger_eng maxent_ne_chunker maxent_ne_chunker_tab words vader_lexicon

# Start the server
..\.venv\Scripts\python.exe -m uvicorn api:app --host 0.0.0.0 --port 8000
```

The model file must exist at
`models\cybermind_threat_classifier.joblib`. It is **not retrained or
replaced** by this web application.

### VS Code steps

1. Open the **project root folder** in VS Code
   (`CYBERMIND-NLP-main\CYBERMIND-NLP-main`, not the outer folder).
2. Open **Terminal → New Terminal** (PowerShell).
3. Make sure the interpreter is the project venv:
   `..\.venv\Scripts\python.exe` (VS Code: `Ctrl+Shift+P` →
   *Python: Select Interpreter* → *Enter interpreter path*).
4. Run `.\start.bat`, or the manual `uvicorn` command above.
5. Open the website link printed in the terminal.

### Optional Gmail monitor

The Gmail feature is not live until Google OAuth and Pub/Sub are configured.
Follow [`GMAIL_SETUP_GUIDE.md`](./GMAIL_SETUP_GUIDE.md), then start
`.\run_gmail_worker.bat` in a second terminal and use the Email Monitor panel
at `http://localhost:8000/ui/`. Gmail analysis is read-only and stays off
until you explicitly enable it. Mocked tests do not connect to a real account
or validate Google Cloud setup.

---

## 4. API

### `GET /`

Application name and API status.

```json
{
  "application": "CYBERMIND-NLP",
  "name": "CYBERMIND",
  "status": "running",
  "api_status": "ready",
  "version": "2.0.0",
  "docs": "/docs",
  "health": "/health",
  "frontend": "/ui/",
  "max_message_length": 5000
}
```

### `GET /health`

Backend and model readiness. Returns **503** if the analyzer could not load.

```json
{
  "status": "healthy",
  "analyzer": "ready",
  "model": "cybermind_threat_classifier.joblib",
  "version": "2.0.0",
  "max_message_length": 5000
}
```

### `POST /analyze`

Request:

```json
{
  "text": "Your bank account will be blocked. Click here to verify your password immediately."
}
```

Success response (real structure; values abbreviated):

```json
{
  "status": "success",
  "result": {
    "input": "Your bank account will be blocked. ...",
    "nlp": {
      "original_text": "...",
      "extracted_urls": [],
      "cleaned_text": "...",
      "tokens": ["..."],
      "filtered_tokens": ["..."],
      "stemmed_tokens": ["..."],
      "lemmatized_tokens": ["..."],
      "pos_tags": [["...", "NN"]],
      "named_entities": []
    },
    "sentiment": {
      "sentiment": "Negative",
      "compound": -0.5,
      "positive": 0.0,
      "negative": 0.4,
      "neutral": 0.6
    },
    "keywords": {
      "keywords": ["..."],
      "security_indicators": {
        "urgency": ["immediately"],
        "credential_request": ["password"],
        "financial": ["bank", "account"],
        "threat": ["blocked", "locked"],
        "social_engineering": ["verify", "click"]
      },
      "total_indicators": 8
    },
    "urls": {
      "urls": [],
      "analyses": [],
      "total_url_indicators": 0
    },
    "heuristic": {
      "threat_category": "PHISHING",
      "risk_score": 58,
      "risk_level": "HIGH"
    },
    "machine_learning": {
      "prediction": "phishing",
      "confidence": 0.7843,
      "probabilities": {
        "benign": 0.0616,
        "phishing": 0.7843,
        "scam": 0.06,
        "social_engineering": 0.0942
      }
    },
    "final_assessment": {
      "final_threat": "phishing",
      "risk_score": 73,
      "risk_level": "CRITICAL",
      "reasons": [
        "8 security indicator(s) detected.",
        "Machine-learning prediction: phishing.",
        "ML confidence: 0.78.",
        "Heuristic classification: PHISHING."
      ],
      "component_scores": {
        "heuristic": 58,
        "machine_learning": 78.43,
        "url_indicators": 0,
        "security_indicators": 8
      }
    }
  }
}
```

Error responses use a consistent envelope:

```json
{
  "status": "error",
  "detail": "Invalid input (text): String should have at least 1 character"
}
```

Validation rules:

- `text` is required and must be a string.
- Whitespace-only input is rejected.
- Maximum length: **5000 characters** (configurable with
  `CYBERMIND_MAX_MESSAGE_LENGTH`).
- Internal errors return a generic 500 message; stack traces and filesystem
  paths are logged server-side only, never returned to the browser.

PowerShell request example:

```powershell
$body = @{
  text = "Your bank account will be blocked. Click here to verify your password immediately."
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/analyze" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

### Frontend ↔ API configuration

The API base URL lives in **one place**:
`frontend/js/api.js`.

- Served by FastAPI at `/ui/`: same-origin, no hardcoded host.
- Served by a separate local static server on port 5500 / 8080 / 3000:
  defaults to `http://127.0.0.1:8000`.
- Override before loading the scripts:

```html
<script>
  window.CYBERMIND_CONFIG = { API_BASE_URL: "https://api.example.com" };
</script>
```

The UI sends only `{ "text": "..." }`, reads the real response, validates
the envelope, and renders only fields that are actually present. It does not
invent classifications or scores.

---

## 5. Testing

### Backend tests

```powershell
cd C:\Users\ASUS\Downloads\CYBERMIND-NLP-main\CYBERMIND-NLP-main
$env:PYTHONUTF8 = "1"
..\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
```

Or double-click `run_tests.bat`.

Coverage includes: status endpoints, Swagger, valid phishing/scam/benign
messages, URL analysis, trimming, empty/whitespace/null/missing input,
over-length input, malformed JSON, method-not-allowed, CORS allow/deny,
security headers, no filesystem paths in responses, static frontend assets,
and the `/app` redirect.

### Browser end-to-end tests (optional)

```powershell
..\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
..\.venv\Scripts\python.exe -m tests.browser_e2e
```

The E2E script starts its own Uvicorn server on port **8123** and drives
headless Edge using the `msedge` channel (no Chromium download needed). It
checks:

- backend health and frontend online indicator;
- light/dark theme toggle and persistence after reload;
- empty-input validation;
- real phishing / scam / benign results rendered from the API;
- reasons, ML probabilities, URL details, and all result cards;
- history save, reload persistence, reopen, and clear;
- XSS safety (`textContent`, no script execution);
- no horizontal overflow, tap-target size, card stacking, and nav behaviour
  at 360, 390, 768, 1024, and 1440 px;
- service-worker registration, offline error handling, and offline fallback;
- no browser console or page errors.

If Edge is not installed, install the Playwright browser instead:

```powershell
..\.venv\Scripts\python.exe -m playwright install chromium
```

Then change `channel="msedge"` in `tests/browser_e2e.py` or run with your
preferred browser.

### Manual test checklist

1. Open `/ui/` — status pill should say **Backend online · model ready**.
2. Click each sample, then **Analyze Message**.
3. Confirm the result matches the table in section 1.
4. Refresh — theme choice and history remain.
5. Open a history item; clear history (confirmation dialog).
6. Resize the browser to 360, 390, 768, 1024, and 1440 px; check there is no
   horizontal scrollbar and the mobile menu opens/closes.
7. Stop the server and try to analyze — a clear connection error appears,
   and no fake result is shown.

---

## 6. Use it on your phone (same Wi-Fi)

1. Start the server with `start.bat` (it binds to `0.0.0.0`).
2. On the PC, run `ipconfig` in PowerShell and find the **IPv4 Address** of
   your Wi-Fi adapter, for example `192.168.1.25`.
3. On the phone (connected to the same Wi-Fi), open:

   ```
   http://192.168.1.25:8000/ui/
   ```

4. If the phone cannot connect:
   - Allow Python through **Windows Defender Firewall** for **Private**
     networks when prompted.
   - Or add a rule in an **Administrator** PowerShell:

     ```powershell
     netsh advfirewall firewall add rule name="CYBERMIND 8000" dir=in action=allow protocol=TCP localport=8000 profile=private
     ```

   - Some routers/guest networks use **AP isolation**, which blocks
     device-to-device traffic. Use the main Wi-Fi network or a phone hotspot.
   - Make sure both devices are on the same network and the server window is
     still running.

The website is fully usable over LAN HTTP. **PWA installation and service
workers require a secure context** (HTTPS or `localhost`), so on a phone
over plain `http://192.168.x.x` the page works and history works, but
"Add to Home Screen" / offline caching may be unavailable. Use HTTPS (for
example a tunnel or deployment) to test full PWA behaviour on a phone.

---

## 7. Deployment notes

The application has not been deployed yet. The included [`render.yaml`](./render.yaml)
describes a **free-tier, analyzer-only** Render web service. It does not create
a service until you connect the repository and approve the Blueprint in Render.
Provider plan availability and limits can change.

The manifest deliberately does not configure Gmail OAuth, Pub/Sub, a database,
or a background worker. The Gmail integration is a single-local-account
implementation and must remain unconfigured on a public deployment. Do not add
Google OAuth secrets to Render for this version. Gmail production use needs a
separate identity model and durable shared storage before it can be exposed
publicly.

### Runtime files

Only these are needed at runtime:

- `api.py`
- `src/`
- `models/cybermind_threat_classifier.joblib`
- `frontend/`
- installed packages from `requirements.txt`
- NLTK corpora listed in section 3

The CSV datasets are only needed for training/evaluation, not for serving
the app.

### Suggested start command

```bash
uvicorn api:app --host 0.0.0.0 --port $PORT
```

Many platforms provide `$PORT` automatically. On Windows PowerShell use
`$env:PORT`; in a Procfile use:

```
web: uvicorn api:app --host 0.0.0.0 --port $PORT
```

### Render

The Blueprint uses the existing FastAPI app to serve both the UI and API,
installs the required NLTK corpora during build, and checks `/health`. To
deploy, push the reviewed code to the intended GitHub repository, create a
Render Blueprint from that repository, review the proposed **free** service,
and approve it. Do not approve a paid plan without first checking its cost.
The free service may sleep when idle and uses an ephemeral filesystem; this
is suitable only while Gmail monitoring is disabled.

### Other platforms

1. Connect the repository or upload the project.
2. Build command:

   ```bash
   pip install -r requirements.txt
   ```

3. Start command: `uvicorn api:app --host 0.0.0.0 --port $PORT`
4. Add a build/release step for NLTK data because `pip` does not install
   corpora:

   ```bash
   python -m nltk.downloader stopwords punkt punkt_tab wordnet omw-1.4 averaged_perceptron_tagger averaged_perceptron_tagger_eng maxent_ne_chunker maxent_ne_chunker_tab words vader_lexicon
   ```

   Or commit an `nltk_data` directory and set `NLTK_DATA` to its path.
5. Keep the model file in the deployment bundle. If the platform uses an
   ephemeral filesystem, the model must be part of the build artifact (it is
   a small `.joblib` file).
6. The platform normally terminates HTTPS for you, which also enables PWA
   installation and service workers.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CYBERMIND_MAX_MESSAGE_LENGTH` | `5000` | Max accepted characters |
| `CYBERMIND_ALLOWED_ORIGINS` | localhost/127.0.0.1 ports 8000, 5500, 8080, 3000 | CORS allow-list (comma-separated) |
| `CYBERMIND_LOG_LEVEL` | `INFO` | Python log level |

If the frontend is served by FastAPI at `/ui/`, requests are same-origin and
CORS is not involved. If you split the frontend onto a different domain, set
`CYBERMIND_ALLOWED_ORIGINS` to that exact origin.

Before exposing the app publicly, consider adding rate limiting, a reverse
proxy, authentication if needed, and restricting or disabling `/docs` if you
do not want the schema public.

---

## 8. Security and privacy

- Input is validated, trimmed, and limited to 5000 characters.
- Validation errors return a clean `{"status": "error", "detail": "..."}`
  envelope without echoing the submitted message.
- Unexpected exceptions return a generic 500 message; details are logged
  server-side only.
- Responses include `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.
- CORS is restricted to an explicit allow-list.
- Submitted message text is never logged by the API and is not written to a
  database or file.
- Gmail integration is disabled by default, uses read-only OAuth scope,
  encrypts stored credentials, binds OAuth state to a signed browser session,
  and never downloads attachments. Message bodies are processed in memory;
  selected headers and analysis metadata are stored in the local SQLite
  database. Gmail and alert endpoints are excluded from the service-worker
  cache.
- The Gmail implementation is for one local account only. Do not expose it as
  a public or multi-user service without a separate identity model, shared
  storage design, and security review.
- The frontend inserts user-provided text with `textContent`, never
  `innerHTML`; the browser E2E test verifies this with an XSS payload.
- Scan history is stored only in the browser's `localStorage` (maximum
  20 entries) and can be cleared from the UI. Clearing browser data removes
  it.
- The app performs automated analysis only. It does **not** guarantee that a
  message is safe.

**Disclaimer:** CyberMind provides automated threat assessments for
informational purposes. Results may be incorrect. Always independently verify
suspicious communications and never share passwords, OTPs, or banking
credentials.

---

## 9. How the pipeline works

1. **Submit** — the browser sends `{ "text": "..." }` to `POST /analyze`.
2. **Preprocess** — `src/preprocessing.py` removes URLs from the linguistic
   text, lowercases and tokenises with NLTK, removes stop words, and produces
   stems, lemmas, POS tags, and named entities.
3. **Keywords** — `src/keyword_analyzer.py` extracts TF-IDF keywords and
   rule-based security indicators (urgency, credential requests, financial
   lures, threats, scams, social engineering).
4. **Sentiment** — `src/sentiment.py` uses VADER to score the message.
5. **Machine learning** — `src/ml_classifier.py` runs the bundled TF-IDF +
   logistic-regression pipeline and returns a prediction plus class
   probabilities.
6. **URL analysis** — `src/url_analyzer.py` inspects explicit links for
   missing HTTPS, IP-address hosts, excessive subdomains, long URLs,
   `@` symbols, and suspicious terms.
7. **Decision** — `src/decision_engine.py` combines heuristic evidence, ML
   confidence, URL indicators, and indicator counts into `final_threat`,
   `risk_score`, `risk_level`, `reasons`, and `component_scores`.

Not implemented: external threat-intelligence feeds, WHOIS/domain-age or
certificate checks, attachment/malware scanning, deep learning, or
large-language-model analysis. The Gmail monitor is implemented as an
optional, read-only, single-local-account integration; real monitoring still
requires Google OAuth/Pub/Sub setup and the worker process. The PWA caches
only the app shell — **analysis always requires a live backend**.

---

## 10. Files created and modified

### New files

- `start.bat`, `run_tests.bat`
- `.env.example`
- `README.md`
- `requirements-dev.txt`
- `frontend/index.html`
- `frontend/css/style.css`
- `frontend/css/responsive.css`
- `frontend/js/api.js`
- `frontend/js/history.js`
- `frontend/js/app.js`
- `frontend/assets/logo.svg`
- `frontend/assets/icons/` (5 PNG icons)
- `frontend/manifest.json`
- `frontend/service-worker.js`
- `frontend/offline.html`
- `tests/__init__.py`
- `tests/test_api.py`
- `tests/test_gmail_security.py`
- `tests/test_preprocessing.py`
- `tests/browser_e2e.py`
- `GMAIL_SETUP_GUIDE.md`
- `run_gmail_worker.bat`
- `src/gmail_security/` — OAuth sessions, encrypted persistence, Gmail
  parsing/sync, Pub/Sub routes and worker
- `frontend/css/gmail.css`
- `frontend/js/gmail.js`

### Modified files

- `api.py` — hardened FastAPI backend, static hosting at `/ui/`, `/app`
  redirect, validation, CORS, security headers, plus Gmail API routes.
- `requirements.txt` — converted to UTF-8 and extended with Gmail dependencies.
- `.env.example`, `.gitignore`, `start.bat`, `frontend/index.html`, and
  `frontend/service-worker.js` — Gmail configuration, launch, dashboard and
  private API cache handling.
- `tests/test_preprocessing.py` — was an empty placeholder; now contains
  tests. No model or training code was changed.

### Unchanged

- The trained model `models/cybermind_threat_classifier.joblib`
- `main.py` and all original NLP / ML modules directly under `src/`
- Datasets and original test scripts

### Backup

The pre-change project was copied to:

```
C:\Users\ASUS\Downloads\CYBERMIND-NLP-main\_backup_cybermind_20261116_213929
```

---

## 11. Known limitations

- **Not a guaranteed security tool.** The classifier can be wrong, especially
  on unusual wording, mixed languages, or very short messages.
- **Small bundled training dataset.** No accuracy, certification, or
  benchmark claim is made.
- **URL extraction is heuristic.** Links must contain `http(s)://` or start
  with `www.`; trailing punctuation may be included in the extracted URL.
  No live reputation, blocklist, WHOIS, or certificate lookup is performed.
- **No server-side history.** History is per-browser `localStorage`, limited
  to 20 entries, and lost if browser data is cleared or private mode blocks
  storage.
- **PWA offline mode is app-shell only.** Threat analysis never runs offline.
- **PWA install over LAN HTTP may be unavailable** because service workers
  require a secure context.
- **CORS defaults to local development origins.** Set
  `CYBERMIND_ALLOWED_ORIGINS` when hosting the frontend separately.
- **No built-in rate limiting or authentication.** Add these via a reverse
  proxy or platform configuration before public use.
- **Swagger `/docs` is public** unless you disable or protect it in
  production.
- The web app was tested on Windows with Edge/Playwright. Other browsers and
  mobile devices were not physically tested, though the CSS targets standard
  responsive breakpoints and touch sizes.
