"""Optional end-to-end browser tests for the CYBERMIND web app.

Requires Playwright (already in requirements-dev.txt) and Microsoft Edge.
Run from the project root:

    ..\\.venv\\Scripts\\python.exe -m tests.browser_e2e

The script starts its own Uvicorn server on port 8123, drives a headless
Edge browser, and prints PASS lines for each feature it verifies.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright


PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
PORT = 8123
BASE_URL = f"http://{HOST}:{PORT}"

PHISHING = (
    "Your bank account will be blocked. Click here to verify your "
    "password immediately."
)
SCAM = (
    "Congratulations! You won a lottery. Pay a processing fee to "
    "receive your prize."
)
BENIGN = "Hi, are we meeting for lunch tomorrow?"
URL_MESSAGE = (
    "Verify your account at http://secure-login-verify.xyz now."
)
XSS_MESSAGE = '<img src=x onerror="window.__xss=1"> <script>window.__xss=2</script>'

THREAT_UI = {
    "benign": "Benign",
    "phishing": "Phishing",
    "scam": "Scam",
    "social_engineering": "Social Engineering",
}

passed = []


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def note(message):
    passed.append(message)
    print("PASS:", message)


def request_json(path, payload=None):
    data = None
    headers = {}
    method = "GET"

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"

    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers=headers,
        method=method,
    )

    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def analyze_via_api(text):
    payload = request_json("/analyze", {"text": text})
    check(payload.get("status") == "success", "API analysis failed")
    return payload["result"]


def wait_for_health(timeout=90):
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        try:
            payload = request_json("/health")
            if payload.get("status") == "healthy":
                return payload
        except Exception as error:  # noqa: BLE001 - startup polling
            last_error = error

        time.sleep(0.5)

    raise RuntimeError(f"Backend did not become healthy: {last_error}")


def start_server():
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "api:app",
            "--host",
            HOST,
            "--port",
            str(PORT),
            "--log-level",
            "warning",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    wait_for_health()
    return process


def stop_server(process):
    if process is None:
        return

    process.terminate()

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def wait_for_backend(page):
    page.wait_for_function(
        """() => {
            const el = document.getElementById('backendStatusText');
            return el && /online/i.test(el.textContent);
        }""",
        timeout=30000,
    )


def wait_for_result(page, expected_text, timeout=120000):
    page.wait_for_function(
        """(expected) => {
            const el = document.querySelector('.scanned-message p');
            return el && el.textContent === expected;
        }""",
        arg=expected_text,
        timeout=timeout,
    )

    page.wait_for_function(
        """() => {
            const button = document.getElementById('analyzeBtn');
            return button && !button.disabled;
        }""",
        timeout=30000,
    )


def run_sample(page, sample_key, expected_text):
    page.click(f'[data-sample="{sample_key}"]')

    value = page.input_value("#messageInput")
    check(
        value == expected_text,
        f"Sample button {sample_key} did not fill the textarea",
    )

    api_result = analyze_via_api(expected_text)

    page.click("#analyzeBtn")
    wait_for_result(page, expected_text)

    final = api_result["final_assessment"]
    threat_text = page.locator(
        ".result-summary .threat-badge"
    ).inner_text()
    score_text = page.locator(
        ".result-summary .gauge-value"
    ).inner_text()
    risk_text = page.locator(
        ".result-summary .risk-pill"
    ).inner_text()

    check(
        threat_text.lower() == THREAT_UI[final["final_threat"]].lower(),
        (
            f"UI threat {threat_text!r} does not match API "
            f"{final['final_threat']!r}"
        ),
    )

    check(
        int(score_text) == final["risk_score"],
        (
            f"UI score {score_text!r} does not match API "
            f"{final['risk_score']!r}"
        ),
    )

    check(
        risk_text.lower()
        == (final["risk_level"].lower() + " risk"),
        f"UI risk pill {risk_text!r} is unexpected",
    )

    return api_result


def run_desktop_tests(browser):
    context = browser.new_context(
        viewport={"width": 1440, "height": 960},
        service_workers="block",
    )
    page = context.new_page()
    console_errors = []

    page.on(
        "console",
        lambda message: (
            console_errors.append(message.text)
            if message.type == "error"
            else None
        ),
    )
    page.on(
        "pageerror",
        lambda error: console_errors.append(f"pageerror: {error}"),
    )

    page.goto(BASE_URL + "/ui/", wait_until="networkidle")
    wait_for_backend(page)
    note("frontend loads and detects the backend as online")
    check(
        page.locator("#gmailTitle").inner_text() == "Gmail security monitor",
        "Gmail monitoring dashboard is missing",
    )
    page.wait_for_function(
        "() => document.querySelector('#gmailStatus').textContent.trim() !== ''"
    )
    note("Gmail dashboard loads its backend status")

    # Theme toggle and persistence.
    initial_theme = page.get_attribute("html", "data-theme")
    page.click("#themeToggle")
    page.wait_for_function(
        """(previous) =>
            document.documentElement.getAttribute('data-theme')
                !== previous""",
        arg=initial_theme,
    )
    toggled_theme = page.get_attribute("html", "data-theme")
    stored_theme = page.evaluate(
        "() => localStorage.getItem('cybermind:theme:v1')"
    )
    check(
        toggled_theme in ("light", "dark"),
        "Theme toggle produced an invalid theme",
    )
    check(
        stored_theme == toggled_theme,
        "Theme choice was not stored in localStorage",
    )
    page.reload(wait_until="networkidle")
    wait_for_backend(page)
    check(
        page.get_attribute("html", "data-theme") == toggled_theme,
        "Theme choice did not persist after reload",
    )
    note("light/dark theme toggle works and persists after reload")

    # Empty input validation.
    page.fill("#messageInput", "")
    page.click("#analyzeBtn")
    page.wait_for_selector("#formError:not([hidden])")
    check(
        "Enter a message" in page.inner_text("#formError"),
        "Empty input message is not helpful",
    )
    note("empty input is rejected in the browser before an API call")

    # Required sample messages.
    phishing_result = run_sample(page, "phishing", PHISHING)
    check(
        phishing_result["final_assessment"]["final_threat"]
        == "phishing",
        "Phishing sample was not classified as phishing",
    )
    note(
        "PHISHING sample rendered: "
        f"{THREAT_UI[phishing_result['final_assessment']['final_threat']]} "
        f"{phishing_result['final_assessment']['risk_score']}/100 "
        f"({phishing_result['final_assessment']['risk_level']})"
    )

    scam_result = run_sample(page, "scam", SCAM)
    check(
        scam_result["final_assessment"]["final_threat"] == "scam",
        "Scam sample was not classified as scam",
    )
    note(
        "SCAM sample rendered: "
        f"{THREAT_UI[scam_result['final_assessment']['final_threat']]} "
        f"{scam_result['final_assessment']['risk_score']}/100 "
        f"({scam_result['final_assessment']['risk_level']})"
    )

    benign_result = run_sample(page, "benign", BENIGN)
    check(
        benign_result["final_assessment"]["final_threat"] == "benign",
        "Benign sample was not classified as benign",
    )
    note(
        "BENIGN sample rendered: "
        f"{THREAT_UI[benign_result['final_assessment']['final_threat']]} "
        f"{benign_result['final_assessment']['risk_score']}/100 "
        f"({benign_result['final_assessment']['risk_level']})"
    )

    # Result details for the phishing sample.
    page.click('[data-sample="phishing"]')
    page.click("#analyzeBtn")
    wait_for_result(page, PHISHING)

    check(
        page.locator(".result-grid .detail-card").count() == 6,
        "Expected six result detail cards",
    )
    check(
        page.locator(".result-summary .reason-list li").count()
        == len(phishing_result["final_assessment"]["reasons"]),
        "Reasons list does not match the API response",
    )
    check(
        page.locator(".prob-row").count()
        == len(phishing_result["machine_learning"]["probabilities"]),
        "Probability rows do not match the API response",
    )
    check(
        "No URLs were detected"
        in page.locator(".result-grid").inner_text(),
        "Missing URL empty state",
    )
    note("threat, risk, reasons, ML probabilities, and cards render")

    # URL analysis rendering.
    page.fill("#messageInput", URL_MESSAGE)
    page.click("#analyzeBtn")
    wait_for_result(page, URL_MESSAGE)
    grid_text = page.locator(".result-grid").inner_text()
    check(
        "secure-login-verify.xyz" in grid_text,
        "URL hostname was not rendered",
    )
    check(
        "No HTTPS" in grid_text,
        "URL indicator labels were not humanised",
    )
    note("URL analysis details render from the API response")

    # XSS safety: user text must never be interpreted as HTML.
    page.fill("#messageInput", XSS_MESSAGE)
    page.click("#analyzeBtn")
    wait_for_result(page, XSS_MESSAGE)
    check(
        page.evaluate("() => window.__xss") is None,
        "User message was executed as HTML/JavaScript",
    )
    check(
        page.locator(".scanned-message img, .scanned-message script").count()
        == 0,
        "User message was inserted as unsafe HTML",
    )
    note("user text is rendered safely with textContent (XSS test)")

    # History persistence and reopening.
    history_count = page.locator("#historyList .history-item").count()
    check(history_count >= 5, "Scan history did not record scans")

    page.reload(wait_until="networkidle")
    wait_for_backend(page)
    check(
        page.locator("#historyList .history-item").count()
        == history_count,
        "Scan history did not persist after reload",
    )

    page.locator("#historyList .history-item").first.click()
    page.wait_for_selector("#results:not([hidden])")
    check(
        page.locator(".result-summary").count() == 1,
        "Opening a history item did not render a result",
    )
    note("scan history saves locally, survives reload, and reopens")

    # Clear history.
    page.once("dialog", lambda dialog: dialog.accept())
    page.click("#clearHistoryBtn")
    page.wait_for_selector("#historyList .history-empty")
    check(
        page.locator("#historyList .history-item").count() == 0,
        "Clear history did not remove entries",
    )
    note("scan history can be cleared")

    # Responsive layout checks.
    for width in (360, 390, 768, 1024, 1440):
        page.set_viewport_size({"width": width, "height": 900})
        page.wait_for_timeout(250)

        overflow = page.evaluate(
            "() => document.documentElement.scrollWidth - "
            "window.innerWidth"
        )
        check(
            overflow <= 1,
            f"Horizontal overflow of {overflow}px at {width}px",
        )

        textarea_box = page.locator("#messageInput").bounding_box()
        check(
            textarea_box is not None and textarea_box["width"] <= width,
            f"Textarea is wider than the viewport at {width}px",
        )

        button_box = page.locator("#analyzeBtn").bounding_box()
        check(
            button_box is not None and button_box["height"] >= 44,
            f"Analyze button is too small to tap at {width}px",
        )

        cards = page.evaluate(
            """() => {
                const items = Array.from(
                    document.querySelectorAll('.feature-card')
                ).slice(0, 2);
                return items.map((item) => {
                    const rect = item.getBoundingClientRect();
                    return { x: rect.x, y: rect.y, height: rect.height };
                });
            }"""
        )

        if width < 640:
            check(
                cards[1]["y"] > cards[0]["y"] + cards[0]["height"] - 2,
                f"Feature cards do not stack at {width}px",
            )
        else:
            check(
                abs(cards[1]["y"] - cards[0]["y"]) < 2,
                f"Feature cards are not in a row at {width}px",
            )

        nav_toggle_visible = page.locator("#navToggle").is_visible()
        nav_menu_visible = page.locator("#navMenu").is_visible()

        if width < 900:
            check(nav_toggle_visible, f"Nav toggle missing at {width}px")
            check(
                not nav_menu_visible,
                f"Mobile nav should start closed at {width}px",
            )
            page.click("#navToggle")
            page.wait_for_timeout(120)
            check(
                page.locator("#navMenu").is_visible(),
                f"Mobile nav did not open at {width}px",
            )
            check(
                page.get_attribute("#navToggle", "aria-expanded")
                == "true",
                "Nav toggle aria-expanded was not updated",
            )
            check(
                page.locator("#themeToggle").is_visible(),
                f"Theme toggle is not reachable at {width}px",
            )
            page.click("#navMenu a[href='#home']")
            page.wait_for_timeout(120)
            check(
                not page.locator("#navMenu").is_visible(),
                f"Mobile nav did not close at {width}px",
            )
        else:
            check(
                not nav_toggle_visible,
                f"Desktop nav toggle should be hidden at {width}px",
            )
            check(
                nav_menu_visible,
                f"Desktop nav is not visible at {width}px",
            )
            check(
                page.locator("#themeToggle").is_visible(),
                f"Theme toggle is not visible at {width}px",
            )

    note("responsive layouts pass at 360, 390, 768, 1024, 1440 px")

    check(
        console_errors == [],
        "Browser console errors: " + " | ".join(console_errors),
    )
    note("no browser console or page errors")

    context.close()


def run_pwa_offline_tests(browser):
    context = browser.new_context(
        viewport={"width": 390, "height": 844},
        service_workers="allow",
    )
    page = context.new_page()
    page.goto(BASE_URL + "/ui/", wait_until="networkidle")
    wait_for_backend(page)

    page.evaluate(
        """async () => {
            if ('serviceWorker' in navigator) {
                await navigator.serviceWorker.ready;
            }
        }"""
    )
    page.reload(wait_until="networkidle")
    wait_for_backend(page)

    controlled = page.evaluate(
        "() => !!(navigator.serviceWorker && navigator.serviceWorker.controller)"
    )
    check(controlled, "Service worker did not control the page")
    note("service worker registers and controls the app shell")

    gmail_status_online = page.evaluate(
        """async () => {
            try {
                const response = await fetch('/gmail/status', {
                    cache: 'no-store'
                });
                return response.ok;
            } catch (error) {
                return false;
            }
        }"""
    )
    check(gmail_status_online, "Gmail status endpoint is unavailable online")
    note("Gmail status endpoint is reachable online")

    context.set_offline(True)
    gmail_status_offline = page.evaluate(
        """async () => {
            try {
                const response = await fetch('/gmail/status', {
                    cache: 'no-store'
                });
                return response.ok;
            } catch (error) {
                return false;
            }
        }"""
    )
    check(
        not gmail_status_offline,
        "Service worker served private Gmail status while offline",
    )
    note("private Gmail status is not served from the offline cache")

    page.fill("#messageInput", BENIGN)
    page.click("#analyzeBtn")
    page.wait_for_selector(".error-card", timeout=60000)

    error_text = page.inner_text(".error-card")
    check(
        page.locator(".result-summary").count() == 0,
        "Offline mode rendered a fabricated analysis result",
    )
    check(
        any(
            word in error_text.lower()
            for word in ("reach", "timed out", "offline", "server")
        ),
        f"Offline error message is unclear: {error_text}",
    )
    note("offline analysis fails gracefully instead of faking a result")

    page.goto(BASE_URL + "/ui/unknown-page-while-offline")
    check(
        "You are offline" in page.content(),
        "Offline fallback page did not load",
    )
    note("offline fallback page is available")

    context.set_offline(False)
    context.close()


def main():
    server = None

    try:
        server = start_server()
        note("backend starts and health check passes")

        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(
                    channel="msedge",
                    headless=True,
                )
                note("headless Microsoft Edge launched")
            except Exception as error:  # noqa: BLE001
                raise RuntimeError(
                    "Microsoft Edge could not be launched by Playwright. "
                    "Install Edge or run `playwright install chromium`."
                ) from error

            try:
                run_desktop_tests(browser)
                run_pwa_offline_tests(browser)
            finally:
                browser.close()

        print("\n" + "=" * 60)
        print(f"BROWSER E2E: {len(passed)} checks passed")
        print("=" * 60)
        return 0

    finally:
        stop_server(server)


if __name__ == "__main__":
    sys.exit(main())
