"""API tests for the CYBERMIND FastAPI backend."""

import json
import os
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

# Keep local .env settings from changing the development-origin CORS tests.
os.environ["CYBERMIND_ALLOWED_ORIGINS"] = ",".join(
    f"http://{host}:{port}"
    for host in ("localhost", "127.0.0.1")
    for port in ("8000", "5500", "8080", "3000")
)

from api import MAX_MESSAGE_LENGTH, app


PROJECT_ROOT = Path(__file__).resolve().parent.parent

PHISHING_MESSAGE = (
    "Your bank account will be blocked. Click here to verify your "
    "password immediately."
)
SCAM_MESSAGE = (
    "Congratulations! You won a lottery. Pay a processing fee to "
    "receive your prize."
)
BENIGN_MESSAGE = "Hi, are we meeting for lunch tomorrow?"

VALID_THREATS = {
    "benign",
    "phishing",
    "scam",
    "social_engineering",
}
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # --------------------------------------------------
    # Status and documentation
    # --------------------------------------------------

    def test_root_returns_application_status(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(payload["application"], "CYBERMIND-NLP")
        self.assertEqual(payload["status"], "running")
        self.assertEqual(payload["api_status"], "ready")
        self.assertEqual(payload["frontend"], "/ui/")
        self.assertEqual(
            payload["max_message_length"], MAX_MESSAGE_LENGTH
        )

    def test_health_reports_ready_model(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["analyzer"], "ready")
        self.assertEqual(
            payload["model"],
            "cybermind_threat_classifier.joblib",
        )

    def test_docs_are_available(self):
        response = self.client.get("/docs")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "swagger",
            response.text.lower(),
        )

    def test_openapi_schema_lists_analyze_endpoint(self):
        response = self.client.get("/openapi.json")

        self.assertEqual(response.status_code, 200)

        schema = response.json()

        self.assertIn("/analyze", schema["paths"])
        self.assertIn("/health", schema["paths"])
        self.assertIn("/gmail/status", schema["paths"])
        self.assertIn("/gmail/monitoring", schema["paths"])

    # --------------------------------------------------
    # Analysis behaviour
    # --------------------------------------------------

    def assert_valid_analysis(self, response):
        self.assertEqual(response.status_code, 200)

        payload = response.json()

        self.assertEqual(payload["status"], "success")
        self.assertIsInstance(payload["result"], dict)

        result = payload["result"]

        for key in (
            "input",
            "nlp",
            "sentiment",
            "keywords",
            "urls",
            "heuristic",
            "machine_learning",
            "final_assessment",
        ):
            self.assertIn(key, result)

        final = result["final_assessment"]

        self.assertIn(final["final_threat"], VALID_THREATS)
        self.assertIn(final["risk_level"], VALID_RISK_LEVELS)
        self.assertIsInstance(final["risk_score"], int)
        self.assertGreaterEqual(final["risk_score"], 0)
        self.assertLessEqual(final["risk_score"], 100)
        self.assertIsInstance(final["reasons"], list)

        return result

    def test_phishing_sample(self):
        result = self.assert_valid_analysis(
            self.client.post(
                "/analyze",
                json={"text": PHISHING_MESSAGE},
            )
        )

        self.assertEqual(
            result["final_assessment"]["final_threat"],
            "phishing",
        )

    def test_scam_sample(self):
        result = self.assert_valid_analysis(
            self.client.post(
                "/analyze",
                json={"text": SCAM_MESSAGE},
            )
        )

        self.assertEqual(
            result["final_assessment"]["final_threat"],
            "scam",
        )

    def test_benign_sample(self):
        result = self.assert_valid_analysis(
            self.client.post(
                "/analyze",
                json={"text": BENIGN_MESSAGE},
            )
        )

        self.assertEqual(
            result["final_assessment"]["final_threat"],
            "benign",
        )
        self.assertEqual(
            result["final_assessment"]["risk_score"],
            0,
        )
        self.assertEqual(
            result["final_assessment"]["risk_level"],
            "LOW",
        )

    def test_url_analysis_is_included(self):
        result = self.assert_valid_analysis(
            self.client.post(
                "/analyze",
                json={
                    "text": (
                        "Verify your account at "
                        "http://secure-login-verify.xyz now."
                    )
                },
            )
        )

        self.assertEqual(
            result["urls"]["urls"],
            ["http://secure-login-verify.xyz"],
        )
        self.assertGreater(
            result["urls"]["total_url_indicators"], 0
        )

    def test_whitespace_is_trimmed(self):
        result = self.assert_valid_analysis(
            self.client.post(
                "/analyze",
                json={"text": "   hello there   "},
            )
        )

        self.assertEqual(result["input"], "hello there")

    # --------------------------------------------------
    # Validation and errors
    # --------------------------------------------------

    def test_empty_input_is_rejected(self):
        response = self.client.post(
            "/analyze",
            json={"text": ""},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["status"], "error")

    def test_whitespace_only_input_is_rejected(self):
        response = self.client.post(
            "/analyze",
            json={"text": "     \n\t  "},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["status"], "error")

    def test_missing_text_field_is_rejected(self):
        response = self.client.post("/analyze", json={})

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["status"], "error")

    def test_null_text_is_rejected(self):
        response = self.client.post(
            "/analyze",
            json={"text": None},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["status"], "error")

    def test_overlong_message_is_rejected(self):
        response = self.client.post(
            "/analyze",
            json={"text": "a" * (MAX_MESSAGE_LENGTH + 1)},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["status"], "error")

    def test_malformed_json_is_rejected(self):
        response = self.client.post(
            "/analyze",
            content="{not valid json",
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["status"], "error")

    def test_method_not_allowed_uses_json_error_envelope(self):
        response = self.client.get("/analyze")

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()["status"], "error")

    # --------------------------------------------------
    # CORS and security headers
    # --------------------------------------------------

    def test_cors_allows_development_origin(self):
        response = self.client.options(
            "/analyze",
            headers={
                "Origin": "http://localhost:5500",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "http://localhost:5500",
        )

    def test_cors_does_not_allow_unknown_origin(self):
        response = self.client.options(
            "/analyze",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )

        self.assertNotEqual(
            response.headers.get("access-control-allow-origin"),
            "https://evil.example",
        )

    def test_security_headers_are_present(self):
        response = self.client.get("/")

        self.assertEqual(
            response.headers.get("x-content-type-options"),
            "nosniff",
        )
        self.assertEqual(
            response.headers.get("x-frame-options"),
            "DENY",
        )
        self.assertEqual(
            response.headers.get("referrer-policy"),
            "no-referrer",
        )

    def test_responses_do_not_expose_filesystem_paths(self):
        combined = json.dumps(self.client.get("/").json())
        combined += json.dumps(self.client.get("/health").json())

        self.assertNotIn(str(PROJECT_ROOT), combined)
        self.assertNotIn("C:\\", combined)
        self.assertNotIn("/Users/", combined)
        self.assertNotIn("Traceback", combined)

    # --------------------------------------------------
    # Frontend hosting
    # --------------------------------------------------

    def test_frontend_index_is_served(self):
        response = self.client.get("/ui/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("CYBERMIND", response.text)
        self.assertIn(
            "AI-Powered Cyber Threat Detection",
            response.text,
        )

    def test_frontend_assets_are_served(self):
        assets = [
            "/ui/css/style.css",
            "/ui/css/responsive.css",
            "/ui/css/gmail.css",
            "/ui/js/api.js",
            "/ui/js/history.js",
            "/ui/js/app.js",
            "/ui/js/gmail.js",
            "/ui/assets/logo.svg",
            "/ui/assets/icons/icon-192.png",
            "/ui/assets/icons/icon-512.png",
            "/ui/manifest.json",
            "/ui/service-worker.js",
            "/ui/offline.html",
        ]

        for asset in assets:
            with self.subTest(asset=asset):
                response = self.client.get(asset)
                self.assertEqual(response.status_code, 200)

    def test_app_redirects_to_frontend(self):
        response = self.client.get(
            "/app", follow_redirects=False
        )

        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/ui/")

    # --------------------------------------------------
    # Preserved CLI files
    # --------------------------------------------------

    def test_existing_project_files_are_preserved(self):
        for relative_path in (
            "main.py",
            "api.py",
            "src/analyzer.py",
            "models/cybermind_threat_classifier.joblib",
            "data/raw/cybersecurity_messages.csv",
            "data/test/unseen_messages.csv",
        ):
            with self.subTest(path=relative_path):
                self.assertTrue(
                    (PROJECT_ROOT / relative_path).exists()
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
