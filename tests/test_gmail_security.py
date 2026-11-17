"""Focused tests for the opt-in Gmail security integration."""

import base64
import json
import logging
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from api import GmailQueryRedactionFilter, app
from src.gmail_security import router as gmail_routes
from src.gmail_security.gmail_client import extract_message
from src.gmail_security.monitor import sync_gmail_history
from src.gmail_security.sessions import SessionCookies
from src.gmail_security.store import GmailStore, session_hash


def encoded(text):
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


class GmailStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "gmail.sqlite3"
        self.key = Fernet.generate_key().decode("ascii")
        self.store = GmailStore(self.database_path, self.key)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_oauth_state_is_single_use_and_bound_to_browser(self):
        owner = session_hash("browser-session")
        self.store.create_oauth_state("random-state", owner)

        self.assertFalse(
            self.store.consume_oauth_state(
                "random-state", session_hash("different-session")
            )
        )
        self.assertFalse(self.store.consume_oauth_state("random-state", owner))

        self.store.create_oauth_state("another-state", owner)
        self.assertTrue(
            self.store.consume_oauth_state("another-state", owner)
        )
        self.assertFalse(
            self.store.consume_oauth_state("another-state", owner)
        )

    def test_oauth_credentials_are_encrypted_and_recovered(self):
        token_json = json.dumps(
            {"token": "sensitive-access-token", "refresh_token": "refresh"}
        )
        owner = session_hash("browser-session")
        self.store.save_account(owner, "user@example.test", token_json)

        with closing(sqlite3.connect(self.database_path)) as connection:
            encrypted = connection.execute(
                "SELECT encrypted_credentials FROM gmail_account"
            ).fetchone()[0]

        self.assertNotIn(b"sensitive-access-token", encrypted)
        self.assertEqual(
            self.store.get_account()["credentials_json"],
            token_json,
        )

    def test_alert_metadata_deduplicates_and_round_trips(self):
        alert = {
            "id": "alert-1",
            "gmail_message_id": "message-1",
            "sender": "sender@example.test",
            "subject": "A test email",
            "received_at": None,
            "threat_category": "phishing",
            "risk_score": 80,
            "risk_level": "CRITICAL",
            "keywords": ["verify"],
            "urls": ["https://example.test"],
            "reasons": ["A test reason"],
            "recommendations": [],
            "attachment_metadata": [
                {"mime_type": "application/pdf", "size": 20}
            ],
            "content_truncated": True,
            "created_at": "2026-01-01T00:00:00+00:00",
        }

        self.assertTrue(self.store.add_alert(alert))
        self.assertFalse(self.store.add_alert(dict(alert, id="duplicate")))
        saved = self.store.get_alert("alert-1")
        self.assertEqual(saved["attachment_metadata"], alert["attachment_metadata"])
        self.assertTrue(saved["content_truncated"])
        self.assertTrue(self.store.has_alert_for_message("message-1"))

    def test_job_retry_backoff_delays_reclaim(self):
        self.store.enqueue_notification("pubsub-1", "10")
        job = self.store.claim_job()
        self.assertEqual(job["attempts"], 0)
        self.store.finish_job("pubsub-1", "gmail_api_error")
        self.assertIsNone(self.store.claim_job())

        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE gmail_jobs SET available_at = 0"
            )
            connection.commit()
        retry = self.store.claim_job()
        self.assertEqual(retry["attempts"], 1)

    def test_existing_database_schema_is_migrated(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy_path)) as connection:
            connection.executescript(
                """
                CREATE TABLE gmail_alerts (
                    id TEXT PRIMARY KEY,
                    gmail_message_id TEXT NOT NULL UNIQUE,
                    sender TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    received_at TEXT,
                    threat_category TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    keywords_json TEXT NOT NULL,
                    urls_json TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    recommendations_json TEXT NOT NULL,
                    content_truncated INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE gmail_jobs (
                    pubsub_message_id TEXT PRIMARY KEY,
                    history_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    safe_error_code TEXT
                );
                """
            )

        GmailStore(legacy_path, self.key)
        with closing(sqlite3.connect(legacy_path)) as connection:
            alert_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(gmail_alerts)"
                )
            }
            job_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(gmail_jobs)"
                )
            }

        self.assertIn("attachment_metadata_json", alert_columns)
        self.assertIn("available_at", job_columns)


class GmailParsingTests(unittest.TestCase):
    def test_html_is_text_only_and_attachment_body_is_never_fetched(self):
        message = {
            "id": "message-1",
            "payload": {
                "headers": [
                    {"name": "From", "value": "Sender <sender@example.test>"},
                    {"name": "Subject", "value": "Encoded test"},
                ],
                "mimeType": "multipart/mixed",
                "parts": [
                    {
                        "mimeType": "text/html",
                        "body": {
                            "data": encoded(
                                "<script>secret()</script><p>Visible message</p>"
                            )
                        },
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "invoice.pdf",
                        "body": {
                            "attachmentId": "never-requested",
                            "size": 42,
                            "data": encoded("attachment bytes"),
                        },
                    },
                ],
            },
        }

        result = extract_message(message)
        self.assertIn("Visible message", result["body"])
        self.assertNotIn("secret()", result["body"])
        self.assertNotIn("attachment bytes", result["body"])
        self.assertEqual(result["attachments"][0]["size"], 42)

    def test_large_inline_bodies_are_bounded(self):
        message = {
            "id": "large-message",
            "payload": {
                "mimeType": "text/plain",
                "body": {"data": encoded("x" * 100000)},
            },
        }
        result = extract_message(message)
        self.assertLessEqual(len(result["body"]), 20000)
        self.assertTrue(result["body_truncated"])


class GmailSyncTests(unittest.TestCase):
    def test_history_sync_deduplicates_and_saves_metadata_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            key = Fernet.generate_key().decode("ascii")
            store = GmailStore(Path(temp_dir) / "gmail.sqlite3", key)
            owner = session_hash("browser")
            store.save_account(owner, "user@example.test", "{}")
            store.set_monitoring(
                owner,
                True,
                history_id="10",
                watch_expiration="2027-01-01T00:00:00+00:00",
            )
            account = store.get_account()

            service = Mock()
            service.users.return_value.history.return_value.list.return_value.execute.return_value = {
                "historyId": "12",
                "history": [
                    {
                        "messagesAdded": [
                            {"message": {"id": "gmail-1"}},
                            {"message": {"id": "gmail-1"}},
                        ]
                    }
                ],
            }
            service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
                "id": "gmail-1",
                "labelIds": ["INBOX"],
                "payload": {
                    "headers": [
                        {"name": "From", "value": "sender@example.test"},
                        {"name": "Subject", "value": "Message subject"},
                    ],
                    "mimeType": "text/plain",
                    "body": {"data": encoded("Please verify your account now")},
                },
            }
            analyzer = Mock()
            analyzer.analyze.return_value = {
                "final_assessment": {
                    "final_threat": "phishing",
                    "risk_score": 82,
                    "risk_level": "CRITICAL",
                    "reasons": ["Suspicious request"],
                },
                "keywords": {
                    "keywords": ["verify"],
                },
                "urls": {"urls": []},
            }
            processed = sync_gmail_history(
                account,
                service,
                analyzer,
                store,
            )
            alerts = store.list_alerts()

            self.assertEqual(processed, 1)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["subject"], "Message subject")
            self.assertNotIn("body", alerts[0])
            self.assertEqual(store.get_account()["history_id"], "12")


class GmailRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_status_is_public_but_does_not_expose_credentials(self):
        response = self.client.get("/gmail/status")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("oauth_configured", payload)
        self.assertIn("pubsub_configured", payload)
        self.assertNotIn("credentials_json", payload)
        self.assertNotIn("client_secret", payload)
        self.assertEqual(
            response.headers["cache-control"],
            "no-store",
        )

    def test_alerts_require_the_owning_browser_session(self):
        response = self.client.get("/gmail/alerts")

        self.assertEqual(response.status_code, 401)

    def test_oauth_start_is_same_origin_and_sets_browser_session(self):
        secret = "s" * 40
        test_settings = replace(
            gmail_routes.settings,
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri="http://testserver/gmail/callback",
            session_secret=secret,
            token_encryption_key=Fernet.generate_key().decode("ascii"),
        )
        flow = Mock()
        flow.authorization_url.return_value = (
            "https://accounts.google.com/o/oauth2/auth?state=test",
            "test",
        )

        with (
            patch.object(gmail_routes, "settings", test_settings),
            patch.object(gmail_routes, "cookies", SessionCookies(secret)),
            patch.object(gmail_routes.store, "create_oauth_state") as save_state,
            patch.object(gmail_routes, "_flow", return_value=flow),
            patch("src.gmail_security.router.secrets.token_urlsafe", return_value="session-id"),
        ):
            client = TestClient(app)
            response = client.post(
                "/gmail/connect",
                headers={"Origin": "http://testserver"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["authorization_url"],
            "https://accounts.google.com/o/oauth2/auth?state=test",
        )
        self.assertTrue(response.headers["set-cookie"].lower().find("httponly") >= 0)
        save_state.assert_called_once()

    def test_oauth_start_rejects_cross_origin_posts(self):
        response = self.client.post(
            "/gmail/connect",
            headers={"Origin": "https://attacker.example"},
        )

        self.assertEqual(response.status_code, 403)

    def test_oauth_query_parameters_are_redacted_from_access_logs(self):
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            "",
            0,
            '%s - "%s %s HTTP/%s" %d',
            (
                "127.0.0.1",
                "GET",
                "/gmail/callback?code=secret&state=state",
                "1.1",
                200,
            ),
            None,
        )

        self.assertTrue(GmailQueryRedactionFilter().filter(record))
        self.assertNotIn("secret", record.getMessage())
        self.assertNotIn("state=", record.getMessage())

    def test_monitoring_is_explicitly_enabled_and_can_be_paused(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            key = Fernet.generate_key().decode("ascii")
            test_store = GmailStore(Path(temp_dir) / "gmail.sqlite3", key)
            session_id = "browser-session"
            owner = session_hash(session_id)
            test_store.save_account(owner, "user@example.test", "{}")
            session_secret = "a" * 40
            test_cookies = SessionCookies(session_secret)
            test_settings = replace(
                gmail_routes.settings,
                client_id="client-id",
                client_secret="client-secret",
                redirect_uri="http://testserver/gmail/callback",
                session_secret=session_secret,
                token_encryption_key=key,
                cloud_project_id="project",
                pubsub_topic="topic",
                pubsub_subscription="subscription",
            )
            service = Mock()
            client = TestClient(app)
            client.cookies.set(
                "cybermind_gmail_session",
                session_id + "." + test_cookies._signature(session_id),
            )
            watch = {
                "history_id": "123",
                "expiration": "2027-01-01T00:00:00+00:00",
            }

            with (
                patch.object(gmail_routes, "settings", test_settings),
                patch.object(gmail_routes, "cookies", test_cookies),
                patch.object(gmail_routes, "store", test_store),
                patch.object(
                    gmail_routes,
                    "gmail_service_for_account",
                    return_value=service,
                ),
                patch.object(
                    gmail_routes,
                    "start_gmail_watch",
                    return_value=watch,
                ),
            ):
                enabled = client.post(
                    "/gmail/monitoring",
                    headers={"Origin": "http://testserver"},
                    json={"enabled": True},
                )
                paused = client.post(
                    "/gmail/monitoring",
                    headers={"Origin": "http://testserver"},
                    json={"enabled": False},
                )

        self.assertEqual(enabled.status_code, 200)
        self.assertTrue(enabled.json()["monitoring_enabled"])
        self.assertEqual(paused.status_code, 200)
        self.assertFalse(paused.json()["monitoring_enabled"])
        self.assertTrue(paused.json()["watch_stopped"])
        service.users.return_value.stop.assert_called_once_with(userId="me")

    def test_authenticated_pubsub_push_is_queued_for_the_connected_account(self):
        test_settings = replace(
            gmail_routes.settings,
            cloud_project_id="project",
            pubsub_topic="topic",
            pubsub_subscription="subscription",
            pubsub_mode="push",
            push_audience="https://example.test/gmail/pubsub/push",
            push_service_account_email="push@example.iam.gserviceaccount.com",
        )
        test_store = Mock()
        test_store.get_account.return_value = {
            "monitoring_enabled": True,
            "email": "user@example.test",
        }
        notification = {
            "emailAddress": "user@example.test",
            "historyId": "123",
        }
        body = {
            "subscription": "projects/project/subscriptions/subscription",
            "message": {
                "messageId": "pubsub-1",
                "data": base64.b64encode(
                    json.dumps(notification).encode("utf-8")
                ).decode("ascii"),
            },
        }

        with (
            patch.object(gmail_routes, "settings", test_settings),
            patch.object(gmail_routes, "store", test_store),
            patch(
                "src.gmail_security.router.id_token.verify_oauth2_token",
                return_value={
                    "email": "push@example.iam.gserviceaccount.com",
                    "email_verified": True,
                },
            ) as verify_identity,
        ):
            response = self.client.post(
                "/gmail/pubsub/push",
                headers={"Authorization": "Bearer signed-token"},
                json=body,
            )

        self.assertEqual(response.status_code, 204)
        verify_identity.assert_called_once()
        test_store.enqueue_notification.assert_called_once_with(
            "pubsub-1", "123"
        )
