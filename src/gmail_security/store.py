"""Encrypted local persistence for Gmail credentials and alert metadata."""

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


class GmailStore:
    """SQLite store that encrypts OAuth credentials before writing them."""

    def __init__(self, database_path: Path, encryption_key: str = ""):
        self.database_path = Path(database_path)
        self.encryption_key = encryption_key
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=30,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialise(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state_hash TEXT PRIMARY KEY,
                    session_hash TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS gmail_account (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    session_hash TEXT NOT NULL,
                    email TEXT NOT NULL,
                    encrypted_credentials BLOB NOT NULL,
                    monitoring_enabled INTEGER NOT NULL DEFAULT 0,
                    watch_expiration TEXT,
                    history_id TEXT,
                    last_synced_at TEXT,
                    monitoring_error TEXT
                );

                CREATE TABLE IF NOT EXISTS gmail_alerts (
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
                    attachment_metadata_json TEXT NOT NULL DEFAULT '[]',
                    content_truncated INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS gmail_jobs (
                    pubsub_message_id TEXT PRIMARY KEY,
                    history_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    safe_error_code TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_gmail_jobs_ready
                    ON gmail_jobs(status, created_at);
                CREATE INDEX IF NOT EXISTS idx_gmail_alerts_created
                    ON gmail_alerts(created_at DESC);
                """
            )
            alert_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(gmail_alerts)"
                ).fetchall()
            }
            if "attachment_metadata_json" not in alert_columns:
                connection.execute(
                    """
                    ALTER TABLE gmail_alerts
                    ADD COLUMN attachment_metadata_json
                    TEXT NOT NULL DEFAULT '[]'
                    """
                )
            job_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(gmail_jobs)"
                ).fetchall()
            }
            if "available_at" not in job_columns:
                connection.execute(
                    """
                    ALTER TABLE gmail_jobs
                    ADD COLUMN available_at REAL NOT NULL DEFAULT 0
                    """
                )

    def _cipher(self) -> Fernet:
        if not self.encryption_key:
            raise RuntimeError(
                "TOKEN_ENCRYPTION_KEY is required to store Gmail tokens."
            )
        try:
            return Fernet(self.encryption_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise RuntimeError(
                "TOKEN_ENCRYPTION_KEY must be a valid Fernet key."
            ) from error

    def create_oauth_state(
        self,
        state: str,
        owner_hash: str,
        lifetime_seconds: int = 600,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "DELETE FROM oauth_states WHERE expires_at < ?",
                (time.time(),),
            )
            connection.execute(
                """
                INSERT INTO oauth_states(state_hash, session_hash, expires_at)
                VALUES (?, ?, ?)
                """,
                (
                    hashlib.sha256(state.encode("utf-8")).hexdigest(),
                    owner_hash,
                    time.time() + lifetime_seconds,
                ),
            )

    def consume_oauth_state(self, state: str, owner_hash: str) -> bool:
        state_digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT session_hash, expires_at
                FROM oauth_states WHERE state_hash = ?
                """,
                (state_digest,),
            ).fetchone()
            connection.execute(
                "DELETE FROM oauth_states WHERE state_hash = ?",
                (state_digest,),
            )
            connection.commit()

        return bool(
            row
            and row["expires_at"] >= time.time()
            and hmac.compare_digest(row["session_hash"], owner_hash)
        )

    def save_account(
        self,
        owner_hash: str,
        email: str,
        credentials_json: str,
    ) -> None:
        encrypted = self._cipher().encrypt(
            credentials_json.encode("utf-8")
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT session_hash FROM gmail_account WHERE singleton = 1"
            ).fetchone()
            if existing and not hmac.compare_digest(
                existing["session_hash"], owner_hash
            ):
                raise PermissionError(
                    "A different local browser session already owns Gmail."
                )

            connection.execute(
                """
                INSERT INTO gmail_account (
                    singleton, session_hash, email, encrypted_credentials,
                    monitoring_enabled, watch_expiration, history_id,
                    last_synced_at, monitoring_error
                ) VALUES (1, ?, ?, ?, 0, NULL, NULL, NULL, NULL)
                ON CONFLICT(singleton) DO UPDATE SET
                    email = excluded.email,
                    encrypted_credentials = excluded.encrypted_credentials,
                    monitoring_enabled = 0,
                    watch_expiration = NULL,
                    history_id = NULL,
                    last_synced_at = NULL,
                    monitoring_error = NULL
                """,
                (owner_hash, email, encrypted),
            )
            connection.commit()

    def get_account(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM gmail_account WHERE singleton = 1"
            ).fetchone()

        if row is None:
            return None

        account = dict(row)
        try:
            account["credentials_json"] = self._cipher().decrypt(
                account.pop("encrypted_credentials")
            ).decode("utf-8")
        except InvalidToken as error:
            raise RuntimeError(
                "Stored Gmail credentials cannot be decrypted. Check "
                "TOKEN_ENCRYPTION_KEY."
            ) from error
        return account

    def update_credentials(
        self,
        owner_hash: str,
        credentials_json: str,
    ) -> None:
        encrypted = self._cipher().encrypt(
            credentials_json.encode("utf-8")
        )
        with closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE gmail_account
                SET encrypted_credentials = ?
                WHERE singleton = 1 AND session_hash = ?
                """,
                (encrypted, owner_hash),
            )

    def set_monitoring(
        self,
        owner_hash: str,
        enabled: bool,
        history_id: str | None = None,
        watch_expiration: str | None = None,
    ) -> None:
        with closing(self._connect()) as connection:
            if enabled:
                connection.execute(
                    """
                    UPDATE gmail_account
                    SET monitoring_enabled = 1,
                        history_id = ?,
                        watch_expiration = ?,
                        last_synced_at = ?,
                        monitoring_error = NULL
                    WHERE singleton = 1 AND session_hash = ?
                    """,
                    (
                        history_id,
                        watch_expiration,
                        utc_now(),
                        owner_hash,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE gmail_account
                    SET monitoring_enabled = 0,
                        monitoring_error = NULL
                    WHERE singleton = 1 AND session_hash = ?
                    """,
                    (owner_hash,),
                )

    def update_watch_expiration(
        self,
        owner_hash: str,
        watch_expiration: str,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE gmail_account
                SET watch_expiration = ?, monitoring_error = NULL
                WHERE singleton = 1 AND session_hash = ?
                """,
                (watch_expiration, owner_hash),
            )

    def update_history(
        self,
        owner_hash: str,
        history_id: str,
        synced_at: str | None = None,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE gmail_account
                SET history_id = ?,
                    last_synced_at = COALESCE(?, last_synced_at),
                    monitoring_error = NULL
                WHERE singleton = 1 AND session_hash = ?
                """,
                (history_id, synced_at, owner_hash),
            )

    def set_monitoring_error(
        self,
        owner_hash: str,
        safe_error_code: str,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE gmail_account
                SET monitoring_error = ?
                WHERE singleton = 1 AND session_hash = ?
                """,
                (safe_error_code[:80], owner_hash),
            )

    def delete_account(self, owner_hash: str) -> bool:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT singleton FROM gmail_account
                WHERE singleton = 1 AND session_hash = ?
                """,
                (owner_hash,),
            ).fetchone()
            if row:
                connection.execute("DELETE FROM gmail_account")
                connection.execute("DELETE FROM gmail_alerts")
                connection.execute("DELETE FROM gmail_jobs")
            connection.commit()
        return row is not None

    def add_alert(
        self,
        alert: dict[str, Any],
        max_entries: int = 1000,
    ) -> bool:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO gmail_alerts (
                    id, gmail_message_id, sender, subject, received_at,
                    threat_category, risk_score, risk_level, keywords_json,
                    urls_json, reasons_json, recommendations_json,
                    attachment_metadata_json, content_truncated, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    alert["gmail_message_id"],
                    alert["sender"],
                    alert["subject"],
                    alert.get("received_at"),
                    alert["threat_category"],
                    alert["risk_score"],
                    alert["risk_level"],
                    json.dumps(alert["keywords"]),
                    json.dumps(alert["urls"]),
                    json.dumps(alert["reasons"]),
                    json.dumps(alert["recommendations"]),
                    json.dumps(alert.get("attachment_metadata", [])),
                    int(alert.get("content_truncated", False)),
                    alert["created_at"],
                ),
            )
            inserted = cursor.rowcount == 1
            if inserted:
                connection.execute(
                    """
                    DELETE FROM gmail_alerts
                    WHERE id NOT IN (
                        SELECT id FROM gmail_alerts
                        ORDER BY created_at DESC LIMIT ?
                    )
                    """,
                    (max_entries,),
                )
        return inserted

    def has_alert_for_message(self, message_id: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM gmail_alerts
                WHERE gmail_message_id = ? LIMIT 1
                """,
                (message_id,),
            ).fetchone()
        return row is not None

    @staticmethod
    def _decode_alert(row: sqlite3.Row) -> dict[str, Any]:
        alert = dict(row)
        for field in (
            "keywords",
            "urls",
            "reasons",
            "recommendations",
        ):
            alert[field] = json.loads(alert.pop(field + "_json"))
        alert["attachment_metadata"] = json.loads(
            alert.pop("attachment_metadata_json")
        )
        alert["content_truncated"] = bool(alert["content_truncated"])
        return alert

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM gmail_alerts
                ORDER BY created_at DESC LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [self._decode_alert(row) for row in rows]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM gmail_alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()
        return self._decode_alert(row) if row else None

    def alert_statistics(self) -> dict[str, int]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT threat_category, COUNT(*) AS count
                FROM gmail_alerts GROUP BY threat_category
                """
            ).fetchall()
        counts = {row["threat_category"]: row["count"] for row in rows}
        return {
            "total_analysed": sum(counts.values()),
            "phishing": counts.get("phishing", 0),
            "scam": counts.get("scam", 0),
            "suspicious": sum(
                value
                for threat, value in counts.items()
                if threat not in ("benign",)
            ),
            "benign": counts.get("benign", 0),
        }

    def clear_alerts(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("DELETE FROM gmail_alerts")

    def enqueue_notification(
        self,
        pubsub_message_id: str,
        history_id: str,
    ) -> bool:
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO gmail_jobs (
                    pubsub_message_id, history_id, status,
                    created_at, updated_at
                ) VALUES (?, ?, 'pending', ?, ?)
                """,
                (
                    pubsub_message_id,
                    history_id,
                    utc_now(),
                    utc_now(),
                ),
            )
        return cursor.rowcount == 1

    def claim_job(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM gmail_jobs
                WHERE status = 'pending'
                  AND attempts < 5 AND available_at <= ?
                ORDER BY created_at LIMIT 1
                """,
                (time.time(),),
            ).fetchone()
            if row:
                connection.execute(
                    """
                    UPDATE gmail_jobs
                    SET status = 'processing', attempts = attempts + 1,
                        updated_at = ?
                    WHERE pubsub_message_id = ?
                    """,
                    (utc_now(), row["pubsub_message_id"]),
                )
            connection.commit()
        return dict(row) if row else None

    def finish_job(
        self,
        pubsub_message_id: str,
        safe_error_code: str | None = None,
    ) -> None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT attempts FROM gmail_jobs
                WHERE pubsub_message_id = ?
                """,
                (pubsub_message_id,),
            ).fetchone()
            if row is None:
                return
            failed = safe_error_code is not None and row["attempts"] >= 5
            available_at = time.time() + min(
                2 ** row["attempts"] * 2, 300
            )
            connection.execute(
                """
                UPDATE gmail_jobs
                SET status = ?, updated_at = ?, safe_error_code = ?,
                    available_at = ?
                WHERE pubsub_message_id = ?
                """,
                (
                    "failed" if failed else (
                        "pending" if safe_error_code else "done"
                    ),
                    utc_now(),
                    safe_error_code[:80] if safe_error_code else None,
                    available_at,
                    pubsub_message_id,
                ),
            )

    def reset_processing_jobs(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                UPDATE gmail_jobs
                SET status = 'pending', updated_at = ?
                WHERE status = 'processing'
                """,
                (utc_now(),),
            )

    def remove_old_jobs(self, older_than_days: int = 30) -> None:
        cutoff = time.time() - older_than_days * 86400
        cutoff_iso = datetime.fromtimestamp(
            cutoff, timezone.utc
        ).isoformat()
        with closing(self._connect()) as connection:
            connection.execute(
                "DELETE FROM gmail_jobs WHERE created_at < ?",
                (cutoff_iso,),
            )
