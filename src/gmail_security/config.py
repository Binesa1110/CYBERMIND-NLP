"""Environment-backed configuration for Gmail monitoring."""

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv


GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
DEFAULT_REDIRECT_URI = "http://localhost:8000/gmail/callback"

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


@dataclass(frozen=True)
class GmailSettings:
    client_id: str
    client_secret: str
    redirect_uri: str
    session_secret: str
    token_encryption_key: str
    database_path: Path
    cloud_project_id: str
    pubsub_topic: str
    pubsub_subscription: str
    pubsub_mode: str
    deployment: str
    push_audience: str
    push_service_account_email: str

    @classmethod
    def from_environment(cls) -> "GmailSettings":
        pubsub_mode = os.getenv(
            "GMAIL_PUBSUB_MODE", "pull"
        ).strip().lower()
        deployment = os.getenv(
            "CYBERMIND_GMAIL_DEPLOYMENT", "local"
        ).strip().lower()
        if pubsub_mode not in ("pull", "push"):
            raise ValueError("GMAIL_PUBSUB_MODE must be 'pull' or 'push'.")
        if deployment not in ("local", "production"):
            raise ValueError(
                "CYBERMIND_GMAIL_DEPLOYMENT must be 'local' or 'production'."
            )

        local_app_data = os.getenv("LOCALAPPDATA")
        default_data_dir = (
            Path(local_app_data) / "CYBERMIND" / "gmail-security"
            if local_app_data
            else Path.home() / ".cybermind" / "gmail-security"
        )
        database_override = os.getenv(
            "CYBERMIND_GMAIL_DATABASE", ""
        ).strip()
        database_path = Path(
            database_override
            if database_override
            else default_data_dir / "gmail-security.sqlite3"
        ).expanduser()

        return cls(
            client_id=os.getenv("GOOGLE_CLIENT_ID", "").strip(),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
            redirect_uri=os.getenv(
                "GOOGLE_REDIRECT_URI", DEFAULT_REDIRECT_URI
            ).strip(),
            session_secret=os.getenv("SESSION_SECRET_KEY", "").strip(),
            token_encryption_key=os.getenv(
                "TOKEN_ENCRYPTION_KEY", ""
            ).strip(),
            database_path=database_path,
            cloud_project_id=os.getenv(
                "GOOGLE_CLOUD_PROJECT_ID", ""
            ).strip(),
            pubsub_topic=os.getenv("GMAIL_PUBSUB_TOPIC", "").strip(),
            pubsub_subscription=os.getenv(
                "GMAIL_PUBSUB_SUBSCRIPTION", ""
            ).strip(),
            pubsub_mode=pubsub_mode,
            deployment=deployment,
            push_audience=os.getenv(
                "GMAIL_PUBSUB_PUSH_AUDIENCE", ""
            ).strip(),
            push_service_account_email=os.getenv(
                "GMAIL_PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL", ""
            ).strip(),
        )

    @property
    def oauth_configured(self) -> bool:
        if (
            not self.client_id
            or not self.client_secret
            or not self.redirect_uri
            or len(self.session_secret.encode("utf-8")) < 32
        ):
            return False
        try:
            Fernet(self.token_encryption_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            return False
        return bool(
            self.client_id
            and self.client_secret
            and self.redirect_uri
            and self.token_encryption_key
        )

    @property
    def pubsub_configured(self) -> bool:
        common = bool(
            self.cloud_project_id
            and self.pubsub_topic
            and self.pubsub_subscription
        )

        if self.pubsub_mode == "pull":
            return common

        if self.pubsub_mode == "push":
            return bool(
                common
                and self.push_audience
                and self.push_service_account_email
            )

        return False

    def safe_setup_status(self) -> dict[str, bool | str]:
        missing_oauth = [
            name
            for name, value in (
                ("GOOGLE_CLIENT_ID", self.client_id),
                ("GOOGLE_CLIENT_SECRET", self.client_secret),
                ("GOOGLE_REDIRECT_URI", self.redirect_uri),
                ("SESSION_SECRET_KEY", self.session_secret),
                ("TOKEN_ENCRYPTION_KEY", self.token_encryption_key),
            )
            if not value
        ]
        if self.session_secret and len(self.session_secret.encode("utf-8")) < 32:
            missing_oauth.append("SESSION_SECRET_KEY (minimum 32 bytes)")
        try:
            Fernet(self.token_encryption_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            if self.token_encryption_key:
                missing_oauth.append("TOKEN_ENCRYPTION_KEY (invalid Fernet key)")
        missing_pubsub = [
            name
            for name, value in (
                ("GOOGLE_CLOUD_PROJECT_ID", self.cloud_project_id),
                ("GMAIL_PUBSUB_TOPIC", self.pubsub_topic),
                ("GMAIL_PUBSUB_SUBSCRIPTION", self.pubsub_subscription),
            )
            if not value
        ]

        if self.pubsub_mode == "push":
            if not self.push_audience:
                missing_pubsub.append("GMAIL_PUBSUB_PUSH_AUDIENCE")
            if not self.push_service_account_email:
                missing_pubsub.append(
                    "GMAIL_PUBSUB_PUSH_SERVICE_ACCOUNT_EMAIL"
                )

        return {
            "oauth_configured": self.oauth_configured,
            "pubsub_configured": self.pubsub_configured,
            "pubsub_mode": self.pubsub_mode,
            "deployment": self.deployment,
            "missing_oauth_settings": missing_oauth,
            "missing_pubsub_settings": missing_pubsub,
        }
