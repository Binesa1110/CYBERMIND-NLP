"""Gmail watch, history sync, and metadata-only threat analysis."""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

from src.analyzer import CyberMindAnalyzer

from .config import GMAIL_READONLY_SCOPE, GmailSettings
from .gmail_client import (
    build_gmail_service,
    extract_message,
    is_gmail_not_found,
)
from .store import GmailStore, utc_now


logger = logging.getLogger("cybermind.gmail")
MAX_EMAIL_ANALYSIS_CHARS = 20000
MAX_RECOVERY_MESSAGES = 5000


def gmail_service_for_account(
    account: dict[str, Any],
    store: GmailStore,
) -> Any:
    """Load, refresh, and persist the account's encrypted OAuth credentials."""

    credentials = Credentials.from_authorized_user_info(
        json.loads(account["credentials_json"]),
        scopes=[GMAIL_READONLY_SCOPE],
    )
    if credentials.expired:
        if not credentials.refresh_token:
            raise RuntimeError("gmail_reauthorization_required")
        credentials.refresh(Request())
        store.update_credentials(
            account["session_hash"],
            credentials.to_json(),
        )
    if not credentials.valid:
        raise RuntimeError("gmail_reauthorization_required")
    return build_gmail_service(credentials)


def start_gmail_watch(
    service: Any,
    settings: GmailSettings,
) -> dict[str, str]:
    if not settings.pubsub_configured:
        raise RuntimeError("pubsub_not_configured")
    topic_name = (
        f"projects/{settings.cloud_project_id}/topics/"
        f"{settings.pubsub_topic}"
    )
    response = (
        service.users()
        .watch(
            userId="me",
            body={"topicName": topic_name, "labelIds": ["INBOX"]},
        )
        .execute()
    )
    history_id = response.get("historyId")
    expiration_ms = response.get("expiration")
    if not history_id or not expiration_ms:
        raise RuntimeError("invalid_gmail_watch_response")
    expiration = datetime.fromtimestamp(
        int(expiration_ms) / 1000,
        tz=timezone.utc,
    ).isoformat()
    return {"history_id": str(history_id), "expiration": expiration}


def _analyse_message(
    service: Any,
    analyzer: CyberMindAnalyzer,
    store: GmailStore,
    message_id: str,
) -> None:
    if store.has_alert_for_message(message_id):
        return
    response = (
        service.users()
        .messages()
        .get(userId="me", id=message_id, format="full")
        .execute()
    )
    if "INBOX" not in response.get("labelIds", []):
        return

    extracted = extract_message(response)
    original_body = extracted["body"]
    body = original_body[:MAX_EMAIL_ANALYSIS_CHARS]
    analysis = analyzer.analyze(body)
    assessment = analysis["final_assessment"]
    keywords = analysis["keywords"]
    urls = analysis["urls"]

    store.add_alert(
        {
            "id": uuid.uuid4().hex,
            "gmail_message_id": message_id,
            "sender": extracted["sender"][:500],
            "subject": extracted["subject"][:500],
            "received_at": extracted["received_at"],
            "threat_category": str(
                assessment.get("final_threat", "unknown")
            )[:40].lower(),
            "risk_score": max(
                0,
                min(100, int(assessment.get("risk_score", 0))),
            ),
            "risk_level": str(
                assessment.get("risk_level", "UNKNOWN")
            )[:20].upper(),
            "keywords": keywords.get("keywords", [])[:30],
            "urls": urls.get("urls", [])[:30],
            "reasons": assessment.get("reasons", [])[:20],
            "recommendations": [],
            "attachment_metadata": extracted["attachments"][:30],
            "content_truncated": (
                extracted["body_truncated"]
                or len(original_body) > len(body)
            ),
            "created_at": utc_now(),
        }
    )


def sync_gmail_history(
    account: dict[str, Any],
    service: Any,
    analyzer: CyberMindAnalyzer,
    store: GmailStore,
) -> int:
    """Process all INBOX additions since the stored history cursor."""

    start_history_id = account.get("history_id")
    if not start_history_id:
        raise RuntimeError("gmail_history_cursor_missing")

    message_ids: set[str] = set()
    page_token: str | None = None
    latest_history_id = str(start_history_id)
    while True:
        request = service.users().history().list(
            userId="me",
            startHistoryId=start_history_id,
            historyTypes=["messageAdded"],
            labelId="INBOX",
            pageToken=page_token,
            maxResults=500,
        )
        response = request.execute()
        latest_history_id = str(
            response.get("historyId", latest_history_id)
        )
        for item in response.get("history", []):
            for added in item.get("messagesAdded", []):
                message_id = added.get("message", {}).get("id")
                if message_id:
                    message_ids.add(message_id)
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    processed = 0
    for message_id in message_ids:
        try:
            _analyse_message(service, analyzer, store, message_id)
            processed += 1
        except HttpError as error:
            if is_gmail_not_found(error):
                continue
            raise

    store.update_history(
        account["session_hash"],
        latest_history_id,
        synced_at=utc_now(),
    )
    return processed


def recover_expired_history(
    account: dict[str, Any],
    service: Any,
    analyzer: CyberMindAnalyzer,
    store: GmailStore,
    settings: GmailSettings,
) -> int:
    """Reconcile the bounded inbox gap, then establish a fresh history cursor."""

    last_synced = account.get("last_synced_at")
    if last_synced:
        timestamp = datetime.fromisoformat(last_synced)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = datetime.now(timezone.utc)
    timestamp -= timedelta(minutes=1)
    watch = start_gmail_watch(service, settings)
    after_seconds = int(timestamp.timestamp())
    page_token: str | None = None
    message_ids: set[str] = set()
    while True:
        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                q=f"in:inbox after:{after_seconds}",
                pageToken=page_token,
                maxResults=500,
            )
            .execute()
        )
        for item in response.get("messages", []):
            message_id = item.get("id")
            if message_id:
                message_ids.add(message_id)
        if len(message_ids) > MAX_RECOVERY_MESSAGES:
            raise RuntimeError("gmail_history_recovery_limit_exceeded")
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    for message_id in message_ids:
        try:
            _analyse_message(service, analyzer, store, message_id)
        except HttpError as error:
            if not is_gmail_not_found(error):
                raise

    store.update_history(
        account["session_hash"],
        watch["history_id"],
        synced_at=utc_now(),
    )
    store.update_watch_expiration(
        account["session_hash"],
        watch["expiration"],
    )
    logger.info(
        "Recovered expired Gmail history for %s inbox messages.",
        len(message_ids),
    )
    return len(message_ids)


def process_notification_job(
    job: dict[str, Any],
    account: dict[str, Any] | None,
    analyzer: CyberMindAnalyzer,
    store: GmailStore,
) -> None:
    message_id = job["pubsub_message_id"]
    try:
        if account is None or not account["monitoring_enabled"]:
            store.finish_job(message_id)
            return
        service = gmail_service_for_account(account, store)
        try:
            sync_gmail_history(account, service, analyzer, store)
        except HttpError as error:
            if is_gmail_not_found(error):
                recover_expired_history(
                    account,
                    service,
                    analyzer,
                    store,
                    GmailSettings.from_environment(),
                )
            else:
                raise
        store.finish_job(message_id)
    except RuntimeError as error:
        code = str(error)
        logger.warning("Gmail job stopped with safe error code: %s", code)
        if account:
            store.set_monitoring_error(account["session_hash"], code)
        store.finish_job(message_id, code)
    except HttpError as error:
        logger.warning(
            "Gmail API job failed with HTTP status %s.",
            getattr(getattr(error, "resp", None), "status", "unknown"),
        )
        if account:
            store.set_monitoring_error(
                account["session_hash"], "gmail_api_error"
            )
        store.finish_job(message_id, "gmail_api_error")
    except Exception as error:
        logger.error(
            "Gmail job failed with %s; retrying through the durable queue.",
            type(error).__name__,
        )
        if account:
            store.set_monitoring_error(
                account["session_hash"], "gmail_processing_error"
            )
        store.finish_job(message_id, "gmail_processing_error")
