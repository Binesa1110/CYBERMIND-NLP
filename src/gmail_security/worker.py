"""Durable Gmail Pub/Sub pull worker and watch reconciler."""

import base64
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from google.cloud import pubsub_v1
from googleapiclient.errors import HttpError

from src.analyzer import CyberMindAnalyzer

from .config import GmailSettings
from .monitor import (
    gmail_service_for_account,
    process_notification_job,
    recover_expired_history,
    start_gmail_watch,
    sync_gmail_history,
)
from .gmail_client import is_gmail_not_found
from .store import GmailStore


logger = logging.getLogger("cybermind.gmail.worker")
PULL_BATCH_SIZE = 20
RECONCILE_SECONDS = 60
WATCH_RENEWAL_MARGIN = timedelta(hours=24)


def _enqueue_pubsub_message(
    message: Any,
    account: dict[str, Any] | None,
    store: GmailStore,
) -> None:
    if account is None or not account["monitoring_enabled"]:
        return
    try:
        notification = json.loads(
            base64.b64decode(message.data, validate=True).decode("utf-8")
        )
        email = notification["emailAddress"]
        history_id = notification["historyId"]
        if (
            not isinstance(email, str)
            or email.casefold() != account["email"].casefold()
            or not isinstance(history_id, str)
            or not history_id.isdigit()
        ):
            logger.warning("Ignoring invalid Gmail Pub/Sub notification.")
            return
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        logger.warning("Ignoring malformed Gmail Pub/Sub notification.")
        return
    store.enqueue_notification(message.message_id, history_id)


def _renew_watch(
    account: dict[str, Any],
    settings: GmailSettings,
    store: GmailStore,
) -> None:
    expiration = account.get("watch_expiration")
    if not expiration:
        return
    expiry = datetime.fromisoformat(expiration)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry > datetime.now(timezone.utc) + WATCH_RENEWAL_MARGIN:
        return
    service = gmail_service_for_account(account, store)
    watch = start_gmail_watch(service, settings)
    store.update_watch_expiration(
        account["session_hash"],
        watch["expiration"],
    )
    logger.info("Renewed Gmail watch before expiration.")


def run_worker() -> None:
    settings = GmailSettings.from_environment()
    if not settings.pubsub_configured:
        raise RuntimeError(
            "Configure Google Cloud Pub/Sub before starting the Gmail worker."
        )
    store = GmailStore(
        settings.database_path,
        encryption_key=settings.token_encryption_key,
    )
    store.reset_processing_jobs()
    analyzer = CyberMindAnalyzer()
    subscriber = pubsub_v1.SubscriberClient() if (
        settings.pubsub_mode == "pull"
    ) else None
    subscription_path = (
        subscriber.subscription_path(
            settings.cloud_project_id,
            settings.pubsub_subscription,
        )
        if subscriber
        else None
    )
    last_reconcile = 0.0
    last_job_cleanup = 0.0
    logger.info(
        "Gmail worker started in %s mode.",
        settings.pubsub_mode,
    )

    while True:
        if subscriber and subscription_path:
            try:
                pulled = subscriber.pull(
                    request={
                        "subscription": subscription_path,
                        "max_messages": PULL_BATCH_SIZE,
                    },
                    timeout=25,
                )
                account = store.get_account()
                acknowledged: list[str] = []
                for received in pulled.received_messages:
                    _enqueue_pubsub_message(
                        received.message,
                        account,
                        store,
                    )
                    acknowledged.append(received.ack_id)
                if acknowledged:
                    subscriber.acknowledge(
                        request={
                            "subscription": subscription_path,
                            "ack_ids": acknowledged,
                        }
                    )
            except Exception as error:
                logger.error(
                    "Pub/Sub pull failed with %s; retrying.",
                    type(error).__name__,
                )
                time.sleep(5)

        while True:
            job = store.claim_job()
            if not job:
                break
            account = store.get_account()
            process_notification_job(job, account, analyzer, store)

        now = time.monotonic()
        if now - last_job_cleanup >= 86400:
            store.remove_old_jobs()
            last_job_cleanup = now

        if now - last_reconcile >= RECONCILE_SECONDS:
            account = store.get_account()
            if account and account["monitoring_enabled"]:
                try:
                    _renew_watch(account, settings, store)
                    service = gmail_service_for_account(account, store)
                    sync_gmail_history(account, service, analyzer, store)
                except HttpError as error:
                    if is_gmail_not_found(error):
                        try:
                            service = gmail_service_for_account(
                                account, store
                            )
                            recover_expired_history(
                                account,
                                service,
                                analyzer,
                                store,
                                settings,
                            )
                            last_reconcile = now
                            continue
                        except Exception as recovery_error:
                            logger.error(
                                "Gmail history recovery failed with %s.",
                                type(recovery_error).__name__,
                            )
                    logger.warning(
                        "Gmail reconciliation failed with HTTP status %s.",
                        getattr(
                            getattr(error, "resp", None),
                            "status",
                            "unknown",
                        ),
                    )
                    store.set_monitoring_error(
                        account["session_hash"], "gmail_api_error"
                    )
                except Exception as error:
                    logger.error(
                        "Gmail reconciliation failed with %s.",
                        type(error).__name__,
                    )
                    store.set_monitoring_error(
                        account["session_hash"],
                        "gmail_reconciliation_error",
                    )
            last_reconcile = now
        if settings.pubsub_mode == "push":
            time.sleep(2)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    run_worker()
