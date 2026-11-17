"""Opt-in Gmail OAuth and monitoring API routes."""

import base64
import binascii
import json
import logging
import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError
from oauthlib.oauth2 import OAuth2Error
from pydantic import BaseModel
import requests

from .config import GMAIL_READONLY_SCOPE, GmailSettings
from .gmail_client import build_gmail_service
from .monitor import gmail_service_for_account, start_gmail_watch
from .sessions import SessionCookies, require_local_client, require_same_origin
from .store import GmailStore, session_hash


logger = logging.getLogger("cybermind.gmail.api")
settings = GmailSettings.from_environment()
store = GmailStore(
    settings.database_path,
    encryption_key=settings.token_encryption_key,
)
cookies = SessionCookies(settings.session_secret)
router = APIRouter(prefix="/gmail", tags=["Gmail security"])


class MonitoringRequest(BaseModel):
    enabled: bool


def _owner_for_request(request: Request, create: bool = False) -> str:
    session_id = cookies.read(request)
    if not session_id and create:
        session_id = secrets.token_urlsafe(32)
    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Connect Gmail from this browser session first.",
        )
    return session_id


def _owned_account(request: Request) -> dict[str, Any]:
    session_id = _owner_for_request(request)
    account = store.get_account()
    if (
        account is None
        or not secrets.compare_digest(
            account["session_hash"], session_hash(session_id)
        )
    ):
        raise HTTPException(
            status_code=404,
            detail="No Gmail account is connected to this browser.",
        )
    return account


def _flow(state: str | None = None) -> Flow:
    if not settings.client_id or not settings.client_secret:
        raise HTTPException(
            status_code=503,
            detail="Google OAuth is not configured on this server.",
        )
    client_config = {
        "web": {
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [settings.redirect_uri],
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=[GMAIL_READONLY_SCOPE],
        state=state,
    )
    flow.redirect_uri = settings.redirect_uri
    return flow


@router.get("/status")
def gmail_status(request: Request) -> dict[str, Any]:
    require_local_client(request, settings.deployment)
    setup = settings.safe_setup_status()
    redirect = urlparse(settings.redirect_uri)
    current_origin = f"{request.url.scheme}://{request.url.netloc}"
    account = None
    session_id = cookies.read(request)
    if session_id:
        candidate = store.get_account()
        if candidate and secrets.compare_digest(
            candidate["session_hash"], session_hash(session_id)
        ):
            account = candidate
    return {
        **setup,
        "redirect_uri_matches_origin": (
            f"{redirect.scheme}://{redirect.netloc}" == current_origin
            and redirect.path == "/gmail/callback"
        ),
        "connected": account is not None,
        "email": account["email"] if account else None,
        "monitoring_enabled": (
            bool(account["monitoring_enabled"]) if account else False
        ),
        "watch_expiration": account["watch_expiration"] if account else None,
        "last_synced_at": account["last_synced_at"] if account else None,
        "monitoring_error": account["monitoring_error"] if account else None,
    }


@router.post("/connect")
def connect_gmail(request: Request) -> JSONResponse:
    require_local_client(request, settings.deployment)
    require_same_origin(request)
    if not settings.oauth_configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "Google OAuth, session signing, and token encryption "
                "must all be configured before connecting Gmail."
            ),
        )
    redirect = urlparse(settings.redirect_uri)
    if (
        f"{redirect.scheme}://{redirect.netloc}"
        != f"{request.url.scheme}://{request.url.netloc}"
        or redirect.path != "/gmail/callback"
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Open CYBERMIND using the same host as "
                "GOOGLE_REDIRECT_URI, including localhost versus 127.0.0.1."
            ),
        )
    session_id = _owner_for_request(request, create=True)
    owner_hash = session_hash(session_id)
    state = secrets.token_urlsafe(32)
    store.create_oauth_state(state, owner_hash)
    flow = _flow(state)
    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    response = JSONResponse(
        content={"authorization_url": authorization_url}
    )
    if not cookies.read(request):
        cookies.issue(response, request, session_id=session_id)
    return response


@router.get("/callback", include_in_schema=False)
def gmail_callback(request: Request) -> RedirectResponse:
    require_local_client(request, settings.deployment)
    state = request.query_params.get("state", "")
    session_id = cookies.read(request)
    if not state or not session_id or not store.consume_oauth_state(
        state, session_hash(session_id)
    ):
        raise HTTPException(
            status_code=400,
            detail="The Gmail authorization state is invalid or expired.",
        )
    if request.query_params.get("error"):
        raise HTTPException(
            status_code=400,
            detail="Google did not authorize Gmail access.",
        )
    if store.get_account() is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "A Gmail account is already connected. Disconnect it "
                "before starting a new authorization."
            ),
        )
    code = request.query_params.get("code", "")
    if not code:
        raise HTTPException(
            status_code=400,
            detail="Google did not return an authorization code.",
        )
    try:
        flow = _flow(state)
        flow.fetch_token(code=code)
        credentials = flow.credentials
        service = build_gmail_service(credentials)
        profile = service.users().getProfile(userId="me").execute()
        email = profile.get("emailAddress")
        if not isinstance(email, str) or not email:
            raise RuntimeError("gmail_profile_missing_email")
        store.save_account(
            session_hash(session_id),
            email[:320],
            credentials.to_json(),
        )
    except PermissionError as error:
        raise HTTPException(
            status_code=409,
            detail=(
                "A different local browser session already owns Gmail. "
                "Disconnect that account before connecting another."
            ),
        ) from error
    except (
        HttpError,
        OAuth2Error,
        GoogleAuthError,
        requests.RequestException,
        ValueError,
        RuntimeError,
    ) as error:
        logger.warning(
            "Gmail authorization failed with %s.",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Gmail authorization could not be completed.",
        ) from error
    return RedirectResponse("/ui/#gmail", status_code=303)


@router.post("/monitoring")
def set_monitoring(
    request: Request,
    payload: MonitoringRequest,
) -> dict[str, Any]:
    require_local_client(request, settings.deployment)
    require_same_origin(request)
    account = _owned_account(request)
    owner_hash = account["session_hash"]
    if not payload.enabled:
        store.set_monitoring(owner_hash, False)
        watch_stopped = True
        if account["monitoring_enabled"]:
            try:
                service = gmail_service_for_account(account, store)
                service.users().stop(userId="me").execute()
            except (
                HttpError,
                GoogleAuthError,
                requests.RequestException,
                RuntimeError,
                ValueError,
            ) as error:
                watch_stopped = False
                logger.warning(
                    "Gmail watch stop failed with %s.",
                    type(error).__name__,
                )
        return {
            "status": "success",
            "monitoring_enabled": False,
            "watch_stopped": watch_stopped,
        }

    try:
        service = gmail_service_for_account(account, store)
        watch = start_gmail_watch(service, settings)
        store.set_monitoring(
            owner_hash,
            True,
            history_id=watch["history_id"],
            watch_expiration=watch["expiration"],
        )
    except (HttpError, RuntimeError, ValueError) as error:
        logger.warning(
            "Gmail monitoring update failed with %s.",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Gmail monitoring could not be updated. Check the "
                "Google Cloud Pub/Sub setup and server logs."
            ),
        ) from error
    return {"status": "success", "monitoring_enabled": True}


@router.post("/disconnect")
def disconnect_gmail(request: Request) -> JSONResponse:
    require_local_client(request, settings.deployment)
    require_same_origin(request)
    account = _owned_account(request)
    credentials = Credentials.from_authorized_user_info(
        json.loads(account["credentials_json"]),
        scopes=[GMAIL_READONLY_SCOPE],
    )
    if account["monitoring_enabled"]:
        try:
            service = build_gmail_service(credentials)
            service.users().stop(userId="me").execute()
        except HttpError as error:
            logger.warning(
                "Gmail watch stop failed with HTTP status %s.",
                getattr(getattr(error, "resp", None), "status", "unknown"),
            )
    remote_revocation = "failed"
    token = credentials.refresh_token or credentials.token
    if token:
        try:
            with requests.post(
                "https://oauth2.googleapis.com/revoke",
                data={"token": token},
                timeout=10,
            ) as result:
                if result.status_code == 200:
                    remote_revocation = "revoked"
                else:
                    logger.warning(
                        "Google token revocation returned HTTP status %s.",
                        result.status_code,
                    )
        except requests.RequestException as error:
            logger.warning(
                "Google token revocation failed with %s.",
                type(error).__name__,
            )
    store.delete_account(account["session_hash"])
    response = JSONResponse(
        content={
            "status": "success",
            "remote_revocation": remote_revocation,
        }
    )
    response.delete_cookie(
        key="cybermind_gmail_session",
        path="/",
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/alerts")
def list_gmail_alerts(request: Request, limit: int = 100) -> dict[str, Any]:
    require_local_client(request, settings.deployment)
    _owned_account(request)
    return {
        "alerts": store.list_alerts(limit),
        "statistics": store.alert_statistics(),
    }


@router.get("/alerts/{alert_id}")
def get_gmail_alert(
    request: Request,
    alert_id: str,
) -> dict[str, Any]:
    require_local_client(request, settings.deployment)
    _owned_account(request)
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Gmail alert not found.")
    return alert


@router.delete("/alerts")
def clear_gmail_alerts(request: Request) -> dict[str, str]:
    require_local_client(request, settings.deployment)
    require_same_origin(request)
    _owned_account(request)
    store.clear_alerts()
    return {"status": "success"}


def _verify_push_identity(request: Request) -> None:
    if not settings.pubsub_configured or settings.pubsub_mode != "push":
        raise HTTPException(
            status_code=503,
            detail="Authenticated Pub/Sub push is not configured.",
        )
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid push identity.")
    try:
        claims = id_token.verify_oauth2_token(
            token,
            GoogleRequest(),
            audience=settings.push_audience,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=401,
            detail="Invalid push identity.",
        ) from error
    except (GoogleAuthError, requests.RequestException) as error:
        logger.warning(
            "Pub/Sub identity verification failed with %s.",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail="Push identity verification is temporarily unavailable.",
        ) from error
    if (
        claims.get("email") != settings.push_service_account_email
        or claims.get("email_verified") is not True
    ):
        raise HTTPException(status_code=401, detail="Invalid push identity.")


@router.post("/pubsub/push", status_code=204)
async def receive_pubsub_push(request: Request) -> Response:
    require_local_client(request, settings.deployment)
    _verify_push_identity(request)
    try:
        envelope = await request.json()
        message = envelope["message"]
        message_id = message["messageId"]
        encoded_data = message["data"]
        subscription = envelope["subscription"]
        expected_subscription = (
            f"projects/{settings.cloud_project_id}/subscriptions/"
            f"{settings.pubsub_subscription}"
        )
        if subscription != expected_subscription:
            raise ValueError("unexpected_subscription")
        if (
            not isinstance(message_id, str)
            or not message_id
            or len(message_id) > 256
            or not isinstance(encoded_data, str)
            or len(encoded_data) > 8192
        ):
            raise ValueError("invalid_push_message")
        decoded = base64.b64decode(
            encoded_data,
            validate=True,
        ).decode("utf-8")
        notification = json.loads(decoded)
        email = notification["emailAddress"]
        history_id = notification["historyId"]
        if (
            not isinstance(email, str)
            or not isinstance(history_id, str)
            or not email
            or not history_id.isdigit()
        ):
            raise ValueError("invalid_notification")
    except (
        KeyError,
        TypeError,
        ValueError,
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail="Invalid Gmail Pub/Sub notification.",
        ) from error

    account = store.get_account()
    if (
        account
        and account["monitoring_enabled"]
        and secrets.compare_digest(
            email.casefold(), account["email"].casefold()
        )
    ):
        store.enqueue_notification(message_id, history_id)
    return Response(status_code=204)
