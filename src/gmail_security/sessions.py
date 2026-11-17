"""Signed, browser-bound sessions for the local single-user Gmail mode."""

import base64
import hashlib
import hmac
import ipaddress
import secrets
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response


COOKIE_NAME = "cybermind_gmail_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 365


class SessionCookies:
    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def _signature(self, session_id: str) -> str:
        digest = hmac.new(
            self.secret, session_id.encode("ascii"), hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def read(self, request: Request) -> str | None:
        value = request.cookies.get(COOKIE_NAME, "")
        session_id, separator, signature = value.partition(".")
        if not separator or not session_id or not signature:
            return None
        expected = self._signature(session_id)
        if not hmac.compare_digest(signature, expected):
            return None
        return session_id

    def issue(
        self,
        response: Response,
        request: Request,
        session_id: str | None = None,
    ) -> str:
        session_id = session_id or secrets.token_urlsafe(32)
        value = session_id + "." + self._signature(session_id)
        response.set_cookie(
            COOKIE_NAME,
            value,
            max_age=SESSION_MAX_AGE,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="lax",
            path="/",
        )
        return session_id


def require_local_client(request: Request, deployment: str) -> None:
    if deployment != "local":
        return
    host = request.client.host if request.client else ""
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "testclient"
    if not is_loopback:
        raise HTTPException(
            status_code=403,
            detail="Gmail development endpoints are available locally only.",
        )


def require_same_origin(request: Request) -> None:
    expected = f"{request.url.scheme}://{request.url.netloc}"
    supplied = request.headers.get("origin", "")
    if not supplied:
        supplied = request.headers.get("referer", "")
    if not supplied or urlparse(supplied).scheme + "://" + urlparse(
        supplied
    ).netloc != expected:
        raise HTTPException(
            status_code=403,
            detail="Cross-origin Gmail actions are not allowed.",
        )
