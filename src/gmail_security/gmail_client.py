"""Official Gmail API operations and safe email metadata extraction."""

import base64
from datetime import timezone
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

from googleapiclient.discovery import build


MAX_INLINE_BODY_BYTES = 20000
MAX_INLINE_BASE64_CHARS = 4 * ((MAX_INLINE_BODY_BYTES + 2) // 3)


def build_gmail_service(credentials: Any) -> Any:
    """Create the official Gmail API client without discovery caching."""

    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


class _HtmlText(HTMLParser):
    _BLOCK_TAGS = {
        "address", "article", "br", "div", "footer", "h1", "h2",
        "h3", "h4", "header", "li", "p", "section", "table", "tr",
    }
    _SUPPRESSED_TAGS = {"script", "style", "template", "svg", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._suppression_stack: list[str] = []

    def handle_starttag(
        self, tag: str, _attrs: list[tuple[str, str | None]]
    ) -> None:
        del _attrs
        if self._suppression_stack:
            self._suppression_stack.append(tag)
        elif tag in self._SUPPRESSED_TAGS:
            self._suppression_stack.append(tag)
        elif tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self._suppression_stack:
            for index in range(len(self._suppression_stack) - 1, -1, -1):
                if self._suppression_stack[index] == tag:
                    del self._suppression_stack[index:]
                    break
        elif tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._suppression_stack:
            self.parts.append(data)


def _decode_header(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeDecodeError, ValueError):
        return value


def _decode_body_data(
    value: str,
    charset: str | None,
) -> tuple[str, bool]:
    encoded = value.encode("ascii")
    truncated = len(encoded) > MAX_INLINE_BASE64_CHARS
    encoded = encoded[:MAX_INLINE_BASE64_CHARS]
    padded = encoded + b"=" * (-len(encoded) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    if len(decoded) > MAX_INLINE_BODY_BYTES:
        decoded = decoded[:MAX_INLINE_BODY_BYTES]
        truncated = True
    try:
        return (
            decoded.decode(charset or "utf-8", errors="replace"),
            truncated,
        )
    except LookupError:
        return decoded.decode("utf-8", errors="replace"), truncated


def _part_charset(part: dict[str, Any]) -> str | None:
    for header in part.get("headers", []):
        if header.get("name", "").lower() == "content-type":
            content_type = Message()
            content_type["Content-Type"] = header.get("value", "")
            return content_type.get_content_charset()
    return None


def _collect_parts(
    payload: dict[str, Any],
    plain_text: list[str],
    html_text: list[str],
    attachments: list[dict[str, Any]],
    truncation: list[bool],
) -> None:
    filename = payload.get("filename") or ""
    mime_type = payload.get("mimeType") or "application/octet-stream"
    body = payload.get("body") or {}

    if filename or body.get("attachmentId"):
        attachments.append(
            {
                "mime_type": mime_type,
                "size": body.get("size", 0),
            }
        )
        return

    parts = payload.get("parts") or []
    if parts:
        for part in parts:
            _collect_parts(
                part,
                plain_text,
                html_text,
                attachments,
                truncation,
            )
        return

    encoded = body.get("data")
    if not encoded:
        return

    try:
        content, truncated = _decode_body_data(
            encoded, _part_charset(payload)
        )
        truncation.append(truncated)
    except (ValueError, UnicodeEncodeError):
        return

    if mime_type.lower() == "text/plain":
        plain_text.append(content)
    elif mime_type.lower() == "text/html":
        parser = _HtmlText()
        parser.feed(content)
        parser.close()
        html_text.append("".join(parser.parts))


def _received_at(value: str) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def extract_message(message: dict[str, Any]) -> dict[str, Any]:
    """Extract plain text and headers; never retrieve attachment bodies."""

    payload = message.get("payload") or {}
    headers = {
        header.get("name", "").lower(): _decode_header(
            header.get("value", "")
        )
        for header in payload.get("headers", [])
        if header.get("name")
    }
    plain_text: list[str] = []
    html_text: list[str] = []
    attachments: list[dict[str, Any]] = []
    truncation: list[bool] = []
    _collect_parts(
        payload,
        plain_text,
        html_text,
        attachments,
        truncation,
    )

    body = "\n".join(plain_text if plain_text else html_text).strip()
    return {
        "message_id": message.get("id", ""),
        "sender": headers.get("from", ""),
        "subject": headers.get("subject", ""),
        "received_at": _received_at(headers.get("date", "")),
        "body": body,
        "attachments": attachments,
        "body_truncated": any(truncation),
    }


def is_gmail_not_found(error: Exception) -> bool:
    """Recognize Gmail history expiration without exposing API error data."""

    return getattr(getattr(error, "resp", None), "status", None) == 404
