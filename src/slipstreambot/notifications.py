"""Provider-independent notifications; retries belong to the caller's outbox."""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
import re
from typing import Protocol
from urllib.parse import urlsplit

import requests
from requests_oauthlib import OAuth1


class NotificationError(RuntimeError):
    """A delivery failure whose message is safe to log."""


def _http_url(value: object, *, endpoint: bool = False) -> str:
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError("Expected an absolute HTTP(S) URL without credentials")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
        )
    except ValueError:
        raise ValueError("Invalid HTTP(S) URL") from None
    if not valid or (endpoint and (parsed.query or parsed.fragment)):
        raise ValueError("Expected an HTTP(S) endpoint without credentials, query, or fragment")
    return value.rstrip("/") if endpoint else value


@dataclass(frozen=True)
class Notification:
    event_id: str
    title: str
    body: str
    url: str | None = None

    def __post_init__(self) -> None:
        for text in (self.event_id, self.title, self.body):
            if not isinstance(text, str):
                raise ValueError("Notification fields must be strings")
            try:
                text.encode("utf-8")
            except UnicodeError:
                raise ValueError("Notification text must be valid Unicode") from None
        if self.url is not None:
            _http_url(self.url)
            try:
                self.url.encode("utf-8")
            except UnicodeError:
                raise ValueError("Notification URL must be valid Unicode") from None


class Backend(Protocol):
    name: str

    def send(self, notification: Notification) -> None: ...


def _message(notification: Notification) -> str:
    # Keep title, body and optional link verbatim, including embedded newlines.
    text = notification.title + "\n\n" + notification.body
    if notification.url is not None:
        text += "\n\n" + notification.url
    return text


def _chunks(text: str, *, utf16: bool) -> list[str]:
    """Split only at code-point boundaries, preserving every input character."""
    chunks: list[str] = []
    start = 0
    size = 0
    for index, char in enumerate(text):
        weight = (2 if ord(char) > 0xFFFF else 1) if utf16 else len(char.encode("utf-8"))
        if size + weight > 4096:
            chunks.append(text[start:index])
            start = index
            size = 0
        size += weight
    if start < len(text):
        chunks.append(text[start:])
    return chunks or [""]


def _delivery_chunks(notification: Notification, *, utf16: bool) -> list[str]:
    if notification.url is None:
        return _chunks(_message(notification), utf16=utf16)
    encoding = "utf-16-le" if utf16 else "utf-8"
    divisor = 2 if utf16 else 1
    link_size = len(notification.url.encode(encoding)) // divisor
    if link_size > 4096:
        raise NotificationError("Notification link exceeds provider message limit")
    chunks = _chunks(notification.title + "\n\n" + notification.body + "\n\n", utf16=utf16)
    if len(chunks[-1].encode(encoding)) // divisor + link_size <= 4096:
        chunks[-1] += notification.url
    else:
        chunks.append(notification.url)
    return chunks


def _character_weight(char: str) -> int:
    code = ord(char)
    # Twitter-text's single-weight ranges. Counting each emoji component
    # independently is deliberately conservative rather than undercounting it.
    return 1 if (
        code <= 0x10FF
        or 0x2000 <= code <= 0x200D
        or 0x2010 <= code <= 0x201F
        or 0x2032 <= code <= 0x2037
    ) else 2


def _twitter_weight(text: str) -> int:
    weight = 0
    for token in re.findall(r"\s+|\S+", text):
        raw = sum(_character_weight(char) for char in token)
        # Also budget for implicitly linked domains and short embedded URLs.
        link_candidates = sum(token.count(dot) for dot in (".", "\u3002", "\uff0e", "\uff61"))
        link_candidates = max(link_candidates, token.count("://"))
        weight += max(23 * link_candidates, raw)
    return weight


def _abbreviate(text: str, budget: int) -> str:
    if _twitter_weight(text) <= budget:
        return text
    suffix = "…"
    # Prefix weights never decrease, including our conservative URL accounting.
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if _twitter_weight(text[:middle] + suffix) <= budget:
            low = middle
        else:
            high = middle - 1
    return text[:low] + suffix


def _tweet(notification: Notification) -> str:
    prefix = "Abbreviated notification:\n"
    link = "\n\n" + notification.url if notification.url is not None else ""
    # The dedicated link is never cut. X's t.co transformation weighs it at 23.
    budget = 280 - _twitter_weight(prefix) - 2 - (25 if link else 0)
    title_weight = _twitter_weight(notification.title)
    body_weight = _twitter_weight(notification.body)
    title_budget = min(title_weight, max(budget // 3, budget - body_weight))
    title = _abbreviate(notification.title, title_budget)
    body = _abbreviate(notification.body, budget - _twitter_weight(title))
    return prefix + title + "\n\n" + body + link


class ConsoleBackend:
    def __init__(self, name: str) -> None:
        self.name = name

    def send(self, notification: Notification) -> None:
        try:
            print(_message(notification), flush=True)
        except Exception:
            raise NotificationError("console output failed") from None


class _HTTPBackend:
    def __init__(self, name: str, timeout: float, kind: str) -> None:
        self.name = name
        self.timeout = timeout
        self.kind = kind

    def _post(self, url: str, **kwargs: object) -> dict:
        # Neither provider descriptions nor request exceptions are safe: both
        # can repeat credentials (especially Telegram's token-bearing URL).
        try:
            response = requests.post(
                url, timeout=self.timeout, allow_redirects=False, **kwargs
            )
        except Exception:
            raise NotificationError(f"{self.kind} transport failed; delivery may be uncertain") from None
        try:
            if not 200 <= response.status_code < 300:
                raise NotificationError(f"{self.kind} rejected delivery (HTTP {response.status_code})")
            try:
                payload = response.json()
            except Exception:
                raise NotificationError(f"{self.kind} returned an invalid response; delivery may be uncertain") from None
            if not isinstance(payload, dict):
                raise NotificationError(f"{self.kind} returned an invalid response; delivery may be uncertain")
            return payload
        finally:
            try:
                response.close()
            except Exception:
                raise NotificationError(f"{self.kind} transport failed; delivery may be uncertain") from None


class TelegramBackend(_HTTPBackend):
    def __init__(self, name: str, timeout: float, token: str, chat_id: str, base_url: str) -> None:
        super().__init__(name, timeout, "telegram")
        self._url = f"{base_url}/bot{token}/sendMessage"
        self._chat_id = chat_id

    def send(self, notification: Notification) -> None:
        for chunk in _delivery_chunks(notification, utf16=True):
            payload = self._post(self._url, json={"chat_id": self._chat_id, "text": chunk})
            result = payload.get("result")
            if (
                payload.get("ok") is not True
                or not isinstance(result, dict)
                or type(result.get("message_id")) is not int
            ):
                raise NotificationError("telegram did not confirm delivery")

class NtfyBackend(_HTTPBackend):
    def __init__(self, name: str, timeout: float, token: str | None, server: str, topic: str) -> None:
        super().__init__(name, timeout, "ntfy")
        self._server = server
        self._topic = topic
        self._headers = {"Authorization": "Bearer " + token} if token is not None else {}

    def send(self, notification: Notification) -> None:
        # JSON publishing preserves Unicode titles without non-ASCII HTTP headers.
        # All notification fields live in the message, with no silent truncation.
        for chunk in _delivery_chunks(notification, utf16=False):
            payload = self._post(
                self._server,
                headers=self._headers,
                json={"topic": self._topic, "message": chunk},
            )
            if (
                payload.get("event") != "message"
                or not isinstance(payload.get("id"), str)
                or not payload["id"]
                or payload.get("topic") != self._topic
                or payload.get("error")
            ):
                raise NotificationError("ntfy did not confirm delivery")


class TwitterBackend(_HTTPBackend):
    def __init__(
        self, name: str, timeout: float, consumer_key: str, consumer_secret: str,
        access_token: str, access_token_secret: str, base_url: str,
    ) -> None:
        super().__init__(name, timeout, "twitter")
        self._url = base_url + "/2/tweets"
        self._auth = OAuth1(consumer_key, consumer_secret, access_token, access_token_secret)

    def send(self, notification: Notification) -> None:
        payload = self._post(self._url, auth=self._auth, json={"text": _tweet(notification)})
        data = payload.get("data")
        if (
            payload.get("errors")
            or not isinstance(data, dict)
            or not isinstance(data.get("id"), str)
            or not data["id"]
            or not isinstance(data.get("text"), str)
        ):
            raise NotificationError("twitter did not confirm delivery")


_COMMON = {"kind", "name", "enabled", "timeout"}
_FIELDS = {
    "console": set(),
    "telegram": {"token_env", "chat_id", "base_url"},
    "ntfy": {"token_env", "server", "topic"},
    "twitter": {
        "consumer_key_env", "consumer_secret_env", "access_token_env",
        "access_token_secret_env", "base_url",
    },
}


def _secret(config: dict, key: str) -> str:
    env_name = config.get(key)
    if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
        raise ValueError(f"{key} must name an environment variable")
    value = os.environ.get(env_name)
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{key} requires a nonempty credential in the environment")
    return value


def build_backends(configs: list[dict]) -> list[Backend]:
    if not isinstance(configs, list):
        raise ValueError("notifiers must be a list of tables")
    names: set[str] = set()
    backends: list[Backend] = []
    for config in configs:
        if not isinstance(config, dict):
            raise ValueError("Each notifier must be a table")
        kind = config.get("kind")
        if not isinstance(kind, str) or kind not in _FIELDS:
            raise ValueError("Unknown notifier kind")
        if set(config) - (_COMMON | _FIELDS[kind]):
            raise ValueError("Unknown notifier configuration key")
        name = config.get("name", kind)
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("Notifier name must be 1-64 ASCII letters, digits, dots, underscores or hyphens")
        if name in names:
            raise ValueError("Duplicate notifier name")
        names.add(name)
        enabled = config.get("enabled", True)
        if type(enabled) is not bool:
            raise ValueError("Notifier enabled must be a boolean")
        timeout = config.get("timeout", 15)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Notifier timeout must be a finite positive number")
        if not enabled:
            continue
        if kind == "console":
            backends.append(ConsoleBackend(name))
        elif kind == "telegram":
            chat_id = config.get("chat_id")
            if isinstance(chat_id, bool) or not isinstance(chat_id, (str, int)) or not str(chat_id).strip():
                raise ValueError("Telegram chat_id must be a nonempty string or integer")
            token = _secret(config, "token_env")
            if not re.fullmatch(r"[A-Za-z0-9_:-]+", token):
                raise ValueError("Telegram credential has invalid characters")
            base_url = _http_url(config.get("base_url", "https://api.telegram.org"), endpoint=True)
            backends.append(TelegramBackend(name, timeout, token, str(chat_id), base_url))
        elif kind == "ntfy":
            topic = config.get("topic")
            if not isinstance(topic, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", topic):
                raise ValueError("ntfy topic must be 1-64 ASCII letters, digits, underscores or hyphens")
            server = _http_url(config.get("server", "https://ntfy.sh"), endpoint=True)
            token = _secret(config, "token_env") if "token_env" in config else None
            backends.append(NtfyBackend(name, timeout, token, server, topic))
        else:
            base_url = _http_url(config.get("base_url", "https://api.x.com"), endpoint=True)
            backends.append(TwitterBackend(
                name, timeout, _secret(config, "consumer_key_env"),
                _secret(config, "consumer_secret_env"), _secret(config, "access_token_env"),
                _secret(config, "access_token_secret_env"), base_url,
            ))
    return backends


def notify_many(notification: Notification, backends: list[Backend]) -> dict[str, str]:
    """Attempt every sink once, returning safe error text indexed by sink name."""
    errors: dict[str, str] = {}
    for backend in backends:
        try:
            backend.send(notification)
        except Exception:
            # Even third-party Backend implementations can leak secrets in their
            # exceptions. Never copy those messages into logs or durable outboxes.
            errors[backend.name] = "Delivery failed; delivery may be uncertain"
    return errors
