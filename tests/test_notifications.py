import io
import json
import os
import traceback
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

from slipstreambot.notifications import (
    Notification,
    NotificationError,
    build_backends,
    notify_many,
)


ENV = {
    "TEST_TELEGRAM": "123:telegram-secret",
    "TEST_NTFY": "ntfy-secret",
    "TEST_CONSUMER_KEY": "consumer-key",
    "TEST_CONSUMER_SECRET": "consumer-secret",
    "TEST_ACCESS_TOKEN": "access-token",
    "TEST_ACCESS_SECRET": "access-secret",
}
TELEGRAM = {"kind": "telegram", "token_env": "TEST_TELEGRAM", "chat_id": "-100123"}
NTFY = {"kind": "ntfy", "topic": "test-topic", "token_env": "TEST_NTFY"}
TWITTER = {
    "kind": "twitter",
    "consumer_key_env": "TEST_CONSUMER_KEY",
    "consumer_secret_env": "TEST_CONSUMER_SECRET",
    "access_token_env": "TEST_ACCESS_TOKEN",
    "access_token_secret_env": "TEST_ACCESS_SECRET",
}
SUCCESS = {
    "telegram": {"ok": True, "result": {"message_id": 123}},
    "ntfy": {"id": "abc123", "event": "message", "topic": "test-topic"},
    "twitter": {"data": {"id": "123", "text": "accepted"}},
}


def response(payload, status=200):
    result = Mock()
    result.status_code = status
    result.json.return_value = payload
    return result


def independent_weight(text):
    total = 0
    for character in text:
        code = ord(character)
        total += 1 if (
            code <= 0x10FF or 0x2000 <= code <= 0x200D
            or 0x2010 <= code <= 0x201F or 0x2032 <= code <= 0x2037
        ) else 2
    return total


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, ENV, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.notification = Notification("event-1", "A title", "A body", "https://example.com/details")

    def test_provider_errors_even_with_success_http_status(self):
        cases = [
            (TELEGRAM, {"ok": False, "description": ENV["TEST_TELEGRAM"]}),
            (TELEGRAM, {"ok": True, "result": {}}),
            (NTFY, {"error": ENV["TEST_NTFY"], "code": 40001}),
            (NTFY, {"id": "id", "event": "keepalive", "topic": "test-topic"}),
            (TWITTER, {"errors": [{"detail": ENV["TEST_ACCESS_TOKEN"]}]}),
            (TWITTER, {"data": {"id": "123"}}),
        ]
        for config, payload in cases:
            with self.subTest(kind=config["kind"], payload=payload):
                backend = build_backends([config])[0]
                with patch("slipstreambot.notifications.requests.post", return_value=response(payload)):
                    with self.assertRaises(NotificationError) as caught:
                        backend.send(self.notification)
                for secret in ENV.values():
                    self.assertNotIn(secret, str(caught.exception))

    def test_http_and_non_json_failures_are_sanitized(self):
        backend = build_backends([TELEGRAM])[0]
        invalid_json = response(None)
        invalid_json.json.side_effect = ValueError("https://secret.example/" + ENV["TEST_TELEGRAM"])
        for result in (response({"description": ENV["TEST_TELEGRAM"]}, 429), invalid_json, response([])):
            with self.subTest(result=result):
                with patch("slipstreambot.notifications.requests.post", return_value=result):
                    with self.assertRaises(NotificationError) as caught:
                        backend.send(self.notification)
                self.assertNotIn(ENV["TEST_TELEGRAM"], str(caught.exception))
                result.close.assert_called_once()

    def test_raw_transport_exception_never_reaches_traceback(self):
        backend = build_backends([TELEGRAM])[0]
        secret_url = "https://api.telegram.org/bot" + ENV["TEST_TELEGRAM"] + "/sendMessage"
        with patch("slipstreambot.notifications.requests.post", side_effect=requests.RequestException(secret_url)):
            try:
                backend.send(self.notification)
            except NotificationError:
                rendered = traceback.format_exc()
            else:
                self.fail("Transport failure was swallowed")
        self.assertNotIn(ENV["TEST_TELEGRAM"], rendered)
        self.assertNotIn(secret_url, rendered)
        self.assertIn("uncertain", rendered)

    def test_fanout_continues_after_partial_multi_chunk_failure(self):
        notification = Notification("event", "Title", "a" * 9000)
        backends = build_backends([TELEGRAM, {"kind": "console"}])
        output = io.StringIO()
        with patch("slipstreambot.notifications.requests.post", side_effect=[
            response(SUCCESS["telegram"]), requests.Timeout(ENV["TEST_TELEGRAM"]),
        ]) as post, redirect_stdout(output):
            errors = notify_many(notification, backends)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(set(errors), {"telegram"})
        self.assertNotIn(ENV["TEST_TELEGRAM"], errors["telegram"])
        self.assertEqual(output.getvalue(), "Title\n\n" + notification.body + "\n")

    def test_custom_backend_exception_is_sanitized_and_other_sinks_run(self):
        broken = Mock(name="broken backend")
        broken.name = "broken"
        broken.send.side_effect = RuntimeError("password=private")
        healthy = Mock()
        healthy.name = "healthy"
        errors = notify_many(self.notification, [broken, healthy])
        healthy.send.assert_called_once_with(self.notification)
        self.assertEqual(set(errors), {"broken"})
        self.assertNotIn("private", errors["broken"])

    def test_unicode_chunk_limits_and_verbatim_reconstruction(self):
        for config, body, encoding, divisor, field in (
            (TELEGRAM, "\U0001f680" * 5000, "utf-16-le", 2, "text"),
            (NTFY, "\u6f22" * 5000, "utf-8", 1, "message"),
        ):
            with self.subTest(kind=config["kind"]):
                notification = Notification("event", "Unicode title", body, self.notification.url)
                backend = build_backends([config])[0]
                with patch("slipstreambot.notifications.requests.post", return_value=response(SUCCESS[config["kind"]])) as post:
                    backend.send(notification)
                chunks = [call.kwargs["json"][field] for call in post.call_args_list]
                self.assertGreater(len(chunks), 1)
                self.assertTrue(all(len(chunk.encode(encoding)) // divisor <= 4096 for chunk in chunks))
                self.assertEqual("".join(chunks), notification.title + "\n\n" + body + "\n\n" + notification.url)
                self.assertTrue(any(notification.url in chunk for chunk in chunks))
                for call in post.call_args_list:
                    self.assertEqual(call.kwargs["timeout"], 15)
                    self.assertFalse(call.kwargs["allow_redirects"])

    def test_link_is_not_split_at_chunk_boundary(self):
        url = "https://example.com/" + "x" * 200
        notification = Notification("event", "T", "b" * 4075, url)
        for config, field in ((TELEGRAM, "text"), (NTFY, "message")):
            with self.subTest(kind=config["kind"]):
                with patch("slipstreambot.notifications.requests.post", return_value=response(SUCCESS[config["kind"]])) as post:
                    build_backends([config])[0].send(notification)
                chunks = [call.kwargs["json"][field] for call in post.call_args_list]
                self.assertEqual(chunks[-1], url)
                self.assertEqual("".join(chunks), "T\n\n" + notification.body + "\n\n" + url)

    def test_oversized_link_fails_before_any_chunks_are_sent(self):
        notification = Notification("event", "Title", "Body", "https://example.com/" + "x" * 4096)
        for config in (TELEGRAM, NTFY):
            with self.subTest(kind=config["kind"]):
                with patch("slipstreambot.notifications.requests.post") as post:
                    with self.assertRaises(NotificationError):
                        build_backends([config])[0].send(notification)
                    post.assert_not_called()

    def test_twitter_abbreviates_both_fields_and_preserves_full_link(self):
        url = "https://example.com/" + "long-path" * 100
        notification = Notification("event", "TITLE " + "\u6f22" * 300, "BODY " + "\U0001f680" * 300, url)
        with patch("slipstreambot.notifications.requests.post", return_value=response(SUCCESS["twitter"])) as post:
            build_backends([TWITTER])[0].send(notification)
        post.assert_called_once()
        text = post.call_args.kwargs["json"]["text"]
        self.assertTrue(text.startswith("Abbreviated notification:\nTITLE "))
        self.assertIn("\n\nBODY ", text)
        self.assertTrue(text.endswith("\n\n" + url))
        self.assertIn("\u2026", text)
        self.assertLessEqual(independent_weight(text[:-len(url)]) + 23, 280)

    def test_short_tweet_preserves_title_body_and_link(self):
        with patch("slipstreambot.notifications.requests.post", return_value=response(SUCCESS["twitter"])) as post:
            build_backends([TWITTER])[0].send(self.notification)
        self.assertEqual(post.call_args.kwargs["json"]["text"],
                         "Abbreviated notification:\nA title\n\nA body\n\nhttps://example.com/details")

    def test_twitter_oauth_user_context_and_custom_endpoint_at_transport(self):
        captured = []

        def transport(session, request, **kwargs):
            captured.append((request, kwargs))
            result = requests.Response()
            result.status_code = 201
            result._content = json.dumps(SUCCESS["twitter"]).encode()
            result.request = request
            return result

        config = {**TWITTER, "base_url": "http://127.0.0.1:9876/provider/", "timeout": 3}
        # Exercise real request preparation and OAuth signing, stopping before I/O.
        with patch("requests.sessions.Session.send", autospec=True, side_effect=transport):
            build_backends([config])[0].send(self.notification)
        self.assertEqual(len(captured), 1)
        request, options = captured[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url, "http://127.0.0.1:9876/provider/2/tweets")
        authorization = request.headers["Authorization"]
        if isinstance(authorization, bytes):
            authorization = authorization.decode()
        self.assertTrue(authorization.startswith("OAuth "))
        self.assertIn('oauth_consumer_key="consumer-key"', authorization)
        self.assertIn('oauth_token="access-token"', authorization)
        self.assertIn("oauth_signature=", authorization)
        self.assertNotIn("consumer-secret", authorization)
        self.assertNotIn("access-secret", authorization)
        self.assertIn("A body", json.loads(request.body)["text"])
        self.assertEqual(options["timeout"], 3)
        self.assertFalse(options["allow_redirects"])

    def test_telegram_custom_endpoint_and_ntfy_optional_bearer(self):
        with patch("slipstreambot.notifications.requests.post", return_value=response(SUCCESS["telegram"])) as post:
            build_backends([{**TELEGRAM, "base_url": "http://127.0.0.1:9876"}])[0].send(self.notification)
        self.assertEqual(post.call_args.args[0], "http://127.0.0.1:9876/bot123:telegram-secret/sendMessage")
        self.assertEqual(post.call_args.kwargs["json"]["chat_id"], "-100123")
        for authenticated in (False, True):
            config = {"kind": "ntfy", "topic": "test-topic", "server": "http://127.0.0.1:9876"}
            if authenticated:
                config["token_env"] = "TEST_NTFY"
            with patch("slipstreambot.notifications.requests.post", return_value=response(SUCCESS["ntfy"])) as post:
                build_backends([config])[0].send(self.notification)
            headers = post.call_args.kwargs["headers"]
            self.assertEqual(headers, {"Authorization": "Bearer ntfy-secret"} if authenticated else {})
            self.assertEqual(post.call_args.args[0], "http://127.0.0.1:9876")
            self.assertEqual(post.call_args.kwargs["json"]["topic"], "test-topic")

    def test_configuration_rejects_ambiguous_or_missing_credentials(self):
        cases = [
            [{"kind": "unknown"}],
            [{"kind": "console"}, {"kind": "console"}],
            [{"kind": "console", "unexpected": True}],
            [{"kind": "console", "enabled": "false"}],
            [{"kind": "console", "timeout": float("nan")}],
            [{"kind": "console", "timeout": True}],
            [{"kind": "console", "name": "unsafe/name"}],
            [{"kind": "telegram", "chat_id": "1"}],
            [{**TELEGRAM, "token_env": "MISSING_TOKEN"}],
            [{**NTFY, "token_env": "MISSING_TOKEN"}],
            [{**NTFY, "topic": "../topic"}],
            [{**TELEGRAM, "base_url": "https://user:secret@example.com"}],
            [{**TWITTER, "base_url": "https://example.com?token=private"}],
            [{**TWITTER, "access_token_secret_env": "MISSING_TOKEN"}],
        ]
        for config in cases:
            with self.subTest(config=config), self.assertRaises(ValueError):
                build_backends(config)
        self.assertEqual(build_backends([{"kind": "telegram", "enabled": False}]), [])
        self.assertEqual(build_backends([]), [])


if __name__ == "__main__":
    unittest.main()
