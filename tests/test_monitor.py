"""Deterministic chain/outbox tests: no node or external message services."""

from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from slipstreambot.monitor import Monitor
from slipstreambot.notifications import Notification
from slipstreambot.rpc import BitcoinRPC, RPCError


class FakeNode:
    def __init__(self, hashes):
        self.blocks = {}
        self.calls = []
        self.failure = None
        self.closed = False
        self.set_chain(hashes)

    def set_chain(self, hashes):
        self.chain = list(hashes)
        for height, block_hash in enumerate(hashes):
            self.blocks[block_hash] = {
                "hash": block_hash, "height": height,
                "previousblockhash": hashes[height - 1] if height else "",
                "findings": ["test finding"],
            }

    def call(self, method, *params):
        self.calls.append((method, params))
        if self.failure and self.failure(method, params):
            raise RPCError("RPC connection failed")
        if method == "getblockcount":
            return len(self.chain) - 1
        if method == "getblockhash":
            if params[0] < 0 or params[0] >= len(self.chain):
                raise RPCError("Height unavailable", code=-8)
            return self.chain[params[0]]
        if method == "getblock":
            if params[1] != 3:
                raise AssertionError("Monitor must request verbosity 3")
            return dict(self.blocks[params[0]])
        raise AssertionError(f"Unexpected RPC method {method}")

    def close(self):
        self.closed = True


class Sink:
    def __init__(self, name="sink", failing=False):
        self.name = name
        self.failing = failing
        self.messages = []
        self.attempts = 0

    def send(self, notification):
        self.attempts += 1
        if self.failing:
            raise RuntimeError("secret token must never appear in a log")
        self.messages.append(notification)


def notice(report):
    return Notification("block:" + report["hash"], "Block " + report["hash"], "Test finding")


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "state.sqlite3")
        self.node = FakeNode(["g", "a1", "a2"])
        self.sink = Sink()

    def monitor(self, *, node=None, sinks=None, start=0, **kwargs):
        monitor = Monitor(
            node or self.node, zmq_endpoint="tcp://127.0.0.1:28332",
            state_path=self.path, analyze=dict, notification=notice,
            backends=sinks if sinks is not None else [self.sink],
            start_height=start, **kwargs,
        )
        self.addCleanup(monitor.close)
        return monitor

    def ids(self, sink=None):
        return [message.event_id for message in (sink or self.sink).messages]

    def test_missed_and_duplicate_hints_are_reconciled_from_rpc(self):
        monitor = self.monitor()
        self.assertEqual(monitor.sync_once(), 3)
        self.assertEqual(monitor.sync_once(), 0)
        self.node.set_chain(["g", "a1", "a2", "a3", "a4", "a5"])
        self.assertEqual(monitor.sync_once(), 3)
        self.assertEqual(monitor.sync_once(), 0)
        self.assertEqual(self.ids(), ["block:g", "block:a1", "block:a2", "block:a3", "block:a4", "block:a5"])

    def test_default_starts_at_tip_and_explicit_start_is_inclusive(self):
        monitor = self.monitor(start=None)
        self.assertEqual(monitor.sync_once(), 1)
        self.assertEqual(self.ids(), ["block:a2"])

    def test_explicit_start_is_inclusive(self):
        monitor = self.monitor(start=1)
        self.assertEqual(monitor.sync_once(), 2)
        self.assertEqual(self.ids(), ["block:a1", "block:a2"])

    def test_restart_resumes_cursor_ignoring_new_start(self):
        monitor = self.monitor(start=1)
        monitor.sync_once()
        monitor.close()
        self.node.set_chain(["g", "a1", "a2", "a3"])
        resumed = self.monitor(start=0)
        self.assertEqual(resumed.sync_once(), 1)
        self.assertEqual(self.ids(), ["block:a1", "block:a2", "block:a3"])

    def test_other_genesis_is_rejected(self):
        monitor = self.monitor()
        monitor.sync_once()
        monitor.close()
        with self.assertRaisesRegex(RuntimeError, "genesis/network"):
            self.monitor(node=FakeNode(["other-genesis", "x1"]))

    def test_second_process_state_lock_is_rejected(self):
        self.monitor()
        with self.assertRaisesRegex(RuntimeError, "already locked"):
            self.monitor(node=FakeNode(["g"]))

    def test_reorg_retracts_before_replacement_reports(self):
        monitor = self.monitor(start=1)
        monitor.sync_once()
        self.node.set_chain(["g", "a1", "b2", "b3"])
        self.assertEqual(monitor.sync_once(), 2)
        ids = self.ids()
        self.assertEqual(ids[:2], ["block:a1", "block:a2"])
        self.assertTrue(ids[2].startswith("retraction:block:a2:"))
        self.assertEqual(ids[3:], ["block:b2", "block:b3"])
        self.assertEqual(monitor.sync_once(), 0)
        self.assertEqual(len(self.ids()), 5)

    def test_deep_reorg_replays_from_original_monitoring_boundary(self):
        monitor = self.monitor(start=None)
        monitor.sync_once()
        self.node.set_chain(["g", "b1", "b2"])
        self.assertEqual(monitor.sync_once(), 1)
        self.assertTrue(self.ids()[1].startswith("retraction:block:a2:"))
        self.assertEqual(self.ids()[2], "block:b2")
        self.assertNotIn("block:b1", self.ids())

    def test_chain_shrink_then_replacement(self):
        monitor = self.monitor(start=1)
        monitor.sync_once()
        self.node.set_chain(["g"])
        self.assertEqual(monitor.sync_once(), 0)
        self.assertEqual(sum(event.startswith("retraction:") for event in self.ids()), 2)
        self.node.set_chain(["g", "b1", "b2"])
        self.assertEqual(monitor.sync_once(), 2)
        self.assertEqual(self.ids()[-2:], ["block:b1", "block:b2"])

    def test_failed_sink_does_not_starve_good_sink_or_checkpoint(self):
        broken = Sink("broken", failing=True)
        monitor = self.monitor(sinks=[broken, self.sink])
        with self.assertLogs("slipstreambot.monitor", level="WARNING") as captured:
            self.assertEqual(monitor.sync_once(), 3)
        self.assertNotIn("secret token", "\n".join(captured.output))
        self.assertEqual(self.ids(), ["block:g", "block:a1", "block:a2"])
        self.assertEqual(broken.attempts, 1)
        self.node.set_chain(["g", "a1", "a2", "a3"])
        self.assertEqual(monitor.sync_once(), 1)
        self.assertEqual(broken.attempts, 1)  # No busy retries during catch-up.
        self.assertEqual(self.ids()[-1], "block:a3")
        monitor.close()
        broken.failing = False
        resumed = self.monitor(sinks=[broken, self.sink])
        self.assertEqual(resumed.sync_once(), 0)
        self.assertEqual(self.ids(broken), ["block:g", "block:a1", "block:a2", "block:a3"])
        self.assertEqual(len(self.ids()), 4)

    def test_unsent_orphans_are_canceled_not_retracted(self):
        broken = Sink("broken", failing=True)
        monitor = self.monitor(sinks=[broken, self.sink], start=1)
        monitor.sync_once()
        self.node.set_chain(["g", "b1", "b2"])
        monitor.sync_once()
        monitor.close()
        broken.failing = False
        resumed = self.monitor(sinks=[broken, self.sink])
        resumed.sync_once()
        self.assertEqual(self.ids(broken), ["block:b1", "block:b2"])
        good = self.ids()
        self.assertTrue(good[2].startswith("retraction:block:a1:"))
        self.assertTrue(good[3].startswith("retraction:block:a2:"))
        self.assertEqual(good[4:], ["block:b1", "block:b2"])

    def test_reactivated_branch_has_one_retraction_per_delivery_cycle(self):
        monitor = self.monitor(start=2)
        monitor.sync_once()
        for branch in ("b2", "a2", "b2"):
            self.node.set_chain(["g", "a1", branch])
            monitor.sync_once()
        ids = self.ids()
        self.assertEqual(len(ids), 7)
        retractions = [event for event in ids if event.startswith("retraction:")]
        self.assertEqual(len(retractions), 3)
        self.assertEqual(len(set(retractions)), 3)

    def test_rpc_failure_does_not_mark_reports_orphaned(self):
        monitor = self.monitor()
        monitor.sync_once()
        self.node.failure = lambda method, params: method == "getblockhash"
        with self.assertRaises(RPCError):
            monitor.sync_once()
        self.node.failure = None
        self.assertEqual(monitor.sync_once(), 0)
        self.assertEqual(self.ids(), ["block:g", "block:a1", "block:a2"])

    def test_unavailable_block_is_not_skipped(self):
        monitor = self.monitor(start=1)
        self.node.failure = lambda method, params: method == "getblock"
        with self.assertRaises(RPCError):
            monitor.sync_once()
        self.assertEqual(self.ids(), [])
        self.node.failure = None
        self.assertEqual(monitor.sync_once(), 2)

    def test_enqueue_and_checkpoint_commit_atomically(self):
        monitor = self.monitor(start=1)
        with patch.object(monitor, "_enqueue", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(sqlite3.OperationalError):
                monitor.sync_once()
        monitor.close()
        resumed = self.monitor(start=0)
        self.assertEqual(resumed.sync_once(), 2)
        self.assertEqual(self.ids(), ["block:a1", "block:a2"])

    def test_failed_retraction_blocks_only_its_own_replacement_reports(self):
        monitor = self.monitor(start=2)
        monitor.sync_once()
        self.sink.failing = True
        self.node.set_chain(["g", "a1", "b2"])
        monitor.sync_once()
        self.assertEqual(self.ids(), ["block:a2"])
        monitor.close()
        self.sink.failing = False
        resumed = self.monitor()
        self.assertEqual(resumed.sync_once(), 0)
        self.assertTrue(self.ids()[1].startswith("retraction:block:a2:"))
        self.assertEqual(self.ids()[2], "block:b2")

    def test_reorg_during_fetch_does_not_enqueue_stale_block(self):
        monitor = self.monitor(start=2)
        original_call = self.node.call

        def switching_call(method, *params):
            result = original_call(method, *params)
            if method == "getblock" and params[0] == "a2":
                self.node.set_chain(["g", "a1", "b2"])
            return result

        with patch.object(self.node, "call", side_effect=switching_call):
            self.assertEqual(monitor.sync_once(), 0)
        self.assertEqual(self.ids(), [])
        self.assertTrue(monitor._more_work)
        self.assertEqual(monitor.sync_once(), 1)
        self.assertEqual(self.ids(), ["block:b2"])

    def test_run_drains_catchup_batches_without_poll_delay(self):
        monitor = self.monitor()
        calls = []

        def sync():
            calls.append(True)
            monitor._more_work = True
            if len(calls) == 3:
                monitor._stop.set()
            return 1

        with patch.object(monitor, "sync_once", side_effect=sync), \
                patch("slipstreambot.monitor.zmq.Context") as context:
            monitor.run()
            context.return_value.socket.return_value.poll.assert_not_called()
            context.return_value.socket.return_value.close.assert_called_once()
            context.return_value.term.assert_called_once()
        self.assertEqual(len(calls), 3)
        self.assertTrue(self.node.closed)

    def test_batches_signal_immediate_catchup(self):
        monitor = self.monitor()
        monitor.BATCH_SIZE = 2
        self.assertEqual(monitor.sync_once(), 2)
        self.assertTrue(monitor._more_work)
        self.assertEqual(monitor.sync_once(), 1)
        self.assertFalse(monitor._more_work)


class RPCTests(unittest.TestCase):
    def response(self, result=None, *, error=None, status=200, response_id=1):
        response = Mock()
        response.status_code = status
        response.json.return_value = {"id": response_id, "result": result, "error": error}
        return response

    def test_cookie_is_reread_on_every_request(self):
        with tempfile.TemporaryDirectory() as directory:
            cookie = Path(directory) / "cookie"
            cookie.write_text("user:first", encoding="utf-8")
            with patch("slipstreambot.rpc.requests.Session") as session:
                session.return_value.post.side_effect = [
                    self.response(1), self.response(2, response_id=2),
                ]
                rpc = BitcoinRPC("http://localhost:8332", cookie_file=str(cookie))
                self.addCleanup(rpc.close)
                self.assertEqual(rpc.call("getblockcount"), 1)
                cookie.write_text("user:second", encoding="utf-8")
                self.assertEqual(rpc.call("getblockcount"), 2)
                calls = session.return_value.post.call_args_list
                self.assertEqual(calls[0].kwargs["auth"], ("user", "first"))
                self.assertEqual(calls[1].kwargs["auth"], ("user", "second"))

    def test_error_text_is_sanitized_and_numeric_code_preserved(self):
        with patch("slipstreambot.rpc.requests.Session") as session:
            session.return_value.post.return_value = self.response(
                error={"code": -5, "message": "password=supersecret"}, status=500,
            )
            rpc = BitcoinRPC("http://localhost:8332", username="user", password="supersecret")
            self.addCleanup(rpc.close)
            with self.assertRaises(RPCError) as caught:
                rpc.call("getblock", "missing", 3)
            self.assertEqual(caught.exception.code, -5)
            self.assertNotIn("supersecret", str(caught.exception))

    def test_mismatched_response_id_is_rejected(self):
        with patch("slipstreambot.rpc.requests.Session") as session:
            session.return_value.post.return_value = self.response(1, response_id=9)
            rpc = BitcoinRPC("http://localhost:8332", username="user", password="password")
            self.addCleanup(rpc.close)
            with self.assertRaisesRegex(RPCError, "response ID"):
                rpc.call("getblockcount")

    def test_mutating_rpc_method_never_reaches_transport(self):
        with patch("slipstreambot.rpc.requests.Session") as session:
            rpc = BitcoinRPC("http://localhost:8332", username="user", password="password")
            self.addCleanup(rpc.close)
            with self.assertRaisesRegex(RPCError, "read-only"):
                rpc.call("sendrawtransaction", "00")
            session.return_value.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
