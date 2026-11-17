import unittest
from unittest.mock import Mock, patch

from slipstreambot.mempool import MempoolObserver
from slipstreambot.rpc import RPCError


def txid(number):
    return f"{number:064x}"


READY = [{"initialblockdownload": False}, {"loaded": True}, {"localrelay": True}]


class MempoolTests(unittest.TestCase):
    def setUp(self):
        self.rpc = Mock()
        self.observer = MempoolObserver(self.rpc)
        self.frame = 0

    def event(self, kind, identifier, seq=None):
        body = bytes.fromhex(txid(identifier)) + kind.encode()
        if seq is not None:
            body += seq.to_bytes(8, "little")
        result = self.observer.process([b"sequence", body, self.frame.to_bytes(4, "little")])
        self.frame = (self.frame + 1) % 2**32
        return result

    def seed(self, height=1, ids=(10,), seq=5):
        self.rpc.call.side_effect = [
            txid(height), *READY, {"mempool_sequence": seq, "txids": list(map(txid, ids))}, txid(height)
        ]
        self.assertTrue(self.event("C", height))
        self.assertTrue(self.observer.has_boundary(txid(height)))
        self.assertIsNone(self.observer.observed_before(txid(height), txid(height - 1)))

    def connect(self, height, parent=None):
        parent = height - 1 if parent is None else parent
        self.rpc.call.side_effect = [{"hash": txid(height), "previousblockhash": txid(parent)}]
        self.assertTrue(self.event("C", height))
        return self.observer.observed_before(txid(height), txid(parent))

    @patch("slipstreambot.mempool.time.time", return_value=5000)
    def test_epoch_preserves_evictions_and_freezes_evidence_at_connection(self, _):
        self.assertFalse(self.event("A", 99, 2))
        self.rpc.call.assert_not_called()
        self.seed()
        self.event("A", 98, 4)  # Admission before snapshot; already gone by the baseline.
        self.event("A", 11, 5)  # Snapshot mempool_sequence is the next event.
        self.event("R", 11, 6)
        first_cut = self.connect(2)
        self.assertEqual(first_cut, (5000, {txid(10), txid(11)}))
        # Mining removals increment the mempool sequence without publishing R.
        self.event("A", 12, 13)
        self.assertEqual(self.connect(3), (5000, {txid(10), txid(11), txid(12)}))
        self.assertEqual(self.observer.observed_before(txid(2), txid(1)), first_cut)
        self.assertIsNone(self.observer.observed_before(txid(2), txid(0)))
        self.assertIsNone(self.observer.observed_before(txid(40), txid(39)))

    def test_transport_gap_on_connect_cannot_classify_that_block(self):
        self.frame = 2**32 - 1
        self.seed()
        self.event("A", 12, 5)  # Wrapping the frame counter is continuous.
        self.assertIn(txid(12), self.connect(2)[1])
        self.frame += 1
        self.seed(3, ids=(13,), seq=37)
        self.assertIsNone(self.observer.observed_before(txid(2), txid(1)))
        self.assertEqual(self.connect(4)[1], {txid(13)})

    def test_disconnect_and_malformed_frame_end_epoch(self):
        self.seed()
        self.assertTrue(self.event("D", 1))
        self.seed(2, ids=(13,))
        self.assertEqual(self.connect(3)[1], {txid(13)})
        self.assertFalse(self.observer.process([b"sequence", b"x" * 32 + b"A", b"\0" * 4]))
        self.seed(4)
        self.event("A", 19, 7)
        self.event("A", 18, 6)  # A backwards event index invalidates the epoch.
        self.seed(5, ids=(10,))
        self.assertEqual(self.connect(6)[1], {txid(10)})

    def test_tips_must_bracket_same_block_and_match_next_parent(self):
        self.rpc.call.side_effect = [
            txid(1), *READY, {"mempool_sequence": 10, "txids": [txid(10)]}, txid(2)
        ]
        self.event("C", 1)
        self.seed(2)
        self.rpc.call.side_effect = [
            {"hash": txid(4), "previousblockhash": txid(3)},
            txid(4), *READY, {"mempool_sequence": 70, "txids": [txid(15)]}, txid(4)
        ]
        self.event("C", 4)
        self.assertIsNone(self.observer.observed_before(txid(4), txid(3)))
        self.frame += 1  # A gap immediately after re-anchoring must also be detected.
        self.seed(5, ids=(99,))
        self.assertEqual(self.connect(6)[1], {txid(99)})

    def test_limits_and_failure_require_fresh_coverage(self):
        self.observer.MAX_SEEN = 2
        self.observer.MAX_CUTS = 1
        self.seed()
        self.connect(2)
        self.assertFalse(self.observer.has_boundary(txid(1)))
        self.event("A", 11, 5)
        self.event("A", 12, 6)
        self.rpc.call.side_effect = [RPCError("offline")]
        self.assertTrue(self.event("C", 3))
        self.seed(4, ids=(13,))
        self.assertEqual(self.connect(5)[1], {txid(13)})

    def test_bootstrap_requires_synced_node_loaded_mempool_and_transaction_relay(self):
        for checks in (
            [{"initialblockdownload": True}],
            [READY[0], {"loaded": False}],
            [*READY[:2], {"localrelay": False}],
        ):
            with self.subTest(checks=checks):
                self.rpc.call.side_effect = [txid(1), *checks]
                self.assertTrue(self.event("C", 1))
                self.assertIsNone(self.observer.observed_before(txid(1), txid(0)))
        self.seed(2)
        self.assertEqual(self.connect(3)[1], {txid(10)})
