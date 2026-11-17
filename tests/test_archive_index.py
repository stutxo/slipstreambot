import sqlite3
import unittest
from unittest.mock import Mock, patch

from slipstreambot.archive_index import PAYOUT_ADDRESSES, check_candidate, discover, initialize, verify
from slipstreambot.rpc import RPCError


def key(n):
    return f"{n:064x}"


class ArchiveIndexTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        initialize(self.db)
        self.tip = 10_000
        self.rpc = Mock()
        def chain(method, *args):
            if method == "getblockcount":
                return self.tip
            if method == "getblockhash":
                return key(args[0])
            if method == "getblockheader":
                return {"height": int(args[0], 16), "confirmations": 2}
            self.fail(f"Unexpected RPC {method}")
        self.rpc.call.side_effect = chain

    def discover_pages(self, pages):
        with patch("slipstreambot.archive_index.requests.Session") as session, \
                patch("slipstreambot.archive_index.time.sleep"):
            get = session.return_value.__enter__.return_value.get
            get.side_effect = [Mock(json=lambda rows=page: [
                {"height": n, "id": key(n)} for n in rows
            ]) for page in pages]
            discover(self.db, self.rpc)
            return [int(call.args[0].rsplit("/", 1)[1]) for call in get.call_args_list]

    def test_pages_checkpoint_and_incremental_refresh_preserve_reports(self):
        self.assertEqual(self.discover_pages([[9999, 9000], [3000], []]), [10001, 9000, 3000])
        with self.db:
            self.db.execute("UPDATE archive_candidates SET status='verified' WHERE height=9999")
            self.db.execute("INSERT INTO archive_blocks VALUES (9999,?,1,1,'[]','saved')", (key(9999),))
        self.tip = 10100
        self.assertEqual(self.discover_pages([[10090, 9999, 8888, 3000]]), [10101])
        self.assertEqual(self.db.execute("SELECT status,listed FROM archive_candidates WHERE height=9999").fetchone(),
                         ("verified", 1))
        self.assertEqual(self.db.execute("SELECT report FROM archive_blocks WHERE height=9999").fetchone(), ("saved",))
        self.assertEqual(self.db.execute("SELECT height FROM archive_candidates WHERE listed=0").fetchall(), [(9000,)])
        self.assertEqual(self.db.execute("SELECT height FROM archive_candidates WHERE listed=1 ORDER BY height").fetchall(),
                         [(3000,), (8888,), (9999,), (10090,)])

    def test_broken_page_resumes_at_last_complete_cursor(self):
        with self.assertRaises(ValueError):
            self.discover_pages([[9900, 9200], [9200]])
        self.assertEqual(self.db.execute("SELECT before_height,complete FROM archive_index_progress").fetchone(),
                         (9200, 0))
        self.assertEqual(self.discover_pages([[8000], []]), [9200, 8000])

    def test_orphaned_anchor_rebuilds_suffix_and_retains_common_prefix(self):
        self.discover_pages([[9999, 8000], []])
        with self.db:
            self.db.executemany("INSERT INTO archive_blocks VALUES (?,?,1,1,'[]','saved')",
                                [(n, key(n)) for n in (9999, 8000)])
        self.tip = 10001
        old_call = self.rpc.call.side_effect
        def revised(method, *args):
            if method == "getblockheader" and args[0] == key(10000):
                return {"confirmations": -1, "previousblockhash": key(9998)}
            return old_call(method, *args)
        self.rpc.call.side_effect = revised
        self.discover_pages([[10001, 8000, 7000]])
        self.assertEqual(self.db.execute("SELECT height,report FROM archive_blocks").fetchall(), [(8000, "saved")])
        self.assertEqual(self.db.execute("SELECT status,listed FROM archive_candidates WHERE height=9999").fetchone(),
                         ("pending", 0))

    def test_verify_uses_only_node_metadata_and_coinbase(self):
        height = 32
        block_hash = key(height)
        address = sorted(PAYOUT_ADDRESSES)[0]
        block = {"height": height, "hash": block_hash, "nTx": 2, "tx": [key(99), key(100)],
                 "confirmations": 3, "time": 10000}
        coinbase = {"txid": key(99), "blockhash": block_hash, "confirmations": 3,
                    "vin": [{"coinbase": b"mara pool".hex()}], "vout": [{"scriptPubKey": {"address": address}}]}
        self.rpc.call.side_effect = [block_hash, block, coinbase]
        status, _, values = check_candidate(self.rpc, height, block_hash, ["MARA Pool"], False)
        self.assertEqual(status, "verified")
        self.assertEqual(values[:4], (height, block_hash, 10000, 2))
        self.assertIn("MARA Pool", values[4])
        self.assertIn(address, values[4])
        self.rpc.call.assert_called_with("getrawtransaction", key(99), True, block_hash)
        coinbase["vin"][0]["coinbase"] = ""
        coinbase["vout"] = []
        self.rpc.call.side_effect = [block_hash, block, coinbase]
        self.assertEqual(check_candidate(self.rpc, height, block_hash, ["MARA Pool"], True)[0], "unattributed")
        coinbase["vin"][0] = {"txid": key(24)}
        self.rpc.call.side_effect = [block_hash, block, coinbase]
        with self.assertRaises(ValueError):
            check_candidate(self.rpc, height, block_hash, [], True)

    def test_conflict_or_stale_candidate_never_yields_visible_row(self):
        self.discover_pages([[9988], []])
        self.rpc.call.side_effect = [{}, key(10), RPCError("Unknown", code=-5)]
        with patch("slipstreambot.archive_index.BitcoinRPC", return_value=self.rpc):
            verify(self.db, {}, [], workers=1)
        self.assertEqual(self.db.execute("SELECT status FROM archive_candidates").fetchone(), ("conflict",))
        self.assertIsNone(self.db.execute("SELECT height FROM archive_blocks").fetchone())
        self.rpc.call.side_effect = [RPCError("Height out of range", code=-8),
                                     {"confirmations": -1, "height": 9988}]
        self.assertEqual(check_candidate(self.rpc, 9988, key(9988), [], True)[0], "stale")
