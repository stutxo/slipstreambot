import fcntl
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from slipstreambot.archive_analyze import _pending, analyze_archive_block, main, save_report
from slipstreambot.policy import SLIPSTREAM_ANNOUNCEMENT, block_notification, block_signals


class ArchiveAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.rpc = Mock()
        self.block = {
            "height": 685833, "hash": "12" * 32, "confirmations": 10,
            "time": SLIPSTREAM_ANNOUNCEMENT - 1, "tx": [
                {"vin": [{"coinbase": b"old pool coinbase".hex()}]},
                {"txid": "ab" * 32, "weight": 400010, "version": 2, "vin": [], "vout": []},
            ],
        }
        self.rpc.call.return_value = self.block
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE archive_blocks (height INTEGER PRIMARY KEY, hash TEXT UNIQUE,
                time INT, tx_count INT, evidence TEXT, report TEXT);
            CREATE TABLE archive_candidates (hash TEXT, status TEXT);
            CREATE TABLE archive_index_progress (singleton INTEGER, complete INTEGER);
            INSERT INTO archive_index_progress VALUES (1, 0);
        """)

    def row(self):
        return (self.block["height"], self.block["hash"], self.block["time"], len(self.block["tx"]),
                json.dumps(["verified coinbase payout address"]))

    def test_verified_attribution_without_tag_and_preannouncement_findings(self):
        report = json.loads(analyze_archive_block(self.rpc, self.row()))
        self.assertEqual(report["pool_evidence"], ["verified coinbase payout address"])
        self.assertEqual(report["transactions_examined"], 1)
        self.assertEqual(report["mempool"]["status"], "unknown")
        self.assertTrue(report["pre_slipstream"])
        finding, = report["findings"]
        self.assertNotIn("route_assessment", finding)
        self.assertEqual(finding["violations"][0]["core"], "reject")
        self.assertNotIn("slipstream", finding["violations"][0])
        self.assertIsNone(block_signals(report)[1][0]["slipstream_assessment"])
        self.assertNotIn("Possible Slipstream", block_notification(report).body)
        self.block["time"] = SLIPSTREAM_ANNOUNCEMENT
        newer = json.loads(analyze_archive_block(self.rpc, self.row()))
        self.assertFalse(newer["pre_slipstream"])
        self.assertIn("route_assessment", newer["findings"][0])
        self.assertEqual(newer["mempool"]["status"], "unknown")

    def test_rejects_mismatch_unverified_attribution_and_orphan(self):
        row = self.row()
        for index, bad in [(0, 0), (1, "00" * 32), (2, 123), (3, 1), (4, "[]")]:
            with self.subTest(index=index):
                changed = list(row)
                changed[index] = bad
                with self.assertRaises(ValueError):
                    analyze_archive_block(self.rpc, changed)
        self.block["confirmations"] = -1
        with self.assertRaises(ValueError):
            analyze_archive_block(self.rpc, row)

    def test_checkpoint_revalidates_hash_and_preserves_existing_report(self):
        row = self.row()
        self.db.execute("INSERT INTO archive_blocks VALUES (?,?,?,?,?,NULL)", row)
        self.db.commit()
        self.rpc.call.return_value = "00" * 32
        with self.assertRaises(ValueError):
            save_report(self.db, self.rpc, *row[:2], "first")
        self.assertIsNone(self.db.execute("SELECT report FROM archive_blocks").fetchone()[0])
        self.rpc.call.return_value = row[1]
        self.assertTrue(save_report(self.db, self.rpc, *row[:2], "first"))
        self.assertFalse(save_report(self.db, self.rpc, *row[:2], "second"))
        self.assertEqual(self.db.execute("SELECT report FROM archive_blocks").fetchone()[0], "first")

    def test_resume_prioritizes_oldest_example_and_latest_pending_and_waits_for_index(self):
        with self.db:
            self.db.executemany("INSERT INTO archive_blocks(height,hash,report) VALUES (?,?,?)",
                                [(n, str(n), "{}" if n == 4 else None) for n in range(1, 6)])
            self.db.execute("UPDATE archive_index_progress SET complete=1")
            self.db.execute("INSERT INTO archive_candidates VALUES ('6','pending')")
        rows, done = _pending(self.db)
        self.assertEqual([r[0] for r in rows], [1, 5, 3, 2])
        self.assertFalse(done)
        with self.db:
            self.db.execute("UPDATE archive_candidates SET status='error'")
        self.assertFalse(_pending(self.db)[1])
        with self.db:
            self.db.execute("UPDATE archive_candidates SET status='verified'")
        self.assertTrue(_pending(self.db)[1])

    def test_overlapping_cli_exits_before_opening_another_rpc_client(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            config = folder / "config.toml"
            config.write_text('[monitor]\nstate_path = "watcher.sqlite3"\n')
            with (folder / "archive.sqlite3.analysis.lock").open("a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with patch("sys.argv", ["archive_analyze", "--config", str(config)]), \
                        patch("slipstreambot.archive_analyze.BitcoinRPC") as rpc:
                    main()
                    rpc.assert_not_called()
