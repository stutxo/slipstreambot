import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from slipstreambot.cli import main
from slipstreambot.explorer import MAINNET_GENESIS, archive_index, archive_reader, detail_bucket, read_blocks


class ExplorerTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "state #1.sqlite3"
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE chain_state (singleton INTEGER, start_height INTEGER, height INTEGER, genesis TEXT);
            CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash TEXT, report TEXT);
            INSERT INTO chain_state VALUES (1, 5, 4, 'unknown');
        """)

    def test_latest_mara_reports_and_committed_reorg(self):
        findings = [{"txid": "abc", "violations": [{"detail": "First reason"}, {"detail": "Second reason"}]}]
        with self.db:
            for height in range(5, 58):
                report = {
                    "pool": "MARA" if height < 57 else None, "time": 1234,
                    "transactions_examined": 12, "findings": findings if height == 56 else [],
                }
                self.db.execute("INSERT INTO blocks VALUES (?,?,?)",
                                (height, f"hash{height}", json.dumps(report)))
            self.db.execute("UPDATE chain_state SET height=57")
        payload = read_blocks(self.path)
        self.assertEqual(payload["height"], 57)
        self.assertEqual([b["height"] for b in payload["blocks"]], list(range(56, 6, -1)))
        self.assertEqual(payload["blocks"][0], {
            "height": 56, "hash": "hash56", "time": 1234, "transactions": 13,
            "analyzed": True, "evidence": [], "pre_slipstream": True,
            "mempool_summary": "Local mempool coverage before block connection is unknown.",
            "mempool_not_observed": None,
            "findings": [{"txid": "abc", "reasons": ["First reason", "Second reason"],
                          "mempool_observation": "Local mempool observation unknown.",
                          "slipstream_assessment": None}],
        })
        with self.db:
            self.db.execute("DELETE FROM blocks WHERE height > 55")
            self.db.execute("UPDATE chain_state SET height=55")
            self.assertEqual(read_blocks(self.path)["height"], 57)
        updated = read_blocks(self.path)
        self.assertEqual(updated["height"], 55)
        self.assertEqual(updated["blocks"][0]["height"], 55)
        self.assertEqual(updated["blocks"][0]["findings"], [])

    def test_mempool_misses_and_policy_findings_share_one_row_per_transaction(self):
        report = {
            "pool": "MARA", "time": 2000, "transactions_examined": 3,
            "findings": [{"txid": txid, "violations": [{"detail": "Weight limit"}]}
                         for txid in ["both", "policy"]],
            "mempool": {"status": "covered", "since": 1200, "seen": 1,
                        "not_observed": ["both", "missing"]},
        }
        with self.db:
            self.db.execute("INSERT INTO blocks VALUES (5, 'hash5', ?)", (json.dumps(report),))
            self.db.execute("UPDATE chain_state SET height=5")
        block = read_blocks(self.path)["blocks"][0]
        self.assertEqual(block["mempool_not_observed"], 2)
        self.assertIn("1 seen, 2 not observed", block["mempool_summary"])
        self.assertIn("1970-01-01 00:20:00 UTC", block["mempool_summary"])
        both, policy, missing = block["findings"]
        self.assertEqual([both["txid"], policy["txid"], missing["txid"]], ["both", "policy", "missing"])
        self.assertEqual(both["reasons"], ["Weight limit"])
        self.assertIn("Not observed", both["mempool_observation"])
        self.assertIn("Seen in this node", policy["mempool_observation"])
        self.assertEqual(missing["mempool_observation"], both["mempool_observation"])
        self.assertEqual(missing["reasons"], [])
        self.assertIsNone(missing["slipstream_assessment"])
        report["mempool"].update(seen=3, not_observed=[])
        with self.db:
            self.db.execute("UPDATE blocks SET report=? WHERE height=5", (json.dumps(report),))
        self.assertEqual(read_blocks(self.path)["blocks"][0]["mempool_not_observed"], 0)

    def test_assessments_only_describe_observed_exceptions(self):
        combinations = [
            ["within_published_rule", "within_published_rule"],
            ["within_published_rule", "unknown"],
            ["unknown", "reject"],
            [],
        ]
        findings = [
            {"txid": str(i), "violations": [{"detail": "Example", "slipstream": value} for value in values]}
            for i, values in enumerate(combinations)
        ]
        report = {"pool": "MARA", "time": 1800000000, "transactions_examined": 4, "findings": findings}
        with self.db:
            self.db.execute("INSERT INTO blocks VALUES (5, 'hash5', ?)", (json.dumps(report),))
            self.db.execute("UPDATE chain_state SET height=5")
        actual = read_blocks(self.path)["blocks"][0]["findings"]
        self.assertEqual([f["slipstream_assessment"] for f in actual], [
            "The observed exceptions fit published Slipstream rules.",
            "Fit with published Slipstream rules is unknown.",
            "An observed exception falls outside a published Slipstream rule.",
            "Fit with published Slipstream rules is unknown.",
        ])

    def test_archive_merge_preserves_live_observations_and_active_chain(self):
        archive = sqlite3.connect(self.path.with_name("archive.sqlite3"))
        self.addCleanup(archive.close)
        archive.execute("CREATE TABLE archive_blocks(height INTEGER PRIMARY KEY, hash TEXT, time INTEGER, "
                        "tx_count INTEGER, evidence TEXT, report TEXT)")
        template = {"pool": "MARA", "time": 1800000000, "transactions_examined": 2, "findings": []}
        with archive:
            for height, block_hash, raw in [
                (1, "analyzed", {**template, "time": 100, "findings": [
                    {"txid": "policy", "violations": [{"detail": "Policy exception"}]}]}),
                (2, "pending", None), (5, "same", template), (6, "payout", template),
                (7, "orphan", template), (8, "rolled-back", template),
            ]:
                archive.execute("INSERT INTO archive_blocks VALUES(?,?,?,?,?,?)",
                                (height, block_hash, raw["time"] if raw else 100, 3, '["payout address"]',
                                 json.dumps(raw) if raw is not None else None))
        live = {**template, "mempool": {"status": "covered", "seen": 1, "not_observed": ["both"], "since": 8},
                "findings": [{"txid": "both", "violations": [{"detail": "Example"}]}]}
        with self.db:
            self.db.execute("UPDATE chain_state SET height=7,genesis=?", (MAINNET_GENESIS,))
            for height, block_hash, report in [(5, "same", live), (6, "payout", {**template, "pool": None}),
                                                (7, "replacement", {**template, "pool": None})]:
                self.db.execute("INSERT INTO blocks VALUES(?,?,?)", (height, block_hash, json.dumps(report)))
        with archive_reader(self.path) as (db, meta, archived):
            index = archive_index(db, meta, archived)["blocks"]
            details = detail_bucket(db, archived, 0)["blocks"]
            self.assertEqual(detail_bucket(db, archived, 1)["blocks"], [])
        self.assertEqual([r["hash"] for r in index], ["payout", "same", "pending", "analyzed"])
        self.assertEqual([r["flagged"] for r in index], [0, 1, None, 1])
        self.assertEqual(index[1]["mempool_not_observed"], 1)
        self.assertNotIn("findings", index[1])
        self.assertEqual(details[1]["evidence"], ["payout address"])
        self.assertEqual(details[1]["findings"][0]["txid"], "both")
        self.assertFalse(details[2]["analyzed"])
        self.assertIsNone(details[3]["findings"][0]["slipstream_assessment"])
        self.assertTrue(details[3]["pre_slipstream"])

    def test_no_scanned_blocks_and_missing_database(self):
        self.assertEqual(read_blocks(self.path), {"height": None, "mainnet": False, "blocks": []})
        with self.db:
            self.db.execute("UPDATE chain_state SET genesis=?",
                            ("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",))
        self.assertIs(read_blocks(self.path)["mainnet"], True)
        missing = self.path.with_name("missing.sqlite3")
        with self.assertRaises(sqlite3.OperationalError):
            read_blocks(missing)
        self.assertFalse(missing.exists())

    def test_explore_uses_configured_state_without_rpc_or_notifier_credentials(self):
        config = self.path.with_name("site.toml")
        config.write_text(
            '[bitcoin]\nrpc_user="user"\nrpc_password_env="UNSET_RPC_KEY"\n'
            '[monitor]\nstate_path="custom.sqlite3"\n'
            '[[notifiers]]\nkind="telegram"\n'
        )
        with patch("slipstreambot.cli.serve_explorer") as serve:
            self.assertEqual(main(["--config", str(config), "explore", "--port", "8085"]), 0)
        serve.assert_called_once_with(str(config.parent / "custom.sqlite3"), 8085)
