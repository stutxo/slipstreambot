"""Exercise publication with a local bare Git remote and no network access."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from slipstreambot.explorer import MAINNET_GENESIS


class ArchivePublishTests(unittest.TestCase):
    def test_only_public_json_reaches_branch_and_ordinary_tips_do_not_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            remote, checkout = root / "remote", root / "data"
            def git(*args):
                return subprocess.check_output(["git", *map(str, args)], text=True, stderr=subprocess.PIPE).strip()

            git("init", "--bare", remote)
            git("init", "-b", "archive-data", checkout)
            git("-C", checkout, "remote", "add", "origin", remote)
            git("-C", checkout, "config", "user.name", "Archive test")
            git("-C", checkout, "config", "user.email", "archive@example.invalid")
            git("-C", checkout, "config", "commit.gpgsign", "false")
            conf = root / "config.toml"
            conf.write_text('[monitor]\nstate_path="watch.sqlite3"\n')
            with closing(sqlite3.connect(root / "watch.sqlite3")) as db:
                db.execute("CREATE TABLE chain_state(singleton,start_height,height,genesis)")
                db.execute("INSERT INTO chain_state VALUES(1,2000,2000,?)", (MAINNET_GENESIS,))
                db.execute("CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash, report)")
                db.commit()
            with closing(sqlite3.connect(root / "archive.sqlite3")) as db:
                db.execute("CREATE TABLE archive_blocks(height INTEGER PRIMARY KEY,hash,time,tx_count,evidence,report)")
                db.execute("INSERT INTO archive_blocks VALUES(1001,'older',100,25,'[]',NULL)")
                db.commit()

            publisher = Path(__file__).resolve().parents[1] / "explorer-site" / "publish_data.py"
            def publish():
                subprocess.run([sys.executable, str(publisher), "--config", str(conf), "--checkout", str(checkout)],
                               check=True, stdout=subprocess.PIPE)
                return git("-C", remote, "rev-parse", "archive-data")

            first = publish()
            self.assertEqual(git("-C", remote, "ls-tree", "-r", "--name-only", first).splitlines(),
                             ["archive.json", "blocks.json", "details/1.json"])
            with closing(sqlite3.connect(root / "watch.sqlite3")) as db:
                db.execute("UPDATE chain_state SET height=2001")
                db.commit()
            self.assertEqual(publish(), first)
            with closing(sqlite3.connect(root / "watch.sqlite3")) as db:
                report = {"pool": "MARA", "time": 1800000000, "transactions_examined": 1, "findings": []}
                db.execute("INSERT INTO blocks VALUES(2001,'new',?)", (json.dumps(report),))
                db.commit()
            final = publish()
            self.assertNotEqual(final, first)
            index = json.loads(git("-C", remote, "show", f"{final}:archive.json"))
            self.assertEqual([b["hash"] for b in index["blocks"]], ["new", "older"])
