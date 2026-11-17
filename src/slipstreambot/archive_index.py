"""Index historical MARA candidates, then verify their coinbases against Bitcoin Core."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import fcntl
import json
import logging
from pathlib import Path
import re
import sqlite3
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import load_config, rpc_options
from .policy import MARA_TAGS
from .rpc import BitcoinRPC, RPCError


LOG = logging.getLogger(__name__)
POOL_BLOCKS = "https://mempool.space/api/v1/mining/pool/marapool/blocks"
REFRESH_OVERLAP = 2016
# MARA Pool, unique_id 115 in mempool/mining-pools' pools-v2.json.
PAYOUT_ADDRESSES = {
    "15MdAHnkxt9TMC2Rj595hsg8Hnv693pPBB",
    "1A32KFEX7JNPmU1PVjrtiXRrTQcesT3Nf1",
    "32i1m6gNcSHwiPX9nfTNXVjme9j5DU8y5g",
}


def initialize(db):
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS archive_blocks (
            height INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, time INTEGER NOT NULL,
            tx_count INTEGER NOT NULL, evidence TEXT NOT NULL, report TEXT
        );
        CREATE TABLE IF NOT EXISTS archive_candidates (
            hash TEXT PRIMARY KEY, height INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            note TEXT, listed INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS archive_pending ON archive_candidates(status, height);
        CREATE TABLE IF NOT EXISTS archive_index_progress (
            singleton INTEGER PRIMARY KEY CHECK (singleton=1), tip_height INTEGER NOT NULL,
            tip_hash TEXT NOT NULL, before_height INTEGER NOT NULL, complete INTEGER NOT NULL,
            floor_height INTEGER NOT NULL DEFAULT 0
        );
    """)
    # Keep the checkpoint and analyzed reports from the original full enumeration.
    with db:
        if "floor_height" not in {r[1] for r in db.execute("PRAGMA table_info(archive_index_progress)")}:
            db.execute("ALTER TABLE archive_index_progress ADD COLUMN floor_height INTEGER NOT NULL DEFAULT 0")
        if "listed" not in {r[1] for r in db.execute("PRAGMA table_info(archive_candidates)")}:
            db.execute("ALTER TABLE archive_candidates ADD COLUMN listed INTEGER NOT NULL DEFAULT 1")


def discover(db, rpc):
    progress = db.execute(
        "SELECT tip_height,tip_hash,before_height,complete,floor_height FROM archive_index_progress"
    ).fetchone()
    floor = 0
    ancestor = None
    if progress:
        height, block_hash, cursor, complete, floor = progress
        header = rpc.call("getblockheader", block_hash)
        if header["confirmations"] < 1:
            while header["confirmations"] < 1:
                header = rpc.call("getblockheader", header["previousblockhash"])
            ancestor = header["height"]
            LOG.warning("Rebuilding archive index above common ancestor %d", ancestor)
            floor = max(0, ancestor - REFRESH_OVERLAP + 1) if complete else min(ancestor + 1, floor)
            progress = None
        elif complete:
            # Include recently indexed late attributions as well as all newly mined heights.
            floor = max(0, height - REFRESH_OVERLAP + 1)
            progress = None
    if not progress:
        height = rpc.call("getblockcount")
        block_hash = rpc.call("getblockhash", height)
        cursor = height + 1
        with db:
            if ancestor is not None:
                db.execute("DELETE FROM archive_blocks WHERE height>?", (ancestor,))
                db.execute("UPDATE archive_candidates SET status='pending',note=NULL,listed=0 WHERE height>?", (ancestor,))
            db.execute("UPDATE archive_candidates SET listed=0 WHERE height BETWEEN ? AND ?", (floor, height))
            db.execute("INSERT OR REPLACE INTO archive_index_progress VALUES(1,?,?,?,0,?)",
                       (height, block_hash, cursor, floor))
    with requests.Session() as session:
        retry = Retry(total=5, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        while True:
            response = session.get(f"{POOL_BLOCKS}/{cursor}", timeout=45)
            response.raise_for_status()
            rows = response.json()
            if not isinstance(rows, list):
                raise ValueError("Expected a page of pool blocks")
            candidates = []
            previous = cursor
            for item in rows:
                block_hash, height = item["id"], item["height"]
                if (type(height) is not int or not 0 <= height < previous or
                        not isinstance(block_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", block_hash)):
                    raise ValueError("Pool history returned an invalid or unordered block")
                if height >= floor:
                    candidates.append((block_hash, height))
                previous = height
            complete = not rows or previous <= floor
            with db:
                db.executemany("""
                    INSERT INTO archive_candidates(hash,height) VALUES(?,?)
                    ON CONFLICT(hash) DO UPDATE SET listed=1,
                      status=CASE WHEN status='verified' THEN status ELSE 'pending' END,
                      note=CASE WHEN status='verified' THEN note END
                """, candidates)
                db.execute("UPDATE archive_index_progress SET before_height=?,complete=? WHERE singleton=1",
                           (previous, int(complete)))
            if complete:
                missing, = db.execute("SELECT count(*) FROM archive_candidates WHERE listed=0").fetchone()
                LOG.info("Candidate enumeration complete; %d prior candidates absent from refreshed index ranges", missing)
                return
            LOG.info("Indexed %d candidates down through height %d", len(rows), previous)
            cursor = previous
            time.sleep(0.5)


def check_candidate(rpc, height, candidate_hash, tags, txindex):
    try:
        active_hash = rpc.call("getblockhash", height)
    except RPCError as exc:
        if exc.code != -8:
            raise
        active_hash = None  # Reorg to a shorter chain; confirm the orphan header below.
    if active_hash != candidate_hash:
        try:
            header = rpc.call("getblockheader", candidate_hash)
        except RPCError as exc:
            if exc.code == -5:
                return "conflict", f"Candidate hash unknown to node; active block is {active_hash}", None
            raise
        if header.get("height") != height or header.get("confirmations", 0) >= 1:
            return "conflict", f"Candidate height disagrees with node; active block is {active_hash}", None
        return "stale", f"Node identifies candidate as orphaned; active block is {active_hash}", None
    block = rpc.call("getblock", candidate_hash, 1)
    if block["hash"] != candidate_hash or block["height"] != height:
        raise ValueError("Block metadata disagrees with requested height/hash")
    if block["confirmations"] < 1:
        return "stale", "Block has left the active chain", None
    txids = block["tx"]
    if not txids or len(txids) != block["nTx"]:
        raise ValueError("Block transaction count mismatch")
    # With txindex the node seeks directly to the coinbase instead of decoding the block again.
    if txindex:
        coinbase = rpc.call("getrawtransaction", txids[0], True)
    else:
        coinbase = rpc.call("getrawtransaction", txids[0], True, candidate_hash)
    if (coinbase["txid"] != txids[0] or coinbase["blockhash"] != candidate_hash or
            len(coinbase["vin"]) != 1 or "coinbase" not in coinbase["vin"][0]):
        raise ValueError("Node transaction is not the identified block's coinbase")
    if coinbase.get("confirmations", 0) < 1:
        return "stale", "Coinbase has left the active chain", None
    script = bytes.fromhex(coinbase["vin"][0]["coinbase"]).lower()
    evidence = [f"Coinbase tag: {tag}" for tag in tags if tag.encode().lower() in script]
    for output in coinbase["vout"]:
        address = output["scriptPubKey"].get("address")
        if address in PAYOUT_ADDRESSES:
            label = f"Coinbase payout: {address}"
            if label not in evidence:
                evidence.append(label)
    if not evidence:
        return "unattributed", "No known MARA coinbase tag or payout address", None
    return "verified", None, (height, candidate_hash, block["time"], len(txids), json.dumps(evidence))


def verify(db, options, tags, workers=3):
    local = threading.local()
    clients = []
    with closing(BitcoinRPC(**options)) as rpc:
        try:
            txindex = rpc.call("getindexinfo", "txindex").get("txindex", {}).get("synced") is True
        except RPCError:
            txindex = False  # The explicit block-hash lookup also works without an index.

    def check(row):
        if not hasattr(local, "rpc"):
            local.rpc = BitcoinRPC(**options)
            clients.append(local.rpc)
        try:
            return row, check_candidate(local.rpc, *row, tags, txindex)
        except (RPCError, ValueError, KeyError, TypeError) as exc:
            return row, ("error", str(exc), None)

    with db:
        db.execute("UPDATE archive_candidates SET status='pending',note=NULL WHERE status='error'")
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            while True:
                # Read completion and available work in one snapshot, including concurrent discovery.
                db.execute("BEGIN")
                progress = db.execute("SELECT complete FROM archive_index_progress WHERE singleton=1").fetchone()
                rows = db.execute("SELECT height,hash FROM archive_candidates WHERE status='pending' "
                                  "ORDER BY height DESC LIMIT 100").fetchall()
                db.commit()
                if not progress:
                    raise RuntimeError("Start candidate discovery before verification")
                if not rows:
                    if progress[0]:
                        break
                    time.sleep(1)
                    continue
                for (height, block_hash), (status, note, values) in pool.map(check, rows):
                    with db:
                        if values:
                            db.execute("""
                                INSERT INTO archive_blocks(height,hash,time,tx_count,evidence) VALUES(?,?,?,?,?)
                                ON CONFLICT(height) DO UPDATE SET hash=excluded.hash,time=excluded.time,
                                    tx_count=excluded.tx_count,evidence=excluded.evidence,
                                    report=CASE WHEN hash=excluded.hash THEN report ELSE NULL END
                            """, values)
                        db.execute("UPDATE archive_candidates SET status=?,note=? WHERE hash=?", (status, note, block_hash))
                LOG.info("Verified candidate batch through height %d", rows[-1][0])
    finally:
        for client in clients:
            client.close()
    counts = dict(db.execute("SELECT status,count(*) FROM archive_candidates GROUP BY status"))
    LOG.info("Finished candidate verification: %s", counts)
    if counts.get("error"):
        raise RuntimeError("Some candidates could not be verified; details are in archive_candidates.note")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--archive", help="Defaults to archive.sqlite3 beside the watcher database")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--discover-only", action="store_true", help="Only acquire the candidate list")
    modes.add_argument("--verify-only", action="store_true", help="Verify the list while discovery is running or after it finishes")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.config)
    monitor_db = Path(config["monitor"]["state_path"]).resolve()
    path = Path(args.archive).expanduser().resolve() if args.archive else monitor_db.with_name("archive.sqlite3")
    if path == monitor_db or (path.exists() and monitor_db.exists() and path.samefile(monitor_db)):
        parser.error("The archive path must differ from the watcher database")
    path.parent.mkdir(parents=True, exist_ok=True)
    options = rpc_options(config)
    with closing(BitcoinRPC(**options)) as rpc:
        if rpc.call("getblockchaininfo")["chain"] != "main":
            raise RuntimeError("MARA pool history requires a mainnet node")
        with closing(sqlite3.connect(path, timeout=30)) as db:
            initialize(db)
            if not args.verify_only:
                with open(str(path) + ".index.lock", "a+b") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    discover(db, rpc)
            if not args.discover_only:
                with open(str(path) + ".verify.lock", "a+b") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    verify(db, options, config["monitor"].get("mara_tags", MARA_TAGS))
                    anchor, = db.execute("SELECT tip_hash FROM archive_index_progress").fetchone()
                    if rpc.call("getblockheader", anchor)["confirmations"] < 1:
                        raise RuntimeError("Archive anchor was reorganized during verification. Rerun the full index command.")


if __name__ == "__main__":
    main()
