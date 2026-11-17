"""Resume structural policy analysis of node-verified historical MARA blocks."""

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from contextlib import closing
import fcntl
import json
import logging
import multiprocessing
from pathlib import Path
import sqlite3
import time

from .config import load_config, rpc_options
from .policy import analyze_block
from .rpc import BitcoinRPC, RPCError

LOG = logging.getLogger(__name__)
_worker_rpc: BitcoinRPC | None = None


def analyze_archive_block(rpc, row: tuple) -> str:
    height, expected_hash, timestamp, tx_count, evidence_json = row
    evidence = json.loads(evidence_json)
    if not isinstance(evidence, list) or not evidence or not all(isinstance(e, str) and e for e in evidence):
        raise ValueError(f"Missing verified attribution for block {height}")
    block = rpc.call("getblock", expected_hash, 3)
    if (block["hash"] != expected_hash or block["height"] != height or block["time"] != timestamp
            or block.get("confirmations", 0) < 1 or len(block["tx"]) != tx_count):
        raise ValueError(f"Node block differs from active archive entry at {height}")
    report = analyze_block(block, verified_pool_evidence=tuple(evidence))
    report["mempool"] = {"status": "unknown", "seen": 0, "not_observed": [], "since": None}
    return json.dumps(report, separators=(",", ":"), allow_nan=False)


def _worker_init(options):
    global _worker_rpc
    _worker_rpc = BitcoinRPC(**options)


def _work(row):
    return analyze_archive_block(_worker_rpc, row)


def save_report(db, rpc, height: int, block_hash: str, encoded: str) -> bool:
    if rpc.call("getblockhash", height) != block_hash:
        raise ValueError(f"Block {height} left the active chain before checkpoint")
    with db:
        changed = db.execute("UPDATE archive_blocks SET report=? WHERE height=? AND hash=? AND report IS NULL",
                             (encoded, height, block_hash))
    return changed.rowcount == 1


def _pending(db):
    # Read producer completion and the corresponding outstanding work together.
    with db:
        db.execute("BEGIN")
        upstream_done = db.execute("""
            SELECT complete AND NOT EXISTS (SELECT 1 FROM archive_candidates WHERE status IN ('pending','error'))
            FROM archive_index_progress WHERE singleton=1
        """).fetchone()
        rows = db.execute("""SELECT height,hash,time,tx_count,evidence FROM archive_blocks
                            WHERE report IS NULL ORDER BY height DESC""").fetchall()
    # Make the earliest known block available alongside the newest results.
    if len(rows) > 1:
        rows.insert(0, rows.pop())
    return rows, bool(upstream_done and upstream_done[0])


def run(db, rpc, pool, workers: int, *, follow: bool) -> None:
    started = time.monotonic()
    count = 0
    while True:
        rows, upstream_done = _pending(db)
        if not rows:
            if upstream_done or not follow:
                LOG.info("Finished %s archive reports in %.1fs", count, time.monotonic() - started)
                return
            time.sleep(2)
            continue
        queue = iter(rows)
        pending = {}
        completed = 0
        errors = 0
        while True:
            while len(pending) < 2 * workers:
                row = next(queue, None)
                if row is None:
                    break
                pending[pool.submit(_work, row)] = row
            if not pending:
                break
            finished, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                height, block_hash, *_ = pending.pop(future)
                try:
                    if save_report(db, rpc, height, block_hash, future.result()):
                        count += 1
                        completed += 1
                        if count == 1 or count % 100 == 0:
                            LOG.info("Checkpointed %s archive reports (%.2f blocks/s); latest checkpoint height %s",
                                     count, count / max(time.monotonic() - started, .001), height)
                except (RPCError, ValueError, KeyError) as exc:
                    LOG.warning("Archive analysis for %s deferred: %s", height, exc)
                    errors += 1
        if errors and not completed:
            raise RuntimeError(f"{errors} archive reports are still pending; rerun after resolving node availability")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--follow", action="store_true", help="Wait until index acquisition and verification finish")
    args = parser.parse_args()
    if not 1 <= args.workers <= 16:
        parser.error("--workers must be between 1 and 16")
    config = load_config(args.config)
    path = Path(config["monitor"]["state_path"]).resolve().with_name("archive.sqlite3")
    options = rpc_options(config)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with path.with_suffix(path.suffix + ".analysis.lock").open("a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            LOG.info("Archive analysis is already running")
            return
        with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=30)) as db, \
                closing(BitcoinRPC(**options)) as rpc, \
                ProcessPoolExecutor(args.workers, mp_context=multiprocessing.get_context("spawn"),
                                    initializer=_worker_init, initargs=(options,)) as pool:
            run(db, rpc, pool, args.workers, follow=args.follow)


if __name__ == "__main__":
    main()
