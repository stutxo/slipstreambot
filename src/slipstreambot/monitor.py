"""Active-chain reconciliation with a transactional, per-backend notification outbox.

Delivery is at least once: a crash after sending but before committing success can
repeat a message. The monitoring boundary is inclusive; a deeper reorg replays
from that boundary, not from unmonitored historical blocks.
"""

from __future__ import annotations

from contextlib import closing
import fcntl
import json
import logging
from pathlib import Path
import signal
import sqlite3
import threading
import time
from typing import Callable

import zmq

from .mempool import MempoolObserver
from .notifications import Backend, Notification
from .rpc import RPCError

LOG = logging.getLogger(__name__)


def _unknown_mempool() -> dict:
    return {"status": "unknown", "seen": 0, "not_observed": [], "since": None}


def saved_mempool_evidence(state_path: str, block_hash: str) -> dict:
    """Recover a live observation for a one-shot scan of the same block."""
    path = Path(state_path).expanduser().resolve()
    if path.is_file():
        try:
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                row = db.execute("SELECT report FROM blocks WHERE hash=?", (block_hash,)).fetchone()
                if row:
                    evidence = json.loads(row[0]).get("mempool")
                    if evidence is not None:
                        return evidence
        except (sqlite3.Error, ValueError):
            LOG.warning("Saved mempool evidence unavailable for block %s", block_hash)
    return _unknown_mempool()


class Monitor:
    BATCH_SIZE = 100
    DELIVERY_BATCH_SIZE = 100

    def __init__(self, rpc, *, zmq_endpoint: str, state_path: str,
                 analyze: Callable[[dict], dict],
                 notification: Callable[[dict], Notification | None],
                 backends: list[Backend], poll_seconds: float = 30,
                 start_height: int | None = None, zmq_sequence_endpoint: str | None = None) -> None:
        if poll_seconds <= 0:
            raise ValueError("Monitor poll_seconds must be positive")
        if start_height is not None and (
            not isinstance(start_height, int) or isinstance(start_height, bool) or start_height < 0
        ):
            raise ValueError("Monitor start_height must be a nonnegative integer")
        if len({backend.name for backend in backends}) != len(backends):
            raise ValueError("Notification backend names must be unique")
        self.rpc = rpc
        self.zmq_endpoint = zmq_endpoint
        self._sequence_endpoint = zmq_sequence_endpoint
        self._observer = MempoolObserver(rpc) if zmq_sequence_endpoint else None
        self._sequence = None
        self._connection_events = None
        self._sequence_retry = 0.0
        self.analyze = analyze
        self.notification = notification
        self.backends = list(backends)
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._closed = False
        self._lock = None
        self._db = None
        self._context = None
        self._socket = None
        self._retry_at: dict[str, float] = {}
        self._more_work = False
        try:
            if state_path != ":memory:":
                path = Path(state_path).expanduser().resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                state_path = str(path)
                self._lock = open(str(path) + ".lock", "a+b")
                try:
                    fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError("Monitor state is already locked by another process") from None
            self._db = sqlite3.connect(state_path)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS chain_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    genesis TEXT NOT NULL,
                    start_height INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blocks (
                    height INTEGER PRIMARY KEY,
                    hash TEXT NOT NULL UNIQUE,
                    previous_hash TEXT NOT NULL,
                    report TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    block_hash TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('report', 'retraction')),
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    url TEXT,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'sent', 'canceled')),
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(backend, status, id);
                CREATE INDEX IF NOT EXISTS outbox_block ON outbox(block_hash, active);
            """)
            genesis = rpc.call("getblockhash", 0)
            state = self._db.execute("SELECT * FROM chain_state").fetchone()
            if state is not None:
                if state["genesis"] != genesis:
                    raise RuntimeError("Monitor state belongs to a different Bitcoin genesis/network")
            else:
                tip = rpc.call("getblockcount")
                floor = tip if start_height is None else start_height
                anchor = rpc.call("getblockhash", floor - 1) if 0 < floor <= tip + 1 else ""
                with self._db:
                    self._db.execute("INSERT INTO chain_state VALUES (1, ?, ?, ?, ?)",
                                     (genesis, floor, floor - 1, anchor))
        except BaseException:
            self.close()
            raise

    def _enqueue(self, backend: str, block_hash: str, kind: str,
                 notice: Notification) -> None:
        self._db.execute(
            "INSERT INTO outbox(event_id,backend,block_hash,kind,title,body,url) "
            "VALUES (?,?,?,?,?,?,?)",
            (notice.event_id, backend, block_hash, kind, notice.title, notice.body, notice.url),
        )

    def _reconcile(self, tip: int) -> None:
        state = self._db.execute("SELECT * FROM chain_state").fetchone()
        floor = state["start_height"]
        ancestor_height = floor - 1
        ancestor_hash = ""
        # Never interpret an RPC exception as an absent/orphaned block. A failed
        # lookup aborts reconciliation before any checkpoint or outbox mutation.
        rows = self._db.execute("SELECT height,hash FROM blocks ORDER BY height DESC")
        for row in rows:
            if row["height"] <= tip and self.rpc.call("getblockhash", row["height"]) == row["hash"]:
                ancestor_height, ancestor_hash = row["height"], row["hash"]
                break
        if not ancestor_hash and 0 <= ancestor_height <= tip:
            ancestor_hash = self.rpc.call("getblockhash", ancestor_height)
        if state["height"] == ancestor_height and state["hash"] == ancestor_hash:
            return
        with self._db:
            # A report can be delivered and later retracted more than once if
            # the same branch becomes active again. 'active' distinguishes cycles.
            delivered = self._db.execute(
                "SELECT o.* FROM outbox o JOIN blocks b ON b.hash=o.block_hash "
                "WHERE b.height>? AND o.kind='report' AND o.active=1 AND o.status='sent' "
                "ORDER BY o.id", (ancestor_height,),
            ).fetchall()
            for row in delivered:
                notice = Notification(
                    event_id=f"retraction:{row['event_id']}:{row['id']}",
                    title="Chain reorganization: previous alert retracted",
                    body=(f"The block {row['block_hash']} is no longer on the active Bitcoin chain. "
                          f"Retract the previous alert: {row['title']}\n"
                          f"Original event: {row['event_id']}"),
                    url=row["url"],
                )
                self._enqueue(row["backend"], row["block_hash"], "retraction", notice)
            self._db.execute(
                "UPDATE outbox SET active=0, "
                "status=CASE WHEN status='pending' THEN 'canceled' ELSE status END "
                "WHERE kind='report' AND active=1 AND block_hash IN "
                "(SELECT hash FROM blocks WHERE height>?)", (ancestor_height,),
            )
            self._db.execute("DELETE FROM blocks WHERE height>?", (ancestor_height,))
            self._db.execute("UPDATE chain_state SET height=?,hash=? WHERE singleton=1",
                             (ancestor_height, ancestor_hash))

    def _drain(self) -> None:
        for backend in self.backends:
            if self._stop.is_set():
                return
            if time.monotonic() < self._retry_at.get(backend.name, 0):
                continue
            rows = self._db.execute(
                "SELECT * FROM outbox WHERE backend=? AND status='pending' ORDER BY id LIMIT ?",
                (backend.name, self.DELIVERY_BATCH_SIZE),
            ).fetchall()
            for row in rows:
                if self._stop.is_set():
                    return
                notice = Notification(row["event_id"], row["title"], row["body"], row["url"])
                try:
                    backend.send(notice)
                except Exception:
                    # Third-party exception strings may contain token-bearing URLs.
                    LOG.warning("Notification delivery failed for backend %s; queued for retry", backend.name)
                    self._retry_at[backend.name] = time.monotonic() + max(1, self.poll_seconds)
                    break
                with self._db:
                    self._db.execute("UPDATE outbox SET status='sent' WHERE id=?", (row["id"],))
            else:
                self._retry_at.pop(backend.name, None)
                if len(rows) == self.DELIVERY_BATCH_SIZE:
                    self._more_work = True

    def _close_sequence(self) -> None:
        if self._connection_events is not None:
            self._connection_events.close(linger=0)
            self._connection_events = None
        if self._sequence is not None:
            self._sequence.close(linger=0)
            self._sequence = None
        if self._observer is not None:
            self._observer.reset()

    def _drain_sequence(self, wait_ms: int = 0) -> bool:
        """Consume a bounded batch. Only chain events should wake reconciliation."""
        if self._observer is None or self._context is None:
            return False
        try:
            if self._sequence is None:
                if time.monotonic() < self._sequence_retry:
                    return False
                self._sequence = self._context.socket(zmq.SUB)
                self._sequence.setsockopt(zmq.LINGER, 0)
                self._sequence.setsockopt(zmq.RCVHWM, 16_384)
                self._sequence.setsockopt(zmq.SUBSCRIBE, b"sequence")
                self._connection_events = self._sequence.get_monitor_socket(events=zmq.EVENT_DISCONNECTED)
                self._sequence.connect(self._sequence_endpoint)
                LOG.info("Subscribed to local mempool sequence events; awaiting a block boundary")
            if self._connection_events.poll(0):
                # A fresh socket discards old frames still buffered across a reconnect.
                self._close_sequence()
                return False
            if wait_ms and not self._sequence.poll(wait_ms):
                return False
            block_event = False
            for _ in range(4096):
                try:
                    frames = self._sequence.recv_multipart(flags=zmq.NOBLOCK)
                except zmq.Again:
                    break
                if self._observer.process(frames):
                    block_event = True
            if self._connection_events.poll(0):
                self._close_sequence()
                return False
            return block_event
        except zmq.ZMQError:
            LOG.warning("Sequence subscription unavailable; continuing block monitoring")
            self._close_sequence()
            self._sequence_retry = time.monotonic() + self.poll_seconds
            return False

    def _mempool_evidence(self, block: dict, *, at_tip: bool) -> dict:
        if self._observer is None:
            return _unknown_mempool()
        # hashblock, sequence and RPC can announce a block in different orders.
        # A missing C frame stays unknown; historical catch-up never waits for one.
        self._drain_sequence()
        block_hash = block["hash"]
        deadline = time.monotonic() + 0.5
        while (at_tip and self._sequence is not None and not self._stop.is_set()
               and not self._observer.has_boundary(block_hash) and time.monotonic() < deadline):
            self._drain_sequence(wait_ms=50)
        cut = self._observer.observed_before(block_hash, block.get("previousblockhash", ""))
        if cut is None:
            return _unknown_mempool()
        since, observed = cut
        txids = [tx["txid"] for tx in block["tx"][1:]]
        missing = [txid for txid in txids if txid not in observed]
        return {"status": "covered", "seen": len(txids) - len(missing), "not_observed": missing,
                "since": since}

    def sync_once(self) -> int:
        """Reconcile and commit at most BATCH_SIZE blocks, then attempt each sink.

        Existing checkpoints override start_height on restart. Unavailable/pruned
        data and RPC failures propagate, leaving that block unprocessed.
        """
        if self._closed:
            raise RuntimeError("Monitor is closed")
        self._more_work = False
        tip = self.rpc.call("getblockcount")
        self._reconcile(tip)
        state = self._db.execute("SELECT * FROM chain_state").fetchone()
        height, previous = state["height"] + 1, state["hash"]
        processed = 0
        while height <= tip and processed < self.BATCH_SIZE and not self._stop.is_set():
            self._drain_sequence()
            block_hash = self.rpc.call("getblockhash", height)
            block = self.rpc.call("getblock", block_hash, 3)
            if block.get("hash") != block_hash or block.get("height") != height:
                raise RPCError("RPC returned block data inconsistent with the requested hash and height")
            if height > 0 and previous and block.get("previousblockhash") != previous:
                self._more_work = True
                break
            report = self.analyze(block)
            if report.get("pool") == "MARA":
                report["mempool"] = self._mempool_evidence(block, at_tip=height == tip)
            if self.rpc.call("getblockhash", height) != block_hash:
                self._more_work = True
                break
            notice = self.notification(report)
            encoded = json.dumps(report, separators=(",", ":"), allow_nan=False)
            with self._db:
                self._db.execute("INSERT INTO blocks VALUES (?,?,?,?)",
                                 (height, block_hash, block.get("previousblockhash", ""), encoded))
                if notice is not None:
                    for backend in self.backends:
                        self._enqueue(backend.name, block_hash, "report", notice)
                self._db.execute("UPDATE chain_state SET height=?,hash=? WHERE singleton=1",
                                 (height, block_hash))
            observation = report.get("mempool")
            detail = ""
            if observation:
                unseen = len(observation["not_observed"]) if observation["status"] == "covered" else "unknown"
                detail = f" mempool_not_observed={unseen}"
            LOG.info("Processed block %d %s: pool=%s policy_findings=%d%s",
                     height, block_hash, report.get("pool"), len(report.get("findings", [])), detail)
            processed += 1
            height += 1
            previous = block_hash
        self._more_work = self._more_work or height <= tip
        self._drain()
        return processed

    def run(self) -> None:
        """Run in the foreground; ZMQ is a hint, and polling remains authoritative."""
        old_handler = None
        installed_handler = False
        try:
            if threading.current_thread() is threading.main_thread():
                old_handler = signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
                installed_handler = True
            self._context = zmq.Context()
            self._socket = self._context.socket(zmq.SUB)
            self._socket.setsockopt(zmq.LINGER, 0)
            self._socket.setsockopt(zmq.RCVHWM, 1000)
            self._socket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
            self._socket.connect(self.zmq_endpoint)
            self._drain_sequence()
            LOG.info("Watching hashblock ZMQ; reconciling RPC every %s seconds", self.poll_seconds)
            while not self._stop.is_set():
                retrying = False
                try:
                    self.sync_once()
                except RPCError as exc:
                    LOG.error("Chain synchronization failed: %s", exc)
                    retrying = True
                if self._more_work and not retrying:
                    continue
                deadline = time.monotonic() + self.poll_seconds
                while not self._stop.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if self._drain_sequence() and not retrying:
                        break
                    if self._socket.poll(max(1, min(250, int(remaining * 1000)))):
                        for _ in range(1000):
                            try:
                                self._socket.recv_multipart(flags=zmq.NOBLOCK)
                            except zmq.Again:
                                break
                        if not retrying:
                            break
        except KeyboardInterrupt:
            self._stop.set()
        finally:
            if installed_handler:
                signal.signal(signal.SIGTERM, old_handler)
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        try:
            self._close_sequence()
            if self._socket is not None:
                self._socket.close(linger=0)
            if self._context is not None:
                self._context.term()
            if self._db is not None:
                self._db.close()
        finally:
            try:
                if self._lock is not None:
                    self._lock.close()
            finally:
                self.rpc.close()
