"""Active-chain reconciliation with a transactional, per-backend notification outbox.

Delivery is at least once: a crash after sending but before committing success can
repeat a message. The monitoring boundary is inclusive; a deeper reorg replays
from that boundary, not from unmonitored historical blocks.
"""

from __future__ import annotations

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

from .notifications import Backend, Notification
from .rpc import RPCError

LOG = logging.getLogger(__name__)


class Monitor:
    BATCH_SIZE = 100
    DELIVERY_BATCH_SIZE = 100

    def __init__(self, rpc, *, zmq_endpoint: str, state_path: str,
                 analyze: Callable[[dict], dict],
                 notification: Callable[[dict], Notification | None],
                 backends: list[Backend], poll_seconds: float = 30,
                 start_height: int | None = None) -> None:
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
            block_hash = self.rpc.call("getblockhash", height)
            block = self.rpc.call("getblock", block_hash, 3)
            if block.get("hash") != block_hash or block.get("height") != height:
                raise RPCError("RPC returned block data inconsistent with the requested hash and height")
            if self.rpc.call("getblockhash", height) != block_hash:
                self._more_work = True
                break
            if height > 0 and previous and block.get("previousblockhash") != previous:
                self._more_work = True
                break
            report = self.analyze(block)
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
            LOG.info("Processed block %d %s: pool=%s findings=%d",
                     height, block_hash, report.get("pool"), len(report.get("findings", [])))
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
            LOG.info("Watching hashblock ZMQ; reconciling RPC every %s seconds", self.poll_seconds)
            while not self._stop.is_set():
                try:
                    self.sync_once()
                except RPCError as exc:
                    LOG.error("Chain synchronization failed: %s", exc)
                    self._stop.wait(self.poll_seconds)
                    continue
                if self._more_work:
                    continue
                deadline = time.monotonic() + self.poll_seconds
                while not self._stop.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if self._socket.poll(max(1, min(250, int(remaining * 1000)))):
                        for _ in range(1000):
                            try:
                                self._socket.recv_multipart(flags=zmq.NOBLOCK)
                            except zmq.Again:
                                break
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
