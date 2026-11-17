"""Pre-block observations from one node's ordered ZMQ sequence topic."""

from collections import OrderedDict
import logging
import re
import time

from .rpc import RPCError

LOG = logging.getLogger(__name__)
_TXID = re.compile(r"[0-9a-f]{64}")


class MempoolObserver:
    """Called on a single thread. A cut contains evidence only up to its C event.

    Start an epoch on a block connection with a tip-bracketed RPC snapshot.
    Keep every admitted txid, including evictions, until an epoch ends. Chain
    disconnects, broken stream continuity, RPC errors and resource limits make
    coverage unavailable until a later verified block can start a new epoch.
    """

    MAX_SEEN = 500_000
    MAX_CUTS = 3

    def __init__(self, rpc):
        self.rpc = rpc
        self.reset()

    def reset(self) -> None:
        self._frame: int | None = None
        self._tip: str | None = None
        self._since = 0
        self._baseline = 0
        self._last_event: int | None = None
        self._seen: set[str] = set()
        self._cuts: OrderedDict[str, tuple[str, int, frozenset[str]] | None] = OrderedDict()

    def has_boundary(self, block_hash: str) -> bool:
        return block_hash in self._cuts

    def observed_before(self, block_hash: str, previous_hash: str) -> tuple[int, frozenset[str]] | None:
        cut = self._cuts.get(block_hash)
        if cut is None or cut[0] != previous_hash:
            return None
        return cut[1], cut[2]

    def _start(self, block_hash: str) -> None:
        if self.rpc.call("getbestblockhash") != block_hash:
            return  # Catching up with historical notifications.
        for method, field, required in (
            ("getblockchaininfo", "initialblockdownload", False),
            ("getmempoolinfo", "loaded", True),
            ("getnetworkinfo", "localrelay", True),
        ):
            info = self.rpc.call(method)
            if not isinstance(info, dict) or info.get(field) is not required:
                LOG.info("Waiting for %s=%s before observing the local mempool", field, required)
                return
        snapshot = self.rpc.call("getrawmempool", False, True)
        since = int(time.time())
        if self.rpc.call("getbestblockhash") != block_hash:
            return
        if not isinstance(snapshot, dict):
            raise ValueError("Invalid mempool snapshot")
        txids = snapshot.get("txids")
        sequence = snapshot.get("mempool_sequence")
        if (type(sequence) is not int or not 0 <= sequence < 2**64
                or not isinstance(txids, list) or len(txids) > self.MAX_SEEN
                or not all(isinstance(t, str) and _TXID.fullmatch(t) for t in txids)):
            raise ValueError("Invalid or oversized mempool snapshot")
        self._seen = set(txids)
        self._since = since
        self._baseline = sequence
        self._last_event = None
        self._tip = block_hash
        LOG.info("Started local mempool observation at block %s (%d txids)", block_hash, len(self._seen))

    def _connect(self, block_hash: str) -> None:
        cut = None
        try:
            if self._tip is not None:
                header = self.rpc.call("getblockheader", block_hash)
                if (isinstance(header, dict) and header.get("hash") == block_hash
                        and header.get("previousblockhash") == self._tip):
                    cut = (self._tip, self._since, frozenset(self._seen))
                    self._tip = block_hash
                else:
                    self.reset()
            if self._tip is None:
                self._start(block_hash)
        except (RPCError, ValueError):
            self.reset()
            LOG.warning("Mempool observation unavailable; will retry on a block connection")
        self._cuts[block_hash] = cut
        if len(self._cuts) > self.MAX_CUTS:
            self._cuts.popitem(last=False)

    def process(self, frames: list[bytes]) -> bool:
        """Apply one sequence message; True wakes chain reconciliation on C/D."""
        if (len(frames) != 3 or frames[0] != b"sequence" or len(frames[2]) != 4
                or len(frames[1]) not in (33, 41)):
            self.reset()
            return False
        body = frames[1]
        kind = body[32:33]
        if not ((kind in (b"A", b"R") and len(body) == 41)
                or (kind in (b"C", b"D") and len(body) == 33)):
            self.reset()
            return False
        frame = int.from_bytes(frames[2], "little")
        if self._frame is not None and frame != (self._frame + 1) % 2**32:
            LOG.warning("Mempool ZMQ sequence gap; resetting observation")
            self.reset()
        if kind == b"D":
            self.reset()
        hash_hex = body[:32].hex()  # Core sends display-order hashes on this topic.
        if kind == b"C":
            self._connect(hash_hex)
        elif kind in (b"A", b"R") and self._tip is not None:
            seq = int.from_bytes(body[33:], "little")
            if self._last_event is None and seq < self._baseline:
                self._frame = frame
                return False  # Already reflected in the RPC snapshot.
            if self._last_event is not None and seq <= self._last_event:
                self.reset()
                return False
            # Mined removals increment Core's mempool sequence without publishing
            # an R event. The four-byte topic counter detects lost messages.
            self._last_event = seq
            if kind == b"A":
                self._seen.add(hash_hex)
                if len(self._seen) > self.MAX_SEEN:
                    LOG.warning("Mempool observation reached txid limit; starting a new epoch on next block")
                    self.reset()
        self._frame = frame
        return kind in (b"C", b"D")
