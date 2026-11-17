"""Read the combined watcher and historical MARA block index."""

from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import re
import sqlite3

from .policy import SLIPSTREAM_ANNOUNCEMENT, block_signals


MAINNET_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
BUCKET_SIZE = 1000


@contextmanager
def archive_reader(state_path: str | Path):
    """Pin both databases for a whole response or export, including reorgs."""
    state_path = Path(state_path).expanduser().resolve()
    with closing(sqlite3.connect(state_path.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        archive = state_path.with_name("archive.sqlite3")
        has_archive = archive != state_path and archive.is_file()
        if has_archive:
            db.execute("ATTACH DATABASE ? AS historical", (archive.as_uri() + "?mode=ro",))
        db.execute("BEGIN")
        state = db.execute("SELECT start_height, height, genesis FROM chain_state WHERE singleton=1").fetchone()
        mainnet = bool(state and state["genesis"].lower() == MAINNET_GENESIS)
        has_archive = mainnet and has_archive
        if has_archive:
            has_archive = bool(db.execute(
                "SELECT 1 FROM historical.sqlite_master WHERE type='table' AND name='archive_blocks'"
            ).fetchone())
        height = state["height"] if state and state["height"] >= state["start_height"] else None
        yield db, {"height": height, "mainnet": mainnet}, has_archive


def _rows(db, has_archive, *, bucket=None, limit=None, summary=False):
    # The live DB records every pool. A conflicting block at the same height, or
    # a rollback below the archived height, supersedes the stale archive entry.
    bounds = () if bucket is None else (bucket * BUCKET_SIZE, (bucket + 1) * BUCKET_SIZE)
    live_filter = " AND b.height>=? AND b.height<?" if bounds else ""
    evidence = "json_extract(b.report,'$.pool_evidence')"
    join = ""
    if has_archive and not summary:
        join = "LEFT JOIN historical.archive_blocks a ON a.hash=b.hash AND a.height=b.height"
        evidence = f"COALESCE(a.evidence,{evidence})"
    live = f"""
        SELECT b.height AS height, b.hash AS hash, json_extract(b.report,'$.time') AS time,
               json_extract(b.report,'$.transactions_examined')+1 AS transactions,
               {evidence} AS evidence, b.report AS report
        FROM blocks b {join}
        WHERE json_extract(b.report,'$.pool')='MARA' {live_filter}
    """
    params = list(bounds)
    if has_archive:
        archive_filter = " AND a.height>=? AND a.height<?" if bounds else ""
        live += f"""
            UNION ALL
            SELECT a.height, a.hash, a.time, a.tx_count, a.evidence, a.report
            FROM historical.archive_blocks a
            LEFT JOIN blocks b ON b.height=a.height
            WHERE (a.height < (SELECT start_height FROM chain_state WHERE singleton=1)
                   OR (a.hash=b.hash AND json_extract(b.report,'$.pool') IS NOT 'MARA'))
                {archive_filter}
        """
        params.extend(bounds)
    if summary:
        # Historical reports can contain thousands of findings. Send only counts to
        # the browser. Compute a union only when covered mempool misses also exist.
        query = f"""
            SELECT height, hash, time, transactions,
                CASE WHEN json_extract(report,'$.mempool.status')='covered'
                     THEN json_array_length(report,'$.mempool.not_observed') END AS mempool_not_observed,
                CASE WHEN json_extract(report,'$.mempool.status')='covered'
                      AND json_array_length(report,'$.mempool.not_observed')>0
                     THEN (SELECT COUNT(*) FROM (
                               SELECT value AS txid FROM json_each(report,'$.mempool.not_observed')
                               UNION SELECT json_extract(value,'$.txid') FROM json_each(report,'$.findings')
                           ))
                     ELSE json_array_length(report,'$.findings') END AS flagged
            FROM ({live})
        """
    else:
        query = live
    query += " ORDER BY height DESC"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
    return db.execute(query, params)


def _detail(row):
    item = {key: row[key] for key in ("height", "hash", "time", "transactions")}
    item["evidence"] = json.loads(row["evidence"] or "[]")
    item["analyzed"] = row["report"] is not None
    item["pre_slipstream"] = row["time"] < SLIPSTREAM_ANNOUNCEMENT
    report = json.loads(row["report"]) if item["analyzed"] else {"findings": []}
    report["pre_slipstream"] = item["pre_slipstream"]
    summary, findings = block_signals(report)
    observation = report.get("mempool") or {}
    item.update(mempool_summary=summary, findings=findings, mempool_not_observed=(
        len(set(observation["not_observed"])) if observation.get("status") == "covered" else None
    ))
    return item


def read_blocks(state_path: str | Path) -> dict:
    with archive_reader(state_path) as (db, meta, archived):
        return {**meta, "blocks": [_detail(r) for r in _rows(db, archived, limit=50)]}


def archive_index(db, meta, archived):
    return {**meta, "blocks": [dict(row) for row in _rows(db, archived, summary=True)]}


def detail_bucket(db, archived, bucket):
    return {"blocks": [_detail(row) for row in _rows(db, archived, bucket=bucket)]}


def serve_explorer(state_path: str, port: int) -> None:
    if not 0 <= port <= 65535:
        raise ValueError("Explorer port must be between 0 and 65535")
    page = Path(__file__).with_name("explorer.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = self.path.partition("?")[0]
            status = 200
            if route == "/":
                content_type, body = "text/html; charset=utf-8", page
            elif route == "/feed-config.json":
                content_type, body = "application/json", b"{}"
            elif route in ("/archive.json", "/blocks.json") or re.fullmatch(r"/details/[0-9]{1,7}\.json", route):
                content_type = "application/json"
                try:
                    if route == "/blocks.json":
                        data = read_blocks(state_path)
                    else:
                        with archive_reader(state_path) as (db, meta, archived):
                            if route == "/archive.json":
                                data = archive_index(db, meta, archived)
                            else:
                                bucket = int(route.split("/")[-1].split(".")[0])
                                data = detail_bucket(db, archived, bucket)
                except (sqlite3.Error, ValueError, KeyError, TypeError):
                    logging.exception("Cannot read explorer reports")
                    status = 503
                    data = {"error": "Watcher reports are unavailable."}
                body = json.dumps(data, separators=(",", ":")).encode()
            else:
                self.send_error(404)
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
        logging.info("MARA explorer listening on http://127.0.0.1:%d", server.server_port)
        server.serve_forever()
