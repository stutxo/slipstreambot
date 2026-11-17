"""Serve the watcher's latest MARA reports from its active-chain database."""

from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import sqlite3


MAINNET_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def _finding_summary(finding: dict) -> dict:
    violations = finding.get("violations", [])
    comparisons = {violation.get("slipstream") for violation in violations}
    if "reject" in comparisons:
        assessment = "An observed exception falls outside a published Slipstream rule."
    elif comparisons == {"within_published_rule"}:
        assessment = "The observed exceptions fit published Slipstream rules."
    else:
        assessment = "Fit with published Slipstream rules is unknown."
    return {"txid": finding["txid"], "reasons": [v["detail"] for v in violations],
            "slipstream_assessment": assessment}


def read_blocks(state_path: str | Path) -> dict:
    uri = Path(state_path).expanduser().resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        # Keep the cursor and reports on the same chain during a reorg.
        db.execute("BEGIN")
        state = db.execute(
            "SELECT CASE WHEN height >= start_height THEN height END, lower(genesis) "
            "FROM chain_state WHERE singleton = 1"
        ).fetchone()
        rows = db.execute("""
            SELECT height, hash, report FROM blocks
            WHERE json_extract(report, '$.pool') = 'MARA'
            ORDER BY height DESC LIMIT 50
        """)
        blocks = []
        for height, block_hash, raw_report in rows:
            report = json.loads(raw_report)
            blocks.append({
                "height": height, "hash": block_hash, "time": report["time"],
                "transactions": report["transactions_examined"] + 1,
                "findings": [_finding_summary(finding) for finding in report["findings"]],
            })
    return {"height": state[0] if state else None,
            "mainnet": state is not None and state[1] == MAINNET_GENESIS, "blocks": blocks}


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
            elif route == "/blocks.json":
                content_type = "application/json"
                try:
                    data = read_blocks(state_path)
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
