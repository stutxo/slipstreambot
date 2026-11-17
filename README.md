# slipstreambot

Small Python app that watches Bitcoin Core's `hashblock` ZMQ feed, identifies MARA coinbase tags, and sends a notification for every MARA-attributed block. Blocks with no findings receive a "no policy exceptions detected" summary with the block height, hash, and number of non-coinbase transactions examined. Detected exceptions are compared with pinned Libre Relay rules and MARA's published Slipstream exceptions. Blocks attributed to other pools do not trigger notifications.

**A mined transaction cannot prove its submission route.** Alerts say what was observed, not "this used Slipstream". Coinbase tags are also spoofable. This is a structural policy analyzer, not a complete script interpreter or historical mempool simulator; no findings does **not** establish standardness.

## Run

Python 3.11+, Bitcoin Core with ZMQ support and `getblock` verbosity 3 (Core 25+). The policy baseline is **Core v32.1 defaults**, independently of the connected node version. Different releases or local policy settings can give different results.

Add to your node's `bitcoin.conf`, then restart the node:

```ini
server=1
zmqpubhashblock=tcp://127.0.0.1:28332
```

Keep RPC and ZMQ on trusted/local interfaces; ZMQ has no authentication. Use a protected tunnel for a remote node. The application only calls read-only RPCs; it never submits transactions or accesses a wallet.

```sh
uv sync --locked
cp config.example.toml config.toml
# Edit config.toml: RPC URL, cookie path, and desired notifier destinations.
uv run slipstreambot --config config.toml watch
```

Without uv: `python3 -m venv .venv && .venv/bin/pip install -e .`, then `.venv/bin/slipstreambot ...`.

Cookie authentication is the default and is reread on each request to handle node restarts. For a remote node, remove `cookie_file`, set `rpc_user` and `rpc_password_env`, and export that environment variable. Do not put credentials in RPC URLs. Config/state paths are relative to the configuration file; `~` expands normally. `config.toml`, environment files, and state are gitignored.

No `txindex` is required: RPC verbosity 3 supplies spent prevouts from undo data when available. Missing prevouts are reported as incomplete coverage; unavailable/pruned blocks are **not silently skipped**. Backfilling old blocks requires the relevant block/undo data.

First run analyzes the current tip, then new blocks. Set `[monitor].start_height` for inclusive backfill. Existing state always resumes its stored cursor; use a different `state_path` for an independent backfill. Reports (including all findings) and delivery state are stored in SQLite. One watcher may use each state database.

ZMQ is a wakeup, not the chain authority: the watcher reconciles RPC on every notification and every `poll_seconds` (30 by default), recovering missed messages and downtime. Reorgs retract previously delivered alerts, cancel unsent orphan alerts, and scan the replacement branch. Reorg replay does not extend before the original monitoring start height. Delivery is **at least once**: crashes after HTTP success or a partially delivered multi-part message may produce duplicates. A failed destination is retried without stopping other destinations or block processing. Disabled/removed destination names retain pending deliveries until re-enabled; keep names stable and use a new name when changing recipients. State retains reports/outbox history and grows over time.

Run in the foreground under your process supervisor if you want automatic restart. SIGTERM and Ctrl-C stop cleanly. Log output records processed heights, attribution, and finding counts.

## Inspect a block

```sh
uv run slipstreambot --config config.toml scan 900000
uv run slipstreambot --config config.toml scan BLOCK_HASH --notify
```

`scan` prints JSON without changing watcher state. Non-MARA blocks are identified but their transactions are skipped. Without `--notify`, scanning does not load notifier credentials or send messages. Orphaned blocks are rejected by `scan`.

Default MARA tags: `MARA Pool`, `MARA Made in USA`, `mara_pool_sv2`, `mara-pool-sv2`, `mara_jdc_sv2`, `Sv2/MARA`. Set `[monitor].mara_tags` to override them. Identification uses coinbase script bytes, not an external explorer API or substring matches against arbitrary transactions.

## Reusable notifications

Each enabled `[[notifiers]]` table receives alerts. `kind` is `console`, `telegram`, `ntfy`, or `twitter`; optional `name` distinguishes multiple destinations of the same kind. Common options: `enabled` (default true) and `timeout` (15 seconds). Unknown options and duplicate names are rejected.

The example config includes all four providers. Credentials are environment-variable **names**, not secret values:

- **Telegram:** `token_env`, `chat_id`; optional `base_url` (default `https://api.telegram.org`). Bot must be permitted to post to the chat/channel. Plain-text messages are split at 4,096 UTF-16 units.
- **ntfy:** `topic`, optional `server` (default `https://ntfy.sh`), optional `token_env`. Use an access-controlled topic for private alerts; an unguessable anonymous topic is not equivalent to authorization. JSON publishing supports Unicode and splits message bodies at 4,096 UTF-8 bytes.
- **Twitter/X:** `consumer_key_env`, `consumer_secret_env`, `access_token_env`, `access_token_secret_env`; optional `base_url` (default `https://api.x.com`). Uses OAuth 1.0a **user-context** credentials and `POST /2/tweets`; an app-only bearer token is insufficient. Your account/app needs write permissions and an API plan allowing posting. Posts are explicitly abbreviated and conservatively limited to 280 weighted characters; an optional dedicated link remains intact. Detailed block reports remain in SQLite/`scan` output.
- **Console:** stdout; no credentials.

Send any message, without connecting to Bitcoin:

```sh
uv run slipstreambot --config config.toml notify \
  --title 'Node status' --body 'Backup complete' --url https://example.com/status
```

Standalone `notify` and `scan --notify` attempt each sink once and return a nonzero exit code on delivery failure; only `watch` has a durable outbox.

Use the same interface from another Python program:

```python
from slipstreambot.notifications import Notification, build_backends, notify_many

backends = build_backends([{"kind": "ntfy", "topic": "my-status", "token_env": "NTFY_TOKEN"}])
errors = notify_many(Notification("backup:2026-11-17", "Backup complete", "Archive uploaded"), backends)
if errors:
    print(errors)  # sanitized provider failures, no credentials
```

A custom backend only needs a unique `name` and `send(notification)` method. There are no Bitcoin dependencies in the notifier module.

## Compared policy snapshots

Retrieved 2026-11-17. Libre Relay is pinned to v31.2 commit `8f182a3c013da07f33102aefed06180862c83102`, not an assumption that all historical/future Libre versions share these rules. Slipstream's public table is **not** a complete mempool-policy specification.

| Rule | Core v32.1 defaults | Libre Relay v31.2 | Published Slipstream |
|---|---|---|---|
| Transaction weight | 400,000 WU | 400,000 WU | 3,991,000 WU |
| OP_RETURN | 100,000 aggregate script bytes, still subject to total tx weight; multiple outputs allowed | Same | 3,991,000 WU, still subject to total tx weight |
| Bare multisig output | Up to 3 keys | Same | Up to 16-of-16 |
| scriptSig size | 1,650 bytes | Same | "10kv/bytes" under "SCRIPT_SIG PUSH ONLY" |
| Push-only scriptSig | Required | Required | Ambiguous wording; not assumed disabled |
| CLEANSTACK | Required | Required | Disabled (legacy policy only) |
| TRUC transaction size | 10,000 sigop-adjusted vbytes; unconfirmed child 1,000 | Same | 3,991,000-WU parent |
| CONST_SCRIPTCODE | Required | Required | Disabled |
| Taproot annex | Rejected | `50` or `5000...`, and **every input** must carry an annex | Unpublished/unknown |
| Replacement | Core replacement policy | Also permits qualifying 1.25x chunk-feerate replacement | Unpublished/unknown |

A scriptSig is non-witness data: this analyzer interprets the ambiguous published size text as 10,000 serialized bytes, not 10,000 WU. It reports that assumption in coverage metadata. OP_RETURN script bytes contribute four WU each; the limit is not a payload-size guarantee because the transaction has other overhead.

Current Core does **not** have the old default 83-byte/single-OP_RETURN restriction. Ordinary inscriptions and large Taproot script bodies are not flagged merely for containing arbitrary data. Libre's replacement behavior cannot be identified retrospectively from a mined transaction.

### Checked observations

- Weight, transaction version and minimum non-witness size.
- Output templates, aggregate OP_RETURN script bytes, bare multisig key counts.
- scriptSig size, push-only status, and non-minimal pushes in push-only scriptSigs.
- Dust count and nonzero-fee dust, allowing uncertainty for single ephemeral-dust outputs.
- With prevouts: unknown input templates, P2SH sigops, transaction sigop cost, BIP54 legacy sigops, P2WSH script/stack limits, Taproot annex rules and argument sizes, unknown witness/leaf versions, P2A witness stuffing.
- TRUC absolute sigop-adjusted size. Same-block parents are context, **not** proof of historical unconfirmed-child/package eligibility; Slipstream only documents the parent exception.
- Legacy `OP_CODESEPARATOR` (including in unexecuted branches) and provable CLEANSTACK failures for known templates/simple straight-line stack operations.

### Deliberately unknown

Full script execution, general CLEANSTACK, signature encoding/low-S/NULLFAIL, execution-dependent minimal-data/NOP/OP_SUCCESS checks, and CONST_SCRIPTCODE's `FindAndDelete` case are not fully evaluated. Witness clean-stack requirements are consensus rules, not exceptions Slipstream can disable. Historical mempool fee deltas, package/cluster topology, conflicts and relay arrival order are unavailable from a block. A single zero-fee dust output is not automatically nonstandard. Node-specific defaults and unpublished Slipstream rules remain unknown.

Per-rule results mean `reject`, `within_pinned_rule`, `within_published_rule`, or `unknown`—never an assertion that a whole transaction would be accepted. A transaction outside Libre's pinned policy might have reached a miner through Slipstream **or another private/custom path**. Running `testmempoolaccept` on already-mined transactions would not answer this: their inputs have been spent.

### Sources

- [MARA Slipstream published rules](https://slipstream.mara.com/) ([retrieved frontend table](https://slipstream.mara.com/assets/index-DXpDYaoE.js)).
- [Core v32.1 policy constants](https://github.com/bitcoin/bitcoin/blob/v32.1/src/policy/policy.h), [checks](https://github.com/bitcoin/bitcoin/blob/v32.1/src/policy/policy.cpp), [TRUC](https://github.com/bitcoin/bitcoin/blob/v32.1/src/policy/truc_policy.h).
- [Pinned Libre policy constants](https://github.com/petertodd/bitcoin/blob/8f182a3c013da07f33102aefed06180862c83102/src/policy/policy.h), [annex checks](https://github.com/petertodd/bitcoin/blob/8f182a3c013da07f33102aefed06180862c83102/src/policy/policy.cpp), [replacement policy](https://github.com/petertodd/bitcoin/blob/8f182a3c013da07f33102aefed06180862c83102/src/policy/rbf.cpp).
- [Mempool mining-pool tag registry](https://github.com/mempool/mining-pools/blob/master/pools-v2.json).

## Development

```sh
uv run python -m unittest discover -s tests -v
```

Tests cover policy boundaries, missing prevouts, annex namespaces/all-input requirements, notification failures/Unicode limits, RPC errors, durable restart/reorg handling, and independent destination delivery. No external notifications are sent by tests.
