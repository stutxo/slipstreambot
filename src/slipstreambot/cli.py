"""Foreground CLI for monitoring, inspecting blocks, and generic notifications."""

import argparse
from functools import partial
import json
import logging
import sys
from uuid import uuid4

from .config import ConfigError, load_config, rpc_options
from .monitor import Monitor
from .notifications import Notification, NotificationError, build_backends, notify_many
from .policy import analyze_block, block_notification
from .rpc import BitcoinRPC, RPCError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watch MARA blocks for policy exceptions; submission routes remain unproven.")
    parser.add_argument("--config", default="config.toml", help="TOML config path (default: config.toml)")
    parser.add_argument("--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("watch", help="Watch hashblock ZMQ and reconcile the active RPC chain")
    scan = commands.add_parser("scan", help="Print policy observations for a block without modifying watcher state")
    scan.add_argument("block", help="Block height or 64-character block hash")
    scan.add_argument("--notify", action="store_true", help="Also send resulting MARA alert to configured destinations")
    notify = commands.add_parser("notify", help="Send a reusable notification, without connecting to Bitcoin")
    notify.add_argument("--title", required=True)
    notify.add_argument("--body", required=True)
    notify.add_argument("--url")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    # HTTP debug loggers can expose credentials in URLs (notably Telegram).
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests_oauthlib").setLevel(logging.WARNING)
    logging.getLogger("oauthlib").setLevel(logging.WARNING)
    rpc = None
    monitor = None
    try:
        config = load_config(args.config)
        if args.command == "notify":
            backends = build_backends(config["notifiers"])
            notification = Notification(f"manual:{uuid4()}", args.title, args.body, args.url)
            failures = notify_many(notification, backends)
            for name, error in failures.items():
                logging.error("Notifier %s: %s", name, error)
            return int(bool(failures))
        options = config["monitor"]
        tags = tuple(options["mara_tags"]) if "mara_tags" in options else None
        analyze = partial(analyze_block, mara_tags=tags)
        rpc = BitcoinRPC(**rpc_options(config))
        if args.command == "scan":
            value = args.block
            if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
                block_hash = value.lower()
            elif value.isdecimal():
                block_hash = rpc.call("getblockhash", int(value))
            else:
                raise ConfigError("Block must be a nonnegative height or 64-character hexadecimal hash")
            block = rpc.call("getblock", block_hash, 3)
            if block.get("confirmations", 0) < 1:
                raise ConfigError("Block is not on the active chain")
            report = analyze(block)
            print(json.dumps(report, indent=2))
            if args.notify and (notification := block_notification(report)):
                failures = notify_many(notification, build_backends(config["notifiers"]))
                for name, error in failures.items():
                    logging.error("Notifier %s: %s", name, error)
                return int(bool(failures))
            return 0
        monitor = Monitor(
            rpc, zmq_endpoint=config["bitcoin"]["zmq_endpoint"], state_path=options["state_path"],
            analyze=analyze, notification=block_notification, backends=build_backends(config["notifiers"]),
            poll_seconds=options["poll_seconds"], start_height=options.get("start_height"),
        )
        monitor.run()
        return 0
    except KeyboardInterrupt:
        return 0
    except (ConfigError, RPCError, NotificationError, OSError, ValueError, RuntimeError) as exc:
        logging.error("%s", exc)
        return 1
    finally:
        if monitor is not None:
            monitor.close()
        if rpc is not None:
            rpc.close()


if __name__ == "__main__":
    sys.exit(main())
