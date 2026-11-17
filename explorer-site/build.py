"""Build the standalone explorer snapshot from the watcher's saved reports."""

import argparse
from datetime import UTC, datetime
from importlib.resources import files
import json
from pathlib import Path

from slipstreambot.config import load_config
from slipstreambot.explorer import read_blocks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml")
    args = parser.parse_args()
    reports = read_blocks(load_config(args.config)["monitor"]["state_path"])
    reports["snapshot"] = datetime.now(UTC).isoformat(timespec="seconds")

    output = Path(__file__).resolve().parent / "dist"
    output.mkdir(exist_ok=True)
    (output / "index.html").write_bytes(files("slipstreambot").joinpath("explorer.html").read_bytes())
    (output / "blocks.json").write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
