"""Export public MARA block metadata and transaction evidence from SQLite."""

import argparse
from datetime import UTC, datetime
from importlib.resources import files
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit

from slipstreambot.config import load_config
from slipstreambot.explorer import BUCKET_SIZE, archive_index, archive_reader, detail_bucket


def write_asset(path, data):
    if path.exists() and path.read_bytes() == data:
        return
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.chmod(temporary, 0o644)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def write_json(path, payload):
    write_asset(path, (json.dumps(payload, separators=(",", ":")) + "\n").encode())


def build(state_path, output, data_base=None):
    output.mkdir(parents=True, exist_ok=True)
    details = output / "details"
    details.mkdir(exist_ok=True)
    # Pin all exported files to the same view of both databases. Publish the index
    # last so new height buckets already exist when readers navigate to them.
    with archive_reader(state_path) as (db, meta, archived):
        index = archive_index(db, meta, archived)
        recent = []
        buckets = dict.fromkeys(row["height"] // BUCKET_SIZE for row in index["blocks"])
        for bucket in buckets:
            content = detail_bucket(db, archived, bucket)
            write_json(details / f"{bucket}.json", content)
            if len(recent) < 50:
                recent.extend(content["blocks"][:50-len(recent)])
        snapshot = datetime.now(UTC).isoformat(timespec="seconds")
        write_json(output / "blocks.json", {**meta, "blocks": recent, "snapshot": snapshot})
        write_json(output / "archive.json", {**index, "snapshot": snapshot})
    write_json(output / "feed-config.json", {"data_base": data_base} if data_base else {})
    write_asset(output / "index.html", files("slipstreambot").joinpath("explorer.html").read_bytes())
    for path in details.glob("*.json"):
        if path.stem.isdecimal() and int(path.stem) not in buckets:
            path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "dist")
    parser.add_argument("--data-base", help="HTTPS directory serving the refreshed public JSON feed")
    args = parser.parse_args()
    if args.data_base:
        base = urlsplit(args.data_base)
        if base.scheme != "https" or not base.hostname or base.username or base.password or base.query or base.fragment:
            parser.error("--data-base must be a public HTTPS directory URL")
    build(load_config(args.config)["monitor"]["state_path"], args.output, args.data_base)


if __name__ == "__main__":
    main()
