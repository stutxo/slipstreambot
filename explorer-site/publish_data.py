"""Publish the explorer's public JSON to a dedicated archive-data Git checkout."""

import argparse
from contextlib import closing
import fcntl
import filecmp
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from slipstreambot.config import load_config


BRANCH = "archive-data"


def git(checkout, *args):
    return subprocess.check_output(["git", "-C", str(checkout), *args], text=True).strip()


def data_files(directory):
    paths = [Path("archive.json"), Path("blocks.json")]
    paths.extend(sorted(path.relative_to(directory) for path in (directory / "details").glob("*.json")
                        if re.fullmatch(r"[0-9]+\.json", path.name)))
    return paths


def equivalent(source, dest, path):
    if not (dest / path).is_file():
        return False
    if filecmp.cmp(source / path, dest / path, shallow=False):
        return True
    if path.parent == Path("details"):
        return False
    # Non-MARA tips and export timestamps alone don't change the public archive.
    def content(directory):
        data = json.loads((directory / path).read_bytes())
        data.pop("snapshot", None)
        data.pop("height", None)
        return data
    expected = content(source)
    try:
        return expected == content(dest)
    except (ValueError, AttributeError):
        # Replace a truncated index left by an interrupted copy.
        return False


def publish(config, checkout):
    if git(checkout, "rev-parse", "--show-toplevel") != str(checkout):
        raise ValueError("Expected a dedicated Git checkout")
    if git(checkout, "symbolic-ref", "--short", "HEAD") != BRANCH:
        raise ValueError("Public data checkout must be on archive-data")

    state = Path(load_config(str(config))["monitor"]["state_path"])
    archive = state.with_name("archive.sqlite3")
    # A missing/unmounted archive must never replace public history with just
    # the few recent live reports. The explorer itself supports live-only use.
    with closing(sqlite3.connect(archive.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if not db.execute("SELECT 1 FROM archive_blocks LIMIT 1").fetchone():
            raise ValueError("No verified archive rows to publish")

    with tempfile.TemporaryDirectory(prefix="mara-public-data-") as folder:
        output = Path(folder)
        subprocess.run([sys.executable, str(Path(__file__).with_name("build.py")), "--config",
                        str(config), "--output", folder], check=True)
        index = json.loads((output / "archive.json").read_bytes())
        if not index["mainnet"] or not index["blocks"]:
            raise ValueError("Public MARA archive requires a populated mainnet index")
        files = data_files(output)
        tracked = git(checkout, "ls-files").splitlines()
        if any(name not in {"archive.json", "blocks.json"} and
               not re.fullmatch(r"details/[0-9]+\.json", name) for name in tracked):
            raise ValueError("Public branch contains files outside the explorer data set")
        stale = set(map(Path, tracked)).difference(files)
        if stale or not all(equivalent(output, checkout, path) for path in files):
            (checkout / "details").mkdir(exist_ok=True)
            for path in files:
                if not (checkout / path).exists() or not filecmp.cmp(output / path, checkout / path, shallow=False):
                    shutil.copyfile(output / path, checkout / path)
            for path in stale:
                (checkout / path).unlink(missing_ok=True)
        # Resume after interruption between copying, staging, committing and pushing.
        git(checkout, "add", "-A", "--", *(str(path) for path in sorted(set(files) | stale)))
        if git(checkout, "diff", "--cached", "--name-only"):
            git(checkout, "commit", "-m", "Update verified MARA block archive")
        head = git(checkout, "rev-parse", "HEAD")
        published = subprocess.run(["git", "-C", str(checkout), "rev-parse", "--verify", "--quiet",
                                    f"refs/remotes/origin/{BRANCH}"], capture_output=True, text=True)
        if head != published.stdout.strip():
            git(checkout, "push", "--set-upstream", "origin", BRANCH)
            print(f"Published archive data at {head}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml", type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    with (checkout / ".git" / "archive-publisher.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        publish(args.config.resolve(), checkout)


if __name__ == "__main__":
    main()
