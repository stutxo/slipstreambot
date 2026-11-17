"""Small TOML configuration; credentials are resolved from the environment."""

import os
from pathlib import Path
import tomllib


class ConfigError(ValueError):
    pass


def load_config(path: str) -> dict:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot load configuration: {config_path}") from exc
    if set(config) - {"bitcoin", "monitor", "notifiers"}:
        raise ConfigError("Unknown configuration section")
    bitcoin = config.setdefault("bitcoin", {})
    monitor = config.setdefault("monitor", {})
    notifiers = config.setdefault("notifiers", [{"kind": "console"}])
    if not isinstance(bitcoin, dict) or not isinstance(monitor, dict):
        raise ConfigError("bitcoin and monitor must be TOML tables")
    if not isinstance(notifiers, list) or not all(isinstance(n, dict) for n in notifiers):
        raise ConfigError("notifiers must be an array of TOML tables")
    if set(bitcoin) - {"rpc_url", "cookie_file", "rpc_user", "rpc_password_env", "zmq_endpoint",
                       "zmq_sequence_endpoint", "timeout"}:
        raise ConfigError("Unknown bitcoin option")
    if set(monitor) - {"state_path", "poll_seconds", "start_height", "mara_tags"}:
        raise ConfigError("Unknown monitor option")
    bitcoin.setdefault("rpc_url", "http://127.0.0.1:8332")
    bitcoin.setdefault("zmq_endpoint", "tcp://127.0.0.1:28332")
    if "zmq_sequence_endpoint" in bitcoin and (
        not isinstance(bitcoin["zmq_sequence_endpoint"], str) or not bitcoin["zmq_sequence_endpoint"].strip()
    ):
        raise ConfigError("zmq_sequence_endpoint must be a nonempty endpoint string")
    bitcoin.setdefault("timeout", 30)
    if not bitcoin.get("rpc_user") and not bitcoin.get("cookie_file"):
        bitcoin["cookie_file"] = "~/.bitcoin/.cookie"
    if bitcoin.get("cookie_file") and (bitcoin.get("rpc_user") or bitcoin.get("rpc_password_env")):
        raise ConfigError("Use either cookie authentication or rpc_user/rpc_password_env")
    if bool(bitcoin.get("rpc_user")) != bool(bitcoin.get("rpc_password_env")):
        raise ConfigError("rpc_user and rpc_password_env must be specified together")
    monitor.setdefault("state_path", "state/slipstreambot.sqlite3")
    monitor.setdefault("poll_seconds", 30)
    for section, key in ((bitcoin, "cookie_file"), (monitor, "state_path")):
        if key in section:
            value = Path(section[key]).expanduser()
            section[key] = str(value if value.is_absolute() else config_path.parent / value)
    for value in (bitcoin["timeout"], monitor["poll_seconds"]):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 3600:
            raise ConfigError("Timeout and poll interval must be between 0 and 3600 seconds")
    if "start_height" in monitor:
        height = monitor["start_height"]
        if type(height) is not int or height < 0:
            raise ConfigError("start_height must be a nonnegative integer")
    if "mara_tags" in monitor:
        tags = monitor["mara_tags"]
        if not isinstance(tags, list) or not tags or not all(isinstance(t, str) and t for t in tags):
            raise ConfigError("mara_tags must contain nonempty coinbase marker strings")
    return config


def rpc_options(config: dict) -> dict:
    bitcoin = config["bitcoin"]
    password = None
    if env_name := bitcoin.get("rpc_password_env"):
        password = os.environ.get(env_name)
        if not password:
            raise ConfigError(f"Missing environment variable: {env_name}")
    return {
        "url": bitcoin["rpc_url"],
        "cookie_file": bitcoin.get("cookie_file"),
        "username": bitcoin.get("rpc_user"),
        "password": password,
        "timeout": bitcoin["timeout"],
    }
