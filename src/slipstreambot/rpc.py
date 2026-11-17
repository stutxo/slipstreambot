"""Small read-only Bitcoin Core JSON-RPC client."""

from __future__ import annotations

import itertools
from pathlib import Path
from urllib.parse import urlsplit

import requests


class RPCError(RuntimeError):
    """A sanitized RPC failure; ``code`` is Core's error code when available."""

    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class BitcoinRPC:
    # An explicit allowlist prevents this client from being used to mutate node
    # or wallet state, including through otherwise innocuous-looking extensions.
    READ_METHODS = frozenset({
        "getblockchaininfo", "getblockcount", "getbestblockhash", "getblockhash",
        "getblock", "getblockheader", "getnetworkinfo", "getindexinfo",
        "getrawtransaction", "decoderawtransaction", "gettxout", "getmempoolinfo",
        "getrawmempool", "getmempoolentry", "getblockstats", "getchaintips",
    })

    def __init__(self, url: str, cookie_file: str | None = None,
                 username: str | None = None, password: str | None = None,
                 timeout: float = 30) -> None:
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment)
            parsed.port  # Validate without including the supplied URL in errors.
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("RPC URL must be HTTP(S), without embedded credentials or query")
        if timeout <= 0:
            raise ValueError("RPC timeout must be positive")
        if cookie_file and (username is not None or password is not None):
            raise ValueError("Choose cookie authentication or explicit RPC credentials")
        if not cookie_file and (username is None or password is None):
            raise ValueError("RPC cookie or both username and password are required")
        self.url = url
        self.cookie_file = Path(cookie_file).expanduser() if cookie_file else None
        self.username = username
        self.password = password
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._session = requests.Session()

    def call(self, method: str, *params):
        if method not in self.READ_METHODS:
            raise RPCError("RPC method is not in the read-only allowlist")
        if self.cookie_file is not None:
            try:
                cookie = self.cookie_file.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                raise RPCError("Cannot read RPC authentication cookie; check path and permissions") from None
            user, separator, password = cookie.partition(":")
            if not separator or not user or not password:
                raise RPCError("RPC authentication cookie is malformed")
            auth = (user, password)
        else:
            auth = (self.username, self.password)
        request_id = next(self._ids)
        try:
            response = self._session.post(
                self.url, json={"jsonrpc": "2.0", "id": request_id,
                                "method": method, "params": list(params)},
                auth=auth, timeout=self.timeout, allow_redirects=False,
            )
        except requests.Timeout:
            raise RPCError("RPC request timed out; check node availability") from None
        except requests.RequestException:
            raise RPCError("RPC connection failed; check network, TLS, and node availability") from None
        try:
            if response.status_code in {401, 403}:
                raise RPCError("RPC authentication or permission denied; check credentials and rpcwhitelist")
            if 300 <= response.status_code < 400:
                raise RPCError("RPC redirects are refused")
            try:
                payload = response.json()
            except ValueError:
                raise RPCError(f"RPC returned invalid JSON (HTTP {response.status_code})") from None
            if not isinstance(payload, dict) or payload.get("id") != request_id:
                raise RPCError("RPC returned an invalid or mismatched response ID")
            error = payload.get("error")
            if error is not None:
                code = error.get("code") if isinstance(error, dict) else None
                if not isinstance(code, int) or isinstance(code, bool):
                    code = None
                reasons = {
                    -1: "node operation failed (requested block data may be pruned or unavailable)",
                    -5: "requested block or transaction is unavailable",
                    -8: "requested parameter or block height is out of range",
                    -28: "node is warming up",
                    -32600: "invalid request or RPC permission denied",
                    -32601: "RPC method unavailable; check node version and permissions",
                    -32602: "RPC parameters are unsupported; check node version",
                }
                # Node/proxy error text is untrusted and can echo credentials.
                reason = reasons.get(code, "node rejected the request")
                raise RPCError(f"RPC {method}: {reason} (code {code})", code=code)
            if response.status_code >= 400:
                raise RPCError(f"RPC HTTP failure ({response.status_code})")
            if "result" not in payload:
                raise RPCError("RPC response is missing its result")
            return payload["result"]
        finally:
            response.close()

    def close(self) -> None:
        self._session.close()
