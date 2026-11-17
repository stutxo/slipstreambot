"""Evidence-based comparison of confirmed transactions, not mempool simulation."""

from decimal import Decimal

from .scripts import (
    is_push_only, legacy_stack_size, minimal_push, multisig, operations,
    pushed_stack, script_kind, sigops, witness_program,
)

MARA_TAGS = (
    "MARA Pool", "MARA Made in USA", "mara_pool_sv2", "mara-pool-sv2",
    "mara_jdc_sv2", "Sv2/MARA",
)
PROFILES = {
    "core": "Bitcoin Core v32.1 defaults",
    "libre": "Libre Relay v31.2 (8f182a3c013da07f33102aefed06180862c83102)",
    "slipstream": "Published MARA rules, retrieved 2026-11-17; incomplete policy specification",
}
COVERAGE = (
    "Structural observations on consensus-validated blocks, NOT a complete policy/script validator.",
    "No finding does not establish standardness. Signature encodings, general script execution, "
    "CONST_SCRIPTCODE FindAndDelete, and execution-dependent flags are not fully evaluated.",
    "CLEANSTACK is checked only for recognized legacy templates and simple straight-line scripts; "
    "SegWit clean-stack requirements are consensus rules, not relaxable policy.",
    "Historical mempool, fee deltas, replacement/RBFR and package/cluster state cannot be reconstructed "
    "from a block. Same-block dependencies are not proof of simultaneous relay.",
    "Coinbase tags are spoofable attribution evidence; no on-chain evidence proves submission route.",
    "Slipstream's SCRIPT_SIG PUSH ONLY / 10kv/bytes wording is interpreted as a 10,000-byte "
    "size ceiling, not evidence that non-push-only scriptSigs are accepted. Unpublished rules are unknown.",
)


def _script(output: dict) -> bytes:
    return bytes.fromhex(output["scriptPubKey"]["hex"])


def _satoshis(value) -> int:
    return int(Decimal(str(value)) * 100_000_000)


def _compact_size(size: int) -> int:
    return 1 if size < 253 else 3 if size <= 65535 else 5


def _dust_threshold(script: bytes) -> int:
    if script[:1] == b"\x6a" or len(script) > 10000:
        return 0
    spend_size = 67 if witness_program(script) else 148
    return 3 * (8 + _compact_size(len(script)) + len(script) + spend_size)


def _route(violations: list[dict]) -> str:
    if any(v["libre"] == "reject" for v in violations):
        if all(v["slipstream"] == "within_published_rule" for v in violations):
            return "Outside pinned Libre policy; observed exceptions fit published Slipstream rules. Route unproven."
        return "Outside pinned Libre policy; Slipstream eligibility unknown or outside published limits. Route unproven."
    if any(v["libre"] == "unknown" for v in violations):
        return "Libre Relay and Slipstream eligibility unknown; missing input context. Route unproven."
    return "Observed Core exceptions fit pinned Libre rules; no proof of Libre Relay or Slipstream submission."


def analyze_transaction(tx: dict) -> tuple[dict | None, list[str]]:
    violations: list[dict] = []
    gaps: list[str] = []

    def add(code: str, detail: str, *, libre: str = "reject", slipstream: str = "unknown"):
        violations.append({"code": code, "detail": detail, "core": "reject", "libre": libre, "slipstream": slipstream})

    def slip_limit(value: int, maximum: int) -> str:
        return "within_published_rule" if value <= maximum else "reject"

    weight = tx["weight"]
    if weight > 400_000:
        add("tx-weight", f"{weight:,} WU > 400,000 WU", slipstream=slip_limit(weight, 3_991_000))
    if tx["version"] not in (1, 2, 3):
        add("version", f"Transaction version {tx['version']} is outside 1..3")
    if "size" in tx and (weight - tx["size"]) // 3 < 65:
        add("tx-size-small", "Non-witness transaction size is below 65 bytes")

    scripts = [_script(out) for out in tx["vout"]]
    kinds = [script_kind(script) for script in scripts]
    datacarrier = sum(len(s) for s, kind in zip(scripts, kinds) if kind == "nulldata")
    if datacarrier > 100_000:
        add("op-return-size", f"OP_RETURN scripts total {datacarrier:,} bytes > 100,000 bytes",
            slipstream=slip_limit(datacarrier * 4, 3_991_000))
    for number, (script, kind) in enumerate(zip(scripts, kinds)):
        if kind == "nonstandard":
            add("scriptpubkey", f"Output {number}: unrecognized output template")
        elif kind == "multisig":
            required, keys = multisig(script)
            if keys > 3:
                add("bare-multisig", f"Output {number}: {required}-of-{keys}, Core/Libre allow at most 3 keys",
                    slipstream=slip_limit(keys, 16))
    dust = [i for i, (out, script) in enumerate(zip(tx["vout"], scripts))
            if _satoshis(out["value"]) < _dust_threshold(script)]
    if len(dust) > 1:
        add("dust", f"{len(dust)} dust outputs; at most one ephemeral dust output is permitted")
    elif dust:
        fee = tx.get("fee")
        if fee is None and all("prevout" in vin for vin in tx["vin"]):
            fee = (sum(_satoshis(v["prevout"]["value"]) for v in tx["vin"])
                   - sum(_satoshis(out["value"]) for out in tx["vout"])) / 100_000_000
        if fee is not None and _satoshis(fee) != 0:
            add("dust-fee", f"Dust output {dust[0]} with nonzero fee (default policy, without fee deltas)")
        else:
            gaps.append("One dust output: ephemeral-dust package eligibility is unknown.")

    legacy_cost = sum(sigops(s, accurate=False) * 4 for s in scripts)
    bip54_sigops = 0
    witness_cost = 0
    extra_p2sh_cost = 0
    missing_prevouts = 0
    annexes: dict[int, bytes] = {}
    for number, vin in enumerate(tx["vin"]):
        script_sig = bytes.fromhex(vin.get("scriptSig", {}).get("hex", ""))
        legacy_cost += sigops(script_sig, accurate=False) * 4
        if len(script_sig) > 1650:
            add("scriptsig-size", f"Input {number}: scriptSig {len(script_sig):,} bytes > 1,650",
                slipstream=slip_limit(len(script_sig), 10_000))
        if not is_push_only(script_sig):
            add("scriptsig-not-pushonly", f"Input {number}: scriptSig is not push-only")
        stack = pushed_stack(script_sig)
        if stack is not None and any(data is not None and not minimal_push(op, data) for op, data in operations(script_sig)):
            add("minimaldata", f"Input {number}: non-minimal scriptSig push encoding")
        prevout = vin.get("prevout")
        if prevout is None:
            missing_prevouts += 1
            continue
        previous_script = _script(prevout)
        kind = script_kind(previous_script)
        if kind in ("nonstandard", "witness_unknown"):
            add("input-template", f"Input {number}: spends {kind} prevout")
        executed = previous_script
        initial = len(stack) if stack is not None else None
        wrapped = kind == "scripthash"
        if wrapped:
            if not stack:
                gaps.append(f"Input {number}: P2SH redeem script unavailable.")
                continue
            executed = stack[-1]
            initial -= 1
            count = sigops(executed)
            extra_p2sh_cost += count * 4
            if count > 15:
                add("p2sh-sigops", f"Input {number}: redeem script has {count} sigops > 15")
        bip54_sigops += sigops(script_sig) + sigops(executed)
        program = witness_program(executed)
        if program is None:
            try:
                has_separator = any(op == 171 for script in (script_sig, executed) for op, _ in operations(script))
            except ValueError:
                has_separator = False
                gaps.append(f"Input {number}: malformed Script cannot be inspected fully.")
            if has_separator:
                add("const-scriptcode", f"Input {number}: OP_CODESEPARATOR in legacy script",
                    slipstream="within_published_rule")
            depth = legacy_stack_size(executed, initial) if initial is not None else None
            if depth is not None and depth > 1:
                add("cleanstack", f"Input {number}: legacy script leaves {depth} stack items",
                    slipstream="within_published_rule")
            elif depth is None:
                gaps.append(f"Input {number}: CLEANSTACK requires general script execution.")
            continue

        version, program_bytes = program
        witness = [bytes.fromhex(item) for item in vin.get("txinwitness", [])]
        if version == 0 and len(program_bytes) == 20:
            witness_cost += 1
        elif version == 0 and len(program_bytes) == 32 and witness:
            witness_cost += sigops(witness[-1])
            if len(witness[-1]) > 3600:
                add("p2wsh-script-size", f"Input {number}: witness script exceeds 3,600 bytes")
            if len(witness) - 1 > 100:
                add("p2wsh-stack-count", f"Input {number}: witness has more than 100 arguments")
            if any(len(item) > 80 for item in witness[:-1]):
                add("p2wsh-stack-item", f"Input {number}: witness argument exceeds 80 bytes")
        elif version == 1 and len(program_bytes) == 32 and not wrapped:
            if len(witness) >= 2 and witness[-1][:1] == b"\x50":
                annexes[number] = witness.pop()
            if len(witness) >= 2 and witness[-1]:
                leaf_version = witness[-1][0] & 0xFE
                if leaf_version != 0xC0:
                    add("taproot-leaf-version", f"Input {number}: unknown Taproot leaf version {leaf_version:#x}")
                elif any(len(item) > 80 for item in witness[:-2]):
                    add("tapscript-stack-item", f"Input {number}: tapscript argument exceeds 80 bytes")
        elif executed == b"\x51\x02\x4e\x73":
            if witness:
                add("anchor-witness", f"Input {number}: P2A witness stuffing")
        else:
            add("unknown-witness-spend", f"Input {number}: unsupported witness version/program")

    if annexes:
        libre_annex = len(annexes) == len(tx["vin"]) and all(len(a) == 1 or a[1] == 0 for a in annexes.values())
        add("taproot-annex", f"Taproot annex in {len(annexes)} of {len(tx['vin'])} inputs",
            libre="within_pinned_rule" if libre_annex else "unknown" if missing_prevouts else "reject")
    if missing_prevouts:
        gaps.append(f"{missing_prevouts} input prevouts missing: input, witness, sigop and fee checks are incomplete.")
    if bip54_sigops > 2500:
        add("legacy-sigops", f"At least {bip54_sigops} potentially executed legacy sigops > 2,500")
    sigop_cost = legacy_cost + extra_p2sh_cost + witness_cost
    if sigop_cost > 16000:
        add("tx-sigops", f"At least {sigop_cost} sigop cost > 16,000")
    adjusted_weight = max(weight, sigop_cost * 20)
    if tx["version"] == 3 and adjusted_weight > 40_000:
        add("truc-size", f"TRUC transaction sigop-adjusted weight at least {adjusted_weight:,} WU > 40,000 WU",
            slipstream=slip_limit(adjusted_weight, 3_991_000))
    if not violations:
        return None, gaps
    return {
        "txid": tx["txid"], "weight": weight, "violations": violations,
        "route_assessment": _route(violations), "coverage": gaps,
    }, gaps


def analyze_block(block: dict, *, mara_tags: tuple[str, ...] | None = None) -> dict:
    tags = MARA_TAGS if mara_tags is None else mara_tags
    coinbase = bytes.fromhex(block["tx"][0]["vin"][0]["coinbase"])
    evidence = [tag for tag in tags if tag.encode("utf-8") in coinbase]
    report = {
        "height": block["height"], "hash": block["hash"],
        "previousblockhash": block.get("previousblockhash"), "time": block["time"],
        "pool": "MARA" if evidence else None, "pool_evidence": evidence,
        "profiles": dict(PROFILES), "findings": [], "coverage": list(COVERAGE),
        "transactions_examined": 0,
    }
    if not evidence:
        report["coverage"].append("Not attributed to MARA; transactions were not analyzed.")
        return report
    incomplete = 0
    block_txids = {tx["txid"] for tx in block["tx"][1:]}
    for tx in block["tx"][1:]:
        finding, gaps = analyze_transaction(tx)
        if finding and tx["version"] == 3 and any(vin.get("txid") in block_txids for vin in tx["vin"]):
            gaps.append("Same-block parent: historical TRUC child/package status is unknown; "
                        "Slipstream only publishes a parent-size exception.")
            for violation in finding["violations"]:
                if violation["code"] == "truc-size":
                    violation["slipstream"] = "unknown"
            finding["route_assessment"] = _route(finding["violations"])
        report["transactions_examined"] += 1
        incomplete += bool(gaps)
        if finding:
            report["findings"].append(finding)
    if incomplete:
        report["coverage"].append(f"{incomplete} transactions have additional input/package coverage gaps.")
    return report


def block_notification(report: dict):
    from .notifications import Notification

    if report["pool"] != "MARA" or not report["findings"]:
        return None
    findings = report["findings"]
    lines = [f"Block {report['height']} ({report['hash']})", "Coinbase tag attribution; submission route UNPROVEN."]
    for finding in findings:
        lines.append(f"\nTX {finding['txid']} ({finding['weight']:,} WU)")
        lines.extend(f"- {item['code']}: {item['detail']}" for item in finding["violations"])
        lines.append(finding["route_assessment"])
    lines.append("\nPartial policy analysis: Core v32.1 / Libre v31.2; not full script or historical mempool validation.")
    return Notification(
        event_id=f"block:{report['hash']}",
        title=f"MARA: {len(findings)} tx with Core policy exceptions",
        body="\n".join(lines),
    )
