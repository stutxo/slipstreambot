"""Structural Script helpers, deliberately not a consensus interpreter."""


# BIP342 reserves these opcodes in tapscript leaves.
TAPSCRIPT_SUCCESS_OPCODES = frozenset({
    80, 98, 126, 127, 128, 129, 131, 132, 133, 134, 137, 138, 141, 142,
    149, 150, 151, 152, 153, *range(187, 255),
})


def operations(script: bytes):
    position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        data = None
        if opcode <= 78:
            size = opcode
            if opcode >= 76:
                width = {76: 1, 77: 2, 78: 4}[opcode]
                if position + width > len(script):
                    raise ValueError("Truncated push length")
                size = int.from_bytes(script[position:position + width], "little")
                position += width
            if position + size > len(script):
                raise ValueError("Truncated push data")
            data = script[position:position + size]
            position += size
        yield opcode, data


def is_push_only(script: bytes) -> bool:
    try:
        return all(op <= 96 for op, _ in operations(script))
    except ValueError:
        return False


def minimal_push(opcode: int, data: bytes) -> bool:
    if not data:
        return opcode == 0
    if len(data) == 1 and (1 <= data[0] <= 16 or data[0] == 129):
        return False  # These values must use OP_1..16 / OP_1NEGATE.
    return opcode == (len(data) if len(data) <= 75 else 76 if len(data) <= 255 else 77 if len(data) <= 65535 else 78)


def pushed_stack(script: bytes) -> list[bytes] | None:
    stack = []
    try:
        for op, data in operations(script):
            if data is not None:
                stack.append(data)
            elif op == 79:
                stack.append(b"\x81")
            elif 81 <= op <= 96:
                stack.append(bytes([op - 80]))
            else:
                return None
    except ValueError:
        return None
    return stack


def _small_number(op: int, data: bytes | None) -> int | None:
    if 81 <= op <= 96:
        return op - 80
    if data is not None and len(data) == 1 and 17 <= data[0] <= 20 and minimal_push(op, data):
        return data[0]
    return None


def _pubkey(data: bytes | None) -> bool:
    return data is not None and (
        (len(data) == 33 and data[0] in (2, 3))
        or (len(data) == 65 and data[0] in (4, 6, 7))
    )


def multisig(script: bytes) -> tuple[int, int] | None:
    if not script or script[-1] != 174:
        return None
    try:
        ops = list(operations(script))
    except ValueError:
        return None
    if len(ops) < 4:
        return None
    required = _small_number(*ops[0])
    keys = _small_number(*ops[-2])
    if required is None or keys is None or not 1 <= required <= keys <= 20:
        return None
    if len(ops) != keys + 3 or not all(_pubkey(data) for _, data in ops[1:-2]):
        return None
    return required, keys


def witness_program(script: bytes) -> tuple[int, bytes] | None:
    if 4 <= len(script) <= 42 and script[1] == len(script) - 2:
        if script[0] == 0:
            return 0, script[2:]
        if 81 <= script[0] <= 96:
            return script[0] - 80, script[2:]
    return None


def script_kind(script: bytes) -> str:
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1] == 135:
        return "scripthash"
    if witness := witness_program(script):
        version, program = witness
        if version == 0:
            return {20: "witness_v0_keyhash", 32: "witness_v0_scripthash"}.get(len(program), "nonstandard")
        if version == 1 and len(program) == 32:
            return "witness_v1_taproot"
        return "anchor" if script == b"\x51\x02\x4e\x73" else "witness_unknown"
    if script[:1] == b"\x6a" and is_push_only(script[1:]):
        return "nulldata"
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return "pubkeyhash"
    if len(script) in (35, 67) and script[0] == len(script) - 2 and script[-1] == 172 and _pubkey(script[1:-1]):
        return "pubkey"
    return "multisig" if multisig(script) else "nonstandard"


def sigops(script: bytes, *, accurate: bool = True) -> int:
    total, previous = 0, 0
    try:
        for op, _ in operations(script):
            if op in (172, 173):
                total += 1
            elif op in (174, 175):
                total += previous - 80 if accurate and 81 <= previous <= 96 else 20
            previous = op
    except ValueError:
        pass  # Core GetSigOpCount stops at the first malformed push too.
    return total


def legacy_stack_size(script: bytes, initial: int) -> int | None:
    """Prove stack depth only for templates or straight-line stack operations.

    Caller supplies a consensus-validated spend. Unknown programs return None;
    signatures are never pretended to have been checked by this module.
    """
    kind = script_kind(script)
    consumed = {"pubkeyhash": 2, "pubkey": 1}.get(kind)
    if kind == "multisig":
        consumed = multisig(script)[0] + 1
    if consumed is not None:
        return initial - consumed + 1 if initial >= consumed else None
    depth = initial
    try:
        for op, data in operations(script):
            if data is not None or op == 79 or 81 <= op <= 96:
                depth += 1
            elif op in (97, 171):  # NOP / CODESEPARATOR: no stack effect
                continue
            elif op in (117, 109):  # DROP / 2DROP
                needed = 1 if op == 117 else 2
                if depth < needed:
                    return None
                depth -= needed
            elif op == 118:  # DUP
                if depth < 1:
                    return None
                depth += 1
            else:
                return None
    except ValueError:
        return None
    return depth
