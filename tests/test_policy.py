import copy
import unittest

from slipstreambot.policy import analyze_block, analyze_transaction
from slipstreambot.scripts import operations, script_kind


KEY = bytes.fromhex("02" + "11" * 32)


def push(data):
    size = len(data)
    if size < 76:
        return bytes([size]) + data
    if size < 256:
        return b"\x4c" + bytes([size]) + data
    return b"\x4d" + size.to_bytes(2, "little") + data


def output(script, value="0.001"):
    return {"value": value, "scriptPubKey": {"hex": script.hex()}}


def transaction():
    return {
        "txid": "ab" * 32, "version": 2, "weight": 400, "size": 160,
        "vin": [{"scriptSig": {"hex": ""}, "txinwitness": ["11" * 64, KEY.hex()],
                 "prevout": output(b"\x00\x14" + b"\x22" * 20, "0.002")}],
        "vout": [output(b"\x00\x14" + b"\x33" * 20)],
    }


def codes(tx):
    finding, _ = analyze_transaction(tx)
    return {} if finding is None else {v["code"]: v for v in finding["violations"]}


class PolicyTests(unittest.TestCase):
    def test_current_op_return_rules_do_not_use_old_83_byte_limit(self):
        tx = transaction()
        tx["vout"] += [output(b"\x6a" + push(b"a" * 1000), "0"), output(b"\x6a\x01x", "0")]
        self.assertEqual(codes(tx), {})

    def test_weight_boundary_and_slipstream_limit(self):
        tx = transaction()
        tx.update(weight=400_000, size=100_100)
        self.assertNotIn("tx-weight", codes(tx))
        tx.update(weight=400_004, size=100_101)
        self.assertEqual(codes(tx)["tx-weight"]["slipstream"], "within_published_rule")
        tx.update(weight=3_991_001, size=1_000_000)
        self.assertEqual(codes(tx)["tx-weight"]["slipstream"], "reject")

    def test_bare_multisig_is_different_from_p2sh_output(self):
        tx = transaction()
        tx["vout"] = [output(b"\x60" + push(KEY) * 16 + b"\x60\xae")]
        violation = codes(tx)["bare-multisig"]
        self.assertEqual(violation["libre"], "reject")
        self.assertEqual(violation["slipstream"], "within_published_rule")
        tx["vout"] = [output(b"\xa9\x14" + b"\x11" * 20 + b"\x87")]
        self.assertNotIn("bare-multisig", codes(tx))

    def test_nonpush_opcode_inside_push_data_is_not_flagged(self):
        tx = transaction()
        tx["vin"][0]["scriptSig"]["hex"] = push(b"\xab\x75").hex()
        self.assertNotIn("scriptsig-not-pushonly", codes(tx))
        self.assertNotIn("const-scriptcode", codes(tx))
        tx["vin"][0]["scriptSig"]["hex"] = "5175"
        self.assertEqual(codes(tx)["scriptsig-not-pushonly"]["slipstream"], "unknown")

    def test_legacy_cleanstack_and_codeseparator(self):
        tx = transaction()
        redeem = b"\xab\x51"  # No-op CODESEPARATOR then TRUE; leaves the extra item.
        tx["vin"] = [{"scriptSig": {"hex": (b"\x51" + push(redeem)).hex()},
                      "prevout": output(b"\xa9\x14" + b"\x22" * 20 + b"\x87")}]
        result = codes(tx)
        self.assertEqual(result["cleanstack"]["slipstream"], "within_published_rule")
        self.assertEqual(result["const-scriptcode"]["slipstream"], "within_published_rule")

    def test_witness_codeseparator_is_not_legacy_violation(self):
        tx = transaction()
        tx["vin"][0]["prevout"] = output(b"\x00\x20" + b"\x22" * 32)
        tx["vin"][0]["txinwitness"] = ["ab51"]
        self.assertNotIn("const-scriptcode", codes(tx))

    def test_missing_prevouts_do_not_guess_witness_type(self):
        tx = transaction()
        del tx["vin"][0]["prevout"]
        tx["vin"][0]["txinwitness"] = ["11" * 64, "5000"]
        finding, gaps = analyze_transaction(tx)
        self.assertIsNone(finding)
        self.assertTrue(any("prevouts missing" in gap for gap in gaps))

    def test_libre_annex_requires_all_inputs_and_correct_namespace(self):
        tx = transaction()
        vin = tx["vin"][0]
        vin["prevout"] = output(b"\x51\x20" + b"\x22" * 32)
        vin["txinwitness"] = ["11" * 64, "5000aabb"]
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "within_pinned_rule")
        vin["txinwitness"][-1] = "5001"
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "reject")
        vin["txinwitness"][-1] = "50"
        tx["vin"].append(copy.deepcopy(vin))
        tx["vin"][1]["txinwitness"] = ["11" * 64]
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "reject")
        del tx["vin"][1]["prevout"]
        finding, _ = analyze_transaction(tx)
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "unknown")
        self.assertIn("eligibility unknown", finding["route_assessment"])

    def test_p2wsh_limits_exclude_script_from_argument_size(self):
        tx = transaction()
        tx["vin"][0]["prevout"] = output(b"\x00\x20" + b"\x22" * 32)
        tx["vin"][0]["txinwitness"] = ["11" * 80, "61" * 100]
        self.assertNotIn("p2wsh-stack-item", codes(tx))
        tx["vin"][0]["txinwitness"][0] += "11"
        self.assertIn("p2wsh-stack-item", codes(tx))

    def test_single_ephemeral_dust_is_not_always_nonstandard(self):
        tx = transaction()
        tx["vout"][0]["value"] = "0.00000001"
        tx["fee"] = 0
        self.assertNotIn("dust-fee", codes(tx))
        tx["fee"] = "0.00000001"
        self.assertIn("dust-fee", codes(tx))
        tx["vout"].append(copy.deepcopy(tx["vout"][0]))
        self.assertIn("dust", codes(tx))

    def test_truc_sigop_adjusted_limit(self):
        tx = transaction()
        tx.update(version=3, weight=40_001, size=10_100)
        self.assertIn("truc-size", codes(tx))
        tx.update(version=2)
        self.assertNotIn("truc-size", codes(tx))

    def test_mara_attribution_skips_coinbase_and_other_pools(self):
        tx = transaction()
        tx["weight"] = 400_004
        block = {"height": 123, "hash": "cd" * 32, "time": 1234,
                 "tx": [{"vin": [{"coinbase": b"/MARA Pool/".hex()}]}, tx]}
        report = analyze_block(block)
        self.assertEqual(report["pool"], "MARA")
        self.assertEqual(report["findings"][0]["txid"], tx["txid"])
        block["tx"][0]["vin"][0]["coinbase"] = b"/OtherPool/".hex()
        self.assertEqual(analyze_block(block)["findings"], [])

    def test_malformed_push_and_unknown_witness_output(self):
        with self.assertRaises(ValueError):
            list(operations(bytes.fromhex("4d0100")))
        self.assertEqual(script_kind(bytes.fromhex("5202aabb")), "witness_unknown")
        tx = transaction()
        tx["vout"] = [output(bytes.fromhex("5202aabb"))]
        self.assertNotIn("scriptpubkey", codes(tx))


if __name__ == "__main__":
    unittest.main()
