import copy
import unittest

from slipstreambot.policy import analyze_block, analyze_transaction, block_notification
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
    def test_mara_blocks_without_findings_still_produce_notifications(self):
        for transactions in ([], [transaction()]):
            with self.subTest(transactions=len(transactions)):
                block = {"height": 123, "hash": "cd" * 32, "time": 1234,
                         "tx": [{"vin": [{"coinbase": b"/MARA Pool/".hex()}]}, *transactions]}
                report = analyze_block(block)
                notice = block_notification(report)
                self.assertEqual(report["findings"], [])
                self.assertIsNotNone(notice)
                self.assertEqual(notice.event_id, f"block:{block['hash']}")
                self.assertIn("coverage before block connection is unknown", notice.body)

    def test_notifications_include_local_mempool_evidence_and_policy_reasons(self):
        report = {
            "pool": "MARA", "time": 2500, "height": 12, "hash": "hash", "transactions_examined": 3,
            "findings": [{"txid": txid, "violations": [{"detail": "Weight limit"}]}
                         for txid in ["both-tx", "seen-tx"]],
            "mempool": {"status": "covered", "since": 1800, "seen": 1,
                        "not_observed": ["both-tx", "missing-tx"]},
        }
        body = block_notification(report).body
        self.assertIn("1 seen, 2 not observed", body)
        self.assertIn("1970-01-01 00:30:00 UTC", body)
        self.assertEqual(body.count("both-tx"), 1)
        self.assertIn("both-tx\nReason: Weight limit\nNot observed in this node", body)
        self.assertIn("seen-tx\nReason: Weight limit\nSeen in this node", body)
        self.assertIn("missing-tx\nReason: Not observed in this node", body)
        report["mempool"]["status"] = "unknown"
        unknown = block_notification(report).body
        self.assertIn("Local mempool observation unknown.", unknown)
        self.assertNotIn("missing-tx", unknown)

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
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "reject")
        tx["vin"][1]["txinwitness"].append("5000")
        finding, _ = analyze_transaction(tx)
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "unknown")
        self.assertIn("eligibility unknown", finding["route_assessment"])
        vin["txinwitness"][-1] = "5001"
        self.assertEqual(codes(tx)["taproot-annex"]["libre"], "reject")

    def test_p2wsh_limits_exclude_script_from_argument_size(self):
        tx = transaction()
        tx["vin"][0]["prevout"] = output(b"\x00\x20" + b"\x22" * 32)
        tx["vin"][0]["txinwitness"] = ["11" * 80, "61" * 100]
        self.assertNotIn("p2wsh-stack-item", codes(tx))
        tx["vin"][0]["txinwitness"][0] += "11"
        self.assertIn("p2wsh-stack-item", codes(tx))

    def test_tapscript_success_opcodes_observe_leaf_and_push_boundaries(self):
        tx = transaction()
        vin = tx["vin"][0]
        vin["prevout"] = output(b"\x51\x20" + b"\x22" * 32)
        control = "c0" + "22" * 32
        for script in ("50", "00637e6851", "fe4d"):
            # A success opcode is recognized even in an inactive branch or before a bad tail.
            with self.subTest(script=script):
                vin["txinwitness"] = [script, control]
                finding = codes(tx)["tapscript-op-success"]
                self.assertEqual((finding["core"], finding["libre"], finding["slipstream"]),
                                 ("reject", "reject", "unknown"))
        vin["txinwitness"] = ["017e7551", control, "50bb"]
        self.assertNotIn("tapscript-op-success", codes(tx))
        vin["txinwitness"] = ["50", "c2" + "22" * 32]
        self.assertNotIn("tapscript-op-success", codes(tx))
        vin["txinwitness"] = ["50" * 64]
        self.assertNotIn("tapscript-op-success", codes(tx))

    def test_anchor_policy_distinguishes_native_and_wrapped_spends(self):
        tx = transaction()
        anchor = bytes.fromhex("51024e73")
        vin = tx["vin"][0]
        vin["prevout"] = output(anchor)
        vin["txinwitness"] = []
        self.assertEqual(codes(tx), {})
        vin["txinwitness"] = ["01"]
        self.assertIn("anchor-witness", codes(tx))
        vin["prevout"] = output(b"\xa9\x14" + b"\x22" * 20 + b"\x87")
        vin["scriptSig"]["hex"] = push(anchor).hex()
        for witness in ([], ["01"]):
            with self.subTest(witness=witness):
                vin["txinwitness"] = witness
                self.assertEqual(set(codes(tx)), {"unknown-witness-spend"})

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
        self.assertIn(tx["txid"], block_notification(report).body)
        block["tx"][0]["vin"][0]["coinbase"] = b"/OtherPool/".hex()
        self.assertEqual(analyze_block(block)["findings"], [])
        self.assertIsNone(block_notification(analyze_block(block)))

    def test_malformed_push_and_unknown_witness_output(self):
        with self.assertRaises(ValueError):
            list(operations(bytes.fromhex("4d0100")))
        self.assertEqual(script_kind(bytes.fromhex("5202aabb")), "witness_unknown")
        tx = transaction()
        tx["vout"] = [output(bytes.fromhex("5202aabb"))]
        self.assertNotIn("scriptpubkey", codes(tx))


if __name__ == "__main__":
    unittest.main()
