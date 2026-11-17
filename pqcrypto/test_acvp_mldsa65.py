#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""NIST ACVP ML-DSA-65 signature-verification vectors (FIPS 204, external interface,
pure mode) run against the EXACT code path producer signatures use on the wire.

Source of the vectors: usnistgov/ACVP-Server at commit a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324,
gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json (sha256 47cdd631…). vectors/make_acvp_mldsa65.py
selects every test of the ML-DSA-65 / external / pure group (15: 3 valid, 12 with a modified signature or message)
and writes them one JSON object per line (vectors/NIST-ACVP-NOTICE.txt: NIST's notice and what was changed). The
idea of running an ACVP subset in both stacks comes from navigatorbuilds (elara-mesh); the file, the selection rule
and the format are this repository's own (until 1.8.0 a copy of elara-mesh's nine-case file was kept here).

What passing proves: the `cryptography`-provided ML-DSA-65 backend implements FIPS 204
FINAL external/pure verification (a round-three Dilithium3 fails these vectors), and
`sigsuite.verify("ml-dsa-65", ...)` — the wire path, which pins context = empty — agrees
with the raw backend on every empty-context case. It does NOT prove anything about the
evidence format above the primitive; that is the AP2 conformance vectors' job.
"""
import base64
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import sigsuite  # noqa: E402

VECTORS = os.path.join(_HERE, "vectors", "acvp_mldsa65_sigver_pure.jsonl")
EXPECTED_CASES = 15         # file-truncation guard: the ML-DSA-65 external/pure group of ACVP-Server, all of it
EXPECTED_VALID = 3          # positive controls — a verifier that rejects everything must fail here
KEYS = ["tgId", "tcId", "testPassed", "reason", "pk", "message", "context", "signature"]


def _parse(line):
    """one case of the file, closed: exactly KEYS, in that order, hex in lower case; ValueError otherwise"""
    c = json.loads(line)
    if not isinstance(c, dict) or list(c) != KEYS or not isinstance(c["testPassed"], bool):
        raise ValueError("a case is not {%s}" % ", ".join(KEYS))
    for k in ("pk", "message", "context", "signature"):
        if not isinstance(c[k], str) or c[k] != c[k].lower():
            raise ValueError(f"{k}: not lower-case hex")
    return {"tc": c["tcId"], "expect": c["testPassed"], "reason": c["reason"], "pk": bytes.fromhex(c["pk"]),
            "msg": bytes.fromhex(c["message"]), "ctx": bytes.fromhex(c["context"]), "sig": bytes.fromhex(c["signature"])}


def _load_vectors():
    with open(VECTORS, encoding="ascii") as f:
        return [_parse(line) for line in f if line.strip()]


@unittest.skipUnless(sigsuite.MLDSA_AVAILABLE, "cryptography>=50.0.1 (FIPS 204 ML-DSA) required")
class TestAcvpMlDsa65SigVer(unittest.TestCase):
    def test_acvp_sigver_external_pure(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import mldsa
        cases = _load_vectors()
        self.assertEqual(len(cases), EXPECTED_CASES, "vector file truncated or grown")
        self.assertEqual(sum(c["expect"] for c in cases), EXPECTED_VALID,
                         "positive controls missing — an always-reject bug would pass")
        wire_ran = 0
        for c in cases:
            pub = mldsa.MLDSA65PublicKey.from_public_bytes(c["pk"])
            try:
                pub.verify(c["sig"], c["msg"], context=c["ctx"])
                got = True
            except (InvalidSignature, ValueError):
                got = False
            self.assertEqual(got, c["expect"],
                             f"ACVP tc{c['tc']} ({c['reason']}): got {got}")
            if not c["ctx"]:
                # the wire path: producer signatures verify via sigsuite with empty context
                wire = sigsuite.verify("ml-dsa-65",
                                       base64.b64encode(c["pk"]).decode("ascii"),
                                       base64.b64encode(c["sig"]).decode("ascii"),
                                       c["msg"])
                self.assertEqual(wire, c["expect"],
                                 f"sigsuite wire path diverges from backend on tc{c['tc']}")
                wire_ran += 1
        self.assertGreaterEqual(wire_ran, 1, "empty-context wire-path case missing")

    def test_a_broken_vector_is_refused(self):
        """positive control: a valid case with one byte of its signature changed does not verify, and a line outside
        the file's format is refused by the loader"""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import mldsa
        c = [c for c in _load_vectors() if c["expect"]][0]
        sig = bytearray(c["sig"])
        sig[len(sig) // 2] ^= 0x01
        pub = mldsa.MLDSA65PublicKey.from_public_bytes(c["pk"])
        with self.assertRaises(InvalidSignature):
            pub.verify(bytes(sig), c["msg"], context=c["ctx"])
        good = json.dumps({"tgId": 3, "tcId": 1, "testPassed": True, "reason": "r", "pk": "00", "message": "",
                           "context": "", "signature": "00"})
        _parse(good)
        for bad in (good.replace('"pk": "00"', '"pk": "AB"'), good.replace('"testPassed": true', '"testPassed": 1'),
                    good.replace('"tgId": 3, ', ""), good[:-1] + ', "sk": "00"}', "33|P|r|00||00|00", "[]"):
            with self.assertRaises(ValueError, msg=bad):
                _parse(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
