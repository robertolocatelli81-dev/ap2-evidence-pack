#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.1, SPEC §6 step 6, §5, §6.9: a pinned producer set implies `require_producer`.

Up to 1.9.0 the set was applied only to a block that was present: measured on 2026-11-20 on 1.9.0, the producer block
removed from a pack whose producer key was pinned gave `valid: true`, `policy.unmet: []` in both verifiers. Now
`policy_ok` and `valid` are false and `policy.unmet` names `trusted_producer_keys` (with `require_producer` too when the
relying party passed it). Every combination of {block present and pinned, present and not pinned, absent} × {no set,
set} × {require_producer or not} is checked in the reference and in the JS verifier (its CLI), with the same receipt
fields. On 1.9.0 `test_pinned_set_without_block` and `test_js_same_table` fail; `test_controls_unchanged` passes on
both."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")
VECTOR = os.path.join(ROOT, "spec", "vectors", "ap2", "key_material_not_used.json")   # a valid pack, no producer block


class PinImpliesProducer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2pin_")
        cls.absent = os.path.join(cls.d, "absent.json")
        shutil.copy(VECTOR, cls.absent)
        cls.pinned = os.path.join(cls.d, "pinned.json")
        shutil.copy(VECTOR, cls.pinned)
        keys = A.sign_evidence(cls.pinned)["producer_public_keys"]
        cls.pins = {alg: [k] for alg, k in keys.items()}
        cls.other = os.path.join(cls.d, "other.json")
        shutil.copy(VECTOR, cls.other)
        A.sign_evidence(cls.other)   # another identity: a key outside the set

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _py(self, path, pins, req):
        r = A.verify_evidence(path, trusted_producer_keys=pins, require_producer=req)
        return r["valid"], r["policy_ok"], r["policy"]["unmet"]

    def _js(self, path, pins, req):
        cmd = [NODE, JS, path] + [a for alg, ks in (pins or {}).items() for k in ks for a in ("--trusted-producer-key", f"{alg}={k}")]
        p = subprocess.run(cmd + (["--require-producer"] if req else []), capture_output=True, text=True, timeout=120)
        r = json.loads(p.stdout)
        self.assertEqual(p.returncode, 0 if r["valid"] else 1)
        return r["valid"], r["policy_ok"], r["policy"]["unmet"]

    def _table(self):
        rows = []
        for path in (self.pinned, self.other, self.absent):
            for pins in (None, self.pins):
                for req in (False, True):
                    rows.append((os.path.basename(path), pins is not None, req, self._py(path, pins, req), (path, pins, req)))
        return rows

    def test_controls_unchanged(self):
        want = {("pinned.json", True, False): (True, True, []), ("pinned.json", True, True): (True, True, []),
                ("pinned.json", False, False): (True, True, []), ("other.json", True, False): (False, True, ["trusted_producer_keys"]),
                ("absent.json", False, False): (True, True, []), ("absent.json", False, True): (False, False, ["require_producer"])}
        for name, pinned, req, got, _ in self._table():
            if (name, pinned, req) in want:
                with self.subTest((name, pinned, req)):
                    self.assertEqual(got, want[(name, pinned, req)])

    def test_pinned_set_without_block(self):
        self.assertEqual(self._py(self.absent, self.pins, False), (False, False, ["trusted_producer_keys"]))
        self.assertEqual(self._py(self.absent, self.pins, True), (False, False, ["require_producer", "trusted_producer_keys"]))
        self.assertEqual(self._py(self.absent, {}, False), (False, False, ["trusted_producer_keys"]))   # an empty set is a set given

    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_js_same_table(self):
        self.assertEqual(self._js(self.absent, self.pins, False), (False, False, ["trusted_producer_keys"]))
        for name, pinned, req, got, (path, pins, _) in self._table():
            with self.subTest((name, pinned, req)):
                self.assertEqual(self._js(path, pins, req), got)


if __name__ == "__main__":
    unittest.main()
