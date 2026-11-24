#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.11.0, SPEC §5, §6 step 6, §6.9, §10: a pinned producer set that holds an `ml-dsa-65` key requires a valid `ml-dsa-65`
signature under a pinned key.

Up to 1.10.0 the `ml-dsa-65` entry of a hybrid block removed and `scheme` relabelled `classical-only` gave `valid: true`
with both producer keys pinned, also with `--trust-set-complete` and `--require-producer` (measured 2026-11-24 on the
PyPI wheel 1.10.0, google-agentic-commerce/AP2#338); only `require_pq` refused it. Now such a pack is not `valid`,
`policy_ok` is false and `policy.unmet` names `trusted_producer_keys`, in the reference and in the JS verifier, whatever
ML-DSA-65 backend the verifier has. Controls: the hybrid pack under the same set, the stripped pack under a set without
an `ml-dsa-65` key (a classical-only producer's pins) and without a set, stay as in 1.10.0. On v1.10.0 the tests
`test_stripped_*`, `test_resigned_*`, `test_shared_set_*`, `test_pin*` and `test_js_*` fail; the
`test_control_*` tests pass on both."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")
VD = os.path.join(ROOT, "spec", "vectors", "ap2")
SIGNED = os.path.join(VD, "valid_signed.json")
with open(os.path.join(VD, "valid_signed.expected.json"), encoding="utf-8") as _f:
    PINS = _f.read()
PINS = json.loads(PINS)["policy"]["trusted_producer_keys"]   # {ed25519: [k], ml-dsa-65: [k]}: the keys valid_signed is signed with
CLASSICAL_PINS = {"ed25519": PINS["ed25519"]}


def _write(path, ev):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(ev, f, ensure_ascii=False, indent=1, sort_keys=True)


def strip_and_relabel(ev):
    """The downgrade: the ml-dsa-65 entry removed, `scheme` set to classical-only; nothing else changes."""
    ev = json.loads(json.dumps(ev))
    blk = ev["producer_signatures"]
    blk["signatures"] = [s for s in blk["signatures"] if s["sig_alg"] != "ml-dsa-65"]
    blk["scheme"] = "classical-only"
    return ev


class PinHoldsMlDsa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2pinpq_")
        with open(SIGNED, encoding="utf-8") as f:
            cls.ev = json.load(f)
        cls.stripped = os.path.join(cls.d, "stripped.json")
        _write(cls.stripped, strip_and_relabel(cls.ev))
        cls.kept = os.path.join(cls.d, "kept_hybrid.json")   # control of the §5 reconciliation: stripped, scheme left hybrid
        e = strip_and_relabel(cls.ev); e["producer_signatures"]["scheme"] = "hybrid"; _write(cls.kept, e)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    @staticmethod
    def _py(path, pins, **kw):
        r = A.verify_evidence(path, trusted_producer_keys=pins, **kw)
        return r["valid"], r["policy_ok"], r["policy"]["unmet"], r["states"]["producer_signature"]["state"]

    def _js(self, path, pins, *flags):
        cmd = [NODE, JS, path] + [a for alg, ks in (pins or {}).items() for k in ks for a in ("--trusted-producer-key", f"{alg}={k}")]
        p = subprocess.run(cmd + list(flags), capture_output=True, timeout=120)
        r = json.loads(p.stdout.decode("utf-8"))
        self.assertEqual(p.returncode, 0 if r["valid"] else 1)
        return r["valid"], r["policy_ok"], r["policy"]["unmet"], r["states"]["producer_signature"]["state"]

    # ---- the rule
    def test_stripped_under_the_hybrid_pins_is_not_valid(self):
        want = (False, False, ["trusted_producer_keys"], "verified")
        self.assertEqual(self._py(self.stripped, PINS), want)
        self.assertEqual(self._py(self.stripped, PINS, trust_set_complete=True), want)
        self.assertEqual(self._py(self.stripped, PINS, require_producer=True), want)   # the block is present and ok
        self.assertEqual(self._py(self.stripped, PINS, require_pq=True), (False, False, ["require_pq", "trusted_producer_keys"], "verified"))
        self.assertEqual(self._py(self.stripped, {"ml-dsa-65": PINS["ml-dsa-65"], "ed25519": PINS["ed25519"][0]}), want)   # a key as one string

    def test_stripped_without_the_backend_is_refused_the_same(self):
        with mock.patch.object(A._sigsuite, "MLDSA_AVAILABLE", False):
            self.assertEqual(self._py(self.stripped, PINS), (False, False, ["trusted_producer_keys"], "verified"))

    def test_resigned_with_the_classical_key_alone_is_not_valid(self):
        """Content changed and the block re-signed by a classical-only identity whose key the relying party pinned beside
        the producer's ml-dsa-65 key: the content's change is not the point, the missing ml-dsa-65 signature is."""
        ident = A._sigsuite.ProducerIdentity.create(post_quantum=False)
        p = os.path.join(self.d, "resigned.json")
        e = {k: v for k, v in self.ev.items() if k != "producer_signatures"}
        e["subject"] = "a subject the producer never sealed"   # sealed content changed
        body = {k: v for k, v in e.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
        import hashlib
        e["evidence_digest_sha256"] = hashlib.sha256(A._canon(body)).hexdigest()
        _write(p, e)
        A.sign_evidence(p, identity=ident)
        pins = {"ed25519": [ident.public_keys()["ed25519"]], "ml-dsa-65": PINS["ml-dsa-65"]}
        self.assertEqual(self._py(p, pins), (False, False, ["trusted_producer_keys"], "verified"))
        self.assertEqual(self._py(p, {"ed25519": pins["ed25519"]})[:3], (True, True, []))   # control: that producer's own pins

    def test_shared_set_refuses_the_classical_only_producer(self):
        """SPEC §5: a set is one producer's. Joined with a classical-only producer's key, the hybrid producer's set refuses
        that producer's genuine packs (closed: no way to tell which producer must sign with ml-dsa-65); its own set
        accepts them."""
        ident = A._sigsuite.ProducerIdentity.create(post_quantum=False)
        p = os.path.join(self.d, "classical_producer.json")
        _write(p, {k: v for k, v in self.ev.items() if k != "producer_signatures"})
        A.sign_evidence(p, identity=ident)
        joined = {"ed25519": PINS["ed25519"] + [ident.public_keys()["ed25519"]], "ml-dsa-65": PINS["ml-dsa-65"]}
        self.assertEqual(self._py(p, joined), (False, False, ["trusted_producer_keys"], "verified"))
        self.assertEqual(self._py(p, {"ed25519": [ident.public_keys()["ed25519"]]})[:3], (True, True, []))
        if A._sigsuite.MLDSA_AVAILABLE:   # the hybrid producer's pack under the joined set: valid
            self.assertEqual(self._py(SIGNED, joined)[:3], (True, True, []))

    # ---- controls: as in 1.10.0
    def test_control_hybrid_pack_under_the_pins(self):
        if not A._sigsuite.MLDSA_AVAILABLE:
            self.skipTest("no ML-DSA-65 backend: the hybrid block is a SKIP entry here")
        self.assertEqual(self._py(SIGNED, PINS), (True, True, [], "verified"))

    def test_control_stripped_under_classical_pins_or_none(self):
        self.assertEqual(self._py(self.stripped, CLASSICAL_PINS), (True, True, [], "verified"))
        self.assertEqual(self._py(self.stripped, None), (True, True, [], "not_evaluated"))
        self.assertEqual(self._py(self.stripped, {"ed25519": PINS["ed25519"], "ml-dsa-65": []}), (True, True, [], "verified"))   # no ml-dsa-65 key in the set

    def test_control_scheme_left_hybrid_is_contradicted(self):
        v = self._py(self.kept, PINS)
        self.assertEqual((v[0], v[3]), (False, "contradicted"))

    # ---- the JS verifier, same table
    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_js_same_table(self):
        cases = [(self.stripped, PINS, ()), (self.stripped, PINS, ("--trust-set-complete",)),
                 (self.stripped, PINS, ("--require-producer",)), (self.stripped, PINS, ("--require-pq",)),
                 (self.stripped, CLASSICAL_PINS, ()), (self.stripped, None, ()), (self.kept, PINS, ())]
        kw = {"--trust-set-complete": "trust_set_complete", "--require-producer": "require_producer", "--require-pq": "require_pq"}
        for path, pins, flags in cases:
            with self.subTest((os.path.basename(path), pins is not None and sorted(pins), flags)):
                self.assertEqual(self._js(path, pins, *flags), self._py(path, pins, **{kw[f]: True for f in flags}))
        self.assertEqual(self._js(self.stripped, PINS), (False, False, ["trusted_producer_keys"], "verified"))

    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_js_string_pin_is_one_key(self):
        """The JS library takes a pin as a string too: it is that key, never a substring match (up to 1.10.0
        String.includes made "x<key>y" pin <key>)."""
        code = ("import { verifyEvidence } from %s;\n"
                "const r = verifyEvidence(%s, { trusted: { ed25519: %s } });\n"
                "process.stdout.write(JSON.stringify([r.producer_signatures.trusted, r.valid]));\n") % (
            json.dumps(pathlib.Path(JS).as_uri()),
            json.dumps(self.stripped), json.dumps("x" + PINS["ed25519"][0] + "y"))
        p = subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, timeout=120)
        self.assertEqual(json.loads(p.stdout.decode("utf-8")), [False, False], p.stderr)

    # ---- the pinned set has a grammar: outside it, an error of the caller, never a set read in silence
    def test_pin_under_a_name_the_format_does_not_define_is_refused(self):
        """Measured on bce80ef: `--trusted-producer-key ML-DSA-65=<key>` beside the ed25519 pin left the stripped pack valid
        (exit 0) in both verifiers — the key was not an `ml-dsa-65` key of the set."""
        e, q = PINS["ed25519"][0], PINS["ml-dsa-65"][0]
        for alg in ("ML-DSA-65", "mldsa65", "ml-dsa-65 ", "ml-dsa-87", "constructor"):
            with self.subTest(alg=alg):
                args = [self.stripped, "--trusted-producer-key", "ed25519=" + e, "--trusted-producer-key", alg + "=" + q]
                p = subprocess.run([sys.executable, os.path.join(ROOT, "ap2_evidence.py"), "verify"] + args, capture_output=True, timeout=120)
                self.assertEqual((p.returncode, p.stdout), (2, b""), p.stderr)
                self.assertIn(b"is not a producer signature algorithm", p.stderr)
                with self.assertRaises(ValueError):
                    A.verify_evidence(self.stripped, trusted_producer_keys={"ed25519": [e], alg: [q]})
                if NODE:
                    p = subprocess.run([NODE, JS] + args, capture_output=True, timeout=120)
                    self.assertEqual((p.returncode, p.stdout), (2, b""), p.stderr)
        for alg in ("ed25519", "ecdsa-p256", "ml-dsa-65"):   # control: the three names of SPEC §5 are pins
            self.assertFalse(A.verify_evidence(self.stripped, trusted_producer_keys={alg: ["x"]})["valid"])

    def test_pinned_set_of_another_type_is_an_error(self):
        e, q = PINS["ed25519"], PINS["ml-dsa-65"]
        for bad in ([e[0], q[0]], {"ed25519": e, "ml-dsa-65": None}, {"ed25519": e, "ml-dsa-65": 7}, {"ed25519": e, "ml-dsa-65": [q]},
                    {"ed25519": e, "ml-dsa-65": {"k": q[0]}}, "ed25519=" + e[0], {"ed25519": e, 7: q}):
            with self.subTest(bad=repr(bad)[:40]):
                with self.assertRaises(ValueError):
                    A.verify_evidence(self.stripped, trusted_producer_keys=bad)
        for good in ({"ed25519": e[0], "ml-dsa-65": tuple(q)}, {"ed25519": e, "ml-dsa-65": set(q)}):   # control: these are sets
            self.assertEqual(self._py(self.stripped, good), (False, False, ["trusted_producer_keys"], "verified"))
        self.assertEqual(self._py(self.stripped, {})[0], False)   # control: an empty set pins nothing

    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_js_pinned_set_of_another_type_is_an_error(self):
        """Measured on bce80ef: `new Set([key])`, 7 or {0: key} under "ml-dsa-65" left the stripped pack valid in the JS library
        (the reference refused it), and null there was a TypeError from inside the verifier."""
        e, q = json.dumps(PINS["ed25519"]), json.dumps(PINS["ml-dsa-65"][0])
        bads = ["{ed25519: %s, 'ml-dsa-65': new Set([%s])}" % (e, q), "{ed25519: %s, 'ml-dsa-65': 7}" % e, "{ed25519: %s, 'ml-dsa-65': null}" % e,
                "{ed25519: %s, 'ml-dsa-65': {0: %s}}" % (e, q), "{ed25519: %s, 'ml-dsa-65': [[%s]]}" % (e, q), "{ed25519: %s, 'ML-DSA-65': [%s]}" % (e, q),
                "new Map([['ed25519', %s]])" % e, "[%s]" % q, "%s" % q]
        code = ("import { verifyEvidence } from %s;\nconst out = [];\nfor (const t of [%s]) { try { out.push(verifyEvidence(%s, { trusted: t }).valid); }"
                " catch (x) { out.push(x instanceof TypeError && /^trusted must be/.test(x.message) ? 'TypeError' : String(x)); } }\n"
                "out.push(verifyEvidence(%s, { trusted: { ed25519: %s, 'ml-dsa-65': %s } }).policy.unmet);\n"
                "out.push(verifyEvidence(%s, { trusted: { ed25519: %s, 'ml-dsa-65': [] } }).valid);   // control: no ml-dsa-65 key in the set\n"
                "process.stdout.write(JSON.stringify(out));\n") % (json.dumps(pathlib.Path(JS).as_uri()), ", ".join(bads), json.dumps(self.stripped),
                                                                   json.dumps(self.stripped), e, q, json.dumps(self.stripped), e)
        p = subprocess.run([NODE, "--input-type=module", "-e", code], capture_output=True, timeout=120)
        self.assertEqual(json.loads(p.stdout.decode("utf-8")), ["TypeError"] * len(bads) + [["trusted_producer_keys"], True], p.stderr)


if __name__ == "__main__":
    unittest.main()
