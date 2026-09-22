#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""One-shot conformance entry point: the ap2-evidence-pack conformance vectors
(spec/vectors/ap2/), the NIST ACVP ML-DSA-65 sigVer subset, and the pqcrypto
signature-suite bench, all in a single run."""
import importlib
import json
import glob
import os
import shutil
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "pqcrypto"))
sys.path.insert(0, os.path.join(_HERE, "spec", "vectors", "ap2"))
import ap2_evidence as ap2  # noqa: E402


class TestAp2ConformanceVectors(unittest.TestCase):
    def test_reference_verifier_is_conformant(self):
        import run_ap2_conformance as rc
        r = rc.run()
        self.assertTrue(r["conformant"], r)
        statuses = {x["vector"]: x["status"] for x in r["results"]}
        self.assertEqual(len(statuses), 8, statuses)   # 1.1.0: + anchor_valid (real token, probe TSA) and anchor_wrong_digest
        # the set must contain the positive control — an always-reject verifier must fail
        self.assertEqual(statuses.get("valid_signed"), "PASS", statuses)

    def test_hostile_files_are_refusal_receipts_never_tracebacks(self):
        # 1.1.0 acceptance profile: non-UTF-8, 100000-deep, float, 2^53+1, lone surrogate, NaN, BOM, non-object, missing path,
        # directory -> a receipt with valid False and `refused`, never an exception (1.0.2 raised on the first two and on
        # missing paths, and accepted float / big int / lone surrogate with a recomputed digest)
        import tempfile, hashlib
        base_text = open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"), encoding="utf-8").read(); base = json.loads(base_text)
        def rehash(ev):
            e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
            ev = dict(ev); ev["evidence_digest_sha256"] = hashlib.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode()).hexdigest(); ev.pop("producer_signatures", None); return ev
        d = tempfile.mkdtemp()
        files = {"raw": json.dumps(rehash(dict(base, subject="x\ufffd")), ensure_ascii=False).encode("utf-8").replace("\ufffd".encode("utf-8"), b"\xff", 1),
                 "deep": b"[" * 100000, "float": json.dumps(rehash(dict(base, extra=1.0))).encode(), "big": json.dumps(rehash(dict(base, extra=9007199254740993))).encode(),
                 "nan": base_text.replace('"created_utc"', '"x": NaN, "created_utc"', 1).encode(), "bom": ("\ufeff" + base_text).encode("utf-8"), "list": b"[1]"}
        lone = dict(base, subject="\ud800"); e2 = {k: v for k, v in lone.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
        lone["evidence_digest_sha256"] = hashlib.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode("utf-8", "surrogatepass")).hexdigest(); lone.pop("producer_signatures", None)
        files["lone"] = json.dumps(lone).encode()
        for name, data in files.items():
            p = os.path.join(d, name + ".json"); open(p, "wb").write(data)
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], name); self.assertFalse(r["digest_ok"], name); self.assertIn("refused", r, name)
        for p in (os.path.join(d, "nope.json"), d):
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"]); self.assertIn("unreadable", r["refused"])
        ok = os.path.join(d, "ok.json"); open(ok, "w", encoding="utf-8").write(json.dumps(rehash(dict(base, subject="café ≥ 1 😀")), ensure_ascii=False))
        self.assertTrue(ap2.verify_evidence(ok)["valid"])          # positive control: non-ASCII IS in profile

    def test_cli_grammar_is_one_with_the_js_verifier(self):
        import subprocess
        V = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")
        for extra in ([], [V, "--no-such"], [V, V], [""], ["--help"], ["-h"], ["--", V], [V, "--require-pq=1"], [V, "--trusted-producer-key", ""],
                      [V, "--trusted-producer-key"], [V, "--trusted-producer-key", "--require-pq"], [V, "--trusted-producer-key", "abc"], [V, "--trusted-producer-key", "", "--trusted-producer-key", "ed25519=AA=="]):
            out = subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "verify"] + extra, capture_output=True, text=True)
            self.assertEqual(out.returncode, 2, (extra, out.stdout[:80], out.stderr[-120:])); self.assertEqual(out.stdout, "")
        out = subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "verify", V], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0); self.assertTrue(json.loads(out.stdout)["valid"])

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier is not measured")
    def test_js_verifier_agrees_on_every_vector(self):
        import subprocess
        for exp_path in sorted(glob.glob(os.path.join(_HERE, "spec", "vectors", "ap2", "*.expected.json"))):
            exp = json.load(open(exp_path)); name = exp["vector"]; pol = exp.get("policy", {})
            if any(not shutil.which(t) for t in exp.get("requires", [])): continue
            flags = []
            for alg, keys in (pol.get("trusted_producer_keys") or {}).items():
                for k in ([keys] if isinstance(keys, str) else keys): flags += ["--trusted-producer-key", f"{alg}={k}"]
            for f in ("require_producer", "require_pq", "require_anchor"):
                if pol.get(f): flags.append("--" + f.replace("_", "-"))
            out = subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), os.path.join(_HERE, "spec", "vectors", "ap2", name + ".json")] + flags, capture_output=True, text=True)
            got = json.loads(out.stdout); norm = exp["normative"]
            self.assertEqual(got["valid"], norm["valid"], name); self.assertEqual(got["digest_ok"], norm["digest_ok"], name)
            self.assertEqual((got.get("rfc3161") or {}).get("verified"), norm["rfc3161_verified"], name); self.assertEqual(got["pq_protected"], norm["pq_protected"], name)


def load_tests(loader, tests, pattern):
    # pull the out-of-glob suites into this CI-visible file
    for mod in ("test_acvp_mldsa65", "test_pqsig"):
        tests.addTests(loader.loadTestsFromModule(importlib.import_module(mod)))
    return tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
