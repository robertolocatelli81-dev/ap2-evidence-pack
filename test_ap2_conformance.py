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
import tempfile
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

    def test_provenance_class_is_reconciled_and_format_is_pinned(self):
        # review r5: `provenance_class` is the field honest_scope sends the relying party to, and it was pure assertion —
        # relabelling jwk_header as x5c_header made self_asserted_only False with no x5c anywhere; out-of-enum values passed.
        # `evidence_format` and the §1 MUSTs were never read, so a "…/2.0" pack verified under the 1.0 rules.
        import tempfile, copy
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"))); d = tempfile.mkdtemp()
        def write(name, ev):
            p = os.path.join(d, name + ".json"); json.dump(ev, open(p, "w")); return p
        for name, v in (("x5c-without-x5c", "x5c_header"), ("out-of-enum", "qualified_eidas_certificate"), ("list", ["jwk_header"])):
            e = copy.deepcopy(base)
            for a in e["artifacts"]: a["key"]["provenance_class"] = v
            r = ap2.verify_evidence(write(name, O.rehash(e)))
            self.assertFalse(r["valid"], name); self.assertIn("provenance_class", r["artifacts"][0]["error"], name)
        e = copy.deepcopy(base)   # positive control: the honest label verifies and keeps self_asserted_only true
        r = ap2.verify_evidence(write("intact", O.rehash(e)))
        self.assertTrue(r["valid"]); self.assertEqual(r["provenance_classes"], ["jwk_header"]); self.assertTrue(r["self_asserted_only"])
        for name, mut, frag in (("format2", lambda e: e.__setitem__("evidence_format", "ap2-evidence-pack/2.0"), "evidence_format"),
                                ("noformat", lambda e: e.pop("evidence_format", None), "evidence_format"),
                                ("nosubject", lambda e: e.pop("subject", None), "subject"),
                                ("nocreated", lambda e: e.pop("created_utc", None), "created_utc"),
                                ("noscope", lambda e: e.pop("honest_scope", None), "honest_scope")):
            e = copy.deepcopy(base); mut(e); r = ap2.verify_evidence(write(name, O.rehash(e)))
            self.assertFalse(r["valid"], name); self.assertIn(frag, r["refused"], name)

    def test_build_refuses_what_verify_refuses(self):
        # review r5: `build` wrote a pack with an empty artifact name (exit 0, success receipt) that both verifiers then
        # refused. The SD-JWT here is VALID, so the only thing that can make build refuse is the name — otherwise the
        # test would pass for the wrong reason (an unparsable artifact raises anyway).
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        sk, n = O._fresh_key(); compact = O._sign_compact(sk, n, '{"iss":"x"}'); d = tempfile.mkdtemp()
        ap2.build_evidence([{"name": "intent", "sd_jwt": compact}], os.path.join(d, "ok.json"))   # positive control: it builds
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "", "sd_jwt": compact}], os.path.join(d, "o.json"))

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier is not measured, so 'one grammar' is not measurable")
    def test_cli_grammar_is_one_with_the_js_verifier(self):
        import subprocess
        V = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")
        clis = [[sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "verify"],
                ["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")]]
        for extra in ([], [V, "--no-such"], [V, V], [""], ["--help"], ["-h"], ["--", V], [V, "--require-pq=1"], [V, "--trusted-producer-key", ""],
                      [V, "--trusted-producer-key"], [V, "--trusted-producer-key", "--require-pq"], [V, "--trusted-producer-key", "abc"], [V, "--trusted-producer-key", "", "--trusted-producer-key", "ed25519=AA=="], [V, "--tsa-cert", ""]):
            for cli in clis:
                out = subprocess.run(cli + extra, capture_output=True, text=True)
                self.assertEqual(out.returncode, 2, (cli[0], extra, out.stdout[:80], out.stderr[-120:])); self.assertEqual(out.stdout, "")
        for cli in clis:
            out = subprocess.run(cli + [V], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, cli[0]); self.assertTrue(json.loads(out.stdout)["valid"])
        # r3: the BARE invocation (no subcommand at all) — the reference printed its help on stdout with exit 2, the JS verifier usage on stderr
        for cli in ([sys.executable, os.path.join(_HERE, "ap2_evidence.py")], clis[1]):   # r5: clis[-1] was the Python entry when node was absent, so the JS bare case never ran
            out = subprocess.run(cli, capture_output=True, text=True)
            self.assertEqual(out.returncode, 2, cli[0]); self.assertEqual(out.stdout, "", cli[0]); self.assertNotEqual(out.stderr, "", cli[0])

    @unittest.skipUnless(shutil.which("node"), "node absent: 'in both verifiers' is not measurable")
    def test_wrong_json_shapes_are_refusals_in_both_verifiers(self):
        # review r1: artifacts / key / jwk / rfc3161_timestamp / producer_signatures of the wrong type were TypeError /
        # AttributeError tracebacks in the reference; {} as a producer block was "absent" (valid True)
        import copy, subprocess, tempfile
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"))); d = tempfile.mkdtemp()
        muts = {"artifacts-null": lambda e: e.__setitem__("artifacts", None), "artifacts-string": lambda e: e.__setitem__("artifacts", "x"),
                "artifacts-list-of-null": lambda e: e.__setitem__("artifacts", [None]), "key-null": lambda e: e["artifacts"][0].__setitem__("key", None),
                "jwk-list": lambda e: e["artifacts"][0]["key"].__setitem__("jwk", [1]), "rfc3161-null": lambda e: e.__setitem__("rfc3161_timestamp", None),
                "rfc3161-string": lambda e: e.__setitem__("rfc3161_timestamp", "x"), "producer-string": lambda e: e.__setitem__("producer_signatures", "x"),
                "producer-empty": lambda e: e.__setitem__("producer_signatures", {}), "producer-list": lambda e: e.__setitem__("producer_signatures", []),
                "producer-sigs-null-entry": lambda e: e.__setitem__("producer_signatures", {"signatures": [None]})}
        for name, mut in muts.items():
            e = copy.deepcopy(base); mut(e); p = os.path.join(d, name + ".json"); json.dump(e, open(p, "w"))
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], name)
            out = subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), p], capture_output=True, text=True)
            self.assertFalse(json.loads(out.stdout)["valid"], name)

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent: TSA verification not measured")
    def test_rfc3161_binding_vs_tsa_authenticity(self):
        # a self-forged TimeStampResp (status 0, imprint = digest, no signer) satisfies BINDING (SPEC §3.2) but not the TSA
        # check; the real probe token passes both with its certificate; the real token for another digest fails binding
        import base64, tempfile
        vdir = os.path.join(_HERE, "spec", "vectors", "ap2"); cert = os.path.join(vdir, "anchor_probe_tsa.crt")
        r = ap2.verify_evidence(os.path.join(vdir, "anchor_valid.json"), require_anchor=True, tsa_cert=cert)
        self.assertTrue(r["valid"]); self.assertTrue(r["rfc3161"]["verified"]); self.assertTrue(r["rfc3161"]["tsa_verified"])
        r = ap2.verify_evidence(os.path.join(vdir, "anchor_wrong_digest.json"), require_anchor=True, tsa_cert=cert)
        self.assertFalse(r["valid"]); self.assertFalse(r["rfc3161"]["verified"])
        base = json.load(open(os.path.join(vdir, "valid_signed.json")))
        def der(tag, body):
            n = len(body); lb = bytes([n]) if n < 128 else bytes([0x82, n >> 8, n & 0xFF]); return bytes([tag]) + lb + body
        dg = bytes.fromhex(base["evidence_digest_sha256"])
        tst = der(0x30, der(0x02, b"\x01") + der(0x06, bytes.fromhex("2a03")) + der(0x30, der(0x30, der(0x06, bytes.fromhex("608648016503040201"))) + der(0x04, dg)) + der(0x02, b"\x01") + der(0x18, b"20260922100000Z"))
        eci = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010904")) + der(0xA0, der(0x04, tst))); sd = der(0x30, der(0x02, b"\x03") + der(0x31, b"") + eci + der(0x31, b""))
        resp = der(0x30, der(0x30, der(0x02, b"\x00")) + der(0x30, der(0x06, bytes.fromhex("2a864886f70d010702")) + der(0xA0, sd)))
        e = dict(base); e["rfc3161_timestamp"] = {"anchored": True, "tsa_url": "forged", "tsr_b64": base64.b64encode(resp).decode()}
        p = os.path.join(tempfile.mkdtemp(), "forged.json"); json.dump(e, open(p, "w"))
        r = ap2.verify_evidence(p, require_anchor=True); self.assertTrue(r["rfc3161"]["verified"]); self.assertTrue(r["valid"])       # binding only: passes (declared)
        r = ap2.verify_evidence(p, require_anchor=True, tsa_cert=cert); self.assertFalse(r["rfc3161"]["tsa_verified"]); self.assertFalse(r["valid"])

    def test_signed_payload_shapes_are_artifact_errors_in_the_reference(self):
        # review r2: the §3.1 profile inside the SD-JWT and the imposed shapes — each case is a fresh ES256-signed single-artifact
        # pack with the digest recomputed, built by the oracle's helper, so only the artifact layer decides; the same builder's
        # well-formed pack is the positive control (valid True). 1.1.0 r1 read the payload with json.loads (dup key last-wins,
        # BOM skipped), verified 31/33-byte JWK coordinates, raised TypeError on `_sd: null` and AttributeError on `cnf: null`.
        import tempfile, base64, hashlib
        sys.path.insert(0, os.path.join(_HERE, "verifiers")); import differential_oracle as O
        base = json.load(open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")))
        sk, n = O._fresh_key(); H = '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}'; d = tempfile.mkdtemp()
        kb = ".".join(base64.urlsafe_b64encode(x).decode().rstrip("=") for x in (b'{"alg":"ES256","typ":"kb+jwt"}', b'{"sd_hash":"x"}', b"\x00" * 64))
        disc = base64.urlsafe_b64encode(b'["salt",[1],"v"]').decode().rstrip("="); dig = base64.urlsafe_b64encode(hashlib.sha256(disc.encode()).digest()).decode().rstrip("=")
        bad = {"dup": ('{"iss":"x","amount":"1","amount":"999"}', {"iss": "x", "amount": "999"}, {}), "bom": (b'\xef\xbb\xbf{"iss":"x"}', {"iss": "x"}, {}),
               "sd-null": ('{"iss":"x","_sd":null}', {"iss": "x"}, {}), "sd-object": ('{"iss":"x","_sd":{}}', {"iss": "x"}, {}), "sd-int": ('{"iss":"x","_sd":[1]}', {"iss": "x"}, {}),
               "sd_alg-null": ('{"iss":"x","_sd_alg":null}', {"iss": "x"}, {}), "dots-list": ('{"iss":"x","a":[{"...":[1]}]}', {"iss": "x", "a": []}, {}),
               "disc-name-list": ('{"iss":"x","_sd":["%s"]}' % dig, {"iss": "x"}, {"disclosures": [disc]}),
               "cnf-null": ('{"iss":"x","cnf":null}', {"iss": "x", "cnf": None}, {"kb": kb}), "cnf-string": ('{"iss":"x","cnf":"k"}', {"iss": "x", "cnf": "k"}, {"kb": kb}),
               "cnf-jwk-empty": ('{"iss":"x","cnf":{"jwk":{}}}', {"iss": "x", "cnf": {"jwk": {}}}, {"kb": kb}),
               "jwk-x-33": ('{"iss":"x"}', {"iss": "x"}, {"jwk_x_bytes": n.x.to_bytes(33, "big")})}
        for name, (payload, resolved, kw) in bad.items():
            p = os.path.join(d, name + ".json"); json.dump(O._fresh_pack(base, sk, n, H, payload, resolved, **kw), open(p, "w"))
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], name); self.assertTrue(r["digest_ok"], name); self.assertIn("error", r["artifacts"][0], name)
        p = os.path.join(d, "ok.json"); json.dump(O._fresh_pack(base, sk, n, H, '{"iss":"x","_sd":[],"_sd_alg":"sha-256"}', {"iss": "x"}), open(p, "w"))
        self.assertTrue(ap2.verify_evidence(p)["valid"])   # positive control of the builder
        # r4: strict base64url measured by the unit suite too (the ablation of that layer alone left the suite green): the same
        # signature segment padded, with a space, with '+' — a lenient decoder verifies it, the profile refuses it
        ok = O._fresh_pack(base, sk, n, H, '{"iss":"x"}', {"iss": "x"}); c = ok["artifacts"][0]["sd_jwt_compact"]; jwt, rest = c.split("~", 1); h_, p_, s_ = jwt.split(".")
        for nm, sig in (("padded", s_ + "=="), ("space", s_[:10] + " " + s_[10:]), ("plus", s_.replace("-", "+", 1) if "-" in s_ else s_[:-1] + "+")):
            e = json.loads(json.dumps(ok)); e["artifacts"][0]["sd_jwt_compact"] = ".".join([h_, p_, sig]) + "~" + rest; p = os.path.join(d, "b64" + nm + ".json"); json.dump(O.rehash(e), open(p, "w"))
            r = ap2.verify_evidence(p); self.assertFalse(r["valid"], nm); self.assertIn("error", r["artifacts"][0], nm)
        # top-level shapes of r2: anchored must be a boolean (refusal), provenance_class a string (artifact error), sig_alg a string (FAIL entry)
        e = dict(base); e["rfc3161_timestamp"] = {"anchored": []}; p = os.path.join(d, "anch.json"); json.dump(e, open(p, "w"))
        r = ap2.verify_evidence(p); self.assertFalse(r["valid"]); self.assertIn("anchored", r["refused"])
        e = json.loads(json.dumps(base)); e["artifacts"][0]["key"]["provenance_class"] = ["x"]; p = os.path.join(d, "prov.json"); json.dump(O.rehash(e), open(p, "w"))
        r = ap2.verify_evidence(p); self.assertFalse(r["valid"]); self.assertIn("provenance_class", r["artifacts"][0]["error"])
        e = json.loads(json.dumps(base)); e["producer_signatures"]["signatures"].append({"sig_alg": ["ed25519"], "public_key_b64": "AA==", "signature_b64": "AA=="}); p = os.path.join(d, "alg.json"); json.dump(e, open(p, "w"))
        r = ap2.verify_evidence(p, trusted_producer_keys={"ed25519": [base["producer_signatures"]["signatures"][0]["public_key_b64"]]})
        self.assertFalse(r["valid"]); self.assertEqual(r["producer_signatures"]["signatures"][-1]["status"], "FAIL")

    @unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier is not measured")
    def test_js_verifier_is_conformant_on_all_normative_fields(self):
        # the JS verifier through the SAME conformance runner as the reference: every normative field of every vector
        import subprocess, run_ap2_conformance as rc
        probe = subprocess.run(["node", "-e", "const{createPublicKey}=require('node:crypto');try{createPublicKey({key:Buffer.concat([Buffer.from('308207b2300b0609608648016503040312038207a100','hex'),Buffer.alloc(1952)]),format:'der',type:'spki'});console.log('yes')}catch{console.log('no')}"], capture_output=True, text=True)
        if probe.stdout.strip() != "yes":   # r2: on a Node build without ML-DSA-65 (OpenSSL < 3.5) the ML-DSA vectors are SKIP in the JS verifier, so 8/8 is NOT measured — skip, never a pass
            self.skipTest("Node build without ML-DSA-65 (OpenSSL < 3.5): JS conformance on the ML-DSA vectors not measured here")
        def js_verify(path, trusted_producer_keys=None, require_pq=False, require_producer=False, require_anchor=False, **_):
            flags = []
            for alg, keys in (trusted_producer_keys or {}).items():
                for k in ([keys] if isinstance(keys, str) else keys): flags += ["--trusted-producer-key", f"{alg}={k}"]
            for flag, on in (("--require-producer", require_producer), ("--require-pq", require_pq), ("--require-anchor", require_anchor)):
                if on: flags.append(flag)
            out = subprocess.run(["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs"), path] + flags, capture_output=True, text=True)
            return json.loads(out.stdout)
        r = rc.run(verify_fn=js_verify)
        self.assertTrue(r["conformant"], r)
        self.assertEqual(len(r["results"]), 8)


def load_tests(loader, tests, pattern):
    # pull the out-of-glob suites into this CI-visible file
    for mod in ("test_acvp_mldsa65", "test_pqsig"):
        tests.addTests(loader.loadTestsFromModule(importlib.import_module(mod)))
    return tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
