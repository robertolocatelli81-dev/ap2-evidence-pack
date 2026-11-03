#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.7.2 — numbers in the SD-JWT layer (SPEC §3.1): a literal with a fraction or an exponent whose value is an integer
within +/-(2^53-1) is read as that integer inside a token, by both verifiers; any other such literal is that artifact's
error; in the evidence FILE a float stays a refusal. Decided on the decimal digits, exactly, never through binary64.

Positive control (measured 2026-11-02): on the 1.7.1 tree this file is red — the SDK tokens below are refused at build
(`float '10.0' in the evidence file`), the vector `sd_number_integral_literal` is an artifact error there.

Run: python3 test_ap2_numbers.py
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "verifiers"))
import ap2_evidence as ap2  # noqa: E402
import differential_oracle as O  # noqa: E402

_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
SAFE = (1 << 53) - 1

# Two open payment mandates minted by the AP2 SDK at e1ea56d (`MandateClient.create`, `Budget(max=10, currency="USD")`
# and `Budget(max=0.29, ...)`, 2026-11-02): the SDK's `Budget.max` is a float, so the signed disclosure reads
# `"max": 10.0` and `"max": 0.29`. The issuer key is the same for both; the private half was discarded.
SDK_ISSUER_JWK = {"crv": "P-256", "kty": "EC", "x": "ggU4nBAir_a2MbFiM5xyGxGtNzmQPJbXttgXSHErh5E", "y": "cz7-z1esdZgJ8IIx1IRo_Nv9IsoMxUjuYp_Rj16DmA0"}
SDK_BUDGET_10 = ("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJkZWxlZ2F0ZV9wYXlsb2FkIjogW3siLi4uIjogIjlCdGctSE1sX0JtcHhDb3dEWUhFLWplRW9COGtJZWVwbW9jeFl0cFBmeWsifV0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.w5GDLThOBEKHsMmbfPwOCSiWLjgjofgR4w_ICvyjDW2UWLsmhQmxJHrgIhfAkSPImuC0MRkr7SzWshPbAaMiTg~"
                 "WyJHX0NWWS1ZNUFuRjZPQl9SajRyenJnIiwgeyJ2Y3QiOiAibWFuZGF0ZS5wYXltZW50Lm9wZW4uMSIsICJjb25zdHJhaW50cyI6IFt7InR5cGUiOiAicGF5bWVudC5idWRnZXQiLCAibWF4IjogMTAuMCwgImN1cnJlbmN5IjogIlVTRCJ9LCB7InR5cGUiOiAicGF5bWVudC5hbW91bnRfcmFuZ2UiLCAiY3VycmVuY3kiOiAiVVNEIiwgIm1heCI6IDEwMDAwMDB9XSwgImNuZiI6IHsiandrIjogeyJjcnYiOiAiUC0yNTYiLCAia3R5IjogIkVDIiwgIngiOiAid0JhSngxRm9XSUZJVVdxcVVWVG1IVHlqOGZraUlSWFlTSlMyY1AtZmxXdyIsICJ5IjogIk44b0FkVnRXbEppOWRyMHktbWVObnhnWVRic1NIcWJuQXN3Ynl6MWU3ZzQifX0sICJpYXQiOiAxNzkzNjQ2MTc1LCAiZXhwIjogMTc5MzY0OTc3NX1d~")
SDK_BUDGET_0_29 = ("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJkZWxlZ2F0ZV9wYXlsb2FkIjogW3siLi4uIjogIkpkX3dyUmRhNkpyVVNqUXNrOHhmOEZOUkdpYV9CNVNybk14ZXVhS01NYzAifV0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.6sbPcxV7aXAcBbsKkrRI3rlTciddQChSFuzEwgJIzFFuBC9b5smzE_IGZOYeZ_Acyy-8v71rCr1Qk21im8gQ6Q~"
                   "WyJ4NFdLVTlCTmV3NXJESHlGQURpQWR3IiwgeyJ2Y3QiOiAibWFuZGF0ZS5wYXltZW50Lm9wZW4uMSIsICJjb25zdHJhaW50cyI6IFt7InR5cGUiOiAicGF5bWVudC5idWRnZXQiLCAibWF4IjogMC4yOSwgImN1cnJlbmN5IjogIlVTRCJ9LCB7InR5cGUiOiAicGF5bWVudC5hbW91bnRfcmFuZ2UiLCAiY3VycmVuY3kiOiAiVVNEIiwgIm1heCI6IDEwMDAwMDB9XSwgImNuZiI6IHsiandrIjogeyJjcnYiOiAiUC0yNTYiLCAia3R5IjogIkVDIiwgIngiOiAid0JhSngxRm9XSUZJVVdxcVVWVG1IVHlqOGZraUlSWFlTSlMyY1AtZmxXdyIsICJ5IjogIk44b0FkVnRXbEppOWRyMHktbWVObnhnWVRic1NIcWJuQXN3Ynl6MWU3ZzQifX0sICJpYXQiOiAxNzkzNjQ2MTc1LCAiZXhwIjogMTc5MzY0OTc3NX1d~")

TABLE = {"10.0": 10, "1e2": 100, "100e-2": 1, "0.0": 0, "-0.0": 0, "1.0e2": 100, "9007199254740991.0": SAFE,
         "9007199254740992.0": None, "0.29": None, "1e-7": None, "10.000000000000000001": None, "1E400": None,
         "0.0e99999999999": 0, "1e99999999999": None, "123.4500e2": 12345, "12.3e1": 123, "12.34e1": None, "1e16": None,
         "900719925474099.1e1": SAFE, "-10.0": -10, "1.5": None, "2.50": None, "1e+2": 100, "0.000e5": 0, "1e-0": 1,
         "15e-1": None, "150e-1": 15, "250.00": 250, "-9007199254740991.0": -SAFE, "-9007199254740992e0": None}


def _exact(text):
    """The oracle: exact decimal arithmetic on the literal (Decimal construction never rounds)."""
    d = Decimal(text)
    if d != d.to_integral_value() or abs(d) > SAFE:
        return None
    return int(d)


def _random_literal(rnd):
    ip = str(rnd.choice([0, rnd.randint(1, 9), rnd.randint(10, 10**6), rnd.randint(10**12, 2**54)]))
    fp = "".join(rnd.choice("0000000123456789") for _ in range(rnd.randint(1, 20))) if rnd.random() < 0.8 else ""
    ex = (rnd.choice("eE") + rnd.choice(["", "+", "-"]) + str(rnd.randint(0, 25))) if rnd.random() < 0.5 else ""
    return ("-" if rnd.random() < 0.2 else "") + ip + ("." + fp if fp else "") + ex


def _js_literal(texts):
    """integralLiteral of the JS verifier on each literal (one node process), through the same regex it uses."""
    with open(_JS, encoding="utf-8") as fh:
        src = fh.read()
    start, end = src.index("function integralLiteral"), src.index("function parseStrict")
    code = ("const SAFE = 2 ** 53 - 1;\n" + src[start:end] + "\nconst T = JSON.parse(process.argv[1]); const out = {};\n"
            "for (const t of T) { const m = /^-?(0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?/.exec(t); out[t] = integralLiteral(m); }\n"
            "process.stdout.write(JSON.stringify(out));")
    p = subprocess.run(["node", "-e", code, json.dumps(texts)], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def _js_verify(path, accept=False):
    p = subprocess.run(["node", _JS, path] + (["--accept-integral-floats"] if accept else []), capture_output=True, text=True, timeout=120)
    return json.loads(p.stdout)


class _Accept:
    """1.7.2 (SPEC §3.1): run a direct parser call under accept_integral_floats, as verify/build do."""
    def __enter__(self):
        self.t = ap2._INTEGRAL_READ.set([]); return ap2._INTEGRAL_READ.get()
    def __exit__(self, *a):
        ap2._INTEGRAL_READ.reset(self.t)


DEFAULT_ERR = " in the SD-JWT needs accept_integral_floats"   # 1.7.2: "float <literal>" before it, whole (1.7.1 named it first too)


class LiteralAlgorithm(unittest.TestCase):
    def test_table(self):
        for lit, want in TABLE.items():
            self.assertEqual(ap2._integral_literal(lit), want, lit)
            self.assertEqual(_exact(lit) if "99999999999" not in lit else want, want, lit)   # the oracle agrees (Decimal(1e99999999999) is slow to compare: pinned)

    def test_generative_against_exact_decimal(self):
        rnd = random.Random(20261102); lits = sorted({_random_literal(rnd) for _ in range(3000)})
        for lit in lits:
            self.assertEqual(ap2._integral_literal(lit), _exact(lit), lit)
        self.assertGreater(sum(1 for l in lits if _exact(l) is not None), 100)   # both outcomes are exercised
        self.assertGreater(sum(1 for l in lits if _exact(l) is None), 100)

    def test_not_a_number_literal(self):
        for bad in ("", "abc", "1.", ".5", "1e", "--1.0", "0x10", "1.0 "):
            self.assertIsNone(ap2._integral_literal(bad), bad)   # json never hands these to parse_float; defensive
        self.assertEqual(ap2._integral_literal("10"), 10)        # a plain integer literal is its own integer

    def test_js_algorithm_agrees(self):
        if not shutil.which("node"):
            self.skipTest("node absent: the JS verifier is not measured")
        rnd = random.Random(7); lits = sorted({_random_literal(rnd) for _ in range(2000)} | set(TABLE))
        js = _js_literal(lits)
        for lit in lits:
            self.assertEqual(js[lit], ap2._integral_literal(lit), lit)


class TokenLayer(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2num-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        with open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"), encoding="utf-8") as fh:
            self.base = json.load(fh)
        self.sk, self.n = O._fresh_key()
        self.H = '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}'

    def _pack(self, name, payload_txt, recorded):
        p = os.path.join(self.d, name + ".json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(O.rehash(O._fresh_pack(self.base, self.sk, self.n, self.H, payload_txt, recorded)), fh)
        return p

    TXT = '{"iss":"x","exp":1700003600.0,"b":{"max":10.0,"n":1e2,"z":-0.0,"big":9007199254740991.0}}'
    LITS = ["1700003600.0", "10.0", "1e2", "-0.0", "9007199254740991.0"]

    def test_default_an_integral_literal_is_the_artifacts_error_both_verifiers(self):
        p = self._pack("ok", self.TXT, {"iss": "x", "exp": 1700003600, "b": {"max": 10, "n": 100, "z": 0, "big": SAFE}})
        r = ap2.verify_evidence(p)
        self.assertFalse(r["valid"]); err = r["artifacts"][0].get("error") or ""
        self.assertIn("float '1700003600.0'" + DEFAULT_ERR, err)   # the literal whole inside the 120 characters of the receipt
        self.assertEqual(r["states"]["sealed_content"]["state"], "contradicted")
        self.assertNotIn("accept_integral_floats", r); self.assertNotIn("integral_literals_read", r["artifacts"][0])   # 1.7.1 receipt shape
        with open(p, encoding="utf-8") as fh:
            compact = json.load(fh)["artifacts"][0]["sd_jwt_compact"]
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.parse_sd_jwt(compact)
        if shutil.which("node"):
            j = _js_verify(p); self.assertFalse(j["valid"]); self.assertIn("float 1700003600.0" + DEFAULT_ERR, j["artifacts"][0].get("error") or "")
            self.assertNotIn("accept_integral_floats", j); self.assertNotIn("integral_literals_read", j["artifacts"][0])

    def test_option_reads_integral_literals_as_integers_and_names_them_both_verifiers(self):
        p = self._pack("ok", self.TXT, {"iss": "x", "exp": 1700003600, "b": {"max": 10, "n": 100, "z": 0, "big": SAFE}})
        r = ap2.verify_evidence(p, accept_integral_floats=True)
        self.assertTrue(r["valid"], r); self.assertTrue(r["artifacts"][0]["claims_match"])   # matched on the integers recorded
        self.assertIs(r["accept_integral_floats"], True); self.assertEqual(r["artifacts"][0]["integral_literals_read"], self.LITS)
        with open(p, encoding="utf-8") as fh:
            compact = json.load(fh)["artifacts"][0]["sd_jwt_compact"]
        with _Accept():
            read = ap2.parse_sd_jwt(compact)["payload"]
        self.assertEqual(read["b"], {"max": 10, "n": 100, "z": 0, "big": SAFE}); self.assertEqual(read["exp"], 1700003600)
        self.assertTrue(all(type(v) is int for v in read["b"].values()))
        self.assertIsNone(ap2._INTEGRAL_READ.get())   # the option does not leak past the call
        if shutil.which("node"):
            j = _js_verify(p, accept=True); self.assertTrue(j["valid"], j); self.assertTrue(j["artifacts"][0]["claims_match"])
            self.assertIs(j["accept_integral_floats"], True); self.assertEqual(j["artifacts"][0]["integral_literals_read"], self.LITS)

    def test_option_must_be_a_boolean(self):
        p = self._pack("ok", '{"iss":"x"}', {"iss": "x"})
        for bad in ("true", 1, None):
            with self.assertRaises(ValueError):
                ap2.verify_evidence(p, accept_integral_floats=bad)
            with self.assertRaises(ValueError):
                ap2.verify_restrictions(p, accept_integral_floats=bad)
            with self.assertRaises(ValueError):
                ap2.build_evidence([], os.path.join(self.d, "x.json"), accept_integral_floats=bad)
        r0, r1 = ap2.verify_evidence(p), ap2.verify_evidence(p, accept_integral_floats=True)   # a token with no such literal:
        self.assertTrue(r0["valid"] and r1["valid"]); self.assertEqual(r1["artifacts"][0]["integral_literals_read"], [])   # same verdict
        self.assertEqual({k: v for k, v in r1.items() if k != "accept_integral_floats"} | {"artifacts": None},
                         r0 | {"artifacts": None})

    def test_recorded_integer_is_what_the_pack_must_carry(self):
        # under the option the record says 10.0 is 10; a pack recording anything else for the same signed bytes is claims_match false
        p = self._pack("mismatch", '{"iss":"x","max":10.0}', {"iss": "x", "max": 11})
        r = ap2.verify_evidence(p, accept_integral_floats=True); self.assertFalse(r["valid"]); self.assertFalse(r["artifacts"][0]["claims_match"])

    def test_fraction_and_past_range_are_the_artifacts_error_with_or_without_the_option(self):
        for name, txt in (("frac", '{"iss":"x","max":0.29}'), ("tiny", '{"iss":"x","max":1e-7}'),
                          ("range", '{"iss":"x","max":9007199254740992.0}'), ("exp", '{"iss":"x","max":1E400}'),
                          ("round", '{"iss":"x","max":10.000000000000000001}')):   # float() says 10.0: the digits say no
            p = self._pack(name, txt, {"iss": "x"})
            for accept, want in ((False, DEFAULT_ERR), (True, "in the SD-JWT: not an integer within")):
                r = ap2.verify_evidence(p, accept_integral_floats=accept)
                self.assertFalse(r["valid"], name); err = r["artifacts"][0].get("error") or ""
                self.assertIn(want, err, (name, accept, err))   # the receipt keeps 120 chars of an error
                self.assertEqual(r["states"]["sealed_content"]["state"], "contradicted", name)
                if shutil.which("node"):
                    j = _js_verify(p, accept=accept); self.assertFalse(j["valid"], name)
                    self.assertIn(DEFAULT_ERR if not accept else "not an integer within", j["artifacts"][0].get("error") or "", (name, accept))

    def test_file_layer_unchanged_a_float_in_the_file_is_a_refusal(self):
        p = os.path.join(self.d, "file.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(O.rehash(dict(self.base, extra=10.0)), fh)          # 10.0 in the FILE: json.dump writes "10.0"
        for accept in (False, True):                                      # the option is for the SD-JWT layer only
            r = ap2.verify_evidence(p, accept_integral_floats=accept)
            self.assertFalse(r["valid"]); self.assertIn("float '10.0' in the evidence file", r["refused"] or "")
            if shutil.which("node"):
                j = _js_verify(p, accept=accept); self.assertFalse(j["valid"]); self.assertIn("float 10.0", j.get("refused") or "")
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.loads_strict('{"a":10.0}')                                   # the file profile, as before
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.loads_strict('{"a":10.0}', token=True)                       # the token layer, default
        with _Accept() as read:
            self.assertEqual(ap2.loads_strict('{"a":10.0}', token=True), {"a": 10}); self.assertEqual(read, ["10.0"])
            with self.assertRaises(ap2.Ap2EvidenceError):
                ap2.loads_strict('{"a":10.0}')                               # the file profile, even under the option

    def test_disclosure_and_kb_jwt_segments_too(self):
        # the rule is for every JSON text of the token; here the KB-JWT payload carries an integral literal in iat
        import test_ap2_evidence as T
        sk, jwk = T._make_signer(); hsk, hjwk = T._make_signer()
        issuer = T._make_sd_jwt(sk, {"iss": "u", "cnf": {"jwk": hjwk}}, {"a": "1"}, header_extra={"jwk": jwk})
        for lit, ok in (("1700000000.0", True), ("1700000000.5", False)):
            sd_hash = T._b64u(__import__("hashlib").sha256(issuer.encode("ascii")).digest())
            kb_payload = '{"iat":%s,"aud":"rp","nonce":"n","sd_hash":"%s"}' % (lit, sd_hash)
            si = T._b64u(json.dumps({"alg": "ES256", "typ": "kb+jwt"}).encode()) + "." + T._b64u(kb_payload.encode())
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            r_, s_ = decode_dss_signature(hsk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
            kb = si + "." + T._b64u(r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))
            out = os.path.join(self.d, "kb_%s.json" % ok)
            with self.assertRaises(ap2.Ap2EvidenceError) as cm0:              # default: refused, nothing written
                ap2.build_evidence([{"name": "a", "sd_jwt": issuer + kb}], out)
            self.assertIn(DEFAULT_ERR, str(cm0.exception)); self.assertFalse(os.path.exists(out))
            if ok:
                res = ap2.build_evidence([{"name": "a", "sd_jwt": issuer + kb}], out, accept_integral_floats=True)
                self.assertEqual(res["integral_literals_read"], [lit])
                self.assertFalse(ap2.verify_evidence(out)["valid"])           # a pack built under the option needs it to verify
                r = ap2.verify_evidence(out, accept_integral_floats=True); self.assertTrue(r["valid"], r); self.assertTrue(r["artifacts"][0]["kb_jwt"]["verified"])
                seg = kb.split(".")[1]
                with _Accept():
                    self.assertEqual(ap2._loads_segment(__import__("base64").urlsafe_b64decode(seg + "=" * (-len(seg) % 4)), "kb")["iat"], 1700000000)
            else:
                with self.assertRaises(ap2.Ap2EvidenceError) as cm:
                    ap2.build_evidence([{"name": "a", "sd_jwt": issuer + kb}], out, accept_integral_floats=True)
                self.assertIn("not an integer", str(cm.exception)); self.assertFalse(os.path.exists(out))


class SdkBudgetMandates(unittest.TestCase):
    """The tokens the AP2 SDK at e1ea56d really writes (`Budget.max: float`): build, verify, both verifiers, the CLI."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2num-sdk-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _budget(self, claims):
        return [c for c in claims["delegate_payload"][0]["constraints"] if c["type"] == "payment.budget"][0]["max"]

    def _cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py")] + list(args), capture_output=True, text=True)

    def test_sdk_budget_10_is_refused_by_default(self):
        out = os.path.join(self.d, "b10.json")
        with self.assertRaises(ap2.Ap2EvidenceError) as cm:
            ap2.build_evidence([{"name": "open_payment", "sd_jwt": SDK_BUDGET_10}], out, keys={"open_payment": SDK_ISSUER_JWK})
        self.assertIn(DEFAULT_ERR, str(cm.exception)); self.assertFalse(os.path.exists(out))

    def test_sdk_budget_10_written_as_10_0_builds_and_verifies_under_the_option_and_records_10(self):
        out = os.path.join(self.d, "b10.json")
        res = ap2.build_evidence([{"name": "open_payment", "sd_jwt": SDK_BUDGET_10}], out, keys={"open_payment": SDK_ISSUER_JWK},
                                 accept_integral_floats=True)
        self.assertEqual(res["artifacts"], 1); self.assertIs(res["accept_integral_floats"], True); self.assertIn("10.0", res["integral_literals_read"])
        with open(out, encoding="utf-8") as fh:
            pack = json.load(fh)
        self.assertEqual(self._budget(pack["artifacts"][0]["resolved_claims"]), 10)
        self.assertIn('"max": 10.0', __import__("base64").urlsafe_b64decode(SDK_BUDGET_10.split("~")[1] + "==").decode())   # the signed literal
        self.assertFalse(ap2.verify_evidence(out)["valid"])                    # default: that artifact's error
        r = ap2.verify_evidence(out, accept_integral_floats=True); self.assertTrue(r["valid"], r); self.assertTrue(r["artifacts"][0]["claims_match"])
        self.assertIn("10.0", r["artifacts"][0]["integral_literals_read"])
        self.assertEqual(ap2.loads_strict(json.dumps(pack)), pack)   # the pack is within the file profile: no float written
        if shutil.which("node"):
            self.assertFalse(_js_verify(out)["valid"])
            j = _js_verify(out, accept=True); self.assertTrue(j["valid"], j); self.assertTrue(j["artifacts"][0]["claims_match"])
        self.assertEqual(self._cli("verify", out).returncode, 1)
        p = self._cli("verify", out, "--accept-integral-floats"); self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIs(json.loads(p.stdout)["accept_integral_floats"], True)
        self.assertEqual(self._cli("verify", out, "--accept-integral-floats=1").returncode, 2)   # a value on a boolean flag: usage
        out2 = os.path.join(self.d, "cli.json"); tok = os.path.join(self.d, "t.sdjwt"); key = os.path.join(self.d, "k.json")
        with open(tok, "w") as fh:
            fh.write(SDK_BUDGET_10)
        with open(key, "w") as fh:
            json.dump(SDK_ISSUER_JWK, fh)
        self.assertNotEqual(self._cli("build", out2, "open_payment=" + tok, "--key", "open_payment=" + key).returncode, 0)
        self.assertFalse(os.path.exists(out2))
        p = self._cli("build", out2, "open_payment=" + tok, "--key", "open_payment=" + key, "--accept-integral-floats")
        self.assertEqual(p.returncode, 0, p.stderr); self.assertIn("10.0", json.loads(p.stdout)["integral_literals_read"])

    def test_sdk_budget_0_29_is_refused_with_the_literal_named(self):
        out = os.path.join(self.d, "b029.json")
        for accept, want in ((False, "float '0.29'" + DEFAULT_ERR),
                             (True, "float '0.29' in the SD-JWT: not an integer within +/-(2^53-1)")):
            with self.assertRaises(ap2.Ap2EvidenceError) as cm:
                ap2.build_evidence([{"name": "open_payment", "sd_jwt": SDK_BUDGET_0_29}], out, keys={"open_payment": SDK_ISSUER_JWK},
                                   accept_integral_floats=accept)
            self.assertIn(want, str(cm.exception)); self.assertFalse(os.path.exists(out))

    def test_restriction_profile_reads_the_budget_as_an_integer_under_the_option(self):
        # SPEC §11.4: `max` well-formed (an int) after the 1.7.2 reading — the constraint schema check passes on the SDK token
        out = os.path.join(self.d, "b10.json")
        ap2.build_evidence([{"name": "open_payment", "sd_jwt": SDK_BUDGET_10}], out, keys={"open_payment": SDK_ISSUER_JWK},
                           accept_integral_floats=True)
        with open(out, encoding="utf-8") as fh:
            claims = json.load(fh)["artifacts"][0]["resolved_claims"]
        budget = [c for c in claims["delegate_payload"][0]["constraints"] if c["type"] == "payment.budget"][0]
        req, opt = ap2._CONSTRAINT_SCHEMAS["payment.budget"]
        self.assertTrue(all(pred(budget[k]) for k, pred in req.items()))
        self.assertTrue(ap2._within("payment.budget", budget, dict(budget, max=9)))
        self.assertFalse(ap2._within("payment.budget", budget, dict(budget, max=11)))
        r0, r1 = ap2.verify_restrictions(out), ap2.verify_restrictions(out, accept_integral_floats=True)
        self.assertNotIn("accept_integral_floats", r0); self.assertIs(r1["accept_integral_floats"], True)


class ReviewGaps172(unittest.TestCase):
    """1.7.2 review: what the mutants of the new lines showed untested — the 30-character cut of a literal read, the list
    per artifact in a pack of two, the option through `restriction` (library and CLI) end to end, and the option on the
    receipt that travels inside Ap2WriteError."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2num-rev-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        with open(os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json"), encoding="utf-8") as fh:
            self.base = json.load(fh)
        self.H = '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}'

    def _write(self, ev, name):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(O.rehash(ev), fh)
        return p

    def test_a_literal_longer_than_30_characters_is_listed_cut_to_30_in_both_verifiers(self):
        lit = "10." + "0" * 40                       # 43 characters, value 10
        sk, n = O._fresh_key()
        p = self._write(O._fresh_pack(self.base, sk, n, self.H, '{"iss":"x","max":%s,"m":%s}' % (lit, "1" + "0" * 29 + "e-29"),
                                      {"iss": "x", "max": 10, "m": 1}), "long.json")
        want = [lit[:30] + "…", ("1" + "0" * 29 + "e-29")[:30] + "…"]   # the second literal is 34 characters: cut too
        r = ap2.verify_evidence(p, accept_integral_floats=True)
        self.assertTrue(r["valid"], r); self.assertEqual(r["artifacts"][0]["integral_literals_read"], want)
        if shutil.which("node"):
            j = _js_verify(p, accept=True); self.assertTrue(j["valid"], j)
            self.assertEqual(j["artifacts"][0]["integral_literals_read"], want)
        exact30 = "10." + "0" * 27                   # exactly 30: not cut
        p2 = self._write(O._fresh_pack(self.base, sk, n, self.H, '{"iss":"x","max":%s}' % exact30, {"iss": "x", "max": 10}), "l30.json")
        self.assertEqual(ap2.verify_evidence(p2, accept_integral_floats=True)["artifacts"][0]["integral_literals_read"], [exact30])
        if shutil.which("node"):
            self.assertEqual(_js_verify(p2, accept=True)["artifacts"][0]["integral_literals_read"], [exact30])

    def test_each_artifact_lists_only_its_own_literals_in_both_verifiers(self):
        sk1, n1 = O._fresh_key(); sk2, n2 = O._fresh_key()
        a = O._fresh_pack(self.base, sk1, n1, self.H, '{"iss":"a","max":10.0}', {"iss": "a", "max": 10})["artifacts"][0]
        b = O._fresh_pack(self.base, sk2, n2, self.H, '{"iss":"b","max":250.00,"n":1e2}', {"iss": "b", "max": 250, "n": 100})["artifacts"][0]
        c = O._fresh_pack(self.base, sk2, n2, self.H, '{"iss":"c"}', {"iss": "c"})["artifacts"][0]
        a["name"], b["name"], c["name"] = "first", "second", "third"
        ev = dict(self.base, artifacts=[a, b, c], bindings=[])
        p = self._write(ev, "three.json")
        want = [["10.0"], ["250.00", "1e2"], []]
        r = ap2.verify_evidence(p, accept_integral_floats=True)
        self.assertTrue(r["valid"], r); self.assertEqual([x["integral_literals_read"] for x in r["artifacts"]], want)
        if shutil.which("node"):
            j = _js_verify(p, accept=True); self.assertTrue(j["valid"], j)
            self.assertEqual([x["integral_literals_read"] for x in j["artifacts"]], want)

    def test_restriction_under_the_option_judges_float_budgets_end_to_end(self):
        import copy
        import test_ap2_restriction as R
        def content(mx):
            c = copy.deepcopy(R.RICH); c["constraints"][R.ci(c, "payment.budget")]["max"] = mx; return c
        o = R.issue(content(1000.0))                 # json.dumps writes the SDK's form: "max": 1000.0
        for rmax, state, met in ((900.0, "verified", True), (1100.0, "contradicted", False)):
            out = os.path.join(self.d, "r%s.json" % rmax)
            ap2.build_evidence([{"name": "original", "sd_jwt": o}, {"name": "restriction", "sd_jwt": R.restrict(o, content(rmax))}],
                               out, accept_integral_floats=True)
            r0 = ap2.verify_restrictions(out)        # default: the tokens are that artifact's error, the pack is not valid
            self.assertIs(r0["valid"], False); self.assertIs(r0["met"], False); self.assertNotIn("accept_integral_floats", r0)
            r1 = ap2.verify_restrictions(out, accept_integral_floats=True)
            self.assertIs(r1["valid"], True, r1); self.assertEqual(r1["restrictions"][0]["state"], state, r1); self.assertIs(r1["met"], met)
            p = subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "restriction", out, "--accept-integral-floats"],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0 if met else 1, p.stderr); self.assertIs(json.loads(p.stdout)["met"], met)
            self.assertEqual(subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "restriction", out],
                                            capture_output=True, text=True).returncode, 1)
        self.assertIsNone(ap2._INTEGRAL_READ.get())

    def test_the_receipt_inside_ap2writeerror_carries_the_option(self):
        import errno
        from unittest import mock
        vdir = os.path.join(_HERE, "spec", "vectors", "ap2")
        pack, cert = os.path.join(vdir, "time_tsa_verified.json"), os.path.join(vdir, "anchor_probe_tsa.crt")
        if not shutil.which("openssl"):
            self.skipTest("openssl absent: the TSA check is not reached")
        with mock.patch("subprocess.run", side_effect=OSError(errno.EAGAIN, "fork refused")):
            for fn in (lambda **k: ap2.verify_evidence(pack, tsa_cert=cert, **k), lambda **k: ap2.verify_restrictions(pack, tsa_cert=cert, **k)):
                with self.assertRaises(ap2.Ap2WriteError) as cm:
                    fn(accept_integral_floats=True)
                self.assertIs(cm.exception.receipt.get("accept_integral_floats"), True)
                with self.assertRaises(ap2.Ap2WriteError) as cm:
                    fn()
                self.assertNotIn("accept_integral_floats", cm.exception.receipt)
        self.assertIsNone(ap2._INTEGRAL_READ.get())

    def test_js_option_is_a_boolean_and_takes_no_value_on_the_cli(self):
        if not shutil.which("node"):
            self.skipTest("node absent: the JS verifier is not measured")
        v = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")
        p = subprocess.run(["node", _JS, v, "--accept-integral-floats=1"], capture_output=True, text=True, timeout=120)
        self.assertEqual((p.returncode, p.stdout), (2, ""))   # a value on a boolean flag: usage, as in the reference
        code = ("import { pathToFileURL } from 'node:url'; const { verifyEvidence } = await import(pathToFileURL(process.env.AP2_JS).href);"
                "const out = []; for (const bad of ['true', 1, null]) { try { verifyEvidence(process.env.AP2_V, { acceptIntegralFloats: bad }); out.push('accepted'); }"
                " catch (e) { out.push(e instanceof TypeError ? 'TypeError' : 'other'); } } process.stdout.write(JSON.stringify(out));")
        p = subprocess.run(["node", "--input-type=module", "-e", code], capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, AP2_JS=_JS, AP2_V=v))   # not argv: the module runs its CLI when argv[1] is itself
        self.assertEqual(json.loads(p.stdout), ["TypeError"] * 3, p.stderr)

    def test_two_threads_one_value_each(self):
        # the option is one value per call and thread (a ContextVar): measured with module-wide state instead, 131 of 480
        # verifications in 8 threads took the other thread's reading
        import threading
        sk, n = O._fresh_key()
        p = self._write(O._fresh_pack(self.base, sk, n, self.H, '{"iss":"x","max":10.0}', {"iss": "x", "max": 10}), "thr.json")
        bad = []
        def work(acc):
            for _ in range(40):
                r = ap2.verify_evidence(p, accept_integral_floats=acc)
                if r["valid"] is not acc or ("accept_integral_floats" in r) is not acc or (acc and r["artifacts"][0]["integral_literals_read"] != ["10.0"]):
                    bad.append(acc)
        ts = [threading.Thread(target=work, args=(i % 2 == 0,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(bad, []); self.assertIsNone(ap2._INTEGRAL_READ.get())


if __name__ == "__main__":
    unittest.main()
