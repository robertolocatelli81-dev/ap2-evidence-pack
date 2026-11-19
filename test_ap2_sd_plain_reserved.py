#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.1, SPEC §3.1 and §6 step 2: the reserved names of RFC 9901 as PLAIN keys. A key `...` is admitted only as the only
key of an array element whose value is a string (the placeholder, §4.2.4.2), and a key `_sd_alg` only at the top level
of the issuer payload (§4.1.1). Variant "report, do not refuse": a plain `...` anywhere else is kept as an ordinary
claim and named in the receipt and in the build result (`reserved_names_in_clear`), in both verifiers; a nested `_sd_alg`
stays the artifact's error `sd_alg_not_top_level`, in the library, in `build`, and in both verifiers.

Measured on 2026-11-18 on the PyPI wheel 1.8.0 by an external review, and on the branch before this change: a plain
`"..."` key (top level or nested) was kept as an ordinary claim and a nested `_sd_alg` dropped in silence, `valid: true`.

The corpus reuses the grower of test_ap2_sd_rules.py (digests in every position, decoys, disclosed objects and arrays)
and plants exactly one reserved key per planted case, at a random depth, inside the payload or inside a disclosed
value before its disclosure is encoded; the generator knows the processed payload it meant and whether it planted. On
the previous commit the four tests that expect a refusal fail (library, named cases, build, sealed packs)."""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "verifiers"))
import ap2_evidence as ap2  # noqa: E402
import differential_oracle as O  # noqa: E402
from test_ap2_evidence import _b64u, _disclosure, _make_signer, _sign_jwt  # noqa: E402
from test_ap2_sd_rules import Grower  # noqa: E402

_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_MANY = os.path.join(_HERE, "verifiers", "js", "verify_many.mjs")
_VALID = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")
REASON = {"sd_alg": "sd_alg_not_top_level"}
DOTS = ("dots", "dots_array")   # variant "report, do not refuse": a plain "..." key is kept as a claim and named in the receipt


def _has_dots(node):
    if isinstance(node, dict):
        return "..." in node or any(_has_dots(v) for v in node.values())
    return isinstance(node, list) and any(_has_dots(v) for v in node)


class Planter(Grower):
    def __init__(self, rnd, kind):
        super().__init__(rnd, None)
        self.kind = kind   # None | "dots" (a plain "..." key in an object) | "dots_array" | "sd_alg" (nested plain _sd_alg)
        self.where = None

    def obj(self, depth):
        raw, out = super().obj(depth)
        # at least one other key: an object whose only key is "..." inside an array is a placeholder, not this plant
        if self.kind in ("dots", "sd_alg") and self.planted is None and (depth > 0 or self.kind == "dots") \
                and raw and self.rnd.random() < 0.6:
            key = "..." if self.kind == "dots" else "_sd_alg"
            raw[key] = self.rnd.choice(["sha-256", _b64u(os.urandom(32)), 5, None, {"a": 1}, []])
            items = list(raw.items()); self.rnd.shuffle(items); raw = dict(items)
            self.planted, self.where = self.kind, depth
        return raw, out

    def arr(self, depth):
        raw, out = super().arr(depth)
        if self.kind == "dots_array" and self.planted is None and self.rnd.random() < 0.5:
            el = {"...": _b64u(os.urandom(32)), self.rnd.choice(["k", "_sd", "x"]): self.rnd.choice([1, "v", []])}
            if "_sd" in el:
                el["_sd"] = []
            raw.insert(self.rnd.randint(0, len(raw)), el)
            self.planted, self.where = self.kind, depth
        return raw, out


def corpus(seed=20261118, n=400):
    rnd = random.Random(seed)
    cases = []
    for i in range(n):
        g = Planter(rnd, (None, "dots", "dots_array", "sd_alg")[i % 4])
        payload, discs, out, planted = g.grow()
        cases.append({"i": i, "payload": payload, "discs": discs, "out": out, "planted": planted, "where": g.where})
    return cases


CASES = corpus()


class PlainReserved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.jwk = _make_signer()

    def test_corpus_holds_every_kind(self):
        kinds = [c["planted"] for c in CASES]
        for k in (None, "dots", "dots_array", "sd_alg"):
            self.assertGreaterEqual(kinds.count(k), 40, k)
        self.assertTrue(any(c["planted"] == "dots" and c["where"] == 0 for c in CASES))   # the payload's top level
        self.assertTrue(any(c["planted"] == "sd_alg" and c["where"] >= 2 for c in CASES))   # inside a disclosed value

    def token(self, c):
        return _sign_jwt(self.sk, {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": self.jwk}, c["payload"]) + "~" + \
            "".join(d + "~" for d in c["discs"])

    def test_library(self):
        for c in CASES:
            p = ap2.parse_sd_jwt(self.token(c))
            with self.subTest(i=c["i"], planted=c["planted"]):
                if c["planted"] is None:
                    census = {}
                    self.assertEqual(ap2.resolve_disclosures(p["payload"], p["disclosures"], census=census), c["out"])
                    self.assertEqual(census["reserved_names_in_clear"], {})
                elif c["planted"] in DOTS:   # kept, exactly once, and counted
                    census = {}
                    res = ap2.resolve_disclosures(p["payload"], p["disclosures"], census=census)
                    self.assertEqual(census["reserved_names_in_clear"], {"...": 1})
                    self.assertTrue(_has_dots(res))
                else:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, "^" + REASON[c["planted"]] + ": "):
                        ap2.resolve_disclosures(p["payload"], p["disclosures"])

    def test_named_cases(self):
        d1 = _disclosure("c2FsdA", "o", {"_sd_alg": "sha-256", "k": 1})
        for payload, n in (({"iss": "x", "...": "hidden"}, 1), ({"iss": "x", "o": {"...": "h"}}, 1),
                           ({"iss": "x", "l": [{"...": "abc", "k": 1}]}, 1), ({"...": 1, "o": {"...": 2, "p": [{"...": "d", "q": 0}]}}, 3)):
            with self.subTest(kept=payload):
                census = {}
                self.assertEqual(ap2.resolve_disclosures(payload, [], census=census), payload)   # an ordinary claim, as up to 1.8.0
                self.assertEqual(census["reserved_names_in_clear"], {"...": n})
        named = [({"iss": "x", "o": {"_sd_alg": "sha-256"}}, [], "sd_alg_not_top_level"),
                 ({"iss": "x", "_sd": [ap2._disclosure_digest(d1)]}, [d1], "sd_alg_not_top_level"),
                 ({"iss": "x", "l": [{"...": 5}]}, [], "array disclosure placeholder must be a digest string")]
        for payload, discs, why in named:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ap2.Ap2EvidenceError, why):
                    ap2.resolve_disclosures(payload, discs)
        # what stays admitted: the placeholder, `_sd_alg` at the top level, a disclosed claim NAMED _sd_alg, names that
        # only look reserved
        d2 = _disclosure("c2FsdA", "_sd_alg", 3)
        self.assertEqual(ap2.resolve_disclosures({"iss": "x", "_sd_alg": "sha-256", "l": [{"...": "abc"}], "..x": 1, "_sd_algx": 2,
                                                  "o": {"_sd": [ap2._disclosure_digest(d2)]}}, [d2]),
                         {"iss": "x", "l": [], "..x": 1, "_sd_algx": 2, "o": {"_sd_alg": 3}})

    def test_build_refuses(self):
        d = tempfile.mkdtemp(prefix="ap2-sdpr-b-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for payload in ({"iss": "x", "o": {"_sd_alg": "sha-256"}},):
            tok = _sign_jwt(self.sk, {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": self.jwk}, payload) + "~"
            out = os.path.join(d, "o.json")
            with self.assertRaisesRegex(ap2.Ap2EvidenceError, "sd_alg_not_top_level"):
                ap2.build_evidence([{"name": "payment", "sd_jwt": tok}], out, tsa_url=None)
            self.assertFalse(os.path.exists(out))
        # a plain "..." builds, and the build result and the receipt name it
        tok = _sign_jwt(self.sk, {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": self.jwk}, {"iss": "x", "...": "hidden"}) + "~"
        out = os.path.join(d, "dots.json")
        r = ap2.build_evidence([{"name": "payment", "sd_jwt": tok}], out, tsa_url=None)
        self.assertEqual(r["reserved_names_in_clear"], {"payment": {"...": 1}})
        rv = ap2.verify_evidence(out)
        self.assertTrue(rv["valid"]); self.assertEqual(rv["artifacts"][0]["reserved_names_in_clear"], {"...": 1})

    def test_sealed_packs_in_both_verifiers(self):
        with open(_VALID, encoding="utf-8") as f:
            base = json.load(f)
        sk, n = O._fresh_key()
        d = tempfile.mkdtemp(prefix="ap2-sdpr-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        manifest = []
        for c in CASES:
            want = c["out"] if c["planted"] not in DOTS else ap2.resolve_disclosures(c["payload"], c["discs"])
            ev = O._fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', json.dumps(c["payload"]), want,
                               disclosures=c["discs"])
            path = os.path.join(d, f"{c['i']}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            r = ap2.verify_evidence(path)
            with self.subTest(i=c["i"], planted=c["planted"], verifier="python"):
                if c["planted"] is None:
                    self.assertTrue(r["valid"], r["artifacts"])
                    self.assertNotIn("reserved_names_in_clear", r["artifacts"][0])
                elif c["planted"] in DOTS:
                    self.assertTrue(r["valid"], r["artifacts"])
                    self.assertEqual(r["artifacts"][0]["reserved_names_in_clear"], {"...": 1})
                else:
                    self.assertFalse(r["valid"])
                    self.assertIn(REASON[c["planted"]] + ": ", r["artifacts"][0].get("error", ""))
            manifest.append({"name": str(c["i"]), "path": path, "flags": []})
        if not shutil.which("node"):
            self.skipTest("node absent: the JS verifier is not measured")
        mpath = os.path.join(d, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        out = subprocess.run(["node", _MANY, _JS, mpath], capture_output=True, text=True, timeout=600)
        self.assertEqual(out.returncode, 0, out.stderr[-500:])
        receipts = json.loads(out.stdout)
        for c in CASES:
            r = receipts[str(c["i"])]
            with self.subTest(i=c["i"], planted=c["planted"], verifier="js"):
                self.assertNotIn("crash", r, r)
                if c["planted"] is None:
                    self.assertTrue(r["valid"], r["artifacts"])
                    self.assertNotIn("reserved_names_in_clear", r["artifacts"][0])
                elif c["planted"] in DOTS:   # the JS verifier resolves the same claims (claims_match) and names the key
                    self.assertTrue(r["valid"], r["artifacts"])
                    self.assertEqual(r["artifacts"][0]["reserved_names_in_clear"], {"...": 1})
                else:
                    self.assertFalse(r["valid"])
                    self.assertTrue(r["artifacts"][0].get("error", "").startswith(REASON[c["planted"]] + ": "), r["artifacts"][0])


if __name__ == "__main__":
    unittest.main()
