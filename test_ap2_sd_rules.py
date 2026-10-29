#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.7.0 — SPEC §6 step 2, RFC 9901 §7.1 steps 4 and 3.c.ii.2, proved generatively (closed by construction, not by example).

A random issuer payload is grown with digests in every position the RFC knows — `_sd` arrays at every depth, `{"...": d}`
array placeholders, both inside disclosed values too, decoys with no disclosure — and, by choice of the generator, a digest
REPEATED (the same value in a second slot of the same kind, anywhere) or a disclosed claim NAMED `_sd` or `...`. The oracle
is the generator itself: it knows the processed payload it meant, and whether it planted a violation. The reference must
resolve exactly that payload, or refuse with the rule's own reason — on the library, on `verify_evidence` over a sealed
pack, and on the JS verifier (one Node process over the whole corpus, `verifiers/js/verify_many.mjs`).

Positive control (run by hand, not in the suite): this file on fffadff (1.6.0) and on 54dd18e (the §11 draft) must FAIL —
measured 2026-10-29: on both trees every planted repeat and every reserved name resolves with no error.
"""
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

_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_MANY = os.path.join(_HERE, "verifiers", "js", "verify_many.mjs")
_VALID = os.path.join(_HERE, "spec", "vectors", "ap2", "valid_signed.json")


class Grower:
    """Grows one (payload, disclosures) with its intended processed payload and the violation it planted, if any."""

    def __init__(self, rnd, plant):
        self.rnd, self.plant = rnd, plant          # plant: None | "repeat" | "reserved"
        self.discs, self.names = [], 0
        self.slots = {"obj": [], "arr": [], "decoy": []}   # digests already emitted, by the slot kind they fit
        self.planted = None
        self.budget = 14                            # digests at most, so the tree stays small and the Node run short

    def name(self):
        self.names += 1
        return f"c{self.names}"

    def scalar(self):
        return self.rnd.choice([1, "s", True, None, -7, "", [], {}])   # no float: the §3.1 profile refuses it in the file, which is not this rule

    def decoy(self):
        d = _b64u(os.urandom(32))
        self.slots["decoy"].append(d)
        return d

    def maybe_repeat(self, kind):
        """A digest already emitted into a slot of this kind (or a decoy, which fits any), when the plant asks for it."""
        if self.plant == "repeat" and self.planted is None and self.rnd.random() < 0.5:
            pool = self.slots[kind] + self.slots["decoy"]
            if pool:
                self.planted = "repeat"
                return self.rnd.choice(pool)
        return None

    def value(self, depth):
        r = self.rnd.random()
        if depth >= 3 or r < 0.35:
            return (lambda s: (s, s))(self.scalar())
        if r < 0.7:
            return self.obj(depth + 1)
        return self.arr(depth + 1)

    def obj(self, depth):
        raw, out = {}, {}
        for _ in range(self.rnd.randint(0, 3)):
            k = self.name(); rv, pv = self.value(depth); raw[k] = rv; out[k] = pv
        sd = []
        for _ in range(self.rnd.randint(0, 2)):
            if self.budget <= 0:
                break
            self.budget -= 1
            rep = self.maybe_repeat("obj")
            if rep is not None:
                sd.append(rep); continue
            kind = self.rnd.random()
            if kind < 0.2:
                sd.append(self.decoy()); continue
            nm = self.name()
            if self.plant == "reserved" and self.planted is None and self.rnd.random() < 0.5:
                nm = self.rnd.choice(["_sd", "..."]); self.planted = "reserved"
            rv, pv = self.value(depth)
            d = _disclosure(_b64u(os.urandom(8)), nm, rv); self.discs.append(d)
            dig = ap2._disclosure_digest(d); self.slots["obj"].append(dig); sd.append(dig); out[nm] = pv
        if sd or self.rnd.random() < 0.3:
            self.rnd.shuffle(sd); raw["_sd"] = sd
        items = list(raw.items()); self.rnd.shuffle(items)
        return dict(items), out

    def arr(self, depth):
        raw, out = [], []
        for _ in range(self.rnd.randint(0, 3)):
            if self.budget > 0 and self.rnd.random() < 0.5:
                self.budget -= 1
                rep = self.maybe_repeat("arr")
                if rep is not None:
                    raw.append({"...": rep}); continue
                if self.rnd.random() < 0.2:
                    raw.append({"...": self.decoy()}); continue
                rv, pv = self.value(depth)
                d = _disclosure(_b64u(os.urandom(8)), None, rv); self.discs.append(d)
                dig = ap2._disclosure_digest(d); self.slots["arr"].append(dig); raw.append({"...": dig}); out.append(pv)
            else:
                rv, pv = self.value(depth); raw.append(rv); out.append(pv)
        return raw, out

    def grow(self):
        raw, out = self.obj(0)
        raw["iss"] = out["iss"] = "w"; raw["_sd_alg"] = "sha-256"
        self.rnd.shuffle(self.discs)
        return raw, self.discs, out, self.planted


def corpus(seed=20261029, n=240):
    """n cases: a third clean, a third asked to plant a repeat, a third a reserved name (planting can fail when the tree
    grew no slot for it: such a case is then a clean one, and counted as such)."""
    rnd = random.Random(seed)
    cases = []
    for i in range(n):
        plant = (None, "repeat", "reserved")[i % 3]
        g = Grower(rnd, plant)
        payload, discs, out, planted = g.grow()
        cases.append({"i": i, "payload": payload, "discs": discs, "out": out, "planted": planted})
    return cases


class TestGenerativeSdRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.jwk = _make_signer()
        cls.cases = corpus()
        kinds = {c["planted"] for c in cls.cases}
        assert kinds == {None, "repeat", "reserved"}, kinds   # the corpus must hold every kind, or the test proves less than it says
        assert sum(c["planted"] == "repeat" for c in cls.cases) >= 40 and sum(c["planted"] == "reserved" for c in cls.cases) >= 40

    def token(self, c):
        return _sign_jwt(self.sk, {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": self.jwk}, c["payload"]) + "~" + "".join(d + "~" for d in c["discs"])

    def test_library_resolves_the_intended_payload_or_refuses_with_the_rules_reason(self):
        n_ok = n_rep = n_res = 0
        for c in self.cases:
            p = ap2.parse_sd_jwt(self.token(c))
            with self.subTest(i=c["i"], planted=c["planted"]):
                if c["planted"] is None:
                    self.assertEqual(ap2.resolve_disclosures(p["payload"], p["disclosures"]), c["out"]); n_ok += 1
                else:
                    want = "more than once" if c["planted"] == "repeat" else "is reserved"
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, want):
                        ap2.resolve_disclosures(p["payload"], p["disclosures"])
                    if c["planted"] == "repeat":
                        n_rep += 1
                    else:
                        n_res += 1
        self.assertGreaterEqual(min(n_ok, n_rep, n_res), 40, (n_ok, n_rep, n_res))

    def test_sealed_packs_in_both_verifiers(self):
        """The same corpus as packs: `verify_evidence` and the JS verifier say `valid` exactly on the clean cases, and
        name the rule on the planted ones (the pack records what the generator meant as `resolved_claims`)."""
        with open(_VALID, encoding="utf-8") as f:
            base = json.load(f)
        sk, n = O._fresh_key()
        d = tempfile.mkdtemp(prefix="ap2-sdrules-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        manifest = []
        for c in self.cases:
            ev = O._fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', json.dumps(c["payload"]), c["out"], disclosures=c["discs"])
            path = os.path.join(d, f"{c['i']}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            r = ap2.verify_evidence(path)
            with self.subTest(i=c["i"], planted=c["planted"], verifier="python"):
                if c["planted"] is None:
                    self.assertTrue(r["valid"], r["artifacts"])
                else:
                    self.assertFalse(r["valid"])
                    self.assertIn("more than once" if c["planted"] == "repeat" else "is reserved", r["artifacts"][0].get("error", ""))
            manifest.append({"name": str(c["i"]), "path": path, "flags": []})
        # the acceptance frontier, pinned in BOTH verifiers (review 2026-10-29: a JS mutant that extended the reserved names to
        # `_sd_alg`, to every `_sd*` prefix or to `..` survived the corpus): a disclosed claim that merely looks like a reserved
        # name is an ordinary claim, at the top level beside the payload's own `_sd_alg` and nested inside a disclosed object
        controls = []
        for name in ("_sdx", "_sd_alg", ".."):
            d1 = _disclosure(_b64u(os.urandom(8)), name, 1)
            controls.append((f"pc_top_{name}", {"iss": "w", "_sd": [ap2._disclosure_digest(d1)], "_sd_alg": "sha-256"}, [d1], {"iss": "w", name: 1}))
            d2 = _disclosure(_b64u(os.urandom(8)), name, 2); inner = _disclosure(_b64u(os.urandom(8)), "inner", {"_sd": [ap2._disclosure_digest(d2)]})
            controls.append((f"pc_nested_{name}", {"iss": "w", "_sd": [ap2._disclosure_digest(inner)], "_sd_alg": "sha-256"}, [inner, d2], {"iss": "w", "inner": {name: 2}}))
        # a disclosed `_sd_alg` beside a plain `_sd_alg` in the same nested object: the plain one is dropped, the disclosed one
        # kept (SPEC §6 step 2, this format's declared reading; §7.1 step 3.c.ii.3 read literally would reject the SD-JWT)
        d3 = _disclosure(_b64u(os.urandom(8)), "_sd_alg", 3)
        controls.append(("pc_nested_beside_plain__sd_alg", {"iss": "w", "inner": {"_sd": [ap2._disclosure_digest(d3)], "_sd_alg": "sha-512", "k": 1}, "_sd_alg": "sha-256"}, [d3], {"iss": "w", "inner": {"k": 1, "_sd_alg": 3}}))
        for cname, payload, discs, want in controls:
            ev = O._fresh_pack(base, sk, n, '{"alg":"ES256","typ":"ap2-mandate+sd-jwt"}', json.dumps(payload), want, disclosures=discs)
            path = os.path.join(d, cname + ".json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            with self.subTest(control=cname, verifier="python"):
                r = ap2.verify_evidence(path)
                self.assertTrue(r["valid"], r["artifacts"])
            manifest.append({"name": cname, "path": path, "flags": []})
        if not shutil.which("node"):
            self.skipTest("node absent: the JS verifier is not measured")
        mpath = os.path.join(d, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        out = subprocess.run(["node", _MANY, _JS, mpath], capture_output=True, text=True, timeout=600)
        self.assertEqual(out.returncode, 0, out.stderr[-500:])
        receipts = json.loads(out.stdout)
        for c in self.cases:
            r = receipts[str(c["i"])]
            with self.subTest(i=c["i"], planted=c["planted"], verifier="js"):
                self.assertNotIn("crash", r, r)
                if c["planted"] is None:
                    self.assertTrue(r["valid"], r["artifacts"])
                else:
                    self.assertFalse(r["valid"])
                    self.assertIn("more than once" if c["planted"] == "repeat" else "is reserved", r["artifacts"][0].get("error", ""))
        for cname, *_ in controls:
            with self.subTest(control=cname, verifier="js"):
                r = receipts[cname]
                self.assertNotIn("crash", r, r)
                self.assertTrue(r["valid"], r.get("artifacts"))


class TestBenchCanFail(unittest.TestCase):
    """The oracle itself must be able to go red: a case with the plant removed from the payload must not be flagged, and a
    repeat spliced by hand into a clean case must be."""

    def test_a_hand_made_repeat_and_a_hand_made_clean_case(self):
        sk, jwk = _make_signer()
        d = _disclosure("s", "k", 1); dig = ap2._disclosure_digest(d)
        tok = _sign_jwt(sk, {"alg": "ES256", "jwk": jwk}, {"iss": "w", "_sd": [dig], "x": {"_sd": [dig]}, "_sd_alg": "sha-256"}) + "~" + d + "~"
        p = ap2.parse_sd_jwt(tok)
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "more than once"):
            ap2.resolve_disclosures(p["payload"], p["disclosures"])
        tok = _sign_jwt(sk, {"alg": "ES256", "jwk": jwk}, {"iss": "w", "_sd": [dig], "x": {"_sd": []}, "_sd_alg": "sha-256"}) + "~" + d + "~"
        p = ap2.parse_sd_jwt(tok)
        self.assertEqual(ap2.resolve_disclosures(p["payload"], p["disclosures"]), {"iss": "w", "k": 1, "x": {}})


if __name__ == "__main__":
    unittest.main()
