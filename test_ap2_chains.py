#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.0, SPEC §2.1, §4, §6.9: AP2 delegation chains in their native form `<hop0>~~<hop1>...`, the binding over the issuer
JWT (AP2's receipt `reference`), and the `require_binding` policy, in the library, the CLI and both verifiers.

Measured on 2026-11-18 on 1.8.0 (gtm reports of that day): 0 of 157 native chains found in public repositories were
accepted, with the message "malformed disclosure: invalid base64url segment"; the KB of a chain hop was never evaluated
(0 of 109 split chains); 16 goodmeta/ap2-conformance vectors declared "reject" came out `valid: true`; a receipt issued
by the AP2 SDK bound nothing. Data: spec/vectors/ap2_chains/ (README.md there: sources, licences, sha256). On the
commit before this change (6728413) all eleven tests fail (measured with this file and the vectors copied onto an
archive of that commit); `test_not_a_chain` only for its message (the refusal of an empty component is 1.8.1's, the
mention of the chain form is new)."""
import base64
import copy
import hashlib
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
import ap2_evidence as ap2  # noqa: E402
from test_ap2_evidence import _b64u, _disclosure, _make_signer, _sign_jwt  # noqa: E402

_D = os.path.join(_HERE, "spec", "vectors", "ap2_chains")
_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_MANY = os.path.join(_HERE, "verifiers", "js", "verify_many.mjs")
_CLI = [sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py")]
_LEGACY = os.path.join(_HERE, "spec", "vectors", "legacy_1_0", "valid_signed_v1.0.2.json")

# goodmeta/ap2-conformance @41dff653, chain.json: the outcome of THIS format, vector by vector (None = built and valid).
# The three of the "reject" vectors that stay valid are checks this format does not make: transaction context (aud, nonce)
# and time (exp), as for a KB-JWT (SPEC §2.1, §6 step 2). The x5c vectors encode certificates in base64url (RFC 7515 §4.1.6
# says base64): refused for that, not for the vector's reason.
GOODMETA_CHAIN = {
    "valid_payment_2hop": None, "valid_payment_3hop": None, "valid_payment_3hop_issuer_jwt_hash": None,
    "tampered_root_payload": "not valid JSON", "wrong_cnf_key": "signature INVALID",
    "binding_sd_hash_mismatch": "chain_binding_mismatch", "aud_mismatch": None, "nonce_mismatch": None,
    "wrong_root_key": "signature INVALID", "wrong_typ": "chain_hop_typ", "both_binding_claims": "chain_binding_mismatch",
    "neither_binding_claim": "chain_binding_mismatch", "terminal_with_cnf": "chain_terminal_with_cnf",
    "intermediate_without_cnf": "chain_intermediate_without_cnf", "expired": None, "alg_swap_none_root": "unsupported: ES256 only",
    "alg_swap_hs256_hop": "unsupported: ES256 only", "valid_x5c": "strict-base64", "x5c_untrusted_root": "strict-base64",
    "x5c_fail_open": "strict-base64", "x5c_expired": "strict-base64", "x5c_non_ca_intermediate": "strict-base64",
    "x5c_wrong_curve_leaf": "unsupported: ES256 only"}
# receipts.json: (built?, valid with no policy, valid under require_binding receipt -> the closed hop). The three "reject"
# vectors that stay valid are receipt contents this format does not read (payment_id, error_code).
GOODMETA_RECEIPTS = {
    "payment_receipt_valid": (True, True, True), "payment_receipt_valid_3hop": (True, True, True),
    "payment_receipt_wrong_key": (False, None, None), "payment_receipt_tampered_payload": (False, None, None),
    "payment_receipt_reference_mismatch": (True, True, False), "payment_receipt_reference_is_root_hash": (True, True, False),
    "payment_receipt_missing_payment_id": (True, True, True), "payment_receipt_missing_reference": (True, True, False),
    "payment_receipt_error_without_error_code": (True, True, True), "checkout_receipt_valid": (True, True, True),
    "checkout_receipt_reference_mismatch": (True, True, False), "checkout_receipt_wrong_key": (False, None, None)}


def _pub(jwk):
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}


def _load(name):
    with open(os.path.join(_D, name), encoding="utf-8") as f:
        return json.load(f) if name.endswith(".json") else f.read().strip()


def _js_many(test, entries):
    """entries: [(name, path, flags)] -> {name: receipt}; skips when node is absent."""
    if not shutil.which("node"):
        test.skipTest("node absent: the JS verifier is not measured")
    d = tempfile.mkdtemp(prefix="ap2-chains-js-"); test.addCleanup(shutil.rmtree, d, ignore_errors=True)
    m = os.path.join(d, "m.json")
    with open(m, "w", encoding="utf-8") as f:
        json.dump([{"name": n, "path": p, "flags": fl} for n, p, fl in entries], f)
    out = subprocess.run(["node", _MANY, _JS, m], capture_output=True, text=True, timeout=600)
    test.assertEqual(out.returncode, 0, out.stderr[-500:])
    return json.loads(out.stdout)


def _rehash(ev):
    e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures", "anchors")}
    ev["evidence_digest_sha256"] = hashlib.sha256(ap2._canon(e2)).hexdigest()
    return ev


class ChainMaker:
    """AP2-shaped chains signed here: a root SD-JWT whose delegate_payload element carries cnf, then KB-SD-JWT hops
    (kb+sd-jwt+kb with a cnf for the next one, kb+sd-jwt at the end), each bound by sd_hash or issuer_jwt_hash."""

    def __init__(self, rnd):
        self.rnd = rnd

    def hop(self, sk, typ, claims, cnf_jwk, prev, mode):
        item = {"amount": self.rnd.randint(1, 10 ** 6)}
        if cnf_jwk is not None:
            item["cnf"] = {"jwk": cnf_jwk}
        d = _disclosure(_b64u(os.urandom(8)), None, item)
        payload = dict(claims, delegate_payload=[{"...": ap2._disclosure_digest(d)}], _sd_alg="sha-256")
        if prev is not None:
            payload[mode] = (ap2._sha256_b64url(prev.encode("ascii")) if mode == "sd_hash" else ap2.issuer_jwt_hash(prev))
        return _sign_jwt(sk, {"alg": "ES256", "typ": typ}, payload) + "~" + d + "~"

    def chain(self, n):
        keys = [_make_signer() for _ in range(n + 1)]
        hops = []
        for i in range(n):
            last = i == n - 1
            typ = "ap2-mandate+sd-jwt" if i == 0 else ("kb+sd-jwt" if last else "kb+sd-jwt+kb")
            cnf = None if (last and i > 0) else keys[i + 1][1]
            hops.append(self.hop(keys[i][0], typ, {"iss": f"h{i}", "aud": "x", "nonce": "n", "iat": 1}, cnf,
                                 hops[-1] if hops else None, self.rnd.choice(["sd_hash", "issuer_jwt_hash"])))
        return keys, hops

    @staticmethod
    def join(hops):
        return "~~".join(h[:-1] for h in hops[:-1]) + "~~" + hops[-1]


class Chains(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-chains-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _build(self, arts, keys=None, name="p"):
        out = os.path.join(self.d, name + ".json")
        return ap2.build_evidence(arts, out, keys=keys), out

    def test_split(self):
        self.assertIsNone(ap2.split_ap2_chain("a.b.c~d~"))
        self.assertIsNone(ap2.split_ap2_chain("a.b.c~~"))              # RFC 9901 §4: an empty component, never a chain
        self.assertIsNone(ap2.split_ap2_chain("a.b.c~d~~e~"))          # a disclosure after ~~, no issuer JWT
        self.assertEqual(ap2.split_ap2_chain("a.b.c~d~~e.f.g~h~"), ["a.b.c~d~", "e.f.g~h~"])
        self.assertEqual(ap2.split_ap2_chain("a.b.c~~e.f.g~"), ["a.b.c~", "e.f.g~"])
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "ap2_chain_malformed"):
            ap2.split_ap2_chain("~~e.f.g~")
        # the last part a JWT with no '~': an AP2 chain that lost its last '~', or (RFC 9901) an empty component before a
        # KB-JWT — refused either way, both readings named
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "ap2_chain_malformed: .*no '~'.*empty component before a KB-JWT"):
            ap2.split_ap2_chain("a.b.c~d~~e.f.g")
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "ap2_chain_malformed: a hop before the last ends with a KB-JWT"):
            ap2.split_ap2_chain("a.b.c~d~k.b.j~~e.f.g~")
        self.assertEqual(ap2.split_ap2_chain("a.b.c~d~~e.f.g~h~k.b.j"), ["a.b.c~d~", "e.f.g~h~k.b.j"])   # only the last hop may carry one

    def test_not_a_chain(self):   # D1 (1.8.1): empty components stay refused; the message names the chain form
        sk, jwk = _make_signer()
        jwt = _sign_jwt(sk, {"alg": "ES256", "typ": "x"}, {"iss": "a"})
        d = _disclosure("c2FsdA", "k", 1)
        for tok in (jwt + "~~", jwt + "~" + d + "~~" + d + "~", jwt + "~~~~"):
            with self.subTest(tok=tok[-20:]):
                with self.assertRaisesRegex(ap2.Ap2EvidenceError, "sd_jwt_empty_component: .*AP2 chain"):
                    self._build([{"name": "m", "sd_jwt": tok}], {"m": jwk})

    def test_goodmeta_chains(self):
        manifest, built = [], {}
        for v in _load("goodmeta_chain.json"):
            want = GOODMETA_CHAIN[v["name"]]
            keys = {"chain": _pub(v["rootKey"])} if v.get("rootKey") else None
            with self.subTest(vector=v["name"]):
                if want is None:
                    r, out = self._build([{"name": "chain", "sd_jwt": v["chain"]}], keys, v["name"])
                    n = v["chain"].count("~~") + 1
                    self.assertEqual(r["ap2_chains"], {"chain": [f"chain.{i}" for i in range(n)]})
                    rv = ap2.verify_evidence(out)
                    self.assertTrue(rv["valid"], rv["artifacts"])
                    self.assertEqual(rv["states"]["holder_binding"], {"state": "verified", "reasons": []})
                    self.assertEqual([a.get("chain_hop", {}).get("from") for a in rv["artifacts"]],
                                     [None] + [f"chain.{i}" for i in range(n - 1)])
                    built[v["name"]] = out; manifest.append((v["name"], out, []))
                else:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, want):
                        self._build([{"name": "chain", "sd_jwt": v["chain"]}], keys, v["name"])
        self.assertEqual(len(built), 6)
        for name, r in _js_many(self, manifest).items():
            with self.subTest(js=name):
                self.assertTrue(r["valid"], r)
                self.assertEqual(r["states"]["holder_binding"]["state"], "verified")

    def test_goodmeta_receipts(self):
        roots = {c["rootKey"]["kid"]: c["rootKey"] for c in _load("goodmeta_chain.json") if c.get("rootKey") and c["expect"] == "valid"}
        manifest, want_js = [], {}
        for v in _load("goodmeta_receipts.json"):
            built, plain, req = GOODMETA_RECEIPTS[v["name"]]
            n = v["mandateChain"].count("~~") + 1
            kid = ap2.parse_sd_jwt(v["mandateChain"].split("~~")[0] + "~")["header"]["kid"]
            keys = {"chain": _pub(roots[kid]), "receipt": _pub(v["issuerPublicKey"])}
            arts = [{"name": "chain", "sd_jwt": v["mandateChain"]}, {"name": "receipt", "sd_jwt": v["receiptJwt"] + "~"}]
            with self.subTest(vector=v["name"]):
                if not built:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, "signature INVALID"):
                        self._build(arts, keys, v["name"])
                    continue
                _, out = self._build(arts, keys, v["name"])
                self.assertEqual(ap2.verify_evidence(out)["valid"], plain)
                rr = ap2.verify_evidence(out, require_bindings=[("receipt", f"chain.{n - 1}")])
                self.assertEqual(rr["valid"], req)
                self.assertEqual(rr["policy"]["unmet"], [] if req else ["require_binding"])
                flags = ["--require-binding", f"receipt->chain.{n - 1}"]
                manifest.append((v["name"], out, flags)); want_js[v["name"]] = req
        for name, r in _js_many(self, manifest).items():
            with self.subTest(js=name):
                self.assertEqual(r["valid"], want_js[name], r.get("policy"))

    def test_sdk_receipt_over_issuer_jwt(self):
        keys = {"chain": _load("sdk_issuer_pub.json"), "receipt": _load("sdk_mpp_pub.json")}
        receipt = _load("sdk_receiptA.jwt") + "~"
        _, a = self._build([{"name": "chain", "sd_jwt": _load("sdk_chainA.txt")}, {"name": "receipt", "sd_jwt": receipt}], keys, "a")
        with open(a, encoding="utf-8") as f:
            b = sorted((x["in"], x["commits_to"], x["claim"], x.get("over")) for x in json.load(f)["bindings"])
        self.assertEqual(b, [("chain.1", "chain.0", "sd_hash", None), ("receipt", "chain.1", "reference", "issuer_jwt")])
        _, bb = self._build([{"name": "chain", "sd_jwt": _load("sdk_chainB.txt")}, {"name": "receipt", "sd_jwt": receipt}], keys, "b")
        self.assertTrue(ap2.verify_evidence(a, require_bindings=[("receipt", "chain.1")])["valid"])
        rb = ap2.verify_evidence(bb, require_bindings=[("receipt", "chain.1")])
        self.assertFalse(rb["valid"]); self.assertEqual(rb["policy"]["require_binding_missing"], [["receipt", "chain.1"]])
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "chain_binding_mismatch"):   # the AP2 SDK refuses it too (sd_hash mismatch)
            self._build([{"name": "chain", "sd_jwt": _load("sdk_chain_mixed.txt")}], {"chain": keys["chain"]}, "m")
        js = _js_many(self, [("a", a, ["--require-binding", "receipt->chain.1"]), ("b", bb, ["--require-binding", "receipt->chain.1"])])
        self.assertTrue(js["a"]["valid"]); self.assertFalse(js["b"]["valid"])

    def test_generative_chains(self):
        """400 chains of 2-4 hops signed here, each mutated once or not: the oracle is the mutation's kind, written apart
        from the code (a hop re-bound, re-typed, its cnf dropped or doubled, its iat dropped, two hops swapped, one dropped,
        a hop re-signed with another key; typ spellings that RFC 7515 §4.1.9 makes the same type stay valid)."""
        rnd = random.Random(20261118); mk = ChainMaker(rnd)
        manifest, expect = [], {}
        for i in range(400):
            n = rnd.randint(2, 4)
            keys, hops = mk.chain(n)
            kind = rnd.choice(["none", "none", "typ_spelling", "rebind", "retype", "cnf_drop", "cnf_double", "swap", "drop",
                               "resign", "both_bindings", "iat_drop"])
            j = rnd.randint(1, n - 1)
            if kind == "typ_spelling" or kind in ("rebind", "retype", "cnf_drop", "cnf_double", "resign", "both_bindings", "iat_drop"):
                prev = hops[j - 1]; last = j == n - 1
                typ = "kb+sd-jwt" if last else "kb+sd-jwt+kb"
                cnf = None if last else keys[j + 1][1]
                sk = keys[j][0]; claims = {"iss": f"h{j}", "aud": "x", "nonce": "n", "iat": 1}; mode = "sd_hash"
                if kind == "typ_spelling":
                    typ = rnd.choice(["KB+SD-JWT", "application/kb+sd-jwt", "Application/Kb+Sd-Jwt"]) + ("" if last else "+KB")
                elif kind == "retype":
                    typ = rnd.choice(["kb+jwt", "ap2-mandate+sd-jwt", "kb+sd-jwt;", "kb+sd-jwt+kb+kb", "JWT"])
                elif kind == "cnf_drop" and not last:
                    cnf = None
                elif kind == "cnf_drop" and last:
                    cnf = _make_signer()[1]
                elif kind == "resign":
                    sk = _make_signer()[0]
                elif kind == "iat_drop":   # asked of a terminal hop only (SPEC §2.1)
                    del claims["iat"]
                    if not last:
                        kind = "none"
                h = mk.hop(sk, typ, claims, cnf, prev, mode)
                if kind == "rebind":
                    h = mk.hop(sk, typ, dict(claims, sd_hash=_b64u(os.urandom(32))), cnf, None, mode)
                elif kind == "both_bindings":
                    h = mk.hop(sk, typ, dict(claims, issuer_jwt_hash=ap2.issuer_jwt_hash(prev)), cnf, prev, "sd_hash")
                elif kind == "cnf_double" and not last:
                    item2 = {"cnf": {"jwk": _make_signer()[1]}}
                    d2 = _disclosure(_b64u(os.urandom(8)), None, item2)
                    body = json.loads(base64.urlsafe_b64decode(h.split(".")[1] + "=="))
                    body["delegate_payload"].append({"...": ap2._disclosure_digest(d2)})
                    h = _sign_jwt(sk, {"alg": "ES256", "typ": typ}, body) + "~" + h.split("~", 1)[1] + d2 + "~"
                elif kind == "cnf_double":
                    kind = "none"   # a terminal hop has no next key: nothing to double
                hops = hops[:j] + [h]
                for t in range(j + 1, n):   # the hops after j re-signed over the new hop, so only the mutation is wrong
                    last_t = t == n - 1
                    hops.append(mk.hop(keys[t][0], "kb+sd-jwt" if last_t else "kb+sd-jwt+kb", {"iss": f"h{t}", "iat": 1},
                                       None if last_t else keys[t + 1][1], hops[-1], "sd_hash"))
            elif kind == "swap" and n >= 3:
                a_ = rnd.randint(1, n - 2); hops[a_], hops[a_ + 1] = hops[a_ + 1], hops[a_]
            elif kind == "drop" and n >= 3:
                del hops[rnd.randint(1, n - 2)]
            elif kind in ("swap", "drop"):
                kind = "none"
            bad = kind not in ("none", "typ_spelling")
            tok = ChainMaker.join(hops)
            out = os.path.join(self.d, f"g{i}.json")
            with self.subTest(i=i, kind=kind, n=n):
                if bad:
                    with self.assertRaises(ap2.Ap2EvidenceError):
                        ap2.build_evidence([{"name": "c", "sd_jwt": tok}], out, keys={"c": keys[0][1]})
                    self.assertFalse(os.path.exists(out))
                else:
                    ap2.build_evidence([{"name": "c", "sd_jwt": tok}], out, keys={"c": keys[0][1]})
                    self.assertTrue(ap2.verify_evidence(out)["valid"])
                    manifest.append((str(i), out, [])); expect[str(i)] = True
        self.assertGreater(len(expect), 60)
        for name, r in _js_many(self, manifest).items():
            with self.subTest(js=name):
                self.assertTrue(r["valid"], r["artifacts"])

    def test_hop_rules_at_verify(self):
        """The hop rules are the verifiers' too, not only build's: chains breaking one rule each, sealed by a build whose
        hop check is switched off for the purpose, are that artifact's error, by name, in both verifiers. The control is
        the same build on a chain that breaks none."""
        rnd = random.Random(99); mk = ChainMaker(rnd)
        real_check = ap2.check_chain_hop
        self.addCleanup(setattr, ap2, "check_chain_hop", real_check)
        cl = {"iss": "h", "aud": "x", "nonce": "n", "iat": 1}
        cases = {   # name -> (which hop, build of that hop, error)
            "control": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", cl, None, prev, "sd_hash"), None),
            "terminal_typ": (2, lambda k, prev: mk.hop(k[2][0], "dc+sd-jwt", cl, None, prev, "sd_hash"), "chain_hop_typ"),
            "terminal_typ_semicolon": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt;", cl, None, prev, "sd_hash"), "chain_hop_typ"),
            "terminal_rebound": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", dict(cl, sd_hash=_b64u(os.urandom(32))), None, None, "sd_hash"),
                                 "chain_binding_mismatch"),
            "terminal_no_binding": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", cl, None, None, "sd_hash"), "chain_binding_mismatch"),
            "terminal_both": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", dict(cl, issuer_jwt_hash=ap2.issuer_jwt_hash(prev)), None, prev, "sd_hash"),
                              "chain_binding_mismatch"),
            "terminal_issuer_jwt_hash_of_compact": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", dict(cl, issuer_jwt_hash=ap2._sha256_b64url(prev.encode("ascii"))), None, None, "sd_hash"),
                                                    "chain_binding_mismatch"),
            "terminal_with_cnf": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", cl, _make_signer()[1], prev, "sd_hash"), "chain_terminal_with_cnf"),
            "terminal_without_iat": (2, lambda k, prev: mk.hop(k[2][0], "kb+sd-jwt", {"iss": "h"}, None, prev, "sd_hash"), "chain_terminal_without_iat"),
            "intermediate_as_terminal_typ": (1, lambda k, prev: mk.hop(k[1][0], "kb+sd-jwt", cl, k[2][1], prev, "sd_hash"), "chain_terminal_with_cnf"),
        }
        manifest, want = [], {}
        for name, (j, make, err) in cases.items():
            keys, hops = mk.chain(3)
            hops[j] = make(keys, hops[j - 1])
            if j == 1:
                hops[2] = mk.hop(keys[2][0], "kb+sd-jwt", cl, None, hops[1], "sd_hash")
            out = os.path.join(self.d, "v_" + name + ".json")
            ap2.check_chain_hop = lambda parsed, resolved, prev: {"binding": "sd_hash", "terminal": True}
            try:
                ap2.build_evidence([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], out, keys={"c": keys[0][1]})
            finally:
                ap2.check_chain_hop = real_check
            with self.subTest(case=name):
                if err:   # the real build refuses it for the same reason
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, err):
                        ap2.build_evidence([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], out + ".x", keys={"c": keys[0][1]})
                r = ap2.verify_evidence(out)
                self.assertEqual(r["valid"], err is None, r["artifacts"])
                if err:
                    self.assertTrue(r["digest_ok"])
                    self.assertIn(err, r["artifacts"][j].get("error", ""), r["artifacts"][j])
                    self.assertEqual(r["states"]["sealed_content"]["state"], "contradicted")
            manifest.append((name, out, [])); want[name] = (j, err)
        for name, r in _js_many(self, manifest).items():
            j, err = want[name]
            with self.subTest(js=name):
                self.assertEqual(r["valid"], err is None, r["artifacts"])
                if err:
                    self.assertIn(err, r["artifacts"][j].get("error", ""), r["artifacts"][j])

    def test_intermediate_without_iat_and_digest_string_item(self):
        """Two declared edges (SPEC §2.1). `iat` is asked of a terminal hop only, as the AP2 SDK asks it
        (verify_expected_claims runs on terminal types). A `delegate_payload` item that is a bare digest string (the form
        the SDK calls CMWallet's and resolves) is no RFC 9901 reference: its disclosure is one no digest refers to (§7.1
        step 5), refused."""
        rnd = random.Random(5); mk = ChainMaker(rnd)
        keys, hops = mk.chain(3)
        hops[1] = mk.hop(keys[1][0], "kb+sd-jwt+kb", {"iss": "h"}, keys[2][1], hops[0], "sd_hash")
        hops[2] = mk.hop(keys[2][0], "kb+sd-jwt", {"iss": "h", "iat": 1}, None, hops[1], "sd_hash")
        _, out = self._build([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], {"c": keys[0][1]}, "noiat")
        self.assertTrue(ap2.verify_evidence(out)["valid"])
        keys, hops = mk.chain(2)
        d = _disclosure(_b64u(os.urandom(8)), None, {"amount": 1})
        payload = {"iss": "h", "iat": 1, "delegate_payload": [ap2._disclosure_digest(d)], "_sd_alg": "sha-256",
                   "sd_hash": ap2._sha256_b64url(hops[0].encode("ascii"))}
        hops[1] = _sign_jwt(keys[1][0], {"alg": "ES256", "typ": "kb+sd-jwt"}, payload) + "~" + d + "~"
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "match no digest"):
            self._build([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], {"c": keys[0][1]}, "cmw")

    def test_sealed_chain_tampered(self):
        """A built chain pack, one member of a hop's key changed and the digest recomputed: each is that artifact's error in
        both verifiers (chain_from naming nothing, a later hop, itself; chain_from on another class; chain_cnf without it;
        another key)."""
        rnd = random.Random(7); keys, hops = ChainMaker(rnd).chain(3)
        out = os.path.join(self.d, "base.json")
        ap2.build_evidence([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], out, keys={"c": keys[0][1]})
        with open(out, encoding="utf-8") as f:
            base = json.load(f)
        cases = {
            "from_nothing": lambda ev: ev["artifacts"][1]["key"].__setitem__("chain_from", "nope"),
            "from_later": lambda ev: ev["artifacts"][1]["key"].__setitem__("chain_from", "c.2"),
            "from_self": lambda ev: ev["artifacts"][1]["key"].__setitem__("chain_from", "c.1"),
            "from_on_supplied": lambda ev: ev["artifacts"][0]["key"].__setitem__("chain_from", "c.1"),
            "chain_cnf_without_from": lambda ev: ev["artifacts"][2]["key"].pop("chain_from"),
            "other_key": lambda ev: ev["artifacts"][2]["key"].__setitem__("jwk", _make_signer()[1]),
            "from_skips_a_hop": lambda ev: ev["artifacts"][2]["key"].__setitem__("chain_from", "c.0"),
        }
        manifest = []
        for name, mut in cases.items():
            ev = copy.deepcopy(base); mut(ev); _rehash(ev)
            p = os.path.join(self.d, name + ".json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            r = ap2.verify_evidence(p)
            with self.subTest(case=name):
                self.assertFalse(r["valid"]); self.assertTrue(r["digest_ok"])
                self.assertTrue(any("error" in a for a in r["artifacts"]), r["artifacts"])
            manifest.append((name, p, []))
        self.assertTrue(ap2.verify_evidence(out)["valid"])   # control: the untouched pack
        for name, r in _js_many(self, manifest + [("control", out, [])]).items():
            with self.subTest(js=name):
                self.assertEqual(r["valid"], name == "control", r["artifacts"])

    def test_legacy_1_0_pack_named(self):
        r = ap2.verify_evidence(_LEGACY)
        self.assertEqual((r["admission"], r["refusal_class"]), ("refused", "format_unsupported"))
        self.assertIn("1.0.0-1.0.2", r["refused"])
        js = _js_many(self, [("l", _LEGACY, [])])["l"]
        self.assertEqual(js["refused"], r["refused"])

    def test_cli_require_binding(self):
        _, out = self._build([{"name": "chain", "sd_jwt": _load("sdk_chainA.txt")},
                              {"name": "receipt", "sd_jwt": _load("sdk_receiptA.jwt") + "~"}],
                             {"chain": _load("sdk_issuer_pub.json"), "receipt": _load("sdk_mpp_pub.json")}, "cli")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        cmds = [_CLI + ["verify", out]] + ([["node", _JS, out]] if shutil.which("node") else [])
        for base in cmds:
            for flag, rc in (("receipt->chain.1", 0), ("chain.0->receipt", 1), ("receipt", 2), ("->chain.1", 2),
                             ("receipt->", 2), ("a->b->c", 2), ("", 2)):
                with self.subTest(verifier=base[-2] if base[0] == "node" else "python", flag=flag):
                    p = subprocess.run(base + ["--require-binding", flag], capture_output=True, text=True, env=env, timeout=120)
                    self.assertEqual(p.returncode, rc, p.stderr[-300:])


if __name__ == "__main__":
    unittest.main()
