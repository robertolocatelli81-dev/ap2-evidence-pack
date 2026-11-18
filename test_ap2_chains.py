#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.0, SPEC §2.1, §4, §6.9: AP2 delegation chains in their native form `<hop0>~~<hop1>...`, the binding over the issuer
JWT (AP2's receipt `reference`), and the `require_binding` policy, in the library, the CLI and both verifiers.

Measured on 2026-11-18 on 1.8.0 (gtm reports of that day): 0 of the 143 distinct native chains found in 14 public
repositories (156 occurrences) were accepted, with the message "malformed disclosure: invalid base64url segment"; the KB
of a chain hop was never evaluated (0 of 109 split chains); 15 goodmeta/ap2-conformance vectors declared "reject" (9
chains split by hand, 6 receipts) came out `valid: true`; a receipt issued
by the AP2 SDK bound nothing. Data: spec/vectors/ap2_chains/ (README.md there: sources, licences, sha256). On the
commit before this change (6728413) all twelve tests fail (measured with this file and the vectors copied onto an
archive of that commit; the two tests of SPEC §4's all-or-none rule, added after, fail on 5a09a53); `test_not_a_chain` only for its message (the refusal of an empty component is 1.8.1's, the
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
            # draft-ietf-oauth-delegate-sd-jwt-00 §6 step 3.2: exactly one disclosed element of delegate_payload
            "terminal_two_elements": (2, lambda k, prev: hop_items(k[2][0], "kb+sd-jwt", prev, [{"a": 1}, {"b": 2}]), "chain_delegate_payload"),
            "terminal_no_element": (2, lambda k, prev: hop_items(k[2][0], "kb+sd-jwt", prev, []), "chain_delegate_payload"),
            "terminal_no_delegate_payload": (2, lambda k, prev: hop_items(k[2][0], "kb+sd-jwt", prev, None), "chain_delegate_payload"),
            "terminal_delegate_payload_object": (2, lambda k, prev: hop_items(k[2][0], "kb+sd-jwt", prev, {"a": 1}), "chain_delegate_payload"),
            # ... §6 step 4.2: a chain that ends in a KB-JWT ends in a KB-SD-JWT+KB
            "kb_jwt_after_terminal": (2, lambda k, prev: (lambda h: h + _sign_jwt(_make_signer()[0], {"alg": "ES256", "typ": "kb+jwt"},
                                      {"iat": 1, "aud": "m", "nonce": "z", "sd_hash": ap2._sha256_b64url(h.encode("ascii"))}))(
                                          mk.hop(k[2][0], "kb+sd-jwt", cl, None, prev, "sd_hash")), "chain_kb_jwt_after_terminal_hop"),
        }

        def hop_items(sk, typ, prev, items):
            payload = dict(cl, _sd_alg="sha-256", sd_hash=ap2._sha256_b64url(prev.encode("ascii")))
            ds = []
            if isinstance(items, list):
                ds = [_disclosure(_b64u(os.urandom(8)), None, it) for it in items]
                payload["delegate_payload"] = [{"...": ap2._disclosure_digest(d)} for d in ds]
            elif items is not None:
                payload["delegate_payload"] = items
            return _sign_jwt(sk, {"alg": "ES256", "typ": typ}, payload) + "~" + "".join(d + "~" for d in ds)
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

    def test_new_members_closed(self):
        """The three members 1.9.0 adds are closed (SPEC §9.1): on a pack with an SDK chain and its receipt, `over` and
        `chain_from` given every wrong type and value, removed, moved where they do not belong, and a member nobody
        defined beside them — with the digest recomputed, so only the member is wrong. None is valid, and the two
        verifiers give the same admission, refusal class and artifact errors' positions."""
        _, out = self._build([{"name": "chain", "sd_jwt": _load("sdk_chainA.txt")},
                              {"name": "receipt", "sd_jwt": _load("sdk_receiptA.jwt") + "~"}],
                             {"chain": _load("sdk_issuer_pub.json"), "receipt": _load("sdk_mpp_pub.json")}, "closed")
        with open(out, encoding="utf-8") as f:
            base = json.load(f)
        bi = next(i for i, b in enumerate(base["bindings"]) if b.get("over") == "issuer_jwt")
        bc = next(i for i, b in enumerate(base["bindings"]) if "over" not in b)
        wrong = [None, 1, 1.5, True, [], {}, "", "compact", "issuer_jwt ", "Issuer_JWT", ["issuer_jwt"], {"issuer_jwt": 1}]
        muts = {}
        for n, w in enumerate(wrong):
            muts[f"over={n}"] = lambda ev, w=w: ev["bindings"][bi].__setitem__("over", w)
            if w != "":
                muts[f"chain_from={n}"] = lambda ev, w=w: ev["artifacts"][1]["key"].__setitem__("chain_from", w)
        muts["chain_from=empty"] = lambda ev: ev["artifacts"][1]["key"].__setitem__("chain_from", "")
        muts["over_removed"] = lambda ev: ev["bindings"][bi].pop("over")
        muts["over_added_to_compact_binding"] = lambda ev: ev["bindings"][bc].__setitem__("over", "issuer_jwt")
        muts["class_to_supplied_keeping_chain_from"] = lambda ev: ev["artifacts"][1]["key"].__setitem__("provenance_class", "supplied")
        muts["class_to_supplied"] = lambda ev: (ev["artifacts"][1]["key"].__setitem__("provenance_class", "supplied"),
                                                ev["artifacts"][1]["key"].pop("chain_from"))
        muts["root_to_chain_cnf"] = lambda ev: (ev["artifacts"][0]["key"].__setitem__("provenance_class", "chain_cnf"),
                                                ev["artifacts"][0]["key"].__setitem__("chain_from", "chain.1"))
        for where, get in (("binding", lambda ev: ev["bindings"][bi]), ("key", lambda ev: ev["artifacts"][1]["key"]),
                           ("artifact", lambda ev: ev["artifacts"][1]), ("top", lambda ev: ev)):
            for k in ("over", "chain_from", "chain_hop", "x"):
                if (where, k) in (("binding", "over"), ("key", "chain_from")):
                    continue
                muts[f"{where}+{k}"] = lambda ev, get=get, k=k: get(ev).__setitem__(k, "issuer_jwt")
        manifest, py = [], {}
        for name, mut in muts.items():
            ev = copy.deepcopy(base); mut(ev); _rehash(ev)
            p = os.path.join(self.d, "closed_%d.json" % len(manifest))
            with open(p, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            r = ap2.verify_evidence(p)
            with self.subTest(case=name):
                # `class_to_supplied` is a consistent pack of another kind (a hop under a supplied key, as a chain split
                # by hand): valid, with no chain_hop and no holder_binding element — the control that the others are
                # refused for the member, not for the rehash
                self.assertEqual(r["valid"], name == "class_to_supplied", (name, r.get("refused"), r.get("artifacts")))
            py[name] = r; manifest.append((name, p, []))
        self.assertEqual(py["class_to_supplied"]["states"]["holder_binding"]["state"], "not_evaluated")
        self.assertGreater(len(manifest), 40)
        for name, r in _js_many(self, manifest).items():
            with self.subTest(js=name):
                self.assertEqual((r["valid"], r["admission"], r["refusal_class"]),
                                 (py[name]["valid"], py[name]["admission"], py[name]["refusal_class"]), (r.get("refused"), py[name].get("refused")))
                self.assertEqual(["error" in a for a in r.get("artifacts") or []], ["error" in a for a in py[name].get("artifacts") or []])

    def test_pack_built_by_1_8_0_stays_valid(self):
        """SPEC §4: a pack built before 1.9.0 records no binding over the issuer JWT. The vector was written by `build` of
        v1.8.0 (README of the vectors) and is `valid: true` there; on the first 1.9.0 draft (5a09a53), which asked the
        recorded set to equal the recomputed one, both verifiers answered `binding_mismatch`. The receipt lists what the
        pack does not record, and the policy, which reads the recomputed set, finds the receipt bound to the closed mandate."""
        p = os.path.join(_D, "pack_built_by_1.8.0.json")
        with open(p, encoding="utf-8") as f:
            recorded = json.load(f)["bindings"]
        self.assertEqual([("over" in b) for b in recorded], [False])
        want = [{"in": "receipt", "claim": "reference", "commits_to": "closed", "encoding": "b64url", "over": "issuer_jwt"}]
        runs = {"plain": [], "required": ["--require-binding", "receipt->closed"], "unmet": ["--require-binding", "receipt->open"]}
        for name, flags in runs.items():
            req = [tuple(flags[1].split("->"))] if flags else None
            r = ap2.verify_evidence(p, require_bindings=req)
            with self.subTest(py=name):
                self.assertEqual((r["valid"], r["bindings_ok"]), (name != "unmet", True), r.get("policy"))
                self.assertEqual(r["bindings_not_recorded"], want)
                self.assertEqual(r["states"]["sealed_content"], {"state": "verified", "reasons": []})
        for name, r in _js_many(self, [(n, p, fl) for n, fl in runs.items()]).items():
            with self.subTest(js=name):
                self.assertEqual((r["valid"], r["bindings_ok"]), (name != "unmet", True), r.get("policy"))
                self.assertEqual(r["bindings_not_recorded"], want)

    def test_bindings_over_issuer_jwt_all_or_none(self):
        """SPEC §4: the recorded set is the recomputed one, or the recomputed one without EVERY binding over the issuer
        JWT. Generated chains whose hops bind by issuer_jwt_hash (each pack holds four such bindings): every
        subset of them removed from the record, the digest recomputed — valid only for none removed and all removed; a
        binding over the compact form removed, or one of either kind added, is a mismatch. Both verifiers, which must list the
        bindings not recorded in one order (two of them sit under keys "b" and "7", which JavaScript enumerates the other way)."""
        rnd = random.Random(31); mk = ChainMaker(rnd)
        manifest, want = [], {}
        for c in range(6):
            n = 3 + c % 2
            keys = [_make_signer() for _ in range(n + 1)]
            hops = []
            for i in range(n):
                last = i == n - 1
                mode = "sd_hash" if (i == 1 and n == 4) else "issuer_jwt_hash"   # the four-hop packs mix the two kinds
                extra = {}
                if i == n - 1:   # the last hop also names the first hops' issuer JWTs under keys JavaScript enumerates in
                    extra = {"refs": {"b": ap2.issuer_jwt_hash(hops[0]), "7": ap2.issuer_jwt_hash(hops[1])}}   # another order
                hops.append(mk.hop(keys[i][0], "ap2-mandate+sd-jwt" if i == 0 else ("kb+sd-jwt" if last else "kb+sd-jwt+kb"),
                                   dict({"iss": f"h{i}", "iat": 1}, **extra), None if last else keys[i + 1][1], hops[-1] if hops else None, mode))
            out = os.path.join(self.d, f"aon{c}.json")
            ap2.build_evidence([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], out, keys={"c": keys[0][1]})
            with open(out, encoding="utf-8") as f:
                base = json.load(f)
            over = [i for i, b in enumerate(base["bindings"]) if "over" in b]
            plain = [i for i, b in enumerate(base["bindings"]) if "over" not in b]
            self.assertGreaterEqual(len(over), 2)
            cases = {}
            for mask in range(1 << len(over)):
                drop = [over[k] for k in range(len(over)) if mask >> k & 1]
                cases[f"drop{mask}"] = (drop, None, len(drop) in (0, len(over)))
            if plain:
                cases["drop_plain"] = ([plain[0]], None, False)
                cases["drop_plain_and_all_over"] = ([plain[0]] + over, None, False)
            cases["add_over"] = ([], {"in": "c.0", "claim": "x", "commits_to": "c.1", "encoding": "b64url", "over": "issuer_jwt"}, False)
            cases["add_plain"] = ([], {"in": "c.0", "claim": "x", "commits_to": "c.1", "encoding": "b64url"}, False)
            cases["add_plain_dropping_all_over"] = (over, {"in": "c.0", "claim": "x", "commits_to": "c.1", "encoding": "b64url"}, False)
            for name, (drop, add, ok) in cases.items():
                ev = copy.deepcopy(base)
                ev["bindings"] = [b for i, b in enumerate(ev["bindings"]) if i not in drop] + ([add] if add else [])
                rnd.shuffle(ev["bindings"]); _rehash(ev)
                p = os.path.join(self.d, f"aon{c}_{name}.json")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(ev, f)
                r = ap2.verify_evidence(p)
                with self.subTest(pack=c, case=name):
                    self.assertEqual((r["valid"], r["bindings_ok"]), (ok, ok))
                    self.assertTrue(r["digest_ok"])
                    self.assertEqual(len(r.get("bindings_not_recorded", [])), len(drop) if ok else 0)
                    if not ok:
                        self.assertEqual(r["states"]["sealed_content"]["reasons"], ["binding_mismatch"])
                nr = r.get("bindings_not_recorded", [])
                self.assertEqual(nr, sorted(nr, key=ap2._canon))   # one order, whatever the scan order of the verifier
                manifest.append((f"{c}/{name}", p, [])); want[f"{c}/{name}"] = (ok, nr)
        self.assertEqual(len(manifest), 120)   # 6 packs, each 4 bindings over the issuer JWT: 16 subsets + 3 or 5 other cases
        for name, r in _js_many(self, manifest).items():
            with self.subTest(js=name):
                self.assertEqual((r["valid"], r["bindings_ok"], r.get("bindings_not_recorded", [])), (want[name][0], want[name][0], want[name][1]))

    def test_dsdjwt_kb_delegate_key(self):
        """SPEC §2.1 (NEMESIS 2026-11-18): a dSD-JWT+KB (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1,
        `<SD-JWT>~~<KB-SD-JWT+KB>~<delegate KB-JWT>`): the delegate KB-JWT is verified with the cnf.jwk the last hop
        delegates to. On 98520d6 a KB-JWT signed by a key foreign to the chain built and verified `valid: true`, its
        holder key reported unknown although the pack carries it."""
        mk = ChainMaker(random.Random(7))
        k = [_make_signer() for _ in range(3)]
        h0 = mk.hop(k[0][0], "ap2-mandate+sd-jwt", {"iss": "h0", "iat": 1}, k[1][1], None, "sd_hash")
        h1 = mk.hop(k[1][0], "kb+sd-jwt+kb", {"iss": "h1", "aud": "x", "nonce": "n", "iat": 1}, k[2][1], h0, "sd_hash")

        def kbjwt(sk):
            return _sign_jwt(sk, {"alg": "ES256", "typ": "kb+jwt"},
                             {"iat": 1, "aud": "m", "nonce": "z", "sd_hash": ap2._sha256_b64url(h1.encode("ascii"))})
        good, foreign = h0[:-1] + "~~" + h1 + kbjwt(k[2][0]), h0[:-1] + "~~" + h1 + kbjwt(_make_signer()[0])
        _, out = self._build([{"name": "c", "sd_jwt": good}], {"c": k[0][1]}, "dkb")
        r = ap2.verify_evidence(out)
        self.assertTrue(r["valid"])
        self.assertIs(r["artifacts"][1]["kb_jwt"]["verified"], True)
        self.assertEqual(r["states"]["holder_binding"], {"state": "verified", "reasons": []})
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "KB-JWT holder binding INVALID"):
            self._build([{"name": "c", "sd_jwt": foreign}], {"c": k[0][1]}, "dkb_foreign")
        with open(out, encoding="utf-8") as f:   # the same pack, its delegate KB-JWT swapped for the foreign one
            ev = json.load(f)
        ev["artifacts"][1]["sd_jwt_compact"] = foreign.split("~~", 1)[1]
        ev["artifacts"][1]["kb_jwt"].pop("verified", None); ev["artifacts"][1]["kb_jwt"].pop("signature_ok", None)
        p = os.path.join(self.d, "dkb_swapped.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(_rehash(ev), f)
        r = ap2.verify_evidence(p)
        self.assertFalse(r["valid"])
        self.assertIs(r["artifacts"][1]["kb_jwt"]["verified"], False)
        js = _js_many(self, [("good", out, []), ("swapped", p, [])])
        self.assertEqual((js["good"]["valid"], js["good"]["artifacts"][1]["kb_jwt"]["verified"]), (True, True))
        self.assertEqual((js["swapped"]["valid"], js["swapped"]["artifacts"][1]["kb_jwt"]["verified"]), (False, False))

    def test_outside_a_chain_a_delegate_cnf_is_not_the_holder_key(self):
        """SPEC §2.1, declared: a mandate presented alone whose only cnf is inside delegate_payload, followed by a KB-JWT —
        the holder key is unknown (verified null, not_evaluated), whoever signed the KB-JWT; in both verifiers."""
        sk, jwk = _make_signer()
        d = _disclosure(_b64u(os.urandom(8)), None, {"cnf": {"jwk": _make_signer()[1]}, "a": 1})
        tok = _sign_jwt(sk, {"alg": "ES256", "typ": "example+sd-jwt"},
                        {"iss": "i", "delegate_payload": [{"...": ap2._disclosure_digest(d)}], "_sd_alg": "sha-256"}) + "~" + d + "~"
        kb = _sign_jwt(_make_signer()[0], {"alg": "ES256", "typ": "kb+jwt"},
                       {"iat": 1, "aud": "a", "nonce": "n", "sd_hash": ap2._sha256_b64url(tok.encode("ascii"))})
        _, out = self._build([{"name": "m", "sd_jwt": tok + kb}], {"m": jwk}, "alone")
        for r in (ap2.verify_evidence(out), _js_many(self, [("a", out, [])])["a"]):
            self.assertTrue(r["valid"])
            self.assertIsNone(r["artifacts"][0]["kb_jwt"]["verified"])
            self.assertEqual(r["states"]["holder_binding"], {"state": "not_evaluated", "reasons": ["holder_key_unknown"]})

    def test_require_binding_reads_only_a_matching_set(self):
        """SPEC §6.9 (NEMESIS 2026-11-18, two live mutants on 98520d6): a pair is held only when bindings_ok — a recorded
        set that is not the recomputed one leaves every pair unmet, in both verifiers, even if the recomputation holds it;
        and require_bindings with an empty name is the caller's ValueError."""
        _, out = self._build([{"name": "chain", "sd_jwt": _load("sdk_chainA.txt")},
                              {"name": "receipt", "sd_jwt": _load("sdk_receiptA.jwt") + "~"}],
                             {"chain": _load("sdk_issuer_pub.json"), "receipt": _load("sdk_mpp_pub.json")}, "rbset")
        with open(out, encoding="utf-8") as f:
            ev = json.load(f)
        ev["bindings"] = [b for b in ev["bindings"] if "over" in b]   # the binding over the compact form removed: a mismatch
        p = os.path.join(self.d, "rbset_mismatch.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(_rehash(ev), f)
        r = ap2.verify_evidence(p, require_bindings=[("receipt", "chain.1")])
        self.assertEqual((r["valid"], r["bindings_ok"], r["policy"]["unmet"]), (False, False, ["require_binding"]))
        js = _js_many(self, [("m", p, ["--require-binding", "receipt->chain.1"])])["m"]
        self.assertEqual((js["valid"], js["bindings_ok"], js["policy"]["unmet"]), (False, False, ["require_binding"]))
        for bad in ([("", "chain.1")], [("receipt", "")], [("receipt",)], "receipt->chain.1", [("receipt", 1)]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ap2.verify_evidence(out, require_bindings=bad)

    def test_hop_needs_a_verified_previous_hop_and_its_key(self):
        """SPEC §2.1, §4 (NEMESIS 2026-11-18, three live mutants on 98520d6): a hop whose previous hop did not verify is
        that hop's error; a chain_cnf key that is not the previous hop's cnf.jwk is refused even when the hop verifies
        under it, in both verifiers; a hex hash of an issuer JWT is a binding with "over" as the b64url one is."""
        keys, hops = ChainMaker(random.Random(11)).chain(3)
        _, out = self._build([{"name": "c", "sd_jwt": ChainMaker.join(hops)}], {"c": keys[0][1]}, "hv")
        with open(out, encoding="utf-8") as f:
            base = json.load(f)
        ev = copy.deepcopy(base)   # (1) the root's signature broken: c.1 names no verified artifact
        jwt, rest = ev["artifacts"][0]["sd_jwt_compact"].split("~", 1)
        h, pl, sg = jwt.split(".")
        sg = sg[:5] + ("A" if sg[5] != "A" else "B") + sg[6:]
        ev["artifacts"][0]["sd_jwt_compact"] = f"{h}.{pl}.{sg}~{rest}"
        p1 = os.path.join(self.d, "hv_root_broken.json")
        with open(p1, "w", encoding="utf-8") as f:
            json.dump(_rehash(ev), f)
        ev = copy.deepcopy(base)   # (2) c.1 re-signed by a key of its own, recorded as its chain_cnf key
        sk2, pub2 = _make_signer()
        c1 = ev["artifacts"][1]["sd_jwt_compact"]
        jwt, rest = c1.split("~", 1)
        h, pl, _ = jwt.split(".")
        resigned = _sign_jwt(sk2, json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))),
                             json.loads(base64.urlsafe_b64decode(pl + "=" * (-len(pl) % 4))))
        self.assertEqual(resigned.split(".")[:2], [h, pl])
        ev["artifacts"][1]["sd_jwt_compact"] = resigned + "~" + rest
        ev["artifacts"][1]["key"]["jwk"] = _pub(pub2)
        ev["bindings"] = ap2.find_bindings([{"name": a["name"], "compact": a["sd_jwt_compact"], "resolved_claims": a["resolved_claims"]}
                                            for a in ev["artifacts"]])
        p2 = os.path.join(self.d, "hv_foreign_key.json")
        with open(p2, "w", encoding="utf-8") as f:
            json.dump(_rehash(ev), f)
        py = {n: ap2.verify_evidence(p) for n, p in (("root_broken", p1), ("foreign_key", p2))}
        js = _js_many(self, [("root_broken", p1, []), ("foreign_key", p2, [])])
        for who, rr in (("python", py), ("js", js)):
            with self.subTest(who=who):
                self.assertFalse(rr["root_broken"]["valid"])
                self.assertIn("names no artifact before this one that verified", rr["root_broken"]["artifacts"][1].get("error", ""))
                self.assertFalse(rr["foreign_key"]["valid"])
                self.assertIn("is not the cnf.jwk of the artifact named by chain_from", rr["foreign_key"]["artifacts"][1].get("error", ""))
        sk_a, pub_a = _make_signer(); sk_b, pub_b = _make_signer()   # (3) hex over the issuer JWT
        a_tok = _sign_jwt(sk_a, {"alg": "ES256", "typ": "example+sd-jwt"}, {"iss": "a", "x": 1}) + "~"
        b_tok = _sign_jwt(sk_b, {"alg": "ES256", "typ": "example+sd-jwt"},
                          {"iss": "b", "ref": hashlib.sha256(a_tok.split("~", 1)[0].encode("ascii")).hexdigest()}) + "~"
        _, out3 = self._build([{"name": "a", "sd_jwt": a_tok}, {"name": "b", "sd_jwt": b_tok}], {"a": pub_a, "b": pub_b}, "hex")
        with open(out3, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["bindings"],
                             [{"in": "b", "claim": "ref", "commits_to": "a", "encoding": "hex", "over": "issuer_jwt"}])
        self.assertTrue(ap2.verify_evidence(out3)["bindings_ok"])
        self.assertTrue(_js_many(self, [("h", out3, [])])["h"]["bindings_ok"])

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
            for flag in ("--require-binding=-x->y", "--require-binding=--a->b"):   # NEMESIS 2026-11-18: Python read it as a value
                with self.subTest(verifier=base[-2] if base[0] == "node" else "python", flag=flag):
                    p = subprocess.run(base + [flag], capture_output=True, text=True, env=env, timeout=120)
                    self.assertEqual(p.returncode, 2, p.stderr[-300:])


if __name__ == "__main__":
    unittest.main()
