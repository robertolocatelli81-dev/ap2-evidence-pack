#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""SPEC §11 (draft 1.7.0) — the restriction record. Every mandate below is built from AP2's own examples
(google-agentic-commerce/AP2 at e1ea56db72a6385bce3e5c1112b3a56ce60acb43): the two encoded tokens are copied verbatim from
the documentation and decoded here; the constraint examples are those of docs/ap2/payment_mandate.md. They are re-issued
with a throwaway key (the documentation does not publish the agent-provider key), in the form the AP2 SDK produces:
the Mandate Content as the one element of `delegate_payload`, the `x-selectively-disclosable-array` lists as array
disclosures. Positive cases, one negative case per rule, and generative cases over the whole space of R."""
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
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

HAVE_OPENSSL = shutil.which("openssl") is not None
CLAIM = "io.github.robertolocatelli81.restricts"

# AP2 e1ea56d, docs/ap2/payment_mandate.md line 351 ("Open Payment Mandate SD-JWT plus disclosures", Encoded Token), verbatim
AP2_PAY_OPEN = (
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0IiwgImtpZCI6ICJhZ2VudC1wcm92aWRlci1rZXktMSJ9.eyJkZWxlZ2F0Z"
    "V9wYXlsb2FkIjogW3siLi4uIjogIjNZUnRaLWxCTmhJX1loZ2dTaHJkSGhyU3VEUFNwd012SjNWV2pVbmhEUU0ifV0sICJfc2RfYWxnIjogInN"
    "oYS0yNTYifQ.ZQ_5x2hYLusuUNAA2OJloeS2w3fxZRCsSvcU-wg9fK7nlMmsbpK6EPlntD8oHq5waegxsLmSL51V5hfyaQViMg~WyJzOVdQdDJ"
    "VNEdhcGNKc255RWI2YmpnIiwgeyJpZCI6ICJtZXJjaGFudF8xIiwgIm5hbWUiOiAiRGVtbyBNZXJjaGFudCIsICJ3ZWJzaXRlIjogImh0dHBzO"
    "i8vZGVtby1tZXJjaGFudC5leGFtcGxlIn1d~WyJadEtTNUZTcklBWTZIbEdCNEhvN21nIiwgeyJ2Y3QiOiAibWFuZGF0ZS5wYXltZW50Lm9wZW"
    "4uMSIsICJjb25zdHJhaW50cyI6IFt7InR5cGUiOiAicGF5bWVudC5hbW91bnRfcmFuZ2UiLCAiY3VycmVuY3kiOiAiVVNEIiwgIm1heCI6IDIw"
    "MDAwLCAibWluIjogMH0sIHsidHlwZSI6ICJwYXltZW50LmFsbG93ZWRfcGF5ZWVzIiwgImFsbG93ZWQiOiBbeyIuLi4iOiAib0VIN2kxZ3liLX"
    "puNmF3d2p5NTdMdnp4a1FEZkQtOHR2bEMyWHVJa2dPQSJ9XX0sIHsidHlwZSI6ICJwYXltZW50LnJlZmVyZW5jZSIsICJjb25kaXRpb25hbF90"
    "cmFuc2FjdGlvbl9pZCI6ICJGekxveGJidGdRR1laeG9TTTJOSllKdGtGVFNzZGZVQm9WRVExMms3Sk44In1dLCAiY25mIjogeyJqd2siOiB7Im"
    "NydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAieCI6ICJRcFN5eFBRSHkzOHhja3l2RHI1NGdaM1Q0MnpqOWlMdFY0a295YjVVMjdjIiwgInki"
    "OiAiMzdITGQ3SkppbnhqSkluOEo3SGlqc3NvZWNCbGZoZFctZ1VMN2ZlSTlsdyJ9fSwgImlhdCI6IDE3NzczNDIzNTcsICJleHAiOiAxNzc3Mz"
    "Q1OTU3fV0~")
AP2_PAY_OPEN_SHA256 = "ba2c681de9a67ebac249b3d1128f63fb388bb8c92a131b0f796af003e3cad029"
# AP2 e1ea56d, docs/ap2/checkout_mandate.md line 244 ("Open Checkout Mandate SD-JWT plus disclosures", Encoded Token), verbatim
AP2_CHK_OPEN = (
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0IiwgImtpZCI6ICJhZ2VudC1wcm92aWRlci1rZXktMSJ9.eyJkZWxlZ2F0Z"
    "V9wYXlsb2FkIjogW3siLi4uIjogIlF0WFRKdFdxZzk5OUNtVVdHakhGVFdNa1JQZ3VEZmVLM3dHU2FJbmQtZHcifV0sICJfc2RfYWxnIjogInN"
    "oYS0yNTYifQ.HvCGk7ye_c0LN2-NFG13wfyu3LA--rckTPGm36ugO2aRvsded7ngw1py8W3JF7wBpoQnsKr17tNTF3zLeYcoWA~WyI0bjNMXy0"
    "zX0ZtMkdneUZBRjhDdF9nIiwgeyJpZCI6ICJzdXBlcnNob2VfbGltaXRlZF9lZGl0aW9uX2dvbGRfc25lYWtlcl93b21lbnNfOV8wIiwgInRpd"
    "GxlIjogIlN1cGVyU2hvZSBMaW1pdGVkIEVkaXRpb24gR29sZCJ9XQ~WyIyelBMNnZxTEJnMldZQWRiVzktMWxRIiwgeyJpZCI6ICJtZXJjaGFu"
    "dF8xIiwgIm5hbWUiOiAiRGVtbyBNZXJjaGFudCIsICJ3ZWJzaXRlIjogImh0dHBzOi8vZGVtby1tZXJjaGFudC5leGFtcGxlIn1d~WyJsYUFvV"
    "0tOUnVHbndSRWpKV1lKN3BnIiwgeyJ2Y3QiOiAibWFuZGF0ZS5jaGVja291dC5vcGVuLjEiLCAiY29uc3RyYWludHMiOiBbeyJ0eXBlIjogImN"
    "oZWNrb3V0LmxpbmVfaXRlbXMiLCAiaXRlbXMiOiBbeyJpZCI6ICJsaW5lXzEiLCAiYWNjZXB0YWJsZV9pdGVtcyI6IFt7Ii4uLiI6ICJ5M2FvY"
    "0FEMnJoWXBKUU9VTU4wMTZmYURGR2tUQkdFRFZsMVIxVFJIZGJ3In1dLCAicXVhbnRpdHkiOiAxfV19LCB7InR5cGUiOiAiY2hlY2tvdXQuYWx"
    "sb3dlZF9tZXJjaGFudHMiLCAiYWxsb3dlZCI6IFt7Ii4uLiI6ICJhNVVNQWR4Q2tfTVJheXlWZFJocElBWjBaaGpWTEVxMWcyQld5cndLVXdnI"
    "n1dfV0sICJjbmYiOiB7Imp3ayI6IHsiY3J2IjogIlAtMjU2IiwgImt0eSI6ICJFQyIsICJ4IjogIlFwU3l4UFFIeTM4eGNreXZEcjU0Z1ozVDQ"
    "yemo5aUx0VjRrb3liNVUyN2MiLCAieSI6ICIzN0hMZDdKSmlueGpKSW44SjdIaWpzc29lY0JsZmhkVy1nVUw3ZmVJOWx3In19LCAiaWF0IjogM"
    "Tc3NzM0MjM1NywgImV4cCI6IDE3NzczNDU5NTd9XQ~")
AP2_CHK_OPEN_SHA256 = "1732e8c5b6ed810198671a12336349609b641534ac75f501a15110d7693b24df"
# docs/ap2/payment_mandate.md, the "Example" of each constraint (same commit). The documentation writes amounts as 100.50 /
# 10.00 / 1000.00; the schema says integers in minor units and SPEC §3.1 refuses fractions, so they are integers here.
EX_RECURRENCE = {"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 12}
EX_INSTRUMENTS = {"type": "payment.allowed_payment_instruments", "allowed": [
    {"id": "abe3c...", "type": "card", "description": "network ··· 1234"},
    {"id": "zde4d...", "type": "UPI", "description": "user****@bankname"}]}
EX_PISPS = {"type": "payment.allowed_pisps", "allowed": [
    {"legal_name": "Example Payment Services Ltd.", "brand_name": "ExamplePay", "domain_name": "examplepay.com"}]}
EX_BUDGET = {"type": "payment.budget", "max": 1000, "currency": "USD"}
EX_EXEC = {"type": "payment.execution_date", "not_before": "2026-03-31T00:00:00Z", "not_after": "2026-04-30T23:59:59Z"}
# docs/ap2/payment_mandate.md "Allowed Payees" example and checkout_mandate.md "Allowed Merchants" example
EX_PAYEE_2 = {"name": "Merchant Choice", "website": "https://merchant-choice.com"}
EX_MERCHANT_2 = {"name": "Second Merchant", "website": "https://second-merchant.com"}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _official(token):
    p = ap2.parse_sd_jwt(token)
    return ap2.resolve_disclosures(p["payload"], p["disclosures"])["delegate_payload"][0]


class Key:
    def __init__(self):
        self.sk = ec.generate_private_key(ec.SECP256R1())
        n = self.sk.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}

    def sign(self, header, payload_text):
        si = f"{_b64u(json.dumps(header).encode())}.{_b64u(payload_text.encode('utf-8'))}"
        r, s = decode_dss_signature(self.sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


K1, K2 = Key(), Key()
_salt = [0]


def _disc(*parts):
    _salt[0] += 1
    return _b64u(json.dumps([f"salt{_salt[0]}", *parts]).encode())


def _hide_arrays(content, discs):
    """The lists AP2 marks x-selectively-disclosable-array become array disclosures, as in the documentation's tokens."""
    c = copy.deepcopy(content)
    cons = c.get("constraints") if isinstance(c, dict) else None
    for con in cons if isinstance(cons, list) else []:
        targets = []
        if isinstance(con, dict) and isinstance(con.get("allowed"), list) and con.get("type") != "payment.allowed_pisps":
            targets.append((con, "allowed"))
        if isinstance(con, dict) and con.get("type") == "checkout.line_items" and isinstance(con.get("items"), list):
            targets += [(it, "acceptable_items") for it in con["items"] if isinstance(it, dict) and isinstance(it.get("acceptable_items"), list)]
        for obj, k in targets:
            out = []
            for el in obj[k]:
                d = _disc(el)
                discs.append(d)
                out.append({"...": ap2._disclosure_digest(d)})
            obj[k] = out
    return c


def issue(content, top=None, key=K1, sd_arrays=True, form="delegate", decoy=False, payload_text_hook=None):
    discs = []
    c = _hide_arrays(content, discs) if sd_arrays else copy.deepcopy(content)
    if form == "delegate":
        d = _disc(c)
        discs.append(d)
        payload = dict(top or {})
        payload["delegate_payload"] = [{"...": ap2._disclosure_digest(d)}]
        payload["_sd_alg"] = "sha-256"
    else:
        payload = dict(c)
        payload.update(top or {})
    if decoy:
        payload.setdefault("_sd", []).append(_b64u(hashlib.sha256(os.urandom(16)).digest()))
    text = json.dumps(payload)
    if payload_text_hook:
        text = payload_text_hook(text)
    return key.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": key.jwk}, text) + "~" + "~".join(discs) + ("~" if discs else "~")


def restrict(orig_compact, content, top=None, **kw):
    t = {CLAIM: ap2.issuer_jwt_hash(orig_compact)}
    t.update(top or {})
    return issue(content, t, **kw)


def direct(orig_compact, r_compact):
    """evaluate_restriction on two artifacts, without a pack (the generative cases; equal to the pack path, measured below)."""
    def art(c):
        p = ap2.parse_sd_jwt(c)
        return {"parsed": p, "resolved": ap2.resolve_disclosures(p["payload"], p["disclosures"]), "jwk": p["header"]["jwk"]}
    return ap2.evaluate_restriction(art(orig_compact), art(r_compact))


def why(res):
    return sorted({(x["state"], x["reason"]) for x in res["reasons"]})


PAY = _official(AP2_PAY_OPEN)
CHK = _official(AP2_CHK_OPEN)
RICH = copy.deepcopy(PAY)   # the official open payment mandate with every other constraint example of payment_mandate.md
RICH["constraints"] += [copy.deepcopy(x) for x in (EX_RECURRENCE, EX_BUDGET, EX_INSTRUMENTS, EX_PISPS, EX_EXEC)]
RICH["constraints"][1]["allowed"].append(copy.deepcopy(EX_PAYEE_2))
CHK2 = copy.deepcopy(CHK)
CHK2["constraints"][1]["allowed"].append(copy.deepcopy(EX_MERCHANT_2))
CHK2["constraints"][0]["items"][0]["acceptable_items"].append({"id": "BAB1234", "title": "Red Style"})   # checkout_mandate.md example


def ci(content, t):
    """The index of the first constraint of type t."""
    return next(i for i, c in enumerate(content["constraints"]) if isinstance(c, dict) and c.get("type") == t)


class TestOfficialExamples(unittest.TestCase):
    def test_tokens_are_the_documentation_bytes_and_decode_fully(self):
        self.assertEqual(hashlib.sha256(AP2_PAY_OPEN.encode()).hexdigest(), AP2_PAY_OPEN_SHA256)
        self.assertEqual(hashlib.sha256(AP2_CHK_OPEN.encode()).hexdigest(), AP2_CHK_OPEN_SHA256)
        for tok, vct in ((AP2_PAY_OPEN, "mandate.payment.open.1"), (AP2_CHK_OPEN, "mandate.checkout.open.1")):
            p = ap2.parse_sd_jwt(tok)
            self.assertEqual(ap2._digest_census(p), (0, False))
            res = ap2.resolve_disclosures(p["payload"], p["disclosures"])
            self.assertEqual(ap2._mandate_form(res)[0], "delegate_payload")
            self.assertEqual(ap2._mandate_form(res)[1]["vct"], vct)

    def test_the_reference_of_the_example_hashes_the_compact_serialization_not_the_issuer_jwt(self):
        """SPEC §11.1 states it as measured: AP2's conditional_transaction_id is the SHA-256 of the whole checkout token."""
        cti = PAY["constraints"][2]["conditional_transaction_id"]
        self.assertEqual(ap2._sha256_b64url(AP2_CHK_OPEN.encode()), cti)
        self.assertNotEqual(ap2.issuer_jwt_hash(AP2_CHK_OPEN), cti)
        self.assertEqual(ap2.issuer_jwt_hash(AP2_CHK_OPEN), ap2._sha256_b64url(AP2_CHK_OPEN.split("~")[0].encode()))

    def test_reissued_tokens_resolve_to_the_official_content(self):
        for content in (PAY, CHK):
            c = issue(content)
            p = ap2.parse_sd_jwt(c)
            self.assertEqual(ap2._mandate_form(ap2.resolve_disclosures(p["payload"], p["disclosures"]))[1], content)
            self.assertEqual(ap2._digest_census(p), (0, False))


class PackCase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-restr-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def pack(self, *arts, name="p.json"):
        out = os.path.join(self.d, name)
        ap2.build_evidence([{"name": n, "sd_jwt": c} for n, c in arts], out)
        return out

    def run_pair(self, o, r):
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r)))
        self.assertEqual(len(rec["restrictions"]), 1, rec)
        return rec, rec["restrictions"][0]


class TestBinding(PackCase):
    def test_an_unchanged_copy_is_verified_in_both_forms_and_for_both_mandates(self):
        for content in (PAY, CHK, RICH, CHK2):
            for form in ("delegate", "payload"):
                o = issue(content, form=form)
                rec, e = self.run_pair(o, restrict(o, content, form=form))
                self.assertEqual((e["state"], e["reasons"], e["original"]), ("verified", [], "original"), (form, e))
                self.assertTrue(rec["met"])
                self.assertTrue(rec["valid"])

    def test_a_narrower_record_is_verified(self):
        o = issue(RICH)
        r = copy.deepcopy(RICH)
        r["constraints"][0]["max"] = 5000
        r["exp"] -= 600
        rec, e = self.run_pair(o, restrict(o, r))
        self.assertEqual(e["state"], "verified", e)

    def test_the_claim_must_name_an_artifact_of_the_pack(self):
        o, other = issue(PAY), issue(CHK)
        rec, e = self.run_pair(o, restrict(other, PAY))
        self.assertEqual(why(e), [("not_evaluated", "original_not_in_pack")])
        self.assertFalse(rec["met"])

    def test_a_malformed_claim_is_contradicted(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        for bad in (None, 7, True, [h], {"h": h}, "", h[:-1], h + "A", h + "=", h.replace(h[0], "+", 1) if h[0] != "+" else "/" + h[1:],
                    base64.b64encode(hashlib.sha256(o.split("~")[0].encode()).digest()).decode(), h.encode().hex()):
            with self.subTest(bad=bad):
                rec, e = self.run_pair(o, issue(PAY, {CLAIM: bad}))
                self.assertEqual(why(e), [("contradicted", "restricts_malformed")])
                self.assertEqual(e["restricts"], bad if isinstance(bad, str) else None)

    def test_a_non_canonical_spelling_of_the_hash_is_malformed(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        bad = h[:-1] + alphabet[alphabet.index(h[-1]) ^ 1]   # same 32 bytes, a trailing bit set: §3.1 refuses the spelling
        self.assertEqual(base64.urlsafe_b64decode(bad + "="), base64.urlsafe_b64decode(h + "="))
        rec, e = self.run_pair(o, issue(PAY, {CLAIM: bad}))
        self.assertEqual(why(e), [("contradicted", "restricts_malformed")])

    def test_a_chain_is_as_strong_as_its_weakest_link(self):
        o = issue(RICH)
        i = ci(RICH, "payment.amount_range")
        wide = copy.deepcopy(RICH); wide["constraints"][i]["max"] = 10 ** 6
        r1 = restrict(o, wide)
        mid = copy.deepcopy(wide); mid["constraints"][i]["max"] = 50000   # narrower than r1, broader than o
        r2 = restrict(r1, mid)
        r3 = restrict(r2, mid)
        rec = ap2.verify_restrictions(self.pack(("o", o), ("r1", r1), ("r2", r2), ("r3", r3)))
        got = {e["in"]: (e["state"], why(e)) for e in rec["restrictions"]}
        self.assertEqual(got["r1"], ("contradicted", [("contradicted", "constraint_widened")]))
        self.assertEqual(got["r2"], ("not_evaluated", [("not_evaluated", "original_not_verified")]))
        self.assertEqual(got["r3"], ("not_evaluated", [("not_evaluated", "original_not_verified")]))
        self.assertFalse(rec["met"])
        narrow = copy.deepcopy(RICH); narrow["constraints"][i]["max"] = 100
        n1 = restrict(o, narrow)
        n2 = restrict(n1, narrow)
        rec = ap2.verify_restrictions(self.pack(("o", o), ("n1", n1), ("n2", n2), ("n1b", restrict(o, RICH)), name="q.json"))
        self.assertEqual([(e["in"], e["state"], e["original"]) for e in rec["restrictions"]],
                         [("n1", "verified", "o"), ("n2", "verified", "n1"), ("n1b", "verified", "o")])
        self.assertTrue(rec["met"])

    def test_a_record_with_a_duplicate_key_is_never_evaluated(self):
        o = issue(PAY)
        p = self.pack(("original", o), ("restriction", restrict(o, PAY)))
        dup = restrict(o, PAY, payload_text_hook=lambda t: t[:-1] + ', "%s": "%s"}' % (CLAIM, "A" * 43))   # the claim twice
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.parse_sd_jwt(dup)
        with open(p, encoding="utf-8") as f:
            ev = json.load(f)
        ev["artifacts"][1]["sd_jwt_compact"] = dup
        ev["evidence_digest_sha256"] = hashlib.sha256(ap2._canon({k: v for k, v in ev.items() if k not in ap2._DIGEST_EXCLUDED})).hexdigest()
        with open(p, "w", encoding="utf-8") as f:
            json.dump(ev, f)
        rec = ap2.verify_restrictions(p)
        self.assertFalse(rec["valid"])
        self.assertEqual(rec["restrictions"], [])   # the record does not parse (§3.1): no entry, and the pack is not valid
        self.assertFalse(rec["met"])

    def test_a_well_formed_value_of_another_case_names_nothing(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        flipped = h[:-1].swapcase() + h[-1]   # 32 other bytes, canonical spelling
        rec, e = self.run_pair(o, issue(PAY, {CLAIM: flipped}))
        self.assertEqual(why(e), [("not_evaluated", "original_not_in_pack")])

    def test_another_key_is_contradicted(self):
        o = issue(PAY)
        rec, e = self.run_pair(o, restrict(o, PAY, key=K2))
        self.assertEqual(why(e), [("contradicted", "issuer_key_differs")])

    def test_another_cnf_is_contradicted(self):
        o = issue(PAY)
        r = copy.deepcopy(PAY)
        r["cnf"] = {"jwk": K2.jwk}
        rec, e = self.run_pair(o, restrict(o, r))
        self.assertEqual(why(e), [("contradicted", "cnf_differs")])
        r["cnf"] = copy.deepcopy(PAY["cnf"]); r["cnf"]["jwk"]["kid"] = "x"   # a member added: not the same cnf
        rec, e = self.run_pair(o, restrict(o, r))
        self.assertEqual(why(e), [("contradicted", "cnf_differs")])
        del r["cnf"]
        rec, e = self.run_pair(o, restrict(o, r))
        self.assertEqual(why(e), [("contradicted", "cnf_differs")])

    def test_exp_later_or_removed_is_contradicted_earlier_or_equal_is_verified(self):
        o = issue(PAY)
        for delta, expect in ((0, []), (-1, []), (1, [("contradicted", "time_widened")])):
            r = copy.deepcopy(PAY); r["exp"] += delta
            self.assertEqual(why(self.run_pair(o, restrict(o, r))[1]), expect, delta)
        r = copy.deepcopy(PAY); del r["exp"]
        self.assertEqual(why(self.run_pair(o, restrict(o, r))[1]), [("contradicted", "time_widened")])
        r = copy.deepcopy(PAY); r["exp"] = str(PAY["exp"])
        self.assertEqual(why(self.run_pair(o, restrict(o, r))[1]), [("contradicted", "malformed")])

    def test_top_level_exp_and_nbf(self):
        o = issue(PAY, {"exp": 2000000000, "nbf": 1700000000, "iss": "https://agent-provider.example.com"})
        for top, expect in (({"exp": 2000000000, "nbf": 1700000000, "iss": "https://agent-provider.example.com"}, []),
                            ({"exp": 1999999999, "nbf": 1700000001, "iss": "https://agent-provider.example.com"}, []),
                            ({"exp": 2000000001, "nbf": 1700000000, "iss": "https://agent-provider.example.com"}, [("contradicted", "time_widened")]),
                            ({"exp": 2000000000, "nbf": 1699999999, "iss": "https://agent-provider.example.com"}, [("contradicted", "time_widened")]),
                            ({"exp": 2000000000, "iss": "https://agent-provider.example.com"}, [("contradicted", "time_widened")]),
                            ({"exp": 2000000000, "nbf": 1700000000}, [("contradicted", "claim_changed")]),
                            ({"exp": 2000000000, "nbf": 1700000000, "iss": "https://other.example"}, [("contradicted", "claim_changed")])):
            with self.subTest(top=top):
                self.assertEqual(why(self.run_pair(o, restrict(o, PAY, top))[1]), expect)

    def test_a_pack_that_is_not_valid_is_never_evaluated(self):
        o = issue(PAY)
        p = self.pack(("original", o), ("restriction", restrict(o, PAY)))
        with open(p, encoding="utf-8") as f:
            ev = json.load(f)
        ev["subject"] = "altered"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(ev, f)
        rec = ap2.verify_restrictions(p)
        self.assertFalse(rec["valid"])
        self.assertEqual([why(e) for e in rec["restrictions"]], [[("not_evaluated", "pack_not_valid")]])
        self.assertFalse(rec["met"])

    def test_a_refused_file_has_no_restriction(self):
        p = os.path.join(self.d, "x.json")
        with open(p, "w") as f:
            f.write('{"a": 1, "a": 2}')
        rec = ap2.verify_restrictions(p)
        self.assertEqual((rec["admission"], rec["restrictions"], rec["met"]), ("refused", [], False))
        self.assertEqual(rec["refusal_class"], ap2.verify_evidence(p)["refusal_class"])

    def test_hidden_content_is_never_assumed_absent(self):
        o = issue(RICH)
        # a decoy digest in O, in R; a disclosure of O left out (an allowed payee kept hidden)
        od = issue(RICH, decoy=True)
        rec, e = self.run_pair(od, restrict(od, RICH))
        self.assertEqual(why(e), [("not_evaluated", "undisclosed_digests")])
        rec, e = self.run_pair(o, restrict(o, RICH, decoy=True))
        self.assertEqual(why(e), [("not_evaluated", "undisclosed_digests")])
        parts = o.split("~")
        hidden = next(d for d in parts[1:-1] if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] == EX_PAYEE_2)
        o_partial = "~".join(p for p in parts if p != hidden)
        r_narrow = copy.deepcopy(RICH); r_narrow["constraints"][1]["allowed"] = r_narrow["constraints"][1]["allowed"][:1]
        rec, e = self.run_pair(o_partial, restrict(o_partial, r_narrow))
        self.assertTrue(rec["valid"])
        self.assertEqual(why(e), [("not_evaluated", "undisclosed_digests")])
        self.assertEqual(e["reasons"][0]["at"], "original")

    def test_the_fully_disclosed_copy_of_the_same_issuer_jwt_is_the_original(self):
        o = issue(RICH)
        parts = o.split("~")
        hidden = next(d for d in parts[1:-1] if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] == EX_PAYEE_2)
        o_partial = "~".join(p for p in parts if p != hidden)
        p = self.pack(("partial", o_partial), ("full", o), ("restriction", restrict(o, RICH)))
        e = ap2.verify_restrictions(p)["restrictions"][0]
        self.assertEqual((e["state"], e["original"], e["same_issuer_jwt"]), ("verified", "full", ["partial"]))

    def test_a_repeated_digest_is_never_verified(self):
        """RFC 9901 §7.1 step 4 — the 1.6.0 resolver does not reject it (measured), so the profile checks it itself."""
        def twice(text):
            pl = json.loads(text)
            pl["delegate_payload"].append(dict(pl["delegate_payload"][0]))
            return json.dumps(pl)
        o = issue(PAY)
        rec, e = self.run_pair(o, restrict(o, PAY, payload_text_hook=twice))
        self.assertTrue(rec["valid"])   # the pack: §6 does not see it
        self.assertEqual(why(e), [("contradicted", "malformed")])
        o2 = issue(PAY, payload_text_hook=twice)
        rec, e = self.run_pair(o2, restrict(o2, PAY))
        self.assertEqual(why(e), [("not_evaluated", "original_malformed")])

    def test_forms(self):
        o = issue(PAY)
        rec, e = self.run_pair(o, restrict(o, PAY, form="payload"))
        self.assertEqual(why(e), [("not_evaluated", "form_differs")])
        for dp in ([], [PAY, PAY], ["x"], {}, "x", None, [[PAY]]):
            with self.subTest(dp=dp):
                r = ap2.issuer_jwt_hash(o)
                bad = K1.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": K1.jwk}, json.dumps({CLAIM: r, "delegate_payload": dp})) + "~"
                rec, e = self.run_pair(o, bad)
                self.assertEqual(why(e), [("not_evaluated", "form_unsupported")])


class TestRules(PackCase):
    """One case per rule of the SPEC §11.4 table: at the boundary (verified), one step inside (verified), one step outside
    (contradicted), removed (contradicted)."""

    def check(self, base, mutate, expect, o=None):
        o = o or issue(base)
        r = copy.deepcopy(base)
        mutate(r)
        rec, e = self.run_pair(o, restrict(o, r))
        self.assertEqual(why(e), expect, e)
        return e

    def test_amount_range(self):
        i = ci(RICH, "payment.amount_range")
        W = [("contradicted", "constraint_widened")]
        for m, exp in ((lambda r: None, []), (lambda r: r["constraints"][i].update(max=19999), []),
                       (lambda r: r["constraints"][i].update(min=1), []), (lambda r: r["constraints"][i].update(max=20001), W),
                       (lambda r: r["constraints"][i].update(min=-1), W), (lambda r: r["constraints"][i].pop("min"), W),
                       (lambda r: r["constraints"][i].update(currency="EUR"), W),
                       (lambda r: r["constraints"].pop(i), [("contradicted", "constraint_removed")])):
            with self.subTest(m=m):
                self.check(RICH, m, exp)

    def test_budget(self):
        i = ci(RICH, "payment.budget")
        W = [("contradicted", "constraint_widened")]
        for m, exp in ((lambda r: r["constraints"][i].update(max=999), []), (lambda r: r["constraints"][i].update(max=1001), W),
                       (lambda r: r["constraints"][i].update(currency="usd"), W),
                       (lambda r: r["constraints"].pop(i), [("contradicted", "constraint_removed")])):
            with self.subTest(m=m):
                self.check(RICH, m, exp)

    def test_agent_recurrence(self):
        i = ci(RICH, "payment.agent_recurrence")
        W = [("contradicted", "constraint_widened")]
        order = ["ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"]
        for f in order:
            with self.subTest(frequency=f):
                self.check(RICH, lambda r: r["constraints"][i].update(frequency=f), [] if order.index(f) >= order.index("MONTHLY") else W)
        for m, exp in ((lambda r: r["constraints"][i].update(max_occurrences=11), []),
                       (lambda r: r["constraints"][i].update(max_occurrences=13), W),
                       (lambda r: r["constraints"][i].pop("max_occurrences"), W),
                       (lambda r: r["constraints"][i].update(frequency="monthly"), [("contradicted", "constraint_widened"), ("contradicted", "malformed")])):
            with self.subTest(m=m):
                self.check(RICH, m, exp)

    def test_allowed_lists(self):
        W = [("contradicted", "constraint_widened")]
        for base, t, new in ((RICH, "payment.allowed_payees", {"id": "merchant_9", "name": "Other"}),
                             (RICH, "payment.allowed_payment_instruments", {"id": "x", "type": "card"}),
                             (RICH, "payment.allowed_pisps", {"legal_name": "L", "brand_name": "B", "domain_name": "d.example"}),
                             (CHK2, "checkout.allowed_merchants", {"id": "merchant_9", "name": "Other"})):
            i = ci(base, t)
            with self.subTest(t=t):
                self.check(base, lambda r: r["constraints"][i].update(allowed=r["constraints"][i]["allowed"][:1]), [])
                self.check(base, lambda r: r["constraints"][i].update(allowed=[]), [])
                self.check(base, lambda r: r["constraints"][i]["allowed"].append(new), W)
                self.check(base, lambda r: r["constraints"][i]["allowed"][0].pop(sorted(r["constraints"][i]["allowed"][0])[0]), W)   # stricter than AP2 (declared)
                self.check(base, lambda r: r["constraints"].pop(i), [("contradicted", "constraint_removed")])

    def test_execution_date(self):
        i = ci(RICH, "payment.execution_date")
        W = [("contradicted", "constraint_widened")]
        for m, exp in ((lambda r: r["constraints"][i].update(not_before="2026-04-01T00:00:00Z", not_after="2026-04-15T00:00:00Z"), []),
                       (lambda r: r["constraints"][i].update(not_after="2026-05-01T00:00:00Z"), W),
                       (lambda r: r["constraints"][i].update(not_before="2026-03-30T23:59:59Z"), W),
                       (lambda r: r["constraints"][i].pop("not_after"), W),
                       (lambda r: r["constraints"][i].update(not_after="2026-04-30"), [("not_evaluated", "date_form")]),
                       (lambda r: r["constraints"][i].update(not_after="2026-04-31T00:00:00Z"), [("not_evaluated", "date_form")]),
                       (lambda r: r["constraints"][i].update(not_after="２０２６-04-30T23:59:59Z"), [("not_evaluated", "date_form")])):
            with self.subTest(m=m):
                self.check(RICH, m, exp)
        o_dates = copy.deepcopy(RICH); o_dates["constraints"][i] = {"type": "payment.execution_date", "not_before": "2026-03-31", "not_after": "2026-04-30"}
        self.check(o_dates, lambda r: r["constraints"][i].update(not_after="2026-04-29"), [])
        self.check(o_dates, lambda r: r["constraints"][i].update(not_after="2026-05-01"), W)

    def test_reference(self):
        i = ci(RICH, "payment.reference")
        self.check(RICH, lambda r: r["constraints"][i].update(conditional_transaction_id="A" * 43), [("contradicted", "constraint_widened")])
        self.check(RICH, lambda r: r["constraints"].pop(i), [("contradicted", "constraint_removed")])

    def test_line_items(self):
        i = ci(CHK2, "checkout.line_items")
        W = [("contradicted", "constraint_widened")]
        for m, exp in ((lambda r: r["constraints"][i]["items"][0]["acceptable_items"].pop(), []),
                       (lambda r: r["constraints"][i]["items"][0]["acceptable_items"].clear(), W),   # empty = wildcard in the SDK
                       (lambda r: r["constraints"][i]["items"][0]["acceptable_items"].append({"id": "x", "title": "x"}), W),
                       (lambda r: r["constraints"][i]["items"][0].update(quantity=2), W),
                       (lambda r: r["constraints"][i]["items"][0].update(id="line_2"), W),
                       (lambda r: r["constraints"][i]["items"].append(copy.deepcopy(r["constraints"][i]["items"][0])), W),
                       (lambda r: r["constraints"].pop(i), [("contradicted", "constraint_removed")])):
            with self.subTest(m=m):
                self.check(CHK2, m, exp)
        wild = copy.deepcopy(CHK2); wild["constraints"][i]["items"][0]["acceptable_items"] = []
        self.check(wild, lambda r: None, [])
        # empty in O: the AP2 text matches no item, the SDK every item — a non-empty list is broader under the first reading
        self.check(wild, lambda r: r["constraints"][i]["items"][0]["acceptable_items"].append({"id": "x", "title": "x"}), W)

    def test_presets(self):
        o_pre = copy.deepcopy(PAY); o_pre["payee"] = {"id": "merchant_1", "name": "Demo Merchant"}; o_pre["payment_amount"] = {"amount": 1000, "currency": "USD"}
        P = [("contradicted", "preset_changed")]
        self.check(o_pre, lambda r: r.pop("payee"), P)
        self.check(o_pre, lambda r: r["payment_amount"].update(amount=999), P)
        self.check(o_pre, lambda r: r.update(risk_data={"x": 1}), [])
        for k, v in (("payee", {"id": "merchant_1", "name": "Demo Merchant"}), ("payment_amount", {"amount": 100, "currency": "USD"}),
                     ("payment_instrument", {"id": "stub", "type": "card"}), ("execution_date", "2026-04-01"), ("risk_data", {"a": "b"}),
                     ("pisp", {"legal_name": "L", "brand_name": "B", "domain_name": "d.example"})):
            with self.subTest(added=k):
                self.check(PAY, lambda r: r.update({k: v}), [])
        o_risk = copy.deepcopy(PAY); o_risk["risk_data"] = {"device": "a"}
        self.check(o_risk, lambda r: r.update(risk_data={"device": "b"}), P)

    def test_added_constraints(self):
        self.check(PAY, lambda r: r["constraints"].append(copy.deepcopy(EX_BUDGET)), [])
        self.check(PAY, lambda r: r["constraints"].append({"type": "payment.amount_range", "currency": "USD", "max": 100}), [])
        e = self.check(PAY, lambda r: r["constraints"].append({"type": "com.example.velocity", "per_day": 1}), [])
        self.assertEqual([x["reason"] for x in e["reported"]], ["unknown_constraint_added"])   # AP2: unknown = failing evaluation
        self.check(PAY, lambda r: r["constraints"].append(copy.deepcopy(EX_RECURRENCE)), [("not_evaluated", "recurrence_added")])
        self.check(PAY, lambda r: r["constraints"].append({"type": "payment.budget", "currency": "USD", "max": "1"}), [("contradicted", "malformed")])
        self.check(PAY, lambda r: r["constraints"].append({"type": "payment.budget", "currency": "USD", "max": 1, "per": "day"}), [("not_evaluated", "unknown_name")])

    def test_unknown_and_malformed_constraints_of_the_original(self):
        o_unk = copy.deepcopy(PAY); o_unk["constraints"].append({"type": "com.example.velocity", "per_day": 3})
        self.check(o_unk, lambda r: None, [])
        self.check(o_unk, lambda r: r["constraints"].pop(), [("not_evaluated", "unknown_name")])
        self.check(o_unk, lambda r: r["constraints"][-1].update(per_day=1), [("not_evaluated", "unknown_name")])
        o_bad = copy.deepcopy(PAY); o_bad["constraints"].append({"type": "payment.budget", "currency": "USD", "max": "500"})
        self.check(o_bad, lambda r: None, [])
        self.check(o_bad, lambda r: r["constraints"][-1].update(max=1), [("not_evaluated", "original_malformed")])

    def test_malformed_bound_in_the_record_is_contradicted(self):
        i = ci(RICH, "payment.amount_range")
        self.check(RICH, lambda r: r["constraints"][i].update(max="5000"), [("contradicted", "constraint_widened"), ("contradicted", "malformed")])
        self.check(RICH, lambda r: r["constraints"][i].update(max=True), [("contradicted", "constraint_widened"), ("contradicted", "malformed")])
        self.check(RICH, lambda r: r.update(constraints={"0": RICH["constraints"][0]}), [("contradicted", "malformed")])

    def test_vct(self):
        self.check(PAY, lambda r: r.update(vct="mandate.checkout.open.1"), [("contradicted", "claim_changed")])
        closed = {"vct": "mandate.payment.1", "transaction_id": "t", "payment_amount": {"amount": 1, "currency": "USD"}}
        self.check(closed, lambda r: None, [])
        self.check(closed, lambda r: r["payment_amount"].update(amount=0), [("not_evaluated", "vct_not_supported")])

    def test_unknown_names(self):
        U = [("not_evaluated", "unknown_name")]
        self.check(PAY, lambda r: r.update(note="x"), U)
        o = issue(PAY, {"com.example.flag": 1})
        rec, e = self.run_pair(o, restrict(o, PAY, {"com.example.flag": 1}))
        self.assertEqual(why(e), [])
        rec, e = self.run_pair(o, restrict(o, PAY))
        self.assertEqual(why(e), U)
        rec, e = self.run_pair(o, restrict(o, PAY, {"com.example.flag": 2}))
        self.assertEqual(why(e), U)

    def test_iat_and_jti_are_typed_not_compared(self):
        self.check(PAY, lambda r: r.update(iat=1), [])
        self.check(PAY, lambda r: r.update(iat="1"), [("contradicted", "malformed")])
        o = issue(PAY, {"jti": "a"})
        self.assertEqual(why(self.run_pair(o, restrict(o, PAY, {"jti": "b"}))[1]), [])
        self.assertEqual(why(self.run_pair(o, restrict(o, PAY, {"jti": 1}))[1]), [("contradicted", "malformed")])


# ───────────────────────────────── generative: the whole space of R, each case's class from the SPEC, not from the code

NARROWINGS = []   # each: (name, fn(r)) — narrower than RICH under SPEC §11.4 whatever else is applied


def _n(f):
    NARROWINGS.append((f.__name__, f))
    return f


@_n
def n_amount(r):
    c = r["constraints"][ci(r, "payment.amount_range")]; c["max"] = random.randint(c.get("min", 0), c["max"]); c["min"] = random.randint(c.get("min", 0), c["max"])


@_n
def n_budget(r):
    c = r["constraints"][ci(r, "payment.budget")]; c["max"] = random.randint(0, c["max"])


@_n
def n_recurrence(r):
    c = r["constraints"][ci(r, "payment.agent_recurrence")]
    c["frequency"] = random.choice(["MONTHLY", "QUARTERLY", "ANNUALLY"]); c["max_occurrences"] = random.randint(0, c["max_occurrences"])


@_n
def n_allowed(r):
    c = r["constraints"][ci(r, random.choice(["payment.allowed_payees", "payment.allowed_payment_instruments", "payment.allowed_pisps"]))]
    c["allowed"] = random.sample(c["allowed"], random.randint(0, len(c["allowed"])))


@_n
def n_exec(r):
    c = r["constraints"][ci(r, "payment.execution_date")]
    c["not_before"] = random.choice(["2026-03-31T00:00:00Z", "2026-04-01T00:00:00Z"]); c["not_after"] = random.choice(["2026-04-30T23:59:59Z", "2026-04-02T00:00:00Z"])


@_n
def n_exp(r):
    r["exp"] -= random.randint(0, 3600)


@_n
def n_add_constraint(r):
    r["constraints"].append(random.choice([copy.deepcopy(EX_BUDGET), {"type": "payment.amount_range", "currency": "USD", "max": 1},
                                           {"type": "com.example.other", "x": [1]}, {"type": "payment.allowed_payees", "allowed": []}]))


@_n
def n_add_preset(r):
    r.setdefault("payment_amount", {"amount": 500, "currency": "USD"})


@_n
def n_duplicate_constraint(r):
    r["constraints"].append(copy.deepcopy(random.choice(r["constraints"])))


WIDENINGS = [   # (name, fn(r), expected (state, reason) in the reasons)
    ("amount_max", lambda r: r["constraints"][ci(r, "payment.amount_range")].update(max=20001), ("contradicted", "constraint_widened")),
    ("amount_min", lambda r: r["constraints"][ci(r, "payment.amount_range")].pop("min"), ("contradicted", "constraint_widened")),
    ("budget", lambda r: r["constraints"][ci(r, "payment.budget")].update(max=10 ** 6), ("contradicted", "constraint_widened")),
    ("freq", lambda r: r["constraints"][ci(r, "payment.agent_recurrence")].update(frequency="DAILY"), ("contradicted", "constraint_widened")),
    ("occ", lambda r: r["constraints"][ci(r, "payment.agent_recurrence")].pop("max_occurrences"), ("contradicted", "constraint_widened")),
    ("payee", lambda r: r["constraints"][ci(r, "payment.allowed_payees")]["allowed"].append({"id": "evil"}), ("contradicted", "constraint_widened")),
    ("pisp", lambda r: r["constraints"][ci(r, "payment.allowed_pisps")]["allowed"].append({"legal_name": "E", "brand_name": "E", "domain_name": "e"}), ("contradicted", "constraint_widened")),
    ("instr", lambda r: r["constraints"][ci(r, "payment.allowed_payment_instruments")]["allowed"].append({"id": "e", "type": "card"}), ("contradicted", "constraint_widened")),
    ("exec", lambda r: r["constraints"][ci(r, "payment.execution_date")].update(not_after="2027-01-01T00:00:00Z"), ("contradicted", "constraint_widened")),
    ("ref", lambda r: r["constraints"][ci(r, "payment.reference")].update(conditional_transaction_id="B" * 43), ("contradicted", "constraint_widened")),
    ("drop", lambda r: r["constraints"].pop(random.randrange(len(RICH["constraints"]))), ("contradicted", "constraint_removed")),
    ("exp", lambda r: r.update(exp=RICH["exp"] + 1), ("contradicted", "time_widened")),   # relative to O, not to a narrowed R
    ("noexp", lambda r: r.pop("exp"), ("contradicted", "time_widened")),
    ("cnf", lambda r: r.update(cnf={"jwk": K2.jwk}), ("contradicted", "cnf_differs")),
]


def _shuffle(r):
    random.shuffle(r["constraints"])
    for c in r["constraints"]:
        if isinstance(c.get("allowed"), list):
            random.shuffle(c["allowed"])
    return {k: r[k] for k in random.sample(list(r), len(r))}


def _paths(node, path=()):
    """Every object in `node` with its path (the places an unknown key can go)."""
    if isinstance(node, dict):
        yield path, node
        for k, v in node.items():
            yield from _paths(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _paths(v, path + (i,))


def _expected_for_new_key(r, path):
    """SPEC §11.4, written from the text: what an unknown key at `path` of R's Mandate Content does."""
    if path == ():
        return ("not_evaluated", "unknown_name")
    if path[0] == "cnf":
        return ("contradicted", "cnf_differs")
    if path[0] in ("payee", "payment_amount", "payment_instrument", "pisp", "risk_data"):
        return ("contradicted", "preset_changed")
    if path[0] == "constraints":
        con = r["constraints"][path[1]]
        if len(path) == 2:
            return ("not_evaluated", "unknown_name")
        if path[2] == "allowed":
            return ("contradicted", "constraint_widened")
        if path[2] == "items" and len(path) == 4:
            return ("not_evaluated", "unknown_name")
        if path[2] == "items" and path[4] == "acceptable_items":
            return ("contradicted", "constraint_widened")
        raise AssertionError((con, path))
    raise AssertionError(path)


HOSTILE_KEYS = ["x", "__proto__", "constructor", "", "MAX", "Type", "max ", "é", "\u0000", "ｍａｘ", "io.github.robertolocatelli81.restricts2"]
HOSTILE_VALUES = [None, True, False, 0, -1, 2 ** 53 - 1, "", "x", "20000", [], [1], {}, {"a": 1}]


def _leaves(node, path=()):
    """(path, value) of every key of every object (lists by index)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path + (k,), v
            yield from _leaves(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield path + (i,), v
            yield from _leaves(v, path + (i,))


def _set(r, path, value):
    for p in path[:-1]:
        r = r[p]
    r[path[-1]] = value


def _same_type(a, b):
    return type(a) is type(b)


class TestGenerative(unittest.TestCase):
    SEED = 20261028

    @classmethod
    def setUpClass(cls):
        cls.o_rich, cls.o_chk = issue(RICH), issue(CHK2)

    def r(self, content, top=None, **kw):
        return direct(self.o_rich, restrict(self.o_rich, content, top, **kw))

    def test_random_narrowings_are_verified(self):
        random.seed(self.SEED)
        n = 0
        for _ in range(400):
            r = copy.deepcopy(RICH)
            for _name, f in random.sample(NARROWINGS, random.randint(1, len(NARROWINGS))):
                f(r)
            r = _shuffle(r)
            res = self.r(r, sd_arrays=random.random() < 0.5)
            self.assertEqual(res["state"], "verified", (res, r))
            n += 1
        self.assertEqual(n, 400)

    def test_one_widening_among_narrowings_is_never_verified(self):
        random.seed(self.SEED + 1)
        for name, f, expect in WIDENINGS:
            for _ in range(25):
                r = copy.deepcopy(RICH)
                ops = random.sample(NARROWINGS, random.randint(0, 4))
                for _n2, g in ops:
                    if _n2 not in ("n_duplicate_constraint", "n_add_constraint"):   # a copy of the original constraint would mask the drop
                        g(r)
                f(r)
                r = _shuffle(r)
                res = self.r(r, sd_arrays=random.random() < 0.5)
                with self.subTest(widening=name):
                    self.assertNotEqual(res["state"], "verified", (name, r))
                    self.assertIn(expect, why(res), (name, res))

    def test_an_unknown_key_at_every_level(self):
        count = 0
        for base, o in ((RICH, self.o_rich), (CHK2, self.o_chk)):
            for path, obj in list(_paths(base)):
                for k in HOSTILE_KEYS:
                    if k in obj:
                        continue
                    r = copy.deepcopy(base)
                    target = r
                    for p in path:
                        target = target[p]
                    target[k] = 1
                    res = direct(o, restrict(o, r))
                    exp = _expected_for_new_key(r, path)
                    with self.subTest(path=path, key=k):
                        self.assertNotEqual(res["state"], "verified")
                        self.assertEqual(res["state"], exp[0], (path, k, res))
                        self.assertIn(exp, why(res), (path, k, res))
                    count += 1
        self.assertEqual(count, 284)   # the cases this bench reaches (deterministic: no randomness here)
        for k in HOSTILE_KEYS:   # the top level of the payload, beside delegate_payload
            res = direct(self.o_rich, restrict(self.o_rich, RICH, {k: 1}))
            self.assertEqual(why(res), [("not_evaluated", "unknown_name")], k)

    def test_every_key_of_another_type_is_never_verified(self):
        count = 0
        for base, o in ((RICH, self.o_rich), (CHK2, self.o_chk)):
            for path, old in list(_leaves(base)):
                for v in HOSTILE_VALUES:
                    if _same_type(v, old):
                        continue
                    r = copy.deepcopy(base)
                    _set(r, path, v)
                    res = direct(o, restrict(o, r))
                    with self.subTest(path=path, value=v):
                        self.assertNotEqual(res["state"], "verified", (path, v, res))
                    count += 1
        self.assertEqual(count, 942)

    def test_removing_any_key_is_never_verified_except_iat(self):
        for base, o in ((RICH, self.o_rich), (CHK2, self.o_chk)):
            for path, _old in list(_leaves(base)):
                if isinstance(path[-1], int):
                    continue
                r = copy.deepcopy(base)
                parent = r
                for p in path[:-1]:
                    parent = parent[p]
                del parent[path[-1]]
                res = direct(o, restrict(o, r))
                with self.subTest(path=path):
                    if path == ("iat",):
                        self.assertEqual(res["state"], "verified")
                    else:
                        self.assertNotEqual(res["state"], "verified", (path, res))

    def test_order_and_spelling_do_not_change_the_verdict(self):
        random.seed(self.SEED + 2)
        cases = [RICH] + [copy.deepcopy(RICH) for _ in range(20)]
        for r in cases[1:]:
            random.choice(NARROWINGS)[1](r)
            random.choice(WIDENINGS)[1](r)
        for r in cases:
            ref = self.r(r)
            for _ in range(5):
                again = self.r(_shuffle(copy.deepcopy(r)), sd_arrays=random.random() < 0.5)
                self.assertEqual((again["state"], why(again)), (ref["state"], why(ref)))
            esc = self.r(r, payload_text_hook=lambda t: t.replace('"delegate_payload"', '"delegate\\u005fpayload"'))   # escaped spelling
            self.assertEqual((esc["state"], why(esc)), (ref["state"], why(ref)))

    def test_constraints_of_another_shape(self):
        for v in (None, {}, "x", 1, True, {"0": EX_BUDGET}):
            r = copy.deepcopy(RICH); r["constraints"] = v
            self.assertEqual(why(self.r(r)), [("contradicted", "malformed")], v)
        for v in (None, 1, "x", [], ["payment.budget"], {"type": None}, {"type": 1}, {}):
            r = copy.deepcopy(RICH); r["constraints"].append(v)
            res = self.r(r)
            self.assertEqual(why(res), [("contradicted", "malformed")], v)


class TestPackEqualsDirect(PackCase):
    def test_the_two_paths_agree(self):
        random.seed(7)
        o = issue(RICH)
        for i in range(30):
            r = copy.deepcopy(RICH)
            random.choice(NARROWINGS)[1](r)
            if i % 2:
                random.choice(WIDENINGS)[1](r)
            rc = restrict(o, r)
            _, e = self.run_pair(o, rc)
            d = direct(o, rc)
            self.assertEqual((e["state"], e["reasons"], e["reported"]), (d["state"], d["reasons"], d["reported"]))


class TestCliAndReceipt(PackCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), *args], capture_output=True, text=True, timeout=120)

    def test_exit_codes(self):
        o = issue(PAY)
        ok = self.pack(("o", o), ("r", restrict(o, PAY)), name="ok.json")
        r = self.cli("restriction", ok)
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(r.stdout)
        self.assertEqual((rec["restriction_profile"], rec["claim"], rec["met"]), ("io.github.robertolocatelli81.restriction/1", CLAIM, True))
        self.assertEqual(set(rec), {"restriction_profile", "claim", "admission", "refusal_class", "valid", "time_anchor", "existed_by", "restrictions", "met"})
        self.assertEqual(set(rec["restrictions"][0]), {"in", "restricts", "original", "same_issuer_jwt", "state", "reasons", "reported"})
        wide = copy.deepcopy(PAY); wide["exp"] += 1
        bad = self.pack(("o", o), ("r", restrict(o, wide)), name="bad.json")
        self.assertEqual(self.cli("restriction", bad).returncode, 1)
        none = self.pack(("o", o), name="none.json")
        r = self.cli("restriction", none)
        self.assertEqual((r.returncode, json.loads(r.stdout)["restrictions"], json.loads(r.stdout)["met"]), (1, [], False))
        junk = os.path.join(self.d, "junk.json")
        with open(junk, "w") as f:
            f.write("[]")
        r = self.cli("restriction", junk)
        self.assertEqual((r.returncode, json.loads(r.stdout)["admission"]), (1, "refused"))
        for argv in (["restriction"], ["restriction", ""], ["restriction", ok, "--require-anchor"], ["restriction", ok, "--tsa-cert"],
                     ["restriction", ok, "--tsa-cert", os.path.join(self.d, "missing.pem")], ["restriction", ok, ok], ["restriction", "--help"]):
            with self.subTest(argv=argv):
                r = self.cli(*argv)
                self.assertEqual((r.returncode, r.stdout), (2, ""), r.stderr)

    def test_the_pack_is_read_once_and_verified_as_a_private_copy(self):
        o = issue(PAY)
        p = self.pack(("o", o), ("r", restrict(o, PAY)))
        seen = []
        real = ap2.verify_evidence

        def spy(path, **kw):
            seen.append(path)
            return real(path, **kw)
        with mock.patch.object(ap2, "verify_evidence", spy):
            rec = ap2.verify_restrictions(p)
        self.assertTrue(rec["met"])
        self.assertEqual(len(seen), 1)
        self.assertNotEqual(os.path.abspath(seen[0]), os.path.abspath(p))
        self.assertFalse(os.path.exists(seen[0]))   # removed afterwards

    def test_a_check_not_run_here_carries_the_restriction_receipt(self):
        o = issue(PAY)
        p = self.pack(("o", o), ("r", restrict(o, PAY)))
        real = ap2.verify_evidence

        def failing(path, **kw):
            rec = real(path, **kw)
            raise ap2.Ap2WriteError("openssl did not answer", receipt=rec)
        with mock.patch.object(ap2, "verify_evidence", failing):
            with self.assertRaises(ap2.Ap2WriteError) as cm:
                ap2.verify_restrictions(p)
        self.assertEqual(cm.exception.receipt["restriction_profile"], "io.github.robertolocatelli81.restriction/1")
        self.assertEqual(cm.exception.receipt["restrictions"][0]["state"], "verified")

    @unittest.skipUnless(HAVE_OPENSSL, "openssl absent: the local TSA cannot run")
    def test_existed_by_needs_a_tsa_verified_anchor(self):
        from test_ap2_anchors import LocalTSA
        tsa = LocalTSA(self.d, "tsaR")
        o = issue(PAY)
        out = os.path.join(self.d, "anch.json")
        with mock.patch.object(ap2, "_rfc3161_stamp", lambda digest, url, timeout=20: tsa.stamp(digest, url)):
            ap2.build_evidence([{"name": "o", "sd_jwt": o}, {"name": "r", "sd_jwt": restrict(o, PAY)}], out, tsa_url="https://tsa.example")
        rec = ap2.verify_restrictions(out)
        self.assertEqual((rec["met"], rec["existed_by"], rec["time_anchor"]["reasons"]), (True, None, ["tsa_not_checked"]))
        rec = ap2.verify_restrictions(out, tsa_cert=tsa.crt)
        self.assertTrue(rec["met"])
        self.assertEqual(rec["time_anchor"]["state"], "verified")
        self.assertRegex(rec["existed_by"], r"^[0-9]{14}Z$")
        other = LocalTSA(self.d, "tsaOther")
        rec = ap2.verify_restrictions(out, tsa_cert=other.crt)
        self.assertEqual((rec["existed_by"], rec["time_anchor"]["reasons"]), (None, ["tsa_invalid"]))


if __name__ == "__main__":
    unittest.main()
