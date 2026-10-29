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
REF = "io.github.robertolocatelli81.restricts"   # SPEC §11.1: the constraint type of the reference

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


def issue(content, top=None, key=K1, sd_arrays=True, form="delegate", decoy=False, payload_text_hook=None, hide_ref=None):
    discs = []
    c = _hide_arrays(content, discs) if sd_arrays else copy.deepcopy(content)
    if hide_ref and isinstance(c, dict) and isinstance(c.get("constraints"), list):
        for j, x in enumerate(c["constraints"]):
            if isinstance(x, dict) and x.get("type") == REF:
                if hide_ref == "element":   # the whole reference an array-element disclosure (SPEC §11.3 step 2)
                    d = _disc(x)
                    c["constraints"][j] = {"...": ap2._disclosure_digest(d)}
                else:                       # one key of the reference a property disclosure
                    d = _disc(hide_ref, x[hide_ref])
                    c["constraints"][j] = dict({k: v for k, v in x.items() if k != hide_ref}, _sd=[ap2._disclosure_digest(d)])
                discs.append(d)
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


def with_ref(content, value, extra=None):
    """`content` with the reference of SPEC §11.1 appended to its `constraints` (created when absent; left alone when it
    is not a list — such a token is then no record, and only the direct path evaluates it)."""
    c = copy.deepcopy(content)
    ref = dict({"type": REF, "issuer_jwt_hash": value}, **(extra or {}))
    if isinstance(c, dict):
        if "constraints" not in c:
            c["constraints"] = []
        if isinstance(c["constraints"], list):
            c["constraints"].append(ref)
    return c


def restrict(orig_compact, content, top=None, **kw):
    return issue(with_ref(content, ap2.issuer_jwt_hash(orig_compact)), top, **kw)


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


PRESET = copy.deepcopy(PAY)   # pre-set values (agent_authorization.md rule 2), from the closed mandate example of payment_mandate.md
PRESET.update(payee={"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"},
              payment_amount={"amount": 19900, "currency": "USD"}, payment_instrument={"id": "stub", "type": "card", "description": "Card ••••4242"},
              risk_data={"device": "trusted-surface"})


def ci(content, t):
    """The index of the first constraint of type t."""
    return next(i for i, c in enumerate(content["constraints"]) if isinstance(c, dict) and c.get("type") == t)


class TestOfficialExamples(unittest.TestCase):
    def test_tokens_are_the_documentation_bytes_and_decode_fully(self):
        self.assertEqual(hashlib.sha256(AP2_PAY_OPEN.encode()).hexdigest(), AP2_PAY_OPEN_SHA256)
        self.assertEqual(hashlib.sha256(AP2_CHK_OPEN.encode()).hexdigest(), AP2_CHK_OPEN_SHA256)
        for tok, vct in ((AP2_PAY_OPEN, "mandate.payment.open.1"), (AP2_CHK_OPEN, "mandate.checkout.open.1")):
            p = ap2.parse_sd_jwt(tok)
            self.assertEqual(ap2._digest_census(p), 0)
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
            self.assertEqual(ap2._digest_census(p), 0)


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
                rec, e = self.run_pair(o, issue(with_ref(PAY, bad)))
                self.assertEqual(why(e), [("contradicted", "restricts_malformed")])
                self.assertEqual(e["restricts"], bad if isinstance(bad, str) else None)

    def test_a_non_canonical_spelling_of_the_hash_is_malformed(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        bad = h[:-1] + alphabet[alphabet.index(h[-1]) ^ 1]   # same 32 bytes, a trailing bit set: §3.1 refuses the spelling
        self.assertEqual(base64.urlsafe_b64decode(bad + "="), base64.urlsafe_b64decode(h + "="))
        rec, e = self.run_pair(o, issue(with_ref(PAY, bad)))
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
        dup = restrict(o, PAY, payload_text_hook=lambda t: t[:-1] + ', "_sd_alg": "sha-256"}')   # a key twice
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
        rec, e = self.run_pair(o, issue(with_ref(PAY, flipped)))
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
        """RFC 9901 §7.1 step 4 — 1.7.0: §6 step 2 refuses the artifact (the 1.6.0 resolver did not, measured 2026-10-28), so
        such a pack is never built; the profile's step 5 reads the resolver's census and, called directly, says malformed."""
        def twice(text):
            pl = json.loads(text)
            pl["delegate_payload"].append(dict(pl["delegate_payload"][0]))
            return json.dumps(pl)
        o = issue(PAY)
        r_twice = restrict(o, PAY, payload_text_hook=twice)
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "more than once"):
            self.pack(("original", o), ("restriction", r_twice))
        o2 = issue(PAY, payload_text_hook=twice)
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "more than once"):
            self.pack(("original", o2), ("restriction", restrict(o2, PAY)))
        self.assertFalse(os.path.exists(os.path.join(self.d, "p.json")))
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "more than once"):
            ap2._digest_census(ap2.parse_sd_jwt(r_twice))
        # the direct call (bypassing §6): step 5, before `resolved` is read
        art = lambda c: {"parsed": ap2.parse_sd_jwt(c), "resolved": None, "jwk": K1.jwk}   # noqa: E731
        self.assertEqual(why(ap2.evaluate_restriction(art(o), art(r_twice))), [("contradicted", "malformed")])
        self.assertEqual(why(ap2.evaluate_restriction(art(o2), art(restrict(o2, PAY)))), [("not_evaluated", "original_malformed")])
        # positive control of the census: the same tokens without the repeat have no hidden digest
        self.assertEqual((ap2._digest_census(ap2.parse_sd_jwt(o)), ap2._digest_census(ap2.parse_sd_jwt(restrict(o, PAY)))), (0, 0))

    def test_a_pack_sealed_by_other_means_around_a_repeated_record_is_not_valid_and_holds_no_record(self):
        """SPEC §11.3 step 5 (1.7.0): `build_evidence` refuses such a token, so the pack is assembled from parts (as 1.6.0 built
        it, `resolved_claims` as recorded then): §6 says not valid, the token is read as no record (its content cannot be
        resolved), and another record of the same pack is `pack_not_valid`. Measured on 54dd18e: `valid: true` and the
        record judged (`restricts_malformed`)."""
        sys.path.insert(0, os.path.join(_HERE, "spec", "vectors", "ap2")); import make_vectors_closed_schema as cs  # noqa: E402,PLC0415

        def twice(text):
            pl = json.loads(text)
            pl["delegate_payload"].append(dict(pl["delegate_payload"][0]))
            return json.dumps(pl)

        def art(name, compact, resolved):
            p = ap2.parse_sd_jwt(compact)
            return cs._artifact(name, compact, p["header"], p["header"]["jwk"], resolved, False)
        o = issue(PAY)
        r_twice = restrict(o, PAY, payload_text_hook=twice)
        content, content_r = _official(o), _official(restrict(o, PAY))   # what 1.6.0 resolved: R's content (with the reference) twice
        scope = cs._load("valid_signed")["honest_scope"]
        for arts in ([art("original", o, {"delegate_payload": [content]}), art("restriction", r_twice, {"delegate_payload": [content_r, content_r]})],
                     [art("original", o, {"delegate_payload": [content]}), art("restriction", r_twice, {"delegate_payload": [content_r, content_r]}),
                      art("second", restrict(o, PAY), {"delegate_payload": [content_r]})]):
            path = os.path.join(self.d, "parts.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cs._pack(scope, "sealed by other means", arts), f)
            v = ap2.verify_evidence(path)
            self.assertEqual((v["admission"], v["valid"]), ("admitted", False))
            self.assertIn("more than once", v["artifacts"][1]["error"])
            rec = ap2.verify_restrictions(path)
            self.assertEqual((rec["valid"], rec["met"]), (False, False))
            self.assertEqual([e["in"] for e in rec["restrictions"]], ["second"] if len(arts) == 3 else [])
            if len(arts) == 3:
                self.assertEqual(why(rec["restrictions"][0]), [("not_evaluated", "pack_not_valid")])

    def test_forms(self):
        o = issue(PAY)
        rec, e = self.run_pair(o, restrict(o, PAY, form="payload"))
        self.assertEqual(why(e), [("not_evaluated", "form_differs")])
        pr = with_ref(PAY, ap2.issuer_jwt_hash(o))
        for dp in ([pr, PAY], [PAY, pr], [pr, "x"], [pr, 7]):   # the reference in an element: a record, form_unsupported
            with self.subTest(dp=dp):
                bad = K1.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": K1.jwk}, json.dumps({"delegate_payload": dp})) + "~"
                rec, e = self.run_pair(o, bad)
                self.assertEqual(why(e), [("not_evaluated", "form_unsupported")])
        for dp in ([], ["x"], {}, "x", None, [[pr]], pr):   # no Mandate Content that can hold the reference: not a record
            with self.subTest(dp=dp):
                bad = K1.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": K1.jwk}, json.dumps({"delegate_payload": dp})) + "~"
                rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", bad), name="nr.json"))
                self.assertEqual((rec["valid"], rec["restrictions"], rec["met"]), (True, [], False))


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
        # `constraints` not a list: the reference cannot be in it, so the token is no record (SPEC §11.2); the direct path
        # still reads it as malformed
        o = issue(RICH)
        r = copy.deepcopy(RICH); r["constraints"] = {"0": RICH["constraints"][0]}
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", restrict(o, r)), name="nl.json"))
        self.assertEqual((rec["valid"], rec["restrictions"]), (True, []))
        self.assertEqual(why(direct(o, restrict(o, r))), [("contradicted", "malformed")])

    def test_vct(self):
        self.check(PAY, lambda r: r.update(vct="mandate.checkout.open.1"), [("contradicted", "claim_changed")])
        closed = {"vct": "mandate.payment.1", "transaction_id": "t", "payment_amount": {"amount": 1, "currency": "USD"}}
        # a closed mandate has no `constraints`: the record adds one to carry the reference, so it is never an equal copy
        self.check(closed, lambda r: None, [("not_evaluated", "vct_not_supported")])
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
        cls.o_rich, cls.o_chk, cls.o_pre = issue(RICH), issue(CHK2), issue(PRESET)
        cls.bases = ((RICH, cls.o_rich), (CHK2, cls.o_chk), (PRESET, cls.o_pre))

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
        for base, o in self.bases:
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
        self.assertEqual(count, 404)   # the cases this bench reaches (deterministic: no randomness here)
        for k in HOSTILE_KEYS:   # the top level of the payload, beside delegate_payload
            res = direct(self.o_rich, restrict(self.o_rich, RICH, {k: 1}))
            self.assertEqual(why(res), [("not_evaluated", "unknown_name")], k)

    def test_every_key_of_another_type_is_never_verified(self):
        count = 0
        for base, o in self.bases:
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
        self.assertEqual(count, 1334)

    def test_removing_any_key_is_never_verified_except_iat(self):
        for base, o in self.bases:
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
        self.assertEqual((rec["restriction_profile"], rec["constraint_type"], rec["met"]), ("io.github.robertolocatelli81.restriction/1", REF, True))
        self.assertEqual(set(rec), {"restriction_profile", "constraint_type", "admission", "refusal_class", "valid", "time_anchor", "existed_by", "restrictions", "met"})
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



class TestMutantGaps(PackCase):
    """Cases added after the first mutation run (the survivors that were gaps, not equivalents)."""

    def check(self, base, mutate, expect, o_mutate=None):
        ob = copy.deepcopy(base)
        if o_mutate:
            o_mutate(ob)
        o = issue(ob)
        r = copy.deepcopy(base)
        mutate(r)
        rec, e = self.run_pair(o, restrict(o, r))
        self.assertEqual(why(e), expect, e)
        return e

    def test_line_items_shapes_in_the_record(self):
        M = [("contradicted", "malformed")]
        self.check(CHK2, lambda r: r["constraints"].append({"type": "checkout.line_items", "items": []}), M)
        self.check(CHK2, lambda r: r["constraints"].append({"type": "checkout.line_items", "items": [1]}), M)
        self.check(CHK2, lambda r: r["constraints"].append({"type": "checkout.line_items", "items": [
            {"id": "a", "acceptable_items": [], "quantity": 0}]}), M)

    def test_dates_of_an_unsupported_form_on_both_sides(self):
        i = ci(RICH, "payment.execution_date")
        D = [("not_evaluated", "date_form")]
        self.check(RICH, lambda r: r["constraints"][i].update(not_after="later"), D,
                   o_mutate=lambda o: o["constraints"][i].update(not_after="soon"))
        self.check(RICH, lambda r: r["constraints"][i].update(not_before="2026-03-30T23:00:00Z", not_after="2026-04-02"), D,
                   o_mutate=lambda o: o["constraints"][i].update(not_before="2026-03-31", not_after="2026-04-30"))

    def test_line_items_with_one_entry_not_an_object(self):
        good = {"id": "a", "acceptable_items": [], "quantity": 1}
        self.check(CHK2, lambda r: r["constraints"].append({"type": "checkout.line_items", "items": [good, 1]}), [("contradicted", "malformed")])

    def test_invalid_calendar_dates_on_both_sides(self):
        i = ci(RICH, "payment.execution_date")
        self.check(RICH, lambda r: r["constraints"][i].update(not_after="2026-02-30T00:00:00Z"), [("not_evaluated", "date_form")],
                   o_mutate=lambda o: o["constraints"][i].update(not_after="2026-02-31T00:00:00Z"))

    def test_a_window_with_one_bound(self):
        i = ci(RICH, "payment.execution_date")
        one = lambda c: c["constraints"][i].pop("not_before")   # noqa: E731
        self.check(RICH, one, [], o_mutate=one)
        self.check(RICH, lambda r: r["constraints"][i].update(not_after="2026-04-01T00:00:00Z"), [], o_mutate=one)

    def test_cli_receipt_not_written_after_a_check_not_run(self):
        import contextlib
        import io
        o = issue(PAY)
        p = self.pack(("o", o), ("r", restrict(o, PAY)))
        real = ap2.verify_evidence

        def with_receipt(path, **kw):
            raise ap2.Ap2WriteError("openssl did not answer", receipt=real(path, **kw))
        err = io.StringIO()
        with mock.patch.object(ap2, "verify_evidence", with_receipt), mock.patch.object(ap2, "_emit", lambda text: "stdout full"), \
                contextlib.redirect_stderr(err):
            rc = ap2.main(["restriction", p])
        self.assertEqual(rc, 74)
        self.assertIn("receipt not written: stdout full", err.getvalue())

    def test_the_original_malformed(self):
        OM = [("not_evaluated", "original_malformed")]
        self.check(PAY, lambda r: r.update(exp=1), OM, o_mutate=lambda o: o.update(exp="1777345957"))
        self.check(PAY, lambda r: r.update(iat=1), OM, o_mutate=lambda o: o.update(iat="1"))
        self.check(PAY, lambda r: r.update(constraints=[]), OM, o_mutate=lambda o: o.update(constraints={"a": 1}))

    def test_the_original_in_an_unsupported_form(self):
        for dp in ([], [PAY, PAY], "x"):
            with self.subTest(dp=dp):
                o = K1.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": K1.jwk}, json.dumps({"delegate_payload": dp})) + "~"
                rec, e = self.run_pair(o, restrict(o, PAY))
                self.assertEqual(e["reasons"], [{"state": "not_evaluated", "reason": "form_unsupported", "at": "original"}])

    def test_keys_that_are_not_objects(self):
        o = issue(PAY)
        p = ap2.parse_sd_jwt(o)
        art = {"parsed": p, "resolved": ap2.resolve_disclosures(p["payload"], p["disclosures"]), "jwk": None}
        self.assertEqual(why(ap2.evaluate_restriction(art, dict(art, jwk=K1.jwk))), [("contradicted", "issuer_key_differs")])
        self.assertEqual(why(ap2.evaluate_restriction(dict(art, jwk=K1.jwk), art)), [("contradicted", "issuer_key_differs")])

    def test_one_constraint_of_the_record_unknown_another_wider(self):
        i = ci(RICH, "payment.amount_range")
        e = self.check(RICH, lambda r: r["constraints"].__setitem__(slice(i, i + 1), [dict(r["constraints"][i], max=10 ** 6), dict(r["constraints"][i], max=1, note="x")]),
                       [("not_evaluated", "unknown_name")])
        self.assertEqual(e["state"], "not_evaluated")

    def test_paths_name_the_place(self):
        n = len(PAY["constraints"])
        e = self.check(PAY, lambda r: r["constraints"].extend([copy.deepcopy(EX_BUDGET), {"type": "payment.budget", "currency": "USD", "max": "1"}]),
                       [("contradicted", "malformed")])
        self.assertEqual(e["reasons"][0]["at"], f"restriction.delegate_payload[0].constraints[{n + 1}].max")
        e = self.check(PAY, lambda r: r.update(exp=r["exp"] + 1), [("contradicted", "time_widened")])
        self.assertEqual(e["reasons"][0]["at"], "restriction.delegate_payload[0].exp")

    def test_states_of_the_early_outcomes(self):
        o = issue(PAY)
        rec, e = self.run_pair(o, issue(with_ref(PAY, 7)))
        self.assertEqual((e["state"], e["original"]), ("contradicted", None))
        p = self.pack(("original", o), ("restriction", restrict(o, PAY)), name="t.json")
        with open(p, encoding="utf-8") as f:
            ev = json.load(f)
        ev["subject"] = "altered"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(ev, f)
        e = ap2.verify_restrictions(p)["restrictions"][0]
        self.assertEqual((e["state"], e["original"], e["same_issuer_jwt"]), ("not_evaluated", None, []))
        rec, e = self.run_pair(o, issue(with_ref(PAY, ap2.issuer_jwt_hash(issue(CHK)))))
        self.assertEqual((e["state"], e["original"]), ("not_evaluated", None))

    def test_a_chain_listed_backwards_is_demoted_whole(self):
        o = issue(RICH)
        i = ci(RICH, "payment.amount_range")
        wide = copy.deepcopy(RICH); wide["constraints"][i]["max"] = 10 ** 6
        r1 = restrict(o, wide); r2 = restrict(r1, wide); r3 = restrict(r2, wide)
        rec = ap2.verify_restrictions(self.pack(("r3", r3), ("r2", r2), ("r1", r1), ("o", o)))
        self.assertEqual([(e["in"], e["state"]) for e in rec["restrictions"]],
                         [("r3", "not_evaluated"), ("r2", "not_evaluated"), ("r1", "contradicted")])

    def test_met_needs_every_record(self):
        o = issue(PAY)
        wide = copy.deepcopy(PAY); wide["exp"] += 1
        rec = ap2.verify_restrictions(self.pack(("o", o), ("good", restrict(o, PAY)), ("bad", restrict(o, wide))))
        self.assertEqual([e["state"] for e in rec["restrictions"]], ["verified", "contradicted"])
        self.assertFalse(rec["met"])

    def test_a_check_not_run_here_without_a_receipt_propagates(self):
        o = issue(PAY)
        p = self.pack(("o", o), ("r", restrict(o, PAY)))

        def failing(path, **kw):
            raise ap2.Ap2WriteError("no temporary file", receipt=None)
        with mock.patch.object(ap2, "verify_evidence", failing):
            with self.assertRaises(ap2.Ap2WriteError) as cm:
                ap2.verify_restrictions(p)
        self.assertIsNone(cm.exception.receipt)

    def test_cli_exit_74_paths(self):
        import contextlib
        import io
        o = issue(PAY)
        p = self.pack(("o", o), ("r", restrict(o, PAY)))
        real = ap2.verify_evidence

        def with_receipt(path, **kw):
            raise ap2.Ap2WriteError("openssl did not answer", receipt=real(path, **kw))

        def without(path, **kw):
            raise ap2.Ap2WriteError("no temporary file", receipt=None)
        for fake, has_receipt, line in ((with_receipt, True, "check not run here: openssl did not answer"),
                                        (without, False, "receipt not written: no temporary file")):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(ap2, "verify_evidence", fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = ap2.main(["restriction", p])
            self.assertEqual(rc, 74)
            self.assertIn(line, err.getvalue())
            if has_receipt:
                self.assertEqual(json.loads(out.getvalue())["restrictions"][0]["state"], "verified")
            else:
                self.assertEqual(out.getvalue(), "")
        with open(os.devnull, "w") as dn, open("/dev/full", "w") as full:   # the receipt cannot be written: 74
            r = subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "restriction", p], stdout=full, stderr=subprocess.PIPE, text=True, timeout=120)
        self.assertEqual(r.returncode, 74, r.stderr)
        self.assertIn("receipt not written", r.stderr)

    def test_cli_grammar_more(self):
        o = issue(PAY)
        p = self.pack(("o", o), ("r", restrict(o, PAY)))
        for argv in (["restriction", p, "--tsa-cert", self.d], ["restriction", p, "--tsa-c", p], ["restriction", p, "--tsa-cert="]):
            with self.subTest(argv=argv):
                r = subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), *argv], capture_output=True, text=True, timeout=120)
                self.assertEqual((r.returncode, r.stdout), (2, ""), r.stderr)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl absent: the local TSA cannot run")
    # NEMESIS 2026-10-28 — four gaps the mutation run left open (mutants 300, and three of the reviewer's own)
    def test_the_original_constraints_not_iterable_is_original_malformed_not_a_crash(self):
        """Mutant 300 (`return done()` removed after `original_malformed` on a non-list `constraints` of O) crashed on null/5/true;
        the suite had only an iterable `{"a": 1}`."""
        for v in (None, 5, True, "abc", {"a": 1}):
            o = copy.deepcopy(RICH); o["constraints"] = v
            oc = issue(o)
            with self.subTest(constraints=v):
                self.assertEqual(why(direct(oc, restrict(oc, RICH))), [("not_evaluated", "original_malformed")])

    def test_dates_with_non_ascii_digits_are_another_form_in_both_forms(self):
        """SPEC §11.4: ASCII digits. With `\\d` the regex and strptime accept Arabic-Indic / fullwidth digits, and a string
        comparison then reads an EARLIER not_before as later (verified where it is broader)."""
        base = copy.deepcopy(RICH); i = ci(base, "payment.execution_date")
        for form, nb, na in (("date", "2026-03-31", "2026-04-30"), ("datetime", "2026-03-31T00:00:00Z", "2026-04-30T23:59:59Z")):
            o = copy.deepcopy(base); o["constraints"][i].update(not_before=nb, not_after=na); oc = issue(o)
            for digits in ("\u0662\u0660\u0662\u0666", "\uff12\uff10\uff12\uff16"):   # ٢٠٢٦ and ２０２６
                r = copy.deepcopy(o); r["constraints"][i]["not_before"] = digits + nb[4:].replace("31", "30")
                with self.subTest(form=form, digits=digits):
                    res = direct(oc, restrict(oc, r))
                    self.assertEqual(why(res), [("not_evaluated", "date_form")], res)

    def test_frequency_order_every_adjacent_pair(self):
        """SPEC §11.4: the whole order, pair by pair (a swap of two neighbours survived the author's tests)."""
        order = ("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY")
        self.assertEqual(ap2._FREQ_ORDER, order)
        base = copy.deepcopy(RICH); i = ci(base, "payment.agent_recurrence")
        for a, b in zip(order, order[1:]):
            o = copy.deepcopy(base); o["constraints"][i]["frequency"] = b; oc = issue(o)
            r = copy.deepcopy(o); r["constraints"][i]["frequency"] = a
            with self.subTest(more_frequent=a, original=b):
                self.assertEqual(why(direct(oc, restrict(oc, r))), [("contradicted", "constraint_widened")])
            o = copy.deepcopy(base); o["constraints"][i]["frequency"] = a; oc = issue(o)
            r = copy.deepcopy(o); r["constraints"][i]["frequency"] = b
            with self.subTest(less_frequent=b, original=a):
                self.assertEqual(direct(oc, restrict(oc, r))["state"], "verified")

    def test_a_constraint_of_the_original_that_is_not_an_object_copied_equal(self):
        """An equal copy meets any constraint of O, an object or not (a shortcut by `type` would crash on a string)."""
        o = copy.deepcopy(RICH); o["constraints"] += ["x", 5, None, ["y"]]; oc = issue(o)
        self.assertEqual(direct(oc, restrict(oc, copy.deepcopy(o)))["state"], "verified")
        r = copy.deepcopy(o); r["constraints"].remove("x")
        self.assertEqual(why(direct(oc, restrict(oc, r))), [("not_evaluated", "original_malformed")])

    def test_a_changed_vct_ends_the_evaluation(self):
        """Mutant 283 (`return done()` removed after `claim_changed` on `vct`): same state, but the receipt would then also list
        the content rules. The receipt lists exactly one reason."""
        r = copy.deepcopy(RICH); r["vct"] = "mandate.checkout.open.1"; r["constraints"][ci(r, "payment.amount_range")]["max"] = 10**9
        o = issue(RICH)
        res = direct(o, restrict(o, r))
        self.assertEqual([(x["state"], x["reason"]) for x in res["reasons"]], [("contradicted", "claim_changed")])

    def test_existed_by_is_the_earliest_counting_anchor_in_anchors_too(self):
        import time
        from test_ap2_anchors import LocalTSA
        a, b = LocalTSA(self.d, "tsaA"), LocalTSA(self.d, "tsaB")
        by = {"https://a.example": a, "https://b.example": b}
        o = issue(PAY)
        out = os.path.join(self.d, "two.json")

        def stamp(digest, url, timeout=20):
            time.sleep(1.1)   # distinct genTime seconds
            return by[url].stamp(digest, url)
        with mock.patch.object(ap2, "_rfc3161_stamp", stamp):   # no rfc3161_timestamp block: both tokens go to `anchors`
            ap2.build_evidence([{"name": "o", "sd_jwt": o}, {"name": "r", "sd_jwt": restrict(o, PAY)}], out)
            ap2.add_anchor(out, "https://a.example")
            ap2.add_anchor(out, "https://b.example")
        bundle = os.path.join(self.d, "bundle.pem")
        with open(bundle, "wb") as f:
            for t in (a, b):
                with open(t.crt, "rb") as g:
                    f.write(g.read())
        rec = ap2.verify_restrictions(out, tsa_cert=bundle)
        times = sorted(x["gen_time"] for x in ap2.verify_evidence(out, tsa_cert=bundle)["anchors"])
        self.assertEqual(len(set(times)), 2)
        self.assertEqual((rec["met"], rec["existed_by"]), (True, times[0]))


class TestSecondReview(PackCase):
    def test_a_key_with_the_same_x_and_the_opposite_y_is_another_key(self):
        """SPEC §11.3 step 4 compares kty, crv, x AND y. The point (x, p - y) is -P: a valid P-256 public key (private scalar
        n - d) with the same `x` as the original's and the opposite `y`. A record signed by it verifies under its own
        snapshotted key, so the pack is valid, and the record is `issuer_key_differs` — a comparison on x alone would bind it."""
        n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)   # order of P-256 (FIPS 186-4 D.1.2.3)
        neg = Key()
        neg.sk = ec.derive_private_key(n - K1.sk.private_numbers().private_value, ec.SECP256R1())
        nn = neg.sk.public_key().public_numbers()
        neg.jwk = {"kty": "EC", "crv": "P-256", "x": _b64u(nn.x.to_bytes(32, "big")), "y": _b64u(nn.y.to_bytes(32, "big"))}
        self.assertEqual(neg.jwk["x"], K1.jwk["x"])
        self.assertNotEqual(neg.jwk["y"], K1.jwk["y"])
        o = issue(PAY)
        rec, e = self.run_pair(o, restrict(o, PAY, key=neg))
        self.assertTrue(rec["valid"], rec)
        self.assertEqual(why(e), [("contradicted", "issuer_key_differs")])
        self.assertFalse(rec["met"])


class TestReferenceAsConstraint(PackCase):
    """SPEC §11.1 (draft change 2026-10-28): the reference is a constraint of this profile's type in the Mandate Content —
    exactly one, exactly two keys, a plain element of the signed list — so an AP2 verifier that does not know the profile
    fails it instead of reading a second mandate. Every other shape of the reference is contradicted, through the pack."""

    def entry(self, o, r, name="rc.json"):
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name=name))
        self.assertTrue(rec["valid"], rec)
        self.assertEqual(len(rec["restrictions"]), 1, rec)
        return rec["restrictions"][0]

    def test_the_reference_lives_in_the_mandate_content_and_is_not_a_term(self):
        o = issue(RICH)
        r = restrict(o, RICH)
        p = ap2.parse_sd_jwt(r)
        res = ap2.resolve_disclosures(p["payload"], p["disclosures"])
        self.assertNotIn(REF, res)
        self.assertEqual(ap2._mandate_form(res)[1]["constraints"][-1], {"type": REF, "issuer_jwt_hash": ap2.issuer_jwt_hash(o)})
        e = self.entry(o, r)
        self.assertEqual((e["state"], e["reported"], e["restricts"]), ("verified", [], ap2.issuer_jwt_hash(o)))
        for form in ("delegate", "payload"):
            oo = issue(PAY, form=form)
            self.assertEqual(self.entry(oo, restrict(oo, PAY, form=form), name=form + ".json")["state"], "verified", form)

    def test_any_position_of_the_reference(self):
        o = issue(RICH)
        for j in range(len(RICH["constraints"]) + 1):
            c = copy.deepcopy(RICH)
            c["constraints"].insert(j, {"type": REF, "issuer_jwt_hash": ap2.issuer_jwt_hash(o)})
            with self.subTest(position=j):
                self.assertEqual(self.entry(o, issue(c), name=f"pos{j}.json")["state"], "verified")

    def test_the_first_drafts_top_level_claim_is_misplaced(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        for r in (issue(PAY, {REF: h}), restrict(o, PAY, {REF: h})):
            with self.subTest():
                e = self.entry(o, r, name="mis.json")
                self.assertEqual(e["reasons"], [{"state": "contradicted", "reason": "restricts_misplaced", "at": "restriction." + REF}])
        payload_form = issue(dict(with_ref(PAY, h), **{REF: h}), form="payload")
        self.assertEqual(why(self.entry(o, payload_form, name="mis2.json")), [("contradicted", "restricts_misplaced")])

    def test_not_exactly_one_reference(self):
        o, o2 = issue(PAY), issue(CHK)
        h = ap2.issuer_jwt_hash(o)
        n = len(PAY["constraints"])
        for second in (h, ap2.issuer_jwt_hash(o2), "x"):
            c = with_ref(with_ref(PAY, h), second)
            with self.subTest(second=second):
                e = self.entry(o, issue(c), name="two.json")
                self.assertEqual(e["reasons"], [{"state": "contradicted", "reason": "restricts_malformed",
                                                 "at": f"restriction.delegate_payload[0].constraints[{n + 1}]"}])
                self.assertIsNone(e["restricts"])

    def test_the_reference_is_closed(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        M = [("contradicted", "restricts_malformed")]
        count = 0
        for k in HOSTILE_KEYS + ["Issuer_jwt_hash", "issuer_jwt_hash ", "sd_hash"]:
            with self.subTest(key=k):
                self.assertEqual(why(self.entry(o, issue(with_ref(PAY, h, {k: 1})), name="k.json")), M)
            count += 1
        for v in HOSTILE_VALUES:
            with self.subTest(value=v):
                self.assertEqual(why(self.entry(o, issue(with_ref(PAY, v)), name="v.json")), M)
            count += 1
        c = copy.deepcopy(PAY); c["constraints"].append({"type": REF})   # the hash missing
        self.assertEqual(why(self.entry(o, issue(c), name="m.json")), M)
        self.assertEqual(count, len(HOSTILE_KEYS) + 3 + len(HOSTILE_VALUES))

    def test_a_reference_the_holder_could_leave_out_is_contradicted(self):
        o = issue(PAY)
        for hide in ("element", "issuer_jwt_hash", "type"):
            with self.subTest(hide=hide):
                r = restrict(o, PAY, hide_ref=hide)
                p = ap2.parse_sd_jwt(r)
                self.assertEqual(ap2._digest_census(p), 0)   # fully disclosed: the resolved content is the same
                e = self.entry(o, r, name="h.json")
                self.assertEqual([(x["state"], x["reason"]) for x in e["reasons"]], [("contradicted", "restricts_disclosable")])
                self.assertEqual(e["reasons"][0]["at"], f"restriction.delegate_payload[0].constraints[{len(PAY['constraints'])}]")
        r = restrict(o, PAY, hide_ref="element")   # the holder drops it: what is left is no record at all
        dropped = "~".join(x for x in r.split("~") if not (x and x[0] == "W" and REF in base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).decode()))
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", dropped), name="drop.json"))
        self.assertEqual((rec["valid"], rec["restrictions"]), (True, []))

    def test_the_originals_own_reference_is_the_chain_rule_not_a_term(self):
        o = issue(RICH)
        r1 = restrict(o, RICH)
        r2 = restrict(r1, RICH)   # r2 carries only its own reference (to r1), not r1's (to o)
        rec = ap2.verify_restrictions(self.pack(("o", o), ("r1", r1), ("r2", r2)))
        self.assertEqual([(e["in"], e["state"], e["original"], e["reported"]) for e in rec["restrictions"]],
                         [("r1", "verified", "o", []), ("r2", "verified", "r1", [])])
        r2c = issue(with_ref(with_ref(RICH, ap2.issuer_jwt_hash(o)), ap2.issuer_jwt_hash(r1)))   # both references: two
        e = ap2.verify_restrictions(self.pack(("o", o), ("r1", r1), ("r2", r2c), name="c2.json"))["restrictions"][1]
        self.assertEqual(why(e), [("contradicted", "restricts_malformed")])


class TestReferenceAsConstraintReview(PackCase):
    """Review of the draft change of 2026-10-28: four mutants of the new lines that the suite above did not see (a look-alike
    type read as the reference; the order of §11.3 step 2; `constraints` itself a property disclosure, with and without
    another property disclosure listed before it in `_sd`)."""

    def entry(self, o, r, name):
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name=name))
        self.assertTrue(rec["valid"], rec)
        return rec

    def test_a_look_alike_type_is_an_unknown_constraint_not_a_reference(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        n = len(PAY["constraints"])
        for v in (" " + REF, REF + " ", REF.upper(), REF.replace("github", "GitHub"), REF + "2", REF[:-1]):
            c = with_ref(PAY, h)
            c["constraints"].append({"type": v, "issuer_jwt_hash": h})
            with self.subTest(type=v):   # beside the reference: one more constraint of a type outside the table (SPEC §11.4)
                e = self.entry(o, issue(c), "la.json")["restrictions"][0]
                self.assertEqual((e["state"], e["reasons"], e["restricts"]), ("verified", [], h))
                self.assertEqual(e["reported"], [{"reason": "unknown_constraint_added", "at": f"restriction.delegate_payload[0].constraints[{n + 1}]"}])
            c = copy.deepcopy(PAY)
            c["constraints"].append({"type": v, "issuer_jwt_hash": h})
            with self.subTest(type=v, alone=True):   # alone: no reference, so no record (SPEC §11.2)
                rec = self.entry(o, issue(c), "la2.json")
                self.assertEqual((rec["restrictions"], rec["met"]), ([], False))

    def test_step_2_judges_the_misplaced_name_before_the_count_the_keys_the_hash_and_the_disclosure(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        M = [{"state": "contradicted", "reason": "restricts_misplaced", "at": "restriction." + REF}]
        for c in (with_ref(with_ref(PAY, h), h), with_ref(PAY, h, {"k": 1}), with_ref(PAY, "x")):
            with self.subTest(refs=[x for x in c["constraints"] if x.get("type") == REF]):
                self.assertEqual(self.entry(o, issue(c, {REF: h}), "ord.json")["restrictions"][0]["reasons"], M)
        self.assertEqual(self.entry(o, restrict(o, PAY, {REF: h}, hide_ref="element"), "ord2.json")["restrictions"][0]["reasons"], M)

    def test_constraints_as_a_property_disclosure_holds_a_plain_reference(self):
        o = issue(PAY)
        h = ap2.issuer_jwt_hash(o)
        for order in ("constraints_first", "exp_first"):
            c = with_ref(PAY, h)
            dc, de = _disc("constraints", c.pop("constraints")), _disc("exp", c.pop("exp"))
            digests = [ap2._disclosure_digest(dc), ap2._disclosure_digest(de)]
            c["_sd"] = digests if order == "constraints_first" else digests[::-1]
            r = issue(c, sd_arrays=False) + dc + "~" + de + "~"
            with self.subTest(order=order):
                self.assertEqual(ap2._digest_census(ap2.parse_sd_jwt(r)), 0)
                e = self.entry(o, r, "pd.json")["restrictions"][0]
                self.assertEqual((e["state"], e["reasons"], e["restricts"]), ("verified", [], h))
        c = with_ref(PAY, h)   # the reference an array-element disclosure inside that disclosed list: still not plain
        cons = c.pop("constraints")
        d_el = _disc(cons[-1])
        cons[-1] = {"...": ap2._disclosure_digest(d_el)}
        dc = _disc("constraints", cons)
        c["_sd"] = [ap2._disclosure_digest(dc)]
        e = self.entry(o, issue(c, sd_arrays=False) + dc + "~" + d_el + "~", "pd2.json")["restrictions"][0]
        self.assertEqual([(x["state"], x["reason"]) for x in e["reasons"]], [("contradicted", "restricts_disclosable")])
        rec = self.entry(o, issue(c, sd_arrays=False), "pd3.json")   # the holder drops `constraints`: no reference, no record
        self.assertEqual((rec["restrictions"], rec["met"]), ([], False))


class TestThirdReview(PackCase):
    """Third review of the constraint form (2026-10-28): `delegate_payload` itself a property disclosure (the holder could
    leave the whole content out — with a mandate signed at the top level beside it, what is left verifies in the SDK's
    typed path as an ordinary mandate), `_sd` / `_sd_alg` keys inside the reference (nothing to leave out, still not the
    signed element), and a `delegate_payload` that is not a list (no Mandate Content: no record)."""

    def sign(self, top):
        return K1.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": K1.jwk}, json.dumps(top))

    def test_delegate_payload_as_a_property_disclosure_is_not_plain(self):
        wide = copy.deepcopy(PAY)
        narrow = copy.deepcopy(PAY); narrow["constraints"][ci(PAY, "payment.amount_range")]["max"] = 100
        d_o = _disc(wide)
        o = self.sign(dict(wide, delegate_payload=[{"...": ap2._disclosure_digest(d_o)}])) + "~" + d_o + "~"
        h = ap2.issuer_jwt_hash(o)
        # beside it at the top level: a mandate, nothing, a mandate whose `constraints` hold an equal copy of the reference
        for top in (wide, {}, with_ref(wide, h)):
            d_r = _disc("delegate_payload", [with_ref(narrow, h)])
            r = self.sign(dict(top, _sd=[ap2._disclosure_digest(d_r)])) + "~" + d_r + "~"
            with self.subTest(top_level=sorted(top)):
                self.assertEqual(ap2._digest_census(ap2.parse_sd_jwt(r)), 0)   # fully disclosed as packed
                rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="dp.json"))
                self.assertTrue(rec["valid"])
                self.assertEqual(rec["restrictions"][0]["reasons"], [{"state": "contradicted", "reason": "restricts_disclosable",
                                                                      "at": f"restriction.delegate_payload[0].constraints[{len(PAY['constraints'])}]"}])
        d_r = _disc(with_ref(narrow, h))   # control: the plain key, the content an array-element disclosure
        r = self.sign(dict(wide, delegate_payload=[{"...": ap2._disclosure_digest(d_r)}])) + "~" + d_r + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="dp2.json"))
        self.assertEqual((rec["restrictions"][0]["state"], rec["met"]), ("verified", True))

    def test_sd_keys_inside_the_reference_are_not_plain(self):
        o = issue(PAY)
        for extra in ({"_sd": []}, {"_sd_alg": "sha-256"}, {"_sd": [], "_sd_alg": "sha-256"}):
            with self.subTest(extra=extra):
                r = issue(with_ref(PAY, ap2.issuer_jwt_hash(o), extra))
                self.assertEqual(ap2._digest_census(ap2.parse_sd_jwt(r)), 0)   # nothing to leave out
                e = self.run_pair(o, r)[1]
                self.assertEqual(why(e), [("contradicted", "restricts_disclosable")])
                self.assertEqual(e["restricts"], ap2.issuer_jwt_hash(o))

    def test_a_delegate_payload_that_is_not_a_list_holds_no_mandate_content(self):
        o = issue(PAY)
        c = with_ref(PAY, ap2.issuer_jwt_hash(o))
        for dp in ("x", 7, None, {}, {"0": c}, True):
            with self.subTest(dp=dp):
                rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", self.sign(dict(c, delegate_payload=dp)) + "~"), name="nl.json"))
                self.assertEqual((rec["valid"], rec["restrictions"], rec["met"]), (True, [], False))
        # control: without `delegate_payload` the same payload IS the Mandate Content — a record, in the other form than O
        self.assertEqual(why(self.run_pair(o, self.sign(c) + "~")[1]), [("not_evaluated", "form_differs")])

    def test_the_guard_reads_the_top_level_sd_in_every_position_and_nothing_nested(self):
        """Cross review (2026-10-29): the `delegate_payload` disclosure is found in the payload's `_sd` whatever its position
        among other property disclosures (mutant `any` -> non-empty `all` lived), and a disclosure named `delegate_payload`
        INSIDE a delegated Mandate Content is not the form's key (mutant iterating every disclosure lived): there it is an
        unknown name of §11.4 (in the payload form the Mandate Content IS the payload: that disclosure is the form's key). And a `delegate_payload` list with no object element holding the reference makes no record."""
        wide = copy.deepcopy(PAY)
        narrow = copy.deepcopy(PAY); narrow["constraints"][ci(PAY, "payment.amount_range")]["max"] = 100
        d_o = _disc(wide)
        o = self.sign(dict(wide, delegate_payload=[{"...": ap2._disclosure_digest(d_o)}])) + "~" + d_o + "~"
        h = ap2.issuer_jwt_hash(o)
        at = f"restriction.delegate_payload[0].constraints[{len(PAY['constraints'])}]"
        for pos in (0, 1):   # the `delegate_payload` disclosure first / second in `_sd`; the reference copied at the top level too
            d_r = _disc("delegate_payload", [with_ref(narrow, h)]); d_x = _disc("foo", "x")
            sd = [ap2._disclosure_digest(d_r), ap2._disclosure_digest(d_x)]
            if pos:
                sd.reverse()
            r = self.sign(dict(with_ref(wide, h), _sd=sd)) + "~" + d_x + "~" + d_r + "~"
            with self.subTest(position=pos):
                rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name=f"sd{pos}.json"))
                self.assertTrue(rec["valid"])
                self.assertEqual(rec["restrictions"][0]["reasons"], [{"state": "contradicted", "reason": "restricts_disclosable", "at": at}])
        d_n = _disc("delegate_payload", "x")
        c = with_ref(narrow, h); c["_sd"] = [ap2._disclosure_digest(d_n)]
        r = self.sign(dict(wide, delegate_payload=[c])) + "~" + d_n + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="nested.json"))
        self.assertTrue(rec["valid"])
        self.assertEqual(rec["restrictions"][0]["reasons"],
                         [{"state": "not_evaluated", "reason": "unknown_name", "at": "restriction.delegate_payload[0].delegate_payload"}])
        d_x = _disc("foo", "x")   # the same, with an `_sd` of the payload holding another name: still nothing nested is read
        r = self.sign(dict(wide, delegate_payload=[c], _sd=[ap2._disclosure_digest(d_x)])) + "~" + d_x + "~" + d_n + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="nested2.json"))
        self.assertEqual([(x["state"], x["reason"], x["at"]) for x in rec["restrictions"][0]["reasons"]],
                         [("not_evaluated", "unknown_name", "restriction.foo"),
                          ("not_evaluated", "unknown_name", "restriction.delegate_payload[0].delegate_payload")])
        for dp in ([], [5], ["x"], [{}], [[with_ref(narrow, h)]]):   # no object element holds the reference: no record
            with self.subTest(dp=dp):
                rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", self.sign(dict(with_ref(wide, h), delegate_payload=dp)) + "~"), name="nr.json"))
                self.assertEqual((rec["valid"], rec["restrictions"], rec["met"]), (True, [], False))
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", self.sign(dict(wide, delegate_payload=[with_ref(narrow, h), 5])) + "~"), name="fu.json"))
        self.assertEqual(why(rec["restrictions"][0]), [("not_evaluated", "form_unsupported")])   # control: an object element holds it

    def test_an_original_whose_delegate_payload_is_a_property_disclosure_has_two_readings(self):
        """Second cross review (2026-10-29): O with `delegate_payload` a property disclosure and terms signed at the top level
        beside it can be presented by its holder without that disclosure as a mandate with the top-level terms (SDK typed
        path, measured) — narrower (10) or wider (10^6) than the content (20000) — so R is `not_evaluated`
        `original_disclosable` at `original` (§11.3 step 6, before the form: the disclosed value may be no content at all),
        after step 5 (a hidden digest in O comes first) and after R's own step 2. Control: with `delegate_payload` a plain
        key the top level cannot be reached by leaving a disclosure out, and R is `verified` against the content."""
        wide = copy.deepcopy(PAY)
        narrow = copy.deepcopy(PAY); narrow["constraints"][ci(PAY, "payment.amount_range")]["max"] = 100
        want = [{"state": "not_evaluated", "reason": "original_disclosable", "at": "original"}]
        tops = {}
        for top_max in (10, 1000000):
            top = tops[top_max] = copy.deepcopy(PAY); top["constraints"][ci(PAY, "payment.amount_range")]["max"] = top_max
            for val in ([wide], "x"):   # a readable content, and no content at all: the disclosure is judged before the form
                d_dp = _disc("delegate_payload", val)
                o = self.sign(dict(top, _sd=[ap2._disclosure_digest(d_dp)])) + "~" + d_dp + "~"
                r = self.sign(dict(top, delegate_payload=[with_ref(narrow, ap2.issuer_jwt_hash(o))])) + "~"
                with self.subTest(top_max=top_max, value=val):
                    rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="two.json"))
                    self.assertTrue(rec["valid"])
                    self.assertEqual(rec["restrictions"][0]["reasons"], want)
                    self.assertEqual((rec["restrictions"][0]["state"], rec["met"]), ("not_evaluated", False))
        top = tops[10]
        d_dp = _disc("delegate_payload", [wide])   # step 5 first: a decoy digest in O's `_sd` beside the disclosure
        o = self.sign(dict(top, _sd=[ap2._disclosure_digest(d_dp), _b64u(hashlib.sha256(b"decoy").digest())])) + "~" + d_dp + "~"
        r = self.sign(dict(top, delegate_payload=[with_ref(narrow, ap2.issuer_jwt_hash(o))])) + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="decoy.json"))
        self.assertEqual(rec["restrictions"][0]["reasons"], [{"state": "not_evaluated", "reason": "undisclosed_digests", "at": "original"}])
        d_dp = _disc("delegate_payload", [wide])   # R's own step 2 first: R with the same disclosure and the reference at the top
        o = self.sign(dict(top, _sd=[ap2._disclosure_digest(d_dp)])) + "~" + d_dp + "~"
        d_r = _disc("delegate_payload", [with_ref(narrow, ap2.issuer_jwt_hash(o))])
        r = self.sign(dict(with_ref(top, ap2.issuer_jwt_hash(o)), _sd=[ap2._disclosure_digest(d_r)])) + "~" + d_r + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="both.json"))
        self.assertEqual(why(rec["restrictions"][0]), [("contradicted", "restricts_disclosable")])
        d_el = _disc(wide)   # control: a plain key holding an array-element disclosure, the narrower top level unreachable
        o = self.sign(dict(top, delegate_payload=[{"...": ap2._disclosure_digest(d_el)}])) + "~" + d_el + "~"
        r = self.sign(dict(top, delegate_payload=[with_ref(narrow, ap2.issuer_jwt_hash(o))])) + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="plain.json"))
        self.assertEqual((rec["restrictions"][0]["state"], rec["restrictions"][0]["reasons"], rec["met"]), ("verified", [], True))

    def test_constraints_as_a_property_disclosure_of_the_payload_is_plain_on_both_sides(self):
        """Third cross review (2026-10-29): in the payload form the payload's own `_sd` may hold `constraints` (SPEC §11.1:
        `constraints` MAY be a property disclosure — the typed mandate requires it) and the guard reads only the name
        `delegate_payload` there: R is `verified` (mutant `in ("delegate_payload", "constraints")` lived), and so is an O
        built the same way. Control: the disclosure named `delegate_payload` beside it is `restricts_disclosable` in R and
        `original_disclosable` in O; with R signed by another key, step 4 is listed before step 6 (§11.3, in this order)."""
        wide = copy.deepcopy(PAY)
        narrow = copy.deepcopy(PAY); narrow["constraints"][ci(PAY, "payment.amount_range")]["max"] = 100
        o = self.sign(wide) + "~"
        rc = with_ref(narrow, ap2.issuer_jwt_hash(o)); d_c = _disc("constraints", rc.pop("constraints"))
        r = self.sign(dict(rc, _sd=[ap2._disclosure_digest(d_c)])) + "~" + d_c + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r), name="pc_r.json"))
        self.assertEqual((rec["valid"], rec["restrictions"][0]["state"], rec["restrictions"][0]["reasons"], rec["met"]), (True, "verified", [], True))
        oc = copy.deepcopy(wide); d_oc = _disc("constraints", oc.pop("constraints"))
        o2 = self.sign(dict(oc, _sd=[ap2._disclosure_digest(d_oc)])) + "~" + d_oc + "~"
        r2 = self.sign(with_ref(narrow, ap2.issuer_jwt_hash(o2))) + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o2), ("restriction", r2), name="pc_o.json"))
        self.assertEqual((rec["restrictions"][0]["state"], rec["restrictions"][0]["reasons"], rec["met"]), ("verified", [], True))
        d_dp = _disc("delegate_payload", [with_ref(narrow, ap2.issuer_jwt_hash(o))])   # control: the other name beside `constraints` in the same `_sd`
        r3 = self.sign(dict(rc, _sd=[ap2._disclosure_digest(d_c), ap2._disclosure_digest(d_dp)])) + "~" + d_c + "~" + d_dp + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o), ("restriction", r3), name="pc_r3.json"))
        self.assertEqual(why(rec["restrictions"][0]), [("contradicted", "restricts_disclosable")])
        d_dp2 = _disc("delegate_payload", [wide])
        o3 = self.sign(dict(oc, _sd=[ap2._disclosure_digest(d_oc), ap2._disclosure_digest(d_dp2)])) + "~" + d_oc + "~" + d_dp2 + "~"
        r4 = self.sign(with_ref(narrow, ap2.issuer_jwt_hash(o3))) + "~"
        rec = ap2.verify_restrictions(self.pack(("original", o3), ("restriction", r4), name="pc_o3.json"))
        self.assertEqual(rec["restrictions"][0]["reasons"], [{"state": "not_evaluated", "reason": "original_disclosable", "at": "original"}])
        r5 = K2.sign({"alg": "ES256", "typ": "example+sd-jwt", "jwk": K2.jwk}, json.dumps(with_ref(narrow, ap2.issuer_jwt_hash(o3)))) + "~"   # step 4 before step 6, both listed
        rec = ap2.verify_restrictions(self.pack(("original", o3), ("restriction", r5), name="pc_o3k2.json"))
        self.assertEqual([(x["reason"], x["at"]) for x in rec["restrictions"][0]["reasons"]],
                         [("issuer_key_differs", "restriction"), ("original_disclosable", "original")])
        self.assertEqual(rec["restrictions"][0]["state"], "contradicted")


if __name__ == "__main__":
    unittest.main()
