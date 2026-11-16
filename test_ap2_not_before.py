#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.0-draft — SPEC §12, the `not_before` block: a NIST Beacon value sealed in one object with the payer's and payee's
IBANs, the amount, the currency, a payment id and salted commitments to the names, beside an AP2 payment mandate.

Real NIST pulses and the real certificate (spec/vectors/beacon, fetched 2026-11-16). The IBANs are the published examples
of the SWIFT IBAN registry (GB82WEST12345698765432, DE89370400440532013000); mandates, names and amounts are test data.
The TSA is a real one run locally (openssl ts -reply), as in test_ap2_anchors.py; its genTime is the clock of this run."""
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
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

VDIR = os.path.join(_HERE, "spec", "vectors", "beacon")
HAVE_OPENSSL = shutil.which("openssl") is not None
IBAN_PAYER, IBAN_PAYEE = "GB82WEST12345698765432", "DE89370400440532013000"   # SWIFT IBAN registry examples
SALTS = {"payer_iban_commitment": bytes(range(16)), "payee_iban_commitment": bytes(range(16, 32)),
         "payer_name_commitment": bytes(range(32, 48)), "payer_details_commitment": bytes(range(48, 64)),
         "payee_name_commitment": bytes(range(64, 80))}
CLEAR = {"payer_iban": IBAN_PAYER, "payee_iban": IBAN_PAYEE, "payer_name": "Test Payer One",
         "payer_details": "1 Test Street, Testville, XX", "payee_name": "Example Test Merchant"}


def _rb(name):
    with open(os.path.join(VDIR, name), "rb") as f:
        return f.read()


def pulse(name):
    return json.loads(_rb(name))["pulse"]


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Key:
    def __init__(self):
        self.sk = ec.generate_private_key(ec.SECP256R1())
        n = self.sk.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}

    def token(self, payload):
        si = f"{_b64u(json.dumps({'alg': 'ES256', 'typ': 'example+sd-jwt', 'jwk': self.jwk}).encode())}.{_b64u(json.dumps(payload).encode())}"
        r, s = decode_dss_signature(self.sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}~"


K = Key()


def mandate(amount=1250, currency="EUR", extra=None):
    """An AP2 Payment Mandate's claims (payment_mandate.json at e1ea56d), test data."""
    c = {"vct": "mandate.payment.1", "transaction_id": "dGVzdC10cmFuc2FjdGlvbg", "payee": {"id": "merchant-test-1",
         "name": "Example Test Merchant"}, "payment_amount": {"amount": amount, "currency": currency},
         "payment_instrument": {"id": "instrument-test-1", "type": "card"}}
    c.update(extra or {})
    return K.token(c)


def block(drop=(), **over):
    p, prev = pulse("chain2_2030310.json"), pulse("chain2_2030309.json")
    pay = ap2.make_payment(payment_id="E2E-TEST-0001", amount="12.50", currency="EUR", salts=SALTS, record_salt=b"\x5a" * 16,
                           beacon={"source": "nist-beacon-2.0", "chain_index": 2, "pulse_index": 2030310,
                                   "output_value": p["outputValue"]}, **CLEAR)
    for k in drop:
        del pay[k]
    pay.update(over)
    return {"profile": "ap2-evidence-pack.not-before/1", "payment": pay,
            "mandate": {"artifact": "payment", "amount_claim": "payment_amount"},
            "pulses": {"pulse": p, "previous_pulse": prev, "certificate": _rb("cert_chain2.pem").decode("ascii")}}


class LocalTSA:
    def __init__(self, d):
        self.d = d; self.key, self.crt = os.path.join(d, "t.key"), os.path.join(d, "t.crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", self.key,
                        "-out", self.crt, "-days", "30", "-subj", "/CN=test-tsa", "-addext", "extendedKeyUsage=critical,timeStamping",
                        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature"], check=True, capture_output=True)
        self.serial = os.path.join(d, "t.serial")
        with open(self.serial, "w") as f:
            f.write("01\n")
        self.cnf = os.path.join(d, "t.cnf")
        with open(self.cnf, "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t\n[ t ]\nserial = {self.serial}\ncrypto_device = builtin\nsigner_cert = {self.crt}\n"
                    f"signer_key = {self.key}\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\nordering = no\n"
                    f"tsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n")

    def stamp(self, digest_hex, tsa_url, timeout=20):
        q, r = os.path.join(self.d, "q.tsq"), os.path.join(self.d, "r.tsr")
        subprocess.run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q], check=True, capture_output=True)
        subprocess.run(["openssl", "ts", "-reply", "-config", self.cnf, "-queryfile", q, "-out", r], check=True, capture_output=True)
        with open(r, "rb") as f:
            return {"anchored": True, "tsa_url": tsa_url, "tsr_b64": base64.b64encode(f.read()).decode()}


def reseal(path, ev):
    """The producer re-seals a changed pack: digest recomputed (no TSA: a new token would be needed)."""
    e2 = {k: v for k, v in ev.items() if k not in ap2._DIGEST_EXCLUDED}
    ev["evidence_digest_sha256"] = hashlib.sha256(ap2._canon(e2)).hexdigest()
    ev["rfc3161_timestamp"] = {"anchored": False, "note": "re-sealed by the test"}
    ev.pop("anchors", None)
    with open(path, "w") as f:
        json.dump(ev, f)


@unittest.skipUnless(HAVE_OPENSSL, "openssl absent: the local TSA cannot run")
class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2-nb-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.tsa = LocalTSA(self.d)
        self._orig = ap2._rfc3161_stamp
        self.addCleanup(setattr, ap2, "_rfc3161_stamp", self._orig)
        ap2._rfc3161_stamp = lambda digest, url, timeout=20: self.tsa.stamp(digest, url)

    def build(self, nb=None, tok=None, name="p.json", tsa=True):
        out = os.path.join(self.d, name)
        ap2.build_evidence([{"name": "payment", "sd_jwt": tok or mandate()}], out,
                           tsa_url="https://tsa.example" if tsa else None, not_before=block() if nb is None else nb)
        return out

    def verify(self, path, **kw):
        return ap2.verify_evidence(path, tsa_cert=self.tsa.crt, **kw)

    def load(self, path):
        with open(path) as f:
            return json.load(f)

    def write(self, ev, name="m.json"):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            json.dump(ev, f)
        return p


class TestVectorsAndHelpers(unittest.TestCase):
    def test_vectors_are_the_fetched_bytes(self):
        for line in _rb("SHA256SUMS").decode().splitlines():
            h, n = line.split()
            self.assertEqual(hashlib.sha256(_rb(n)).hexdigest(), h, n)

    def test_iban(self):
        self.assertIsNone(ap2.iban_problem(IBAN_PAYER)); self.assertIsNone(ap2.iban_problem(IBAN_PAYEE))
        for bad, why in (("GB82WEST12345698765433", "iban_checksum"), ("DE89370400440532013001", "iban_checksum"),
                         ("gb82WEST12345698765432", "iban_charset"), ("GB82 WEST 1234 5698 7654 32", "iban_charset"),
                         ("GB82WEST1234", "iban_length"), ("GB82" + "1" * 31, "iban_length"), ("", "iban_length"),
                         ("1282WEST12345698765432", "iban_charset"), ("GB00WEST12345698765432", "iban_check_digits"),
                         ("GB99WEST12345698765432", "iban_check_digits"), (None, "iban_charset"), (12, "iban_charset")):
            self.assertEqual(ap2.iban_problem(bad), why, bad)
        # every single-digit substitution of a digit is caught (ISO 7064 MOD 97-10), counted on both examples
        n = 0
        for iban in (IBAN_PAYER, IBAN_PAYEE):
            for i, ch in enumerate(iban):
                if ch.isdigit():
                    for d in "0123456789":
                        if d != ch:
                            self.assertIsNotNone(ap2.iban_problem(iban[:i] + d + iban[i + 1:]))
                            n += 1
        self.assertEqual(n, 9 * sum(c.isdigit() for c in IBAN_PAYER + IBAN_PAYEE))

    def test_commitment_known_answer(self):
        """The encoding written out here, not taken from ap2_evidence (a mutant of it must not pass)."""
        salt = bytes(range(16))
        want = hashlib.sha256(b"cryptovalid-payment/1/payer_iban_commitment\x00" + salt + IBAN_PAYER.encode()).hexdigest()
        self.assertEqual(ap2.payment_commitment("payer_iban_commitment", salt, IBAN_PAYER), want)
        self.assertEqual(ap2.payment_commitment("payer_iban_commitment", salt, "gb82 west 1234 5698 7654 32"), want)
        self.assertNotEqual(ap2.payment_commitment("payee_iban_commitment", salt, IBAN_PAYER), want)   # the member is hashed
        want = hashlib.sha256(b"cryptovalid-payment/1/payee_name_commitment\x00" + salt + "Caf\u00e9 Test".encode()).hexdigest()
        self.assertEqual(ap2.payment_commitment("payee_name_commitment", salt, "Cafe\u0301 Test"), want)   # NFC
        for bad in (("payer_iban_commitment", salt, "GB82WEST12345698765433"), ("payer_iban_commitment", salt[:15], IBAN_PAYER),
                    ("payer_iban_commitment", salt + b"\0", IBAN_PAYER), ("payer_name_commitment", salt, ""),
                    ("payer_name_commitment", salt, "x" * 1025), ("payer_iban", salt, IBAN_PAYER),
                    ("payer_iban_commitment", salt, "GB82WE\u00dfT12345698765432"),   # non-ASCII refused before upper case
                    ("payer_iban_commitment", salt, "GB82WE\u017fT12345698765432")):  # long s: its upper case IS the example
            with self.assertRaises(ValueError):
                ap2.payment_commitment(*bad)

    def test_amount_minor_units(self):
        f = ap2._amount_equals_minor
        self.assertTrue(f("12.50", "EUR", 1250)); self.assertTrue(f("12.5", "EUR", 1250)); self.assertTrue(f("12", "EUR", 1200))
        self.assertFalse(f("12.501", "EUR", 1250)); self.assertFalse(f("12.51", "EUR", 1250)); self.assertFalse(f("12.50", "EUR", True))
        self.assertTrue(f("1250", "JPY", 1250)); self.assertFalse(f("12.5", "JPY", 12)); self.assertIsNone(f("1", "XAU", 1))

    def test_paths(self):
        c = {"a": {"b": [{"c": 1}]}, "x.y": 2}
        self.assertEqual(ap2._resolve_path(c, "a.b[0].c"), 1)
        for bad in ("a.b[1].c", "a..b", ".a", "a.b.0", "a[0]", "a.b[01].c", "a.b[0]c", "x.y", "a.", ""):
            self.assertIs(ap2._resolve_path(c, bad), ap2._MISSING, bad)


class TestPositive(Base):
    def test_window_closed(self):
        p = self.build()
        r = self.verify(p)
        nb = r["not_before"]
        self.assertTrue(r["valid"], r)
        self.assertEqual(nb["checks"], {"NB1": "verified", "NB2": "verified", "NB3": "verified"})
        self.assertEqual(nb["state"], "verified")
        self.assertEqual(nb["window"]["not_before"], "2026-11-16T13:11:00Z")
        self.assertEqual(nb["window"]["not_before_operator_promise"], "2026-11-16T13:10:00Z")
        self.assertIsNotNone(nb["window"]["not_after"])
        self.assertEqual(nb["mandate_payee"], {"id": "merchant-test-1", "name": "Example Test Merchant"})
        self.assertIn("payer_iban_commitment", nb["covers"]); self.assertIn("record_salt", nb["covers"])
        self.assertNotIn("beacon", nb["covers"])               # the beacon value is the bound, not a covered field

    def test_without_tsa_cert_the_window_stays_open(self):
        r = ap2.verify_evidence(self.build())
        self.assertEqual(r["not_before"]["checks"]["NB3"], "not_evaluated:no_verified_time_anchor")
        self.assertEqual(r["not_before"]["state"], "not_evaluated")
        self.assertTrue(r["valid"])

    def test_no_clear_personal_data_in_the_pack(self):
        p = self.build()
        text = open(p, encoding="utf-8").read()
        ev = json.loads(text)
        block_text = json.dumps(ev["not_before"], ensure_ascii=False)
        for v in list(CLEAR.values()) + ["GB82 WEST", "DE89 3704"]:
            self.assertNotIn(v, block_text, v)                 # nothing in clear in OUR block
        for k in ("payer_iban", "payee_iban", "payer_name", "payer_details"):
            self.assertNotIn(CLEAR[k], text, k)                  # nor anywhere in the file
        # the merchant's name is in clear inside the AP2 mandate (AP2's format, payee.name, signed by its issuer): not ours
        self.assertIn(CLEAR["payee_name"], json.dumps(ev["artifacts"][0]["resolved_claims"]))

    def test_disclosure(self):
        p = self.build()
        D = lambda m, salt, v: ap2.check_disclosure(p, {"member": m, "salt": salt.hex() if isinstance(salt, bytes) else salt, "value": v})["outcome"]
        for m, key in (("payer_iban_commitment", "payer_iban"), ("payee_iban_commitment", "payee_iban"),
                       ("payer_name_commitment", "payer_name"), ("payer_details_commitment", "payer_details"),
                       ("payee_name_commitment", "payee_name")):
            self.assertEqual(D(m, SALTS[m], CLEAR[key]), "matches", m)
            other = SALTS["payee_name_commitment" if m != "payee_name_commitment" else "payer_name_commitment"]
            self.assertEqual(D(m, other, CLEAR[key]), "disclosure_mismatch", m)                       # another member's salt
        self.assertEqual(D("payer_iban_commitment", SALTS["payer_iban_commitment"], "gb82 west1234 5698765432"), "matches")
        self.assertEqual(D("payer_iban_commitment", SALTS["payer_iban_commitment"], IBAN_PAYEE), "disclosure_mismatch")
        self.assertEqual(D("payee_iban_commitment", SALTS["payer_iban_commitment"], IBAN_PAYER), "disclosure_mismatch")   # value of another member
        self.assertEqual(D("payer_iban_commitment", SALTS["payer_iban_commitment"], "GB82WEST12345698765433"), "disclosure_iban_invalid")
        self.assertEqual(D("payer_iban_commitment", SALTS["payer_iban_commitment"], "GB82WE\u00dfT12345698765432"), "disclosure_iban_invalid")
        self.assertEqual("GB82WE\u017fT12345698765432".upper(), IBAN_PAYER)          # so only the ASCII rule refuses it
        self.assertEqual(D("payer_iban_commitment", SALTS["payer_iban_commitment"], "GB82WE\u017fT12345698765432"), "disclosure_iban_invalid")
        self.assertEqual(D("payer_name_commitment", SALTS["payer_name_commitment"], "Test Payer Two"), "disclosure_mismatch")
        self.assertEqual(D("payee_name_commitment", SALTS["payee_name_commitment"], "Example Test Merchant "), "disclosure_mismatch")
        p2 = self.build(nb=block(drop=("payer_details_commitment",)), name="p2.json")
        self.assertEqual(ap2.check_disclosure(p2, {"member": "payer_details_commitment", "salt": "00" * 16, "value": "x"})["outcome"], "member_absent")
        ev = self.load(p); ev["not_before"]["payment"]["payer_iban_commitment"] = ev["not_before"]["payment"]["payer_iban_commitment"].upper()
        with self.assertRaises(ap2.Ap2EvidenceError):           # a block outside §12.2 is never used to open a commitment
            ap2.check_disclosure(self.write(ev, "bad.json"), {"member": "payee_iban_commitment",
                                                              "salt": SALTS["payee_iban_commitment"].hex(), "value": IBAN_PAYEE})
        for bad in ({"member": "payer_iban", "salt": "00" * 16, "value": "x"}, {"member": "payer_iban_commitment", "salt": "00" * 15, "value": "x"},
                    {"member": "payer_iban_commitment", "salt": "AA" * 16, "value": "x"}, {"member": "payer_iban_commitment", "salt": "00" * 16, "value": ""},
                    {"member": "payer_iban_commitment", "salt": "00" * 16, "value": 5}, {"member": "payer_iban_commitment", "salt": "00" * 16},
                    {"member": "payer_iban_commitment", "salt": "00" * 16, "value": "x", "extra": 1}, ["payer_iban_commitment"],
                    {"member": "payer_name_commitment", "salt": "00" * 16, "value": "\ud800"}):   # a lone surrogate is not text
            with self.assertRaises(ap2.Ap2EvidenceError):
                ap2.check_disclosure(p, bad)

    def test_without_the_block_nothing_changes(self):
        out = os.path.join(self.d, "plain.json")
        ap2.build_evidence([{"name": "payment", "sd_jwt": mandate()}], out, tsa_url="https://tsa.example")
        r = self.verify(out)
        self.assertTrue(r["valid"]); self.assertNotIn("not_before", r)


class TestAfterSealing(Base):
    """A change after sealing breaks the digest; the same change re-sealed by the producer is judged by NB2/NB3."""
    def test_changed_after_sealing(self):
        ev = self.load(self.build())
        for path, val in ((("amount",), "12.51"), (("currency",), "USD"), (("payee_iban_commitment",), "1" * 64),
                          (("payer_iban_commitment",), "2" * 64), (("payment_id",), "E2E-TEST-0002"), (("record_salt",), "5b" * 16),
                          (("payer_name_commitment",), "0" * 64), (("beacon", "output_value"), pulse("chain2_2030309.json")["outputValue"])):
            e = copy.deepcopy(ev)
            tgt = e["not_before"]["payment"]
            for k in path[:-1]:
                tgt = tgt[k]
            tgt[path[-1]] = val
            r = self.verify(self.write(e))
            self.assertFalse(r["valid"], path); self.assertFalse(r["digest_ok"], path)

    def test_amount_or_currency_resealed(self):
        for over, want in (({"amount": "12.51"}, "failed:amount_not_the_mandate_amount"),
                           ({"currency": "USD"}, "failed:amount_not_the_mandate_amount"),
                           ({"amount": "12.505"}, "failed:amount_not_the_mandate_amount")):
            ev = self.load(self.build())
            ev["not_before"]["payment"].update(over)
            r = self.verify(self.write(ev))
            self.assertEqual(r["not_before"]["checks"]["NB2"], want, over)
            self.assertFalse(r["valid"])
            with self.assertRaises(ap2.Ap2EvidenceError):           # and a producer cannot build it
                self.build(nb=block(**over), name="x.json")

    def test_mandate_amount_changed(self):
        r = self.verify(self.build(nb=block(), tok=mandate(amount=1250)))
        self.assertTrue(r["valid"])
        with self.assertRaises(ap2.Ap2EvidenceError):
            self.build(tok=mandate(amount=1251), name="y.json")
        with self.assertRaises(ap2.Ap2EvidenceError):
            self.build(tok=mandate(currency="USD"), name="z.json")

    def test_mandate_named_wrongly(self):
        nb = block(); nb["mandate"]["artifact"] = "other"
        with self.assertRaises(ap2.Ap2EvidenceError):
            self.build(nb=nb)
        ev = self.load(self.build()); ev["not_before"]["mandate"]["artifact"] = "other"
        self.assertEqual(self.verify(self.write(ev))["not_before"]["checks"]["NB2"], "failed:mandate_not_in_pack")
        ev = self.load(self.build()); ev["not_before"]["mandate"]["amount_claim"] = "payee"
        self.assertEqual(self.verify(self.write(ev))["not_before"]["checks"]["NB2"], "failed:amount_not_the_mandate_amount")
        ev = self.load(self.build()); ev["not_before"]["mandate"]["amount_claim"] = "nothing.here"
        self.assertEqual(self.verify(self.write(ev))["not_before"]["checks"]["NB2"], "failed:amount_claim_not_found")

    def test_beacon_outside_the_sealed_content(self):
        p = self.build()
        ev = self.load(p)
        nb = ev.pop("not_before")
        ev["rfc3161_timestamp"]["not_before"] = nb          # beside the seal: outside the digest
        r = self.verify(self.write(ev))
        self.assertEqual(r["admission"], "refused"); self.assertEqual(r["refusal_class"], "unknown_member")
        ev = self.load(p); nb = ev.pop("not_before")
        reseal(os.path.join(self.d, "q.json"), ev)
        ev = self.load(os.path.join(self.d, "q.json")); ev["anchors"] = [dict(nb, mechanism="rfc3161", tsr_b64="AA==")]
        r = self.verify(self.write(ev))
        self.assertEqual(r["admission"], "refused")

    def test_pulse_of_another_chain_and_other_certificate(self):
        nb = block(); nb["pulses"]["certificate"] = _rb("cert_chain1.pem").decode("ascii")
        with self.assertRaises(ap2.Ap2EvidenceError):
            self.build(nb=nb)
        ev = self.load(self.build()); ev["not_before"]["pulses"]["certificate"] = _rb("cert_chain1.pem").decode("ascii")
        reseal(os.path.join(self.d, "c.json"), ev)
        r = ap2.verify_evidence(os.path.join(self.d, "c.json"))
        self.assertEqual(r["not_before"]["checks"]["NB1"], "failed:previous_certificate_not_the_certificate_id")
        self.assertFalse(r["valid"])
        ev = self.load(self.build()); ev["not_before"]["pulses"]["pulse"] = pulse("chain1_1000.json")
        reseal(os.path.join(self.d, "c1.json"), ev)
        self.assertEqual(ap2.verify_evidence(os.path.join(self.d, "c1.json"))["admission"], "refused")   # "Version 2.0"
        ev = self.load(self.build()); ev["not_before"]["payment"]["beacon"]["chain_index"] = 1
        reseal(os.path.join(self.d, "c2.json"), ev)
        self.assertEqual(ap2.verify_evidence(os.path.join(self.d, "c2.json"))["not_before"]["checks"]["NB1"],
                         "failed:beacon_value_mismatch")
        ev = self.load(self.build()); ev["not_before"]["payment"]["beacon"]["output_value"] = pulse("chain2_2030310.json")["outputValue"].lower()
        reseal(os.path.join(self.d, "c3.json"), ev)
        self.assertEqual(ap2.verify_evidence(os.path.join(self.d, "c3.json"))["not_before"]["checks"]["NB1"], "verified")   # either case

    def test_window_inverted_and_created_before_beacon(self):
        p = self.build()
        orig = ap2._verify_rfc3161
        def early(*a, **k):
            r = orig(*a, **k); r["gen_time"] = "20261116131059.5Z"; return r
        ap2._verify_rfc3161 = early
        try:
            r = self.verify(p)
        finally:
            ap2._verify_rfc3161 = orig
        self.assertEqual(r["not_before"]["checks"]["NB3"], "failed:window_inverted"); self.assertFalse(r["valid"])
        def same(*a, **k):
            r = orig(*a, **k); r["gen_time"] = "20261116131100Z"; return r
        ap2._verify_rfc3161 = same
        try:
            r = self.verify(p)
        finally:
            ap2._verify_rfc3161 = orig
        self.assertEqual(r["not_before"]["checks"]["NB3"], "verified")       # genTime = T: one instant
        ev = self.load(p); ev["created_utc"] = "2026-11-16T13:10:59Z"
        reseal(os.path.join(self.d, "e.json"), ev)
        r = ap2.verify_evidence(os.path.join(self.d, "e.json"))
        self.assertEqual(r["not_before"]["checks"]["NB3"], "failed:created_before_beacon"); self.assertFalse(r["valid"])

    def test_impossible_times(self):
        """A time that matches the pattern and is no calendar time: refused in a pulse, failed as created_utc (both used to
        be a ValueError traceback in the reference, found by the JS port of 2026-11-16)."""
        nb = block(); nb["pulses"]["pulse"]["timeStamp"] = "2026-02-30T13:11:00.000Z"
        ev = self.load(self.build()); ev["not_before"] = nb
        p = os.path.join(self.d, "t1.json"); reseal(p, ev)
        r = ap2.verify_evidence(p)
        self.assertEqual((r["admission"], r["refusal_class"]), ("refused", "malformed"))
        ev = self.load(self.build()); ev["created_utc"] = "2026-02-30T00:00:00Z"
        p = os.path.join(self.d, "t2.json"); reseal(p, ev)
        r = ap2.verify_evidence(p)
        self.assertEqual(r["not_before"]["checks"]["NB3"], "failed:created_utc_not_a_time"); self.assertFalse(r["valid"])
        for t in ("2026-11-16T24:00:00.000Z", "2026-13-01T00:00:00.000Z", "0000-01-01T00:00:00.000Z", "2026-11-16T13:11:60.000Z"):
            with self.assertRaises(NB.PulseError):
                NB.check_grammar(dict(pulse("chain2_2030310.json"), timeStamp=t))

    def test_every_bit_of_every_hex_field(self):
        rnd = random.Random(20261116)
        ev = self.load(self.build())
        n = 0
        for which in ("pulse", "previous_pulse"):
            for k in ("localRandomValue", "precommitmentValue", "outputValue", "signatureValue"):
                s = ev["not_before"]["pulses"][which][k]
                for pos in rnd.sample(range(len(s)), 4):
                    e = copy.deepcopy(ev)
                    e["not_before"]["pulses"][which][k] = s[:pos] + "%X" % (int(s[pos], 16) ^ (1 << rnd.randrange(4))) + s[pos + 1:]
                    p = os.path.join(self.d, "b.json"); reseal(p, e)
                    r = ap2.verify_evidence(p)
                    self.assertTrue(r["admission"] == "refused" or r["not_before"]["checks"]["NB1"].startswith("failed:"), (which, k, pos))
                    self.assertFalse(r["valid"])
                    n += 1
        self.assertEqual(n, 32)


class TestClosed(Base):
    def refused(self, nb, cls=None):
        ev = self.load(self.build())
        ev["not_before"] = nb
        p = os.path.join(self.d, "r.json"); reseal(p, ev)
        r = ap2.verify_evidence(p)
        self.assertEqual(r["admission"], "refused", r.get("not_before"))
        if cls:
            self.assertEqual(r["refusal_class"], cls)
        with self.assertRaises(ap2.Ap2EvidenceError):
            self.build(nb=nb, name="b2.json")
        return r["refused"]

    def test_unknown_key_at_every_level(self):
        for path in ((), ("payment",), ("payment", "beacon"), ("mandate",), ("pulses",), ("pulses", "pulse"),
                     ("pulses", "previous_pulse"), ("pulses", "pulse", "external"), ("pulses", "pulse", "listValues", 3)):
            nb = block(); tgt = nb
            for k in path:
                tgt = tgt[k]
            tgt["x_extra"] = "1"
            self.refused(nb, "unknown_member" if path[:2] != ("pulses", "pulse") or len(path) == 2 else None)

    def test_missing_key_at_every_level(self):
        for path in ((), ("payment",), ("payment", "beacon"), ("mandate",), ("pulses",)):
            nb0 = block(); tgt0 = nb0
            for k in path:
                tgt0 = tgt0[k]
            for k in list(tgt0):
                if k in ap2.TEXT_MEMBERS:
                    continue            # optional: absent is allowed (test_optional_members)
                nb = copy.deepcopy(nb0); tgt = nb
                for p in path:
                    tgt = tgt[p]
                del tgt[k]
                self.refused(nb, "malformed")

    def test_optional_members(self):
        r = self.verify(self.build(nb=block(drop=ap2.TEXT_MEMBERS)))
        self.assertTrue(r["valid"]); self.assertNotIn("payer_name_commitment", r["not_before"]["covers"])

    def test_wrong_types(self):
        wrong = [None, True, 0, 1.5, "x", [], {}]
        for path in (("payment",), ("payment", "beacon"), ("mandate",), ("pulses",)):
            nb0 = block(); tgt0 = nb0
            for k in path:
                tgt0 = tgt0[k]
            for k in list(tgt0):
                for w in wrong:
                    if type(w) is type(tgt0[k]):
                        continue        # a value of the right type is not a wrong type (forms: test_malformed_values)
                    nb = copy.deepcopy(nb0); tgt = nb
                    for p in path:
                        tgt = tgt[p]
                    tgt[k] = w
                    self.refused(nb)

    def test_malformed_values(self):
        for over in ({"payer_iban_commitment": "AB" * 32}, {"payee_iban_commitment": "ab" * 31}, {"payer_name_commitment": "g" * 64},
                     {"payer_details_commitment": ""}, {"payee_name_commitment": "ab" * 33}, {"record_salt": "ab" * 15},
                     {"record_salt": "ab" * 65}, {"record_salt": "AB" * 16}, {"record_salt": "a" * 33},
                     {"amount": "0"}, {"amount": "0.00"}, {"amount": "012.50"},
                     {"amount": "12.50000"}, {"amount": "1e3"}, {"amount": "-1"}, {"amount": " 12.50"}, {"currency": "eur"},
                     {"currency": "EURO"}, {"payment_id": ""}, {"payment_id": "x" * 36}, {"payment_id": " E2E"},
                     {"payment_id": "E2E "}, {"payment_id": "E2E\n1"}, {"payment_id": "E2E_1"}, {"payment_id": "E2E\u00e91"},
                     {"amount": 12.5}, {"amount": 1250}, {"payer_iban": IBAN_PAYER}):
            self.refused(block(**over))
        for rs in (b"\0" * 15, b"\0" * 65, "00" * 16):        # record salt: 16 to 64 bytes
            with self.assertRaises(ValueError):
                ap2.make_payment(payment_id="E", amount="1", currency="EUR", payer_iban=IBAN_PAYER, payee_iban=IBAN_PAYEE,
                                 beacon={}, salts=SALTS, record_salt=rs)
        with self.assertRaises(ValueError):                    # an IBAN that fails MOD 97-10 is never committed
            ap2.make_payment(
                payment_id="E", amount="1", currency="EUR", payer_iban="GB82WEST12345698765433", payee_iban=IBAN_PAYEE,
                beacon={}, salts=SALTS, record_salt=b"\0" * 16)
        nb = block(); nb["payment"]["beacon"]["source"] = "curby"; self.refused(nb)
        nb = block(); nb["profile"] = "ap2-evidence-pack.not-before/2"; self.refused(nb)
        nb = block(); nb["pulses"]["certificate"] += nb["pulses"]["certificate"]; self.refused(nb)

    def test_duplicate_key_in_the_file(self):
        p = self.build()
        text = open(p).read().replace('"payment_id": ', '"payment_id": "DUP", "payment_id": ', 1)
        self.assertIn('"DUP"', text)
        q = os.path.join(self.d, "dup.json")
        with open(q, "w") as f:
            f.write(text)
        self.assertEqual(ap2.verify_evidence(q)["admission"], "refused")

    def test_copy_without_the_beacon_module(self):
        p = self.build()
        saved = ap2._nb
        ap2._nb = None
        try:
            r = ap2.verify_evidence(p)
        finally:
            ap2._nb = saved
        self.assertEqual(r["refusal_class"], "format_unsupported")


import ap2_nist_beacon as NB  # noqa: E402


def PULSE_BASE():
    return pulse("chain2_2030310.json")


def _synthetic_chain(nb, base, n=2):
    """Pulses of a TEST beacon (a throwaway RSA key and self-signed certificate made here, pinned only by the test), built
    from a real pulse's shape, so that the rules no real NIST pair can break (previous value, period, commitment) are
    exercised. Returns (pulses oldest first, certificate PEM, pinned)."""
    import datetime as _dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _h, serialization as _s
    from cryptography.hazmat.primitives.asymmetric import padding as _pad, rsa as _rsa
    from cryptography.x509.oid import NameOID
    k = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-beacon")])
    now = _dt.datetime(2026, 11, 1, tzinfo=_dt.timezone.utc)
    crt = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
           .serial_number(1).not_valid_before(now).not_valid_after(now + _dt.timedelta(days=60)).sign(k, _h.SHA256()))
    der = crt.public_bytes(_s.Encoding.DER)
    pem = crt.public_bytes(_s.Encoding.PEM).decode("ascii")
    cid = hashlib.sha512(der).hexdigest()
    lrv = [os.urandom(64) for _ in range(n + 1)]
    out, prev_out = [], "00" * 64
    for i in range(n):
        p = copy.deepcopy(base)
        p["certificateId"] = cid
        p["pulseIndex"] = 100 + i
        p["uri"] = "https://beacon.nist.gov/beacon/2.0/chain/%d/pulse/%d" % (p["chainIndex"], p["pulseIndex"])
        p["timeStamp"] = "2026-11-16T12:%02d:00.000Z" % i
        p["localRandomValue"] = lrv[i].hex().upper()
        p["precommitmentValue"] = hashlib.sha512(lrv[i + 1]).hexdigest().upper()
        p["statusCode"] = 0
        for v in p["listValues"]:
            if v["type"] == "previous":
                v["value"] = prev_out.upper()
        out.append(p)
        _resign(nb, p, k)
        prev_out = p["outputValue"]
    return out, pem, {cid: base["chainIndex"]}, k


def _resign(nb, p, k):
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    msg = nb.signed_message(p)
    sig = k.sign(msg, _pad.PKCS1v15(), _h.SHA512())
    p["signatureValue"] = sig.hex().upper()
    p["outputValue"] = hashlib.sha512(msg + sig).hexdigest().upper()


class TestReviewMutants(Base):
    def test_output_value_resealed(self):
        ev = self.load(self.build())
        ev["not_before"]["payment"]["beacon"]["output_value"] = pulse("chain2_2030309.json")["outputValue"]
        p = os.path.join(self.d, "o.json"); reseal(p, ev)
        self.assertEqual(ap2.verify_evidence(p)["not_before"]["checks"]["NB1"], "failed:beacon_value_mismatch")

    def test_mandate_not_verified(self):
        ev = self.load(self.build())
        ev["artifacts"][0]["resolved_claims"]["payment_amount"]["amount"] = 1250   # same value: claims still match
        ev["artifacts"][0]["resolved_claims"]["extra_claim"] = "x"                  # claims no longer match the token
        p = os.path.join(self.d, "u.json"); reseal(p, ev)
        r = ap2.verify_evidence(p)
        self.assertEqual(r["not_before"]["checks"]["NB2"], "not_evaluated:mandate_not_verified")
        self.assertFalse(r["valid"])

    def test_minor_unit_boolean(self):
        self.assertFalse(ap2._amount_equals_minor("0.01", "EUR", True))
        self.assertTrue(ap2._amount_equals_minor("0.01", "EUR", 1))


class TestPairRules(unittest.TestCase):
    """The rules of the predecessor (cryptovalid-opencore SPEC §19 rules 2-8) on a TEST beacon's pulses (see
    _synthetic_chain): a real NIST pair cannot break them with valid signatures."""
    def setUp(self):
        self.nb = NB
        self.base = PULSE_BASE()
        self.ps, self.pem, self.pin, self.k = _synthetic_chain(NB, self.base)

    def check(self, change, want, which=1):
        ps = copy.deepcopy(self.ps)
        change(ps[which])
        _resign(NB, ps[which], self.k)
        r = NB.verify_pair(ps[1], ps[0], self.pem, self.pin)
        self.assertEqual((r["ok"], r["reason"]), (False, want))

    def test_rules(self):
        r = NB.verify_pair(self.ps[1], self.ps[0], self.pem, self.pin)
        self.assertEqual((r["ok"], r["reason"]), (True, None))
        self.assertFalse(NB.verify_pair(self.ps[1], self.ps[0], self.pem, NB.PINNED)["ok"])      # not NIST's pin
        def prev(p):
            next(v for v in p["listValues"] if v["type"] == "previous")["value"] = "AB" * 64
        self.check(prev, "previous_mismatch")
        self.check(lambda p: p.update(timeStamp="2026-11-16T12:02:00.000Z"), "period_mismatch")
        self.check(lambda p: p.update(localRandomValue="CD" * 64), "commitment_mismatch")
        self.check(lambda p: p.update(statusCode=1), "status_not_supported")
        self.check(lambda p: p.update(statusCode=4), "status_not_supported", which=0)
        def idx(p):
            p["pulseIndex"] = 102
            p["uri"] = "https://beacon.nist.gov/beacon/2.0/chain/%d/pulse/102" % p["chainIndex"]
        self.check(idx, "pulse_mismatch")
        self.check(lambda p: p.update(period=30000), "chain_inconsistent")
        ps = copy.deepcopy(self.ps)
        ps[0]["signatureValue"] = ("0" if ps[0]["signatureValue"][0] != "0" else "1") + ps[0]["signatureValue"][1:]
        self.assertEqual(NB.verify_pair(ps[1], ps[0], self.pem, self.pin)["reason"], "previous_pulse_signature_invalid")


if __name__ == "__main__":
    unittest.main()
