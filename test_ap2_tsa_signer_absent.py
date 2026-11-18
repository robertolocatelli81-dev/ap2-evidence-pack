#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.1, SPEC §3.2 and §6.9: an RFC 3161 token whose signer certificate is not found is `tsa_verified: null` with
`tsa_reason: "signer_certificate_absent"` and `time_anchor` `not_evaluated / signer_certificate_absent`, not `false` /
`tsa_invalid` (ETSI EN 319 102-1 V1.4.1 §5.2.3.3: INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND).

Positive control: on v1.8.0 (d5601e4) such a token is `tsa_verified: false` (openssl "signer certificate not found");
measured on 2026-11-18, `test_generative` and `test_pack_time_bounds` fail there. Every token is made here with
openssl (test_ap2_tsa_key_id.Lab), in both SignerInfo forms (issuer and serial number, subjectKeyIdentifier), with its
certificates kept or removed (as certReq FALSE), under the own CA, the own CA and the TSA certificate, or another CA,
intact or with its signature altered."""
import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
import test_ap2_tsa_key_id as K  # noqa: E402


def tlv(tag, v):
    return A._ski_tlv(tag, v)


def strip_certs(token):
    ci = A._ski_items(A._ski_one(token, "ContentInfo", 0x30), "ContentInfo")
    sd = A._ski_items(A._ski_one(ci[1][1], "SignedData", 0x30), "SignedData")
    assert any(t == 0xA0 for t, _ in sd[3:-1])
    return tlv(0x30, tlv(*ci[0]) + tlv(0xA0, tlv(0x30, b"".join(tlv(t, v) for t, v in sd if t != 0xA0))))


def alter(token):
    si = A._ski_items(A._ski_items(A._ski_items(A._ski_one(A._ski_items(A._ski_one(token, "c", 0x30), "c")[1][1], "s", 0x30),
                                                "s")[-1][1], "sis")[0][1], "si")
    sig = [v for t, v in si if t == 0x04][-1]
    i = token.index(sig) + len(sig) // 2
    return token[:i] + bytes([token[i] ^ 1]) + token[i + 1:]


def expected(form, kept, pin, intact):
    """SPEC §3.2 (1.8.1): where the check looks for the signer — the token's certificates; for the key-identifier form
    also the --tsa-cert file"""
    found = kept or (form == "ski" and pin == "own+leaf")
    if not found:
        return None, "signer_certificate_absent"
    if pin == "other" or not intact:
        return False, None
    return True, None


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class SignerAbsent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.a, cls.b = K.Lab(cls.td, "a"), K.Lab(cls.td, "b")
        tok = cls.a.token()
        cls.tokens = {"ias": cls.a.resign(tok, key_id=False), "ski": cls.a.resign(tok, key_id=True)}
        with open(os.path.join(cls.td, "own_leaf.pem"), "wb") as f:
            f.write(open(cls.a.j("ca.crt"), "rb").read() + open(cls.a.j("tsa.crt"), "rb").read())
        cls.pins = {"own": cls.a.j("ca.crt"), "own+leaf": os.path.join(cls.td, "own_leaf.pem"), "other": cls.b.j("ca.crt")}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def test_generative(self):
        n = 0
        for form, base in self.tokens.items():
            for kept in (True, False):
                for pin in self.pins:
                    for intact in (True, False):
                        tok = base if kept else strip_certs(base)
                        tok = tok if intact else alter(tok)
                        r = A._verify_rfc3161(base64.b64encode(K.reply(tok)).decode(), K.DIGEST.hex(), tsa_cert=self.pins[pin])
                        want = expected(form, kept, pin, intact)
                        with self.subTest(form=form, kept=kept, pin=pin, intact=intact):
                            self.assertEqual((r["tsa_verified"], r.get("tsa_reason")), want, r.get("tsa_note"))
                            self.assertIs(r["verified"], True)   # the binding does not change
                            el = A._anchor_element(r, True)
                            self.assertEqual(el[:2], {True: ("verified", None), False: ("not_evaluated", "tsa_invalid"),
                                                      None: ("not_evaluated", "signer_certificate_absent")}[want[0]])
                        n += 1
        self.assertEqual(n, 24)

    def test_absence_is_never_presumed(self):
        tok = K.reply(strip_certs(self.tokens["ski"]))
        good = open(self.a.j("ca.crt"), "rb").read()
        self.assertTrue(A.tsa_signer_certificate_absent(tok, good))
        self.assertFalse(A.tsa_signer_certificate_absent(tok, good + b"-----BEGIN CERTIFICATE-----\nAAAA\n"))
        self.assertFalse(A.tsa_signer_certificate_absent(b"\x30\x00"))

    def test_issuer_compared_as_openssl_compares_names(self):
        """the sid's issuer is compared as X509_NAME_cmp (canonical: case and spaces folded), not byte for byte: the same
        token with the issuer of its sid written in upper case still names the certificate it carries, and openssl
        verifies it — it must not become `signer_certificate_absent`"""
        from cryptography import x509
        base = self.tokens["ias"]
        ca_cn = x509.load_pem_x509_certificate(open(self.a.j("ca.crt"), "rb").read()).subject.rfc4514_string().encode()
        ci = A._ski_items(A._ski_one(base, "c", 0x30), "c")
        sd = A._ski_items(A._ski_one(ci[1][1], "s", 0x30), "s")
        sid = A._ski_items(A._ski_items(sd[-1][1], "sis")[0][1], "si")[1]
        sid_tlv = A._ski_tlv(*sid)
        at = base.rfind(sid_tlv)
        self.assertGreater(at, 0)
        cn = ca_cn.split(b"=", 1)[1].split(b",")[0]
        j = base.index(cn, at)
        self.assertLess(j, at + len(sid_tlv))
        self.assertNotEqual(cn.upper(), cn)
        tok = base[:j] + cn.upper() + base[j + len(cn):]
        self.assertFalse(A.tsa_signer_certificate_absent(tok, open(self.a.j("ca.crt"), "rb").read()))
        r = A._verify_rfc3161(base64.b64encode(K.reply(tok)).decode(), K.DIGEST.hex(), tsa_cert=self.pins["own"])
        self.assertEqual((r["tsa_verified"], r.get("tsa_reason")), (True, None), r.get("tsa_note"))

    def test_unreadable_pin_presumes_nothing(self):
        """a --tsa-cert file that cannot be read (library call; the CLI makes it a usage error) is reported by openssl as
        before (`tsa_verified: false`), never turned into `signer_certificate_absent`: the absence is never presumed"""
        missing = os.path.join(self.td, "no-such-pin.pem")
        for form, base in self.tokens.items():
            r = A._verify_rfc3161(base64.b64encode(K.reply(strip_certs(base))).decode(), K.DIGEST.hex(), tsa_cert=missing)
            with self.subTest(form=form):
                self.assertIs(r["tsa_verified"], False, r.get("tsa_note"))
                self.assertNotIn("tsa_reason", r)

    def test_pack_time_bounds(self):
        """a pack anchored by such a token, verified under --tsa-cert: no proven upper bound — not counted, no
        existed-by time, --require-anchor unmet; the binding and `valid` unchanged"""
        d = tempfile.mkdtemp(prefix="ap2tsa_")
        try:
            import test_ap2_evidence as E
            sk, jwk = E._make_signer()
            sd = E._make_sd_jwt(sk, {"iss": "w"}, {"amount": "10.00"}, header_extra={"jwk": jwk})
            out = os.path.join(d, "p.json")
            A.build_evidence([{"name": "m", "sd_jwt": sd}], out)
            ev = json.load(open(out, encoding="utf-8"))
            digest = bytes.fromhex(ev["evidence_digest_sha256"])
            K.DIGEST, old = digest, K.DIGEST
            try:
                tok = self.a.token()
            finally:
                K.DIGEST = old
            for kept, want in ((True, ("verified", 1)), (False, ("signer_certificate_absent", 0))):
                t = tok if kept else strip_certs(tok)
                ev["rfc3161_timestamp"] = {"anchored": True, "tsr_b64": base64.b64encode(K.reply(t)).decode()}
                json.dump(ev, open(out, "w", encoding="utf-8"))
                r = A.verify_evidence(out, tsa_cert=self.a.j("ca.crt"), require_anchor=True)
                ta = r["states"]["time_anchor"]
                got = ("verified" if ta["state"] == "verified" else ta["reasons"][0], r["anchors_verified"])
                with self.subTest(kept=kept):
                    self.assertEqual(got, want, ta)
                    self.assertIs(r["rfc3161"]["verified"], True)
                    self.assertEqual(r["policy"]["unmet"], [] if kept else ["require_anchor"])
                    self.assertEqual(r["valid"], kept)   # valid falls only through the require-anchor policy
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
