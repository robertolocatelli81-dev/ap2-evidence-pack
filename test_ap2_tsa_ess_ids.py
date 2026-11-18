#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.0, SPEC §3.2: a signingCertificate(V2) attribute with more than one ESSCertID, on the key-identifier path.

RFC 2634 §5.4 as RFC 5035 rewrites it (read on rfc-editor.org on 2026-11-18; RFC 2634 updated by 5035, neither
obsoleted): the first ESSCertID MUST be the certificate that verifies the signature; the ones after it "limit the set of
certificates that are used during validation". Up to 1.8.x the key-identifier step refused any list longer than one
("exactly one is evaluated here"), so a TSA that lists its chain (openssl `ess_cert_id_chain = yes`, Sectigo) was
`tsa_verified: false` there. Now: the first must be the signer (hash, and issuerSerial when present); every ESSCertID has
the closed shape (a known algorithm, a certHash of that algorithm's length, no certificate listed twice); a later one
that hashes a certificate of the token must name it in its issuerSerial when it has one; and the path may use, besides
the pinned certificates, only the token certificates a later ESSCertID names. Positive control: on 6728413 (before 1.9.0's
chains and this change) 3 of the 4 tests fail; `test_one_id_as_before` is the control and passes on both."""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
from test_ap2_tsa_key_id import NEEDS, ChainLab, Lab, _oid, _run, _tlv, reply, tsa_ok  # noqa: E402


def crafted_ids(lab, token, ids):
    """the TSTInfo of `token` signed with lab's TSA key, signer named by key identifier, one signingCertificateV2 whose
    ESSCertIDs are `ids`: "signer", "ca" (the certificate lab puts in the token beside the signer), "rand" (a hash of
    nothing here), "short" (a 20-byte certHash), "ca_bad_serial" (the ca's hash with an issuerSerial naming another
    serial)"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    j = lab.j
    with open(j("in.der"), "wb") as f:
        f.write(token)
    _run("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in.der"), "-out", j("tst.der"))
    with open(j("tst.der"), "rb") as f:
        tst = f.read()
    with open(j("tsa.crt"), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(j("ca.crt"), "rb") as f:
        ca = x509.load_pem_x509_certificate(f.read())
    with open(j("tsa.key"), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), None)
    cder, cader = cert.public_bytes(serialization.Encoding.DER), ca.public_bytes(serialization.Encoding.DER)
    out = b""
    for i in ids:
        if i == "signer":
            out += _tlv(0x30, _tlv(0x04, hashlib.sha256(cder).digest()))
        elif i == "ca":
            out += _tlv(0x30, _tlv(0x04, hashlib.sha256(cader).digest()))
        elif i == "rand":
            out += _tlv(0x30, _tlv(0x04, hashlib.sha256(b"no certificate").digest()))
        elif i == "short":
            out += _tlv(0x30, _tlv(0x04, hashlib.sha1(cader).digest()))
        elif i == "ca_bad_serial":
            s = ca.serial_number + 1
            iss = _tlv(0x30, _tlv(0x30, _tlv(0xA4, ca.issuer.public_bytes())) + _tlv(0x02, s.to_bytes(s.bit_length() // 8 + 1, "big")))
            out += _tlv(0x30, _tlv(0x04, hashlib.sha256(cader).digest()) + iss)
    sc = _tlv(0x30, _tlv(0x30, out))
    ess_attr = _tlv(0x30, _oid("1.2.840.113549.1.9.16.2.47") + _tlv(0x31, sc))
    attrs = [_tlv(0x30, _oid("1.2.840.113549.1.9.3") + _tlv(0x31, _oid("1.2.840.113549.1.9.16.1.4"))),
             _tlv(0x30, _oid("1.2.840.113549.1.9.4") + _tlv(0x31, _tlv(0x04, hashlib.sha256(tst).digest()))), ess_attr]
    sa = b"".join(sorted(attrs))
    sig = key.sign(_tlv(0x31, sa), ec.ECDSA(hashes.SHA256()))
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    sha256 = _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1"))
    si = _tlv(0x30, _tlv(0x02, b"\x03") + _tlv(0x80, ski) + sha256 + _tlv(0xA0, sa)
              + _tlv(0x30, _oid("1.2.840.10045.4.3.2")) + _tlv(0x04, sig))
    sd = _tlv(0x30, _tlv(0x02, b"\x03") + _tlv(0x31, sha256)
              + _tlv(0x30, _oid("1.2.840.113549.1.9.16.1.4") + _tlv(0xA0, _tlv(0x04, tst)))
              + _tlv(0xA0, cder + cader) + _tlv(0x31, si))
    return _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, sd))


@NEEDS
class EssCertIds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.a = Lab(cls.td, "a")
        cls.c = ChainLab(cls.td, "c")
        cls.tok_a, cls.tok_c = cls.a.token(), cls.c.token()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def v(self, lab, tok, ids, pin):
        der = reply(crafted_ids(lab, tok, ids))
        self.assertTrue(A.signer_named_by_key_id(der))
        return tsa_ok(der, pin)

    def test_chain_listed_after_the_signer(self):   # CA pinned and in the token; intermediate only in the token
        self.assertEqual(self.v(self.a, self.tok_a, ["signer", "ca"], self.a.j("ca.crt"))[0], True)
        self.assertEqual(self.v(self.c, self.tok_c, ["signer", "ca"], self.c.j("root.crt"))[0], True)

    def test_later_ids_limit_the_path(self):
        # the intermediate is in the token but no later ESSCertID names it: the path to the root may not use it
        v, note = self.v(self.c, self.tok_c, ["signer", "rand"], self.c.j("root.crt"))
        self.assertEqual(v, False, note)
        # the pin issues the signer directly: no token certificate is needed
        self.assertEqual(self.v(self.a, self.tok_a, ["signer", "rand"], self.a.j("ca.crt"))[0], True)

    def test_one_id_as_before(self):   # control: one ESSCertID sets no limit, the intermediate of the token is used
        self.assertEqual(self.v(self.c, self.tok_c, ["signer"], self.c.j("root.crt"))[0], True)
        self.assertEqual(self.v(self.a, self.tok_a, ["signer"], self.a.j("ca.crt"))[0], True)

    def test_refused_shapes(self):
        for ids, why in ((["ca", "signer"], "not the hash of the signer"), (["signer", "signer"], "listed twice"),
                         (["signer", "ca", "ca"], "listed twice"), (["signer", "short"], "certHash is not a sha256"),
                         (["signer", "ca_bad_serial"], "does not name the certificate it hashes"), ([], "no ESSCertID")):
            with self.subTest(ids=ids):
                v, note = self.v(self.a, self.tok_a, ids, self.a.j("ca.crt"))
                self.assertEqual(v, False, note)
                self.assertIn(why, note or "")


if __name__ == "__main__":
    unittest.main()
