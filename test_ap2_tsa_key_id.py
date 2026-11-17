#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.0, SPEC §3.2: an RFC 3161 token whose SignerInfo names its signer by subjectKeyIdentifier (RFC 5652 §5.3).

`openssl ts -verify` cannot read that form, so a valid token was `tsa_verified: false` (positive control: on the head
before this change the valid key-identified token below is false, measured on 2026-11-17). Every case is made with
openssl here and signed twice from the same TSTInfo, keys and certificates: with the signer named by issuer and serial
number (checked by `openssl ts -verify`, as before) and by key identifier (checked step by step); the two verdicts must be
equal, which is the rule of SPEC §3.2, and equal to the expected one."""
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl"), "needs openssl")


def _run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True)


DIGEST = hashlib.sha256(b"a payment ledger head").digest()
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
EXT = ("[ v3_ca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
       "subjectKeyIdentifier = hash\n"
       "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
       "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
       "[ v3_plain ]\nbasicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nsubjectKeyIdentifier = hash\n"
       "[ v3_badca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature\n"
       "subjectKeyIdentifier = hash\n")


class Lab:
    """a CA with a subjectKeyIdentifier and the certificates it issued, all made by openssl (as in cryptovalid-opencore's
    test_tsa_signer_key_id_20261116.py); tokens by `openssl ts -reply`, signed again by `openssl cms -sign`"""

    def __init__(self, td, name, ca_ext="v3_ca"):
        self.d = os.path.join(td, name)
        os.makedirs(self.d)
        j = self.j
        with open(j("ext.cnf"), "w") as f:
            f.write(EXT)
        with open(j("req.cnf"), "w") as f:
            f.write("[ req ]\ndistinguished_name = dn\n[ dn ]\n" + EXT)
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", j("ca.key"), "-out", j("ca.crt"), "-subj", "/CN=%s-ca" % name, "-days", "2",
             "-config", j("req.cnf"), "-extensions", ca_ext)
        for cert, ext in (("tsa", "v3_tsa"), ("plain", "v3_plain")):
            _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-keyout", j(cert + ".key"), "-out", j(cert + ".csr"), "-subj", "/CN=%s-%s" % (name, cert),
                 "-config", j("req.cnf"))
            _run("openssl", "x509", "-req", "-in", j(cert + ".csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"),
                 "-CAcreateserial", "-out", j(cert + ".crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", ext)
        with open(j("serial"), "w") as f:
            f.write("01\n")

    def j(self, n):
        return os.path.join(self.d, n)

    def token(self, tsa_name=False):
        """a token of `openssl ts -reply` (a ContentInfo); `tsa_name`: the TSTInfo carries the tsa field"""
        j = self.j
        with open(j("tsa.cnf"), "w") as f:
            f.write("[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = %s\ncrypto_device = builtin\nsigner_cert = %s\n"
                    "certs = %s\nsigner_key = %s\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\n"
                    "accuracy = secs:1\nordering = yes\ntsa_name = %s\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n"
                    % (j("serial"), j("tsa.crt"), j("ca.crt"), j("tsa.key"), "yes" if tsa_name else "no"))
        _run("openssl", "ts", "-query", "-digest", DIGEST.hex(), "-sha256", "-cert", "-out", j("q.tsq"))
        _run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1",
             "-token_out", "-out", j("tok.der"))
        with open(j("tok.der"), "rb") as f:
            return f.read()

    def resign(self, token, signer="tsa", ess=True, key_id=True):
        """the TSTInfo of `token` signed again with `signer`'s key; the signer named by its key identifier (`key_id`) or
        by issuer and serial number"""
        j = self.j
        with open(j("in.der"), "wb") as f:
            f.write(token)
        _run("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in.der"), "-out", j("tst.der"))
        _run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO,
             *(["-keyid"] if key_id else []), *(["-cades"] if ess else []), "-md", "sha256", "-nosmimecap",
             "-signer", j(signer + ".crt"), "-inkey", j(signer + ".key"), "-certfile", j("ca.crt"), "-in", j("tst.der"),
             "-outform", "DER", "-out", j("re.der"))
        with open(j("re.der"), "rb") as f:
            return f.read()


def reply(token):
    """a granted TimeStampResp around a token: SEQUENCE { PKIStatusInfo { 0 }, token }"""
    def tlv(tag, v):
        n = len(v)
        ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag]) + ln + v
    return tlv(0x30, tlv(0x30, b"\x02\x01\x00") + token)


def ski_of(cert_path):
    out = _run("openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectKeyIdentifier").stdout.decode()
    return bytes.fromhex(out.strip().splitlines()[-1].strip().replace(":", ""))


def _tlv(tag, v):
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def _oid(s):
    a = [int(x) for x in s.split(".")]
    out = bytes([40 * a[0] + a[1]])
    for v in a[2:]:
        b = [v & 0x7F]
        v >>= 7
        while v:
            b.insert(0, 0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(b)
    return _tlv(0x06, out)


def crafted(lab, token, ess="ok"):
    """the TSTInfo of `token` in a SignedData built here and signed with lab's TSA key (ECDSA P-256, SHA-256), the signer
    named by key identifier, with an ESS signingCertificateV2 attribute shaped by `ess`: ok, bad_hash, two_ids,
    two_values, bad_serial, bad_issuer (the cases openssl cannot write)"""
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
    cder = cert.public_bytes(serialization.Encoding.DER)
    h = hashlib.sha256(cder).digest()
    if ess == "bad_hash":
        h = bytes([h[0] ^ 1]) + h[1:]
    serial = cert.serial_number + (1 if ess == "bad_serial" else 0)
    issuer = cert.issuer.public_bytes() if ess != "bad_issuer" else ca.subject.public_bytes()[:-1] + b"X"
    iss_serial = _tlv(0x30, _tlv(0x30, _tlv(0xA4, issuer)) + _tlv(0x02, serial.to_bytes(serial.bit_length() // 8 + 1, "big")))
    cid = _tlv(0x30, _tlv(0x04, h) + (iss_serial if ess in ("bad_serial", "bad_issuer") else b""))
    sc = _tlv(0x30, _tlv(0x30, cid + (cid if ess == "two_ids" else b"")))
    ess_attr = _tlv(0x30, _oid("1.2.840.113549.1.9.16.2.47") + _tlv(0x31, sc + (sc if ess == "two_values" else b"")))
    attrs = [_tlv(0x30, _oid("1.2.840.113549.1.9.3") + _tlv(0x31, _oid("1.2.840.113549.1.9.16.1.4"))),
             _tlv(0x30, _oid("1.2.840.113549.1.9.4") + _tlv(0x31, _tlv(0x04, hashlib.sha256(tst).digest()))), ess_attr]
    if ess == "two_attributes":   # the attribute twice, the second naming another certificate
        bad = _tlv(0x30, _tlv(0x30, _tlv(0x30, _tlv(0x04, bytes(32)))))
        attrs.append(_tlv(0x30, _oid("1.2.840.113549.1.9.16.2.47") + _tlv(0x31, bad)))
    sa = b"".join(sorted(attrs))
    sig = key.sign(_tlv(0x31, sa), ec.ECDSA(hashes.SHA256()))
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    sha256 = _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1"))
    si = _tlv(0x30, _tlv(0x02, b"\x03") + _tlv(0x80, ski) + sha256 + _tlv(0xA0, sa)
              + _tlv(0x30, _oid("1.2.840.10045.4.3.2")) + _tlv(0x04, sig))
    sd = _tlv(0x30, _tlv(0x02, b"\x03") + _tlv(0x31, sha256)
              + _tlv(0x30, _oid("1.2.840.113549.1.9.16.1.4") + _tlv(0xA0, _tlv(0x04, tst)))
              + _tlv(0xA0, cder + ca.public_bytes(serialization.Encoding.DER)) + _tlv(0x31, si))
    return _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, sd))


class ChainLab(Lab):
    """root -> intermediate -> TSA; the intermediate is carried only in the token"""

    def __init__(self, td, name):
        Lab.__init__(self, td, name)
        j = self.j
        _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("int.key"),
             "-out", j("int.csr"), "-subj", "/CN=%s-int" % name, "-config", j("req.cnf"))
        _run("openssl", "x509", "-req", "-in", j("int.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("int.crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", "v3_ca")
        _run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("int.crt"), "-CAkey", j("int.key"),
             "-CAcreateserial", "-out", j("tsa.crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", "v3_tsa")
        shutil.copy(j("ca.crt"), j("root.crt"))
        shutil.copy(j("int.crt"), j("ca.crt"))   # resign() and token() put "ca.crt" in the token: here the intermediate


def tsa_ok(der, pin):
    r = A._verify_rfc3161(base64.b64encode(der).decode(), DIGEST.hex(), tsa_cert=pin)
    return r["tsa_verified"], r.get("tsa_note")


@NEEDS
class SignerByKeyId(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.a, cls.b = Lab(cls.td, "a"), Lab(cls.td, "b")
        cls.bad = Lab(cls.td, "badca", ca_ext="v3_badca")
        cls.tok = cls.a.token()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def both(self, lab, token, pin, **kw):
        """(verdict of the issuer-and-serial form, verdict of the key-identifier form)"""
        iss = reply(lab.resign(token, key_id=False, **kw))
        ski = reply(lab.resign(token, key_id=True, **kw))
        self.assertFalse(A.signer_named_by_key_id(iss))
        self.assertTrue(A.signer_named_by_key_id(ski))
        return tsa_ok(iss, pin)[0], tsa_ok(ski, pin)[0]

    def test_valid_token_named_by_key_id(self):
        self.assertEqual(self.both(self.a, self.tok, self.a.j("ca.crt")), (True, True))
        self.assertEqual(tsa_ok(reply(self.tok), self.a.j("ca.crt"))[0], True)       # openssl ts -reply's own token

    def test_same_verdict_as_openssl_ts_for_the_other_form(self):
        cases = [  # (lab, token, pin, options, expected)
            (self.a, self.tok, self.a.j("ca.crt"), {}, True),
            (self.a, self.tok, self.a.j("tsa.crt"), {}, False),                     # a leaf alone: no partial chain here
            (self.a, self.tok, self.b.j("ca.crt"), {}, False),                      # another CA pinned
            (self.b, self.tok, self.a.j("ca.crt"), {}, False),                      # another TSA's key
            (self.a, self.tok, self.a.j("ca.crt"), {"signer": "plain"}, False),     # no timeStamping
            (self.bad, self.bad.token(), self.bad.j("ca.crt"), {}, None),           # a CA without keyCertSign
            (self.a, self.a.token(tsa_name=True), self.a.j("ca.crt"), {}, True),    # tsa names this TSA
            (self.a, self.b.token(tsa_name=True), self.a.j("ca.crt"), {}, False),   # tsa names another TSA
        ]
        for lab, token, pin, kw, expected in cases:
            iss, ski = self.both(lab, token, pin, **kw)
            self.assertEqual(ski, iss, (lab.d, pin, kw))
            if expected is not None:
                self.assertEqual(ski, expected, (lab.d, pin, kw))

    def test_no_ess_attribute(self):
        v, note = tsa_ok(reply(self.a.resign(self.tok, ess=False)), self.a.j("ca.crt"))
        self.assertEqual(v, False)
        self.assertIn("ESS", note)

    def test_key_id_of_another_certificate(self):
        mine, theirs = ski_of(self.a.j("tsa.crt")), ski_of(self.b.j("tsa.crt"))
        tok = self.a.resign(self.tok)
        sid = bytes([0x80, len(mine)]) + mine
        self.assertEqual(tok.count(sid), 1)
        forged = reply(tok.replace(sid, bytes([0x80, len(theirs)]) + theirs))
        self.assertTrue(A.signer_named_by_key_id(forged))
        for pin in (self.a.j("ca.crt"), self.b.j("ca.crt"), self.b.j("tsa.crt")):
            self.assertEqual(tsa_ok(forged, pin)[0], False, pin)

    def test_the_system_store_is_not_a_pin(self):
        store = os.path.join(self.td, "store")
        os.makedirs(store, exist_ok=True)
        shutil.copy(self.b.j("ca.crt"), os.path.join(store, "b-ca.pem"))
        _run("openssl", "rehash", store)
        ski = reply(self.b.resign(self.tok))
        old = os.environ.get("SSL_CERT_DIR")
        os.environ["SSL_CERT_DIR"] = store
        try:
            r = subprocess.run(["openssl", "verify", "-purpose", "timestampsign", self.b.j("tsa.crt")], capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)                  # control: openssl trusts the directory
            v = tsa_ok(ski, self.a.j("ca.crt"))[0]
        finally:
            if old is None:
                del os.environ["SSL_CERT_DIR"]
            else:
                os.environ["SSL_CERT_DIR"] = old
        self.assertEqual(v, False)

    def test_imprint_and_gen_time(self):
        tok = reply(self.a.resign(self.tok))
        r = A._verify_rfc3161(base64.b64encode(tok).decode(), "00" * 32, tsa_cert=self.a.j("ca.crt"))
        self.assertEqual((r["verified"], r["imprint_ok"], r["tsa_verified"]), (False, False, False))
        self.assertIsNone(A.key_id_token_problem(tok, DIGEST.hex(), self.a.j("ca.crt"), __import__("time").time(), self.td))
        self.assertIsNotNone(A.key_id_token_problem(tok, DIGEST.hex(), self.a.j("ca.crt"),
                                                    __import__("time").time() + 10 * 86400, self.td))   # 2-day certificates


@NEEDS
class CraftedEss(unittest.TestCase):
    """ESS attributes openssl cannot write, in a SignedData signed here with the TSA's key (the signature verifies, so
    each check of the attribute is reached)"""

    @classmethod
    def setUpClass(cls):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("needs cryptography to sign the crafted SignedData")
        cls.td = tempfile.mkdtemp()
        cls.a = Lab(cls.td, "a")
        cls.tok = cls.a.token()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def test_each_shape(self):
        for ess, ok in (("ok", True), ("bad_hash", False), ("two_ids", False), ("two_values", False),
                        ("bad_serial", False), ("bad_issuer", False), ("two_attributes", False)):
            v, note = tsa_ok(reply(crafted(self.a, self.tok, ess)), self.a.j("ca.crt"))
            self.assertEqual(v, ok, (ess, note))

    def test_a_broken_signature(self):
        tok = bytearray(crafted(self.a, self.tok))
        tok[-1] ^= 1                                                     # the last byte of the ECDSA signature
        self.assertEqual(tsa_ok(reply(bytes(tok)), self.a.j("ca.crt"))[0], False)


@NEEDS
class IntermediateInTheToken(unittest.TestCase):
    def test_same_verdict_with_an_intermediate_only_in_the_token(self):
        td = tempfile.mkdtemp()
        try:
            c = ChainLab(td, "c")
            tok = c.token()
            iss, ski = reply(c.resign(tok, key_id=False)), reply(c.resign(tok))
            self.assertEqual((tsa_ok(iss, c.j("root.crt"))[0], tsa_ok(ski, c.j("root.crt"))[0]), (True, True))
        finally:
            shutil.rmtree(td)


if __name__ == "__main__":
    unittest.main()
