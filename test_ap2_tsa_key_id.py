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
        # 1.8.1 (SPEC §3.2): no certificate with that key identifier in the token or the --tsa-cert file is a signer
        # certificate not found, `null` (it was `false`); with b's TSA certificate given it is found, and the signature fails
        for pin, want in ((self.a.j("ca.crt"), None), (self.b.j("ca.crt"), None), (self.b.j("tsa.crt"), False)):
            self.assertEqual(tsa_ok(forged, pin)[0], want, pin)

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


@NEEDS
class NamesAsOpenssl(unittest.TestCase):
    """the tsa field compared as `openssl ts -verify` compares names (X509_NAME_cmp): the TSTInfo of a token with a tsa
    field in another case, other spaces or another string type, signed in both forms; the verdicts are equal"""

    @classmethod
    def setUpClass(cls):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("needs cryptography to write the names")
        cls.td = tempfile.mkdtemp()
        cls.a = Lab(cls.td, "a")
        cls.tok = cls.a.token()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def signed(self, name_der, key_id, cert="tsa.crt", general_name=None, tok=None):
        j = self.a.j
        with open(j("in.der"), "wb") as f:
            f.write(tok or self.tok)
        _run("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in.der"), "-out", j("tst.der"))
        with open(j("tst.der"), "rb") as f:
            tst = f.read()
        n = tst[1] & 0x7F if tst[1] & 0x80 else 0
        body = tst[2 + n:]
        tst2 = _tlv(0x30, body + _tlv(0xA0, general_name or _tlv(0xA4, name_der)))
        with open(j("tst2.der"), "wb") as f:
            f.write(tst2)
        _run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO, *(["-keyid"] if key_id else []),
             "-cades", "-md", "sha256", "-nosmimecap", "-signer", j(cert), "-inkey", j("tsa.key"), "-certfile",
             j("ca.crt"), "-in", j("tst2.der"), "-outform", "DER", "-out", j("n.der"))
        with open(j("n.der"), "rb") as f:
            return reply(f.read())

    def test_tsa_names(self):
        from cryptography import x509
        from cryptography.x509.name import _ASN1Type
        from cryptography.x509.oid import NameOID
        cn = "a-tsa"
        for value, typ, ok in ((cn, None, True), (cn.upper(), None, True), ("  " + cn + " ", None, True),
                               (cn, _ASN1Type.PrintableString, True), (cn + "x", None, False)):
            attr = x509.NameAttribute(NameOID.COMMON_NAME, value, typ) if typ else x509.NameAttribute(NameOID.COMMON_NAME, value)
            name = x509.Name([attr]).public_bytes()
            iss, ski = (tsa_ok(self.signed(name, k), self.a.j("ca.crt"))[0] for k in (False, True))
            self.assertEqual((iss, ski), (ok, ok), (value, typ))

    def test_tsa_in_subject_alt_name(self):
        j = self.a.j
        with open(j("san.cnf"), "w") as f:
            f.write("[ v3_san ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
                    "subjectKeyIdentifier = hash\nsubjectAltName = DNS:tsa.example\n")
        _run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("tsa_san.crt"), "-days", "2", "-extfile", j("san.cnf"), "-extensions", "v3_san")
        # a TSTInfo made after tsa_san.crt: the class's token can be a second older than this certificate's notBefore,
        # and a genTime before it is outside the validity in both forms (seen in 2 of 34 runs before this line)
        tok = self.a.token()
        for dns, ok in ((b"tsa.example", True), (b"other.example", False), (b"TSA.example", False)):
            gn = _tlv(0x82, dns)
            iss, ski = (tsa_ok(self.signed(None, k, "tsa_san.crt", gn, tok), self.a.j("ca.crt"))[0] for k in (False, True))
            self.assertEqual((iss, ski), (ok, ok), dns)


class NameEquality(unittest.TestCase):
    """the canonical comparison itself, as cryptovalid-opencore's test of the same function"""

    def setUp(self):
        try:
            from cryptography import x509  # noqa: F401
        except ImportError:
            self.skipTest("needs cryptography to write the names")

    def test_rules(self):
        from cryptography import x509
        from cryptography.x509.name import _ASN1Type
        from cryptography.x509.oid import NameOID
        N, A_ = x509.Name, x509.NameAttribute
        eq = A._ski_names_equal
        cn = lambda v, t=None: N([A_(NameOID.COMMON_NAME, v, t) if t else A_(NameOID.COMMON_NAME, v)]).public_bytes()  # noqa: E731
        self.assertTrue(eq(cn("a b"), cn("A\tB")))
        self.assertTrue(eq(cn("a b"), cn("  a   b ")))
        self.assertTrue(eq(cn("ab"), cn("ab", _ASN1Type.PrintableString)))
        self.assertFalse(eq(cn("É"), cn("é")))                  # ASCII letters only
        self.assertFalse(eq(cn("ab"), cn("a b")))
        self.assertFalse(eq(b"\x30\x00", b"\x31\x00"))                     # not a Name: never equal
        cn_o = N([A_(NameOID.COMMON_NAME, "x"), A_(NameOID.ORGANIZATION_NAME, "y")]).public_bytes()
        o_cn = N([A_(NameOID.ORGANIZATION_NAME, "y"), A_(NameOID.COMMON_NAME, "x")]).public_bytes()
        self.assertFalse(eq(cn_o, o_cn))                                    # RDNs in order
        multi = N([x509.RelativeDistinguishedName([A_(NameOID.COMMON_NAME, "x"), A_(NameOID.ORGANIZATION_NAME, "y")])])
        rdn = A._ski_items(A._ski_one(multi.public_bytes(), "n", 0x30), "n")[0][1]
        a = [A._ski_tlv(t, v) for t, v in A._ski_items(rdn, "rdn")]
        swapped = A._ski_tlv(0x30, A._ski_tlv(0x31, a[1] + a[0]))
        self.assertNotEqual(swapped, multi.public_bytes())
        self.assertTrue(eq(swapped, multi.public_bytes()))                  # one RDN: any order
        self.assertFalse(eq(cn("x"), N([A_(NameOID.ORGANIZATION_NAME, "x")]).public_bytes()))   # the OID counts
        ge = A._ski_general_names_equal
        self.assertFalse(ge((0x82, cn_o), (0xA4, cn_o)))                     # the type counts
        self.assertTrue(ge((0xA4, cn("a")), (0xA4, cn("A"))))
        self.assertFalse(ge((0x82, b"tsa.example"), (0x82, b"TSA.example")))   # bytes, not a Name


@NEEDS
class ClosedShapes(unittest.TestCase):
    """SPEC §3.2: the key-id step closed (measured on 2026-11-17 with omega-cra-evol's generative bench): one
    SignerInfo (RFC 3161 §2.4.2), and an openssl too old for `verify -no-CAstore` is a check not run. Positive control:
    on the head before this change the two-signer token passed this step and the old openssl gave a refusal."""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.a, cls.b = Lab(cls.td, "a"), Lab(cls.td, "b")
        cls.tok = cls.a.token()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def two_signers(self, key_id):
        j, o = self.a.j, self.b.j
        with open(j("in2.der"), "wb") as f:
            f.write(self.tok)
        _run("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in2.der"), "-out", j("tst2.der"))
        _run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO, *(["-keyid"] if key_id else []),
             "-cades", "-md", "sha256", "-nosmimecap", "-signer", j("tsa.crt"), "-inkey", j("tsa.key"),
             "-signer", o("tsa.crt"), "-inkey", o("tsa.key"), "-certfile", j("ca.crt"), "-in", j("tst2.der"),
             "-outform", "DER", "-out", j("two.der"))
        with open(j("two.der"), "rb") as f:
            return reply(f.read())

    def both_cas(self):
        p = os.path.join(self.td, "both.pem")
        with open(p, "wb") as f:
            f.write(open(self.a.j("ca.crt"), "rb").read() + open(self.b.j("ca.crt"), "rb").read())
        return p

    def test_two_signer_infos(self):
        pin = self.both_cas()
        ski, iss = self.two_signers(True), self.two_signers(False)
        self.assertEqual(tsa_ok(ski, pin)[0], False)
        self.assertIn("2 SignerInfos", tsa_ok(ski, pin)[1])
        self.assertEqual(tsa_ok(iss, pin)[0], False)          # the other form: openssl ts -verify refuses two signers
        self.assertEqual(tsa_ok(reply(self.a.resign(self.tok, key_id=True)), self.a.j("ca.crt"))[0], True)   # control

    def test_policies_shape(self):
        oid = _tlv(0x06, bytes.fromhex("2a0304"))
        ok = [(0x30, _tlv(0x30, oid)), (0x30, _tlv(0x30, oid + _tlv(0x30, b""))), (0x30, b"")]
        bad = [(0x31, _tlv(0x30, oid)), (0x30, _tlv(0x31, oid)), (0x30, _tlv(0x30, b"")), (0x30, _tlv(0x30, _tlv(0x02, b"\x01"))),
               (0x04, b"x")]
        for el in ok:
            self.assertTrue(A._ski_policies_shape(el), el)
        for el in bad:
            self.assertFalse(A._ski_policies_shape(el), el)

    def old_openssl(self):
        import stat
        bindir = os.path.join(self.td, "bin")
        os.makedirs(bindir, exist_ok=True)
        fake = os.path.join(bindir, "openssl")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nif [ \"$1\" = verify ]; then echo 'verify: Unknown option: -no-CAstore' >&2; exit 1; fi\n"
                    "exec %s \"$@\"\n" % shutil.which("openssl"))
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        return bindir

    def test_openssl_without_no_castore(self):
        bindir, old = self.old_openssl(), os.environ["PATH"]
        os.environ["PATH"] = bindir + os.pathsep + old
        try:
            r = A._verify_rfc3161(base64.b64encode(reply(self.a.resign(self.tok, key_id=True))).decode(), DIGEST.hex(),
                                  tsa_cert=self.a.j("ca.crt"))
            self.assertIsNone(r["tsa_verified"], r)
            self.assertIn("check not run here", r["tsa_note"])
            self.assertTrue(r["_not_run"])
            self.assertEqual(tsa_ok(reply(self.a.resign(self.tok, key_id=False)), self.a.j("ca.crt"))[0], True)   # other form
        finally:
            os.environ["PATH"] = old


if __name__ == "__main__":
    unittest.main()
