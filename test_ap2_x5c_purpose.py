#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.1, SPEC §6 step 7 and §6.9: a validated x5c chain clears `self_asserted_only` only when the leaf was issued for
signing — keyUsage (RFC 5280 §4.2.1.3) with digitalSignature or nonRepudiation/contentCommitment, extendedKeyUsage
(§4.2.1.12) with anyExtendedKeyUsage or id-kp-documentSigning (RFC 9336). `x5c_leaf.key_purpose` is the same object in
both verifiers.

Up to 1.9.0 neither extension was read: measured on 2026-11-20 on 1.9.0, a leaf with keyUsage keyCertSign only and
extendedKeyUsage serverAuth only, under the relying party's anchor, gave `chain_verified: true`,
`self_asserted_only: false`, `issuer_identity` `verified / ca_certified`.

What is measured here:
- generated leaves (keyUsage subsets, extendedKeyUsage lists drawn from ten KeyPurposeIds, critical flags, other
  extensions around them, extension order): the reference's answer equals the one computed from the generator's own
  parameters, and the JS verifier's answer equals the reference's;
- extension values written by hand (malformed, duplicated, at the edge of the DER rules), and byte mutations of a real
  leaf: both verifiers give the same answer and neither raises;
- the whole path with openssl: chain under the anchor + leaf not for signing → `chain_verified: true`, the flag stays
  set, `issuer_identity` `contradicted / key_purpose_not_signing`, `valid` unchanged; leaves for signing → `ca_certified`;
  and the JS CLI reports the same `key_purpose` for the same pack.
On 1.9.0 every test here fails or errors except the two controls (`test_controls_*`)."""
import base64
import datetime
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier  # noqa: E402

OPENSSL = shutil.which("openssl")
NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")

KU_FLAGS = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
            "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
ANY_EKU = ObjectIdentifier("2.5.29.37.0")
DOC_SIGNING = ObjectIdentifier("1.3.6.1.5.5.7.3.36")
EKU_POOL = (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.CODE_SIGNING,
            ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.OCSP_SIGNING,
            ANY_EKU, DOC_SIGNING, ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"), ObjectIdentifier("1.2.3.4.5"))
SIGNING_EKUS = {ANY_EKU, DOC_SIGNING}
PLACEHOLDER_A, PLACEHOLDER_B = ObjectIdentifier("2.5.29.98"), ObjectIdentifier("2.5.29.99")   # 55 1d 62 / 55 1d 63
KU_OID, EKU_OID = bytes.fromhex("551d0f"), bytes.fromhex("551d25")
_KEY = ec.generate_private_key(ec.SECP256R1())


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _builder(cn="leaf", issuer="leaf", pub=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(pub or _KEY.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30)))


def _ku(flags):
    return x509.KeyUsage(**{f: f in flags for f in KU_FLAGS})


def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def expected(ku_flags, ekus):
    """The rule of SPEC §6 step 7 written from the generator's parameters, not from the certificate."""
    if ku_flags is not None and not ({"digital_signature", "content_commitment"} & set(ku_flags)):
        return {"signing": False, "reason": "key_usage_not_signing"}
    if ekus is not None and not (SIGNING_EKUS & set(ekus)):
        return {"signing": False, "reason": "extended_key_usage_not_signing"}
    return {"signing": True, "reason": None}


def generated_leaves(n=400, seed=20261120):
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        ku = None if rnd.random() < 0.25 else [f for f in KU_FLAGS if rnd.random() < 0.3]
        if ku is not None:
            if not ku:
                ku = [rnd.choice(KU_FLAGS[:7])]   # RFC 5280 §4.2.1.3: at least one bit; the builder refuses none
            if ("encipher_only" in ku or "decipher_only" in ku) and "key_agreement" not in ku:
                ku.append("key_agreement")         # the builder refuses encipher/decipher_only without key_agreement
        ekus = None if rnd.random() < 0.3 else rnd.sample(EKU_POOL, rnd.randint(1, 4))
        exts = []
        if ku is not None:
            exts.append((_ku(ku), rnd.random() < 0.5))
        if ekus is not None:
            exts.append((x509.ExtendedKeyUsage(ekus), rnd.random() < 0.3))
        if rnd.random() < 0.5:
            exts.append((x509.BasicConstraints(ca=False, path_length=None), True))
        if rnd.random() < 0.5:
            exts.append((x509.SubjectAlternativeName([x509.DNSName(f"h{i}.example")]), False))
        if rnd.random() < 0.3:
            exts.append((x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00"), False))
        rnd.shuffle(exts)
        b = _builder()
        for e, crit in exts:
            b = b.add_extension(e, critical=crit)
        out.append((_der(b.sign(_KEY, hashes.SHA256())), expected(ku, ekus), (ku, [o.dotted_string for o in ekus or []])))
    return out


def raw_leaf(values_a=None, values_b=None, oid_a=KU_OID, oid_b=KU_OID) -> bytes:
    """A leaf whose extension values are written by hand: up to two placeholder extensions (2.5.29.98, 2.5.29.99) are
    built with the bytes given and then renamed to `oid_a` / `oid_b` (same length, 3 octets). The signature does not
    cover the change: these bytes go to the purpose rule only, which reads no signature."""
    b = _builder()
    if values_a is not None:
        b = b.add_extension(x509.UnrecognizedExtension(PLACEHOLDER_A, values_a), critical=False)
    if values_b is not None:
        b = b.add_extension(x509.UnrecognizedExtension(PLACEHOLDER_B, values_b), critical=False)
    der = _der(b.sign(_KEY, hashes.SHA256()))
    for ph, oid in ((bytes.fromhex("0603551d62"), oid_a), (bytes.fromhex("0603551d63"), oid_b)):
        assert der.count(ph) <= 1
        der = der.replace(ph, b"\x06\x03" + oid)
    return der


HAND = [   # (name, ku value or None, eku value or None, duplicate?, expected)
    ("ku_digital_signature", "03020780", None, False, (True, None)),
    ("ku_non_repudiation", "03020640", None, False, (True, None)),
    ("ku_cert_sign_only", "03020204", None, False, (False, "key_usage_not_signing")),
    ("ku_no_bit", "03020000", None, False, (False, "key_usage_not_signing")),
    ("ku_empty_bitstring", "030100", None, False, (False, "key_usage_not_signing")),
    ("ku_two_octets_decipher_only", "0303070080", None, False, (False, "key_usage_not_signing")),
    ("ku_no_unused_octet", "0300", None, False, (False, "key_usage_malformed")),
    ("ku_unused_8", "03020880", None, False, (False, "key_usage_malformed")),
    ("ku_unused_8_zero_octet", "03020800", None, False, (False, "key_usage_malformed")),
    ("ku_unused_bit_set", "03020181", None, False, (False, "key_usage_malformed")),
    ("ku_unused_without_octets", "030101", None, False, (False, "key_usage_malformed")),
    ("ku_wrong_tag", "04020080", None, False, (False, "key_usage_malformed")),
    ("ku_trailing", "0302008000", None, False, (False, "key_usage_malformed")),
    ("ku_overrun", "03030080", None, False, (False, "key_usage_malformed")),
    ("ku_empty_value", "", None, False, (False, "key_usage_malformed")),
    ("ku_long_length_form", "0381020080", None, False, (True, None)),
    ("eku_any", None, "3006060455" "1d2500", False, (True, None)),
    ("eku_doc_signing", None, "300a06082b06010505070324", False, (True, None)),
    ("eku_server_auth", None, "300a06082b06010505070301", False, (False, "extended_key_usage_not_signing")),
    ("eku_server_then_doc", None, "301406082b0601050507030106082b06010505070324", False, (True, None)),
    ("eku_empty_sequence", None, "3000", False, (False, "extended_key_usage_malformed")),
    ("eku_empty_oid", None, "30020600", False, (False, "extended_key_usage_malformed")),
    ("eku_oid_unterminated", None, "3003060181", False, (False, "extended_key_usage_malformed")),
    ("eku_oid_leading_80", None, "300406028001", False, (False, "extended_key_usage_malformed")),
    ("eku_not_oid", None, "300304010a", False, (False, "extended_key_usage_malformed")),
    ("eku_set_not_sequence", None, "3106060455" "1d2500", False, (False, "extended_key_usage_malformed")),
    ("eku_trailing", None, "3006060455" "1d250000", False, (False, "extended_key_usage_malformed")),
    ("eku_any_long_doc", None, "3006060455" "1d2501", False, (False, "extended_key_usage_not_signing")),
    ("ku_ok_eku_server", "03020780", "300a06082b06010505070301", False, (False, "extended_key_usage_not_signing")),
    ("ku_bad_eku_doc", "03020204", "300a06082b06010505070324", False, (False, "key_usage_not_signing")),
    ("ku_twice", "03020780", "03020780", True, (False, "duplicate_extension")),
    ("eku_twice", "3006060455" "1d2500", "3006060455" "1d2500", "eku", (False, "duplicate_extension")),
]


def _hand_der(ku, eku, dup):
    h = (lambda x: None if x is None else bytes.fromhex(x))
    if dup is True:
        return raw_leaf(h(ku), h(eku), KU_OID, KU_OID)
    if dup == "eku":
        return raw_leaf(h(ku), h(eku), EKU_OID, EKU_OID)
    if ku is not None and eku is not None:
        return raw_leaf(h(ku), h(eku), KU_OID, EKU_OID)
    if ku is not None:
        return raw_leaf(h(ku), None, KU_OID)
    return raw_leaf(None, h(eku), KU_OID, EKU_OID)


def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([0x81, n])) + body


_KU_SIGNING_EXT = _tlv(0x30, _tlv(0x06, KU_OID) + _tlv(0x01, b"\xff") + _tlv(0x04, bytes.fromhex("03020780")))
# a TBSCertificate walk with two [3] fields, the first holding a keyUsage that would be signing: not one extensions field
TWO_EXTENSION_FIELDS = _tlv(0x30, _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0xA3, _tlv(0x30, _KU_SIGNING_EXT))
                                     + _tlv(0xA3, _tlv(0x30, _KU_SIGNING_EXT))))
ONE_EXTENSION_FIELD = _tlv(0x30, _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0xA3, _tlv(0x30, _KU_SIGNING_EXT))))


_JS_PURPOSE = """
import { leafKeyPurpose } from %s;
import { readFileSync } from "node:fs";
const out = JSON.parse(readFileSync(0, "utf8")).map((h) => {
  try { return leafKeyPurpose(Buffer.from(h, "hex")); } catch (e) { return { raised: String(e) }; } });
process.stdout.write(JSON.stringify(out));
"""


def js_purposes(ders):
    from urllib.parse import quote
    url = json.dumps("file://" + quote(JS))
    p = subprocess.run([NODE, "--input-type=module", "-e", _JS_PURPOSE % url], input=json.dumps([d.hex() for d in ders]),
                       capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        raise AssertionError(p.stderr[-2000:])
    return json.loads(p.stdout)


class Reference(unittest.TestCase):
    def test_controls_generator_reaches_both_answers(self):
        # control of the bench: the generated set holds leaves of each kind, so the comparison below is not vacuous
        got = [e for _, e, _ in generated_leaves()]
        kinds = {(e["signing"], e["reason"]) for e in got}
        self.assertEqual(kinds, {(True, None), (False, "key_usage_not_signing"), (False, "extended_key_usage_not_signing")})

    def test_generated_leaves_follow_the_rule(self):
        bad = [(params, e, A.leaf_key_purpose(der)) for der, e, params in generated_leaves()
               if A.leaf_key_purpose(der) != e]
        self.assertEqual(bad, [])

    def test_hand_written_values(self):
        for name, ku, eku, dup, (signing, reason) in HAND:
            with self.subTest(name):
                self.assertEqual(A.leaf_key_purpose(_hand_der(ku, eku, dup)), {"signing": signing, "reason": reason})

    def test_no_extension_and_unreadable(self):
        self.assertEqual(A.leaf_key_purpose(_der(_builder().sign(_KEY, hashes.SHA256()))), {"signing": True, "reason": None})
        self.assertEqual(A.leaf_key_purpose(ONE_EXTENSION_FIELD), {"signing": True, "reason": None})   # control of the next
        for junk in (b"", b"\x30", b"\x30\x00", b"\x04\x00", b"\x30\x03\x02\x01\x01", b"\x30\x84\xff\xff\xff\xff",
                     TWO_EXTENSION_FIELDS):
            self.assertEqual(A.leaf_key_purpose(junk), {"signing": False, "reason": "extensions_unreadable"}, junk.hex())


@unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
class SameInJs(unittest.TestCase):
    def test_generated_and_hand_written(self):
        ders = ([d for d, _, _ in generated_leaves()] + [_hand_der(ku, eku, dup) for _, ku, eku, dup, _ in HAND]
                + [ONE_EXTENSION_FIELD, TWO_EXTENSION_FIELDS])
        js = js_purposes(ders)
        self.assertEqual(len(js), len(ders))
        diff = [i for i, (d, j) in enumerate(zip(ders, js)) if A.leaf_key_purpose(d) != j]
        self.assertEqual(diff, [])

    def test_byte_mutations(self):
        """3000 mutations of a leaf carrying keyUsage, extendedKeyUsage and two other extensions (one byte changed,
        inserted or removed, or the bytes cut): the two verifiers give the same answer and neither raises."""
        b = (_builder().add_extension(_ku(["digital_signature"]), critical=True)
             .add_extension(x509.ExtendedKeyUsage([DOC_SIGNING, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("m.example")]), critical=False))
        base = _der(b.sign(_KEY, hashes.SHA256()))
        rnd = random.Random(1191)
        muts = []
        for _ in range(3000):
            d = bytearray(base)
            op, i = rnd.randrange(4), rnd.randrange(len(d))
            if op == 0:
                d[i] = rnd.randrange(256)
            elif op == 1:
                d.insert(i, rnd.randrange(256))
            elif op == 2:
                del d[i]
            else:
                d = d[:i]
            muts.append(bytes(d))
        py = [A.leaf_key_purpose(m) for m in muts]   # raises here = test error
        js = js_purposes(muts)
        self.assertEqual([i for i in range(len(muts)) if py[i] != js[i]], [])
        self.assertGreater(len({(p["signing"], p["reason"]) for p in py}), 3)   # the mutations reach several answers


def _ca(cn):
    k = ec.generate_private_key(ec.SECP256R1())
    c = (_builder(cn, cn, k.public_key()).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(_ku(["key_cert_sign", "crl_sign"]), critical=True).sign(k, hashes.SHA256()))
    return k, c


@unittest.skipUnless(OPENSSL, "openssl absent: the x5c chain cannot be checked")
class WholePath(unittest.TestCase):
    CASES = {   # name: (keyUsage flags or None, EKUs or None, issuer_identity, self_asserted_only)
        "tls_leaf": (["key_cert_sign"], [ExtendedKeyUsageOID.SERVER_AUTH], ("contradicted", ["key_purpose_not_signing"]), True),
        "client_auth_only": (None, [ExtendedKeyUsageOID.CLIENT_AUTH], ("contradicted", ["key_purpose_not_signing"]), True),
        "code_signing": (["digital_signature"], [ExtendedKeyUsageOID.CODE_SIGNING], ("contradicted", ["key_purpose_not_signing"]), True),
        "key_encipherment": (["key_encipherment"], None, ("contradicted", ["key_purpose_not_signing"]), True),
        "plain": (None, None, ("verified", ["ca_certified"]), False),
        "digital_signature": (["digital_signature"], None, ("verified", ["ca_certified"]), False),
        "content_commitment_doc": (["content_commitment"], [DOC_SIGNING], ("verified", ["ca_certified"]), False),
        "any_eku": (["digital_signature"], [ExtendedKeyUsageOID.SERVER_AUTH, ANY_EKU], ("verified", ["ca_certified"]), False),
    }

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2purpose_")
        cls.ca_key, ca = _ca("rp-ca")
        _, other = _ca("other-ca")
        cls.anchor, cls.other = os.path.join(cls.d, "ca.pem"), os.path.join(cls.d, "other.pem")
        for p, c in ((cls.anchor, ca), (cls.other, other)):
            with open(p, "wb") as f:
                f.write(c.public_bytes(serialization.Encoding.PEM))
        cls.packs = {}
        for name, (ku, ekus, _, _) in cls.CASES.items():
            k = ec.generate_private_key(ec.SECP256R1())
            b = _builder("issuer-leaf", "rp-ca", k.public_key())
            if ku is not None:
                b = b.add_extension(_ku(ku), critical=True)
            if ekus is not None:
                b = b.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
            leaf = b.sign(cls.ca_key, hashes.SHA256())
            hdr = {"alg": "ES256", "typ": "example+sd-jwt", "x5c": [base64.b64encode(_der(leaf)).decode()]}
            claims = {"vct": "mandate.payment.1", "transaction_id": "dGVzdC10cmFuc2FjdGlvbg",
                      "payee": {"id": "m", "name": "M"}, "payment_amount": {"amount": 1250, "currency": "EUR"},
                      "payment_instrument": {"id": "i", "type": "card"}}
            si = _b64u(json.dumps(hdr).encode()) + "." + _b64u(json.dumps(claims).encode())
            r, s = decode_dss_signature(k.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
            pack = os.path.join(cls.d, name + ".json")
            A.build_evidence([{"name": "payment", "sd_jwt": si + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~"}],
                             pack, tsa_url=None)
            cls.packs[name] = pack

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_controls_anchor_and_unrelated_anchor(self):
        r = A.verify_evidence(self.packs["plain"], trust_anchor=self.anchor)
        self.assertEqual((r["chain_verified"], r["self_asserted_only"]), (True, False))
        r = A.verify_evidence(self.packs["plain"], trust_anchor=self.other)
        self.assertEqual((r["chain_verified"], r["self_asserted_only"]), (False, True))

    def test_purpose_under_the_anchor(self):
        for name, (_, _, issuer, flag) in self.CASES.items():
            with self.subTest(name):
                r = A.verify_evidence(self.packs[name], trust_anchor=self.anchor)
                st = r["states"]["issuer_identity"]
                self.assertEqual(((st["state"], st["reasons"]), r["self_asserted_only"], r["chain_verified"], r["valid"]),
                                 (issuer, flag, True, True))
                self.assertEqual(r["artifacts"][0]["x5c_leaf"]["key_purpose"]["signing"], not flag)

    def test_purpose_reported_without_anchor(self):
        r = A.verify_evidence(self.packs["tls_leaf"])
        self.assertEqual(r["artifacts"][0]["x5c_leaf"]["key_purpose"], {"signing": False, "reason": "key_usage_not_signing"})
        self.assertEqual(r["states"]["issuer_identity"]["reasons"], ["no_trust_anchor"])

    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_js_cli_reports_the_same_purpose(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        for name in self.CASES:
            with self.subTest(name):
                p = subprocess.run([NODE, JS, self.packs[name]], capture_output=True, text=True, env=env, timeout=120)
                js = json.loads(p.stdout)
                py = A.verify_evidence(self.packs[name])
                self.assertEqual(js["artifacts"][0]["x5c_leaf"]["key_purpose"], py["artifacts"][0]["x5c_leaf"]["key_purpose"])
                self.assertTrue(js["self_asserted_only"])


if __name__ == "__main__":
    unittest.main()
