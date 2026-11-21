#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.10.0, SPEC §2 (d): the x5c leaf is walked as DER (ITU-T X.690 02/2021) with the shape of RFC 5280 §4.1, by the same
rules in both verifiers, before cryptography (reference) or node:crypto (JS verifier) reads it.

Up to 1.9.0 each verifier left the question to its library, and they disagree: measured on 2026-11-21 with one leaf
(seed 11, 12 000 cases), after the minimal-length check of the same release, 52 of 5205 one-bit and one-byte changes were
a certificate for one verifier only — a BOOLEAN `01`, a version INTEGER `00`, a UTF8String retagged, a constructed OCTET
STRING or SET retagged primitive for node:crypto only; a UTF8String retagged OCTET STRING or GeneralizedTime for
cryptography only. A pack whose x5c leaf carries `critical` `01` was `valid: true` for the JS verifier and that artifact's
error for the reference.

What is measured here:
- one case per rule, built on a fresh leaf, gives that rule in both verifiers (the same name);
- a pack whose leaf breaks a rule is that artifact's error in both verifiers (and on 1.9.0 the JS verifier said valid);
- 1500 generated changes of three leaves (octets, bits, and the cases above): the same answer from the two walks, and
  a leaf is a certificate for the reference exactly when it is one for the JS verifier — on these changes; what the
  two libraries still decide differently after the walk is listed in SPEC §2 (d) and is not measured here;
- the bound on nesting (`depth`): sixteen constructed elements pass, seventeen and 1500 do not, in both (without the
  bound the reference ended in a RecursionError on 1500 and the JS verifier accepted the leaf);
- a leaf that node:crypto refuses on its own names its rule in the JS receipt too (the walk runs first), and a leaf
  whose public key is the point at infinity gets a receipt from the JS verifier (node:crypto 22.23.2 aborts on it);
- controls: three well-formed leaves, and a leaf of each allowed string type, are certificates in both."""
import base64
import copy
import datetime
import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier  # noqa: E402

NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")
KEY = ec.generate_private_key(ec.SECP256R1())
NOW = datetime.datetime(2026, 11, 21, tzinfo=datetime.timezone.utc)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def leaf(subject=None, extensions=True, days=30):
    nm = subject or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
    b = (x509.CertificateBuilder().subject_name(nm).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca")]))
         .public_key(KEY.public_key()).serial_number(0x1234567).not_valid_before(NOW - datetime.timedelta(days=1))
         .not_valid_after(NOW + datetime.timedelta(days=days)))
    if extensions:
        b = (b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.5.5.7.3.36")]), critical=False)
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("x.example"), x509.IPAddress(ipaddress.ip_address("10.0.0.1"))]),
                            critical=False))
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def BASES():
    multi = x509.Name([x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "a"),
                                                       x509.NameAttribute(NameOID.ORGANIZATION_NAME, "b")]),
                       x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.EMAIL_ADDRESS, "m@x.example")]),
                       x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COUNTRY_NAME, "IT")])])
    return [leaf(), leaf(multi, days=40000), leaf(extensions=False)]


# ── a small DER tree: parse a well-formed leaf, change one node, write it back with minimal lengths ───────────────────
def parse(buf, s, e):
    out, o = [], s
    while o < e:
        t, cs, ce = A._der_tlv(buf, o)
        out.append([t, parse(buf, cs, ce) if t & 0x20 else bytes(buf[cs:ce])]); o = ce
    return out


def _len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def ser(nodes):
    out = b""
    for t, c in nodes:
        body = ser(c) if isinstance(c, list) else c
        out += bytes([t]) + _len(len(body)) + body
    return out


def node(tree, path):
    n = tree[path[0]]
    for i in path[1:]:
        n = n[1][i]
    return n


def walk(nodes, path=()):
    for i, (t, c) in enumerate(nodes):
        yield path + (i,), t, c
        if isinstance(c, list):
            yield from walk(c, path + (i,))


def first(tree, tag):
    return next(p for p, t, c in walk(tree) if t == tag)


def mutate(der, fn):
    tree = parse(der, 0, len(der)); fn(tree); return ser(tree)


TBS = (0, 0)   # Certificate -> tbsCertificate


def _set(path, tag=None, value=None):
    def f(tree):
        n = node(tree, path)
        if tag is not None:
            n[0] = tag
        if value is not None:
            n[1] = value
    return f


def _first(which, **kw):
    def f(tree):
        _set(first(tree, which), **kw)(tree)
    return f


def _crit(value):
    def f(tree):
        _set(first(tree, 0x01), value=value)(tree)
    return f


def _name_value(tag, value=None):
    def f(tree):   # the CN value of the subject: tbs[5] -> RDN 0 -> ATV 0 -> value
        n = node(tree, TBS + (5, 0, 0, 1))
        n[0] = tag
        if value is not None:
            n[1] = value
    return f


def _validity(value, tag=0x17):
    def f(tree):
        n = node(tree, TBS + (4, 0))
        n[0], n[1] = tag, value
    return f


def _swap_rdn(tree):   # the multi-valued RDN of BASES()[1]: components out of DER order
    n = node(tree, TBS + (5, 0)); n[1].reverse()


def _long_length(der):   # the serial's length written 81 nn (X.690 §10.1)
    tree = parse(der, 0, len(der)); serial = node(tree, TBS + (1,))[1]
    body = ser([node(tree, TBS + (0,))]) + bytes([0x02, 0x81, len(serial)]) + serial + ser(node(tree, TBS)[1][2:])
    tbs = bytes([0x30]) + _len(len(body)) + body
    rest = ser(tree[0][1][1:])
    return bytes([0x30]) + _len(len(tbs) + len(rest)) + tbs + rest


def _nested(n):
    """A signature AlgorithmIdentifier parameter of `n` SEQUENCEs one inside the other, the innermost empty: that one is
    inside n - 1 of them and inside Certificate, tbsCertificate and the AlgorithmIdentifier. The algorithm is renamed
    1.2.3: cryptography types the parameters of the algorithms it knows and refuses any under ecdsa-with-SHA256, a
    difference between the two libraries this walk does not decide (SPEC §2 (d)). Built with a loop: the tree helpers
    above recurse."""
    def f(tree):
        body = b""
        for _ in range(n - 1):
            body = bytes([0x30]) + _len(len(body)) + body
        alg = node(tree, TBS + (2,))[1]
        alg[0][1] = b"\x2a\x03"
        alg.append([0x30, body])
    return f


def _alg_param(param):
    """One parameter under a signature algorithm renamed 1.2.3 (as in _nested: the libraries agree on an algorithm
    neither knows)."""
    def f(tree):
        alg = node(tree, TBS + (2,))[1]
        alg[0][1] = b"\x2a\x03"
        alg.append(copy.deepcopy(param))
    return f


def _sig_unused_bit(tree):   # the signature BIT STRING says one unused bit (and that bit is zero)
    n = node(tree, (0, 2)); n[1] = b"\x01" + n[1][1:-1] + b"\x00"


# (name, base index, function of the DER, expected rule)
CASES = [
    # one case for each mutant of the walk that survived the cases below (a second review, 2026-11-21: 30 of 74)
    ("unique_id_unused_bits_set", 0, lambda d: mutate(d, lambda t: node(t, TBS)[1].insert(7, [0x81, b"\x01\x03"])), "bit_string"),
    ("printable_at_sign", 0, lambda d: mutate(d, _name_value(0x13, b"a@b")), "string"),
    ("numeric_letter", 0, lambda d: mutate(d, _alg_param([0x12, b"12a"])), "string"),
    ("numeric_control", 0, lambda d: mutate(d, _alg_param([0x12, b"12 3"])), None),
    ("bmp_two_octets_control", 0, lambda d: mutate(d, _name_value(0x1E, b"\x00l")), None),
    ("universal_six_octets", 0, lambda d: mutate(d, _name_value(0x1C, b"\x00\x00\x00l\x00\x00")), "string"),
    ("utctime_day_00", 0, lambda d: mutate(d, _validity(b"261100000000Z")), "time"),
    ("utctime_second_60", 0, lambda d: mutate(d, _validity(b"261121000060Z")), "time"),
    ("generalized_feb_29_2000_control", 0, lambda d: mutate(d, _validity(b"20000229000000Z", 0x18)), None),
    ("set_equal_elements_control", 0, lambda d: mutate(d, _alg_param([0x31, [[0x05, b""], [0x05, b""]]])), None),
    ("spki_three_parts", 0, lambda d: mutate(d, lambda t: node(t, TBS + (6,))[1].append([0x05, b""])), "tbs"),
    ("signature_unused_bit", 0, lambda d: mutate(d, _sig_unused_bit), "bit_string"),
    ("validity_three_times", 0, lambda d: mutate(d, lambda t: node(t, TBS + (4,))[1].append([0x17, b"261121000000Z"])), "tbs"),
    ("atv_three_parts", 0, lambda d: mutate(d, lambda t: node(t, TBS + (5, 0, 0))[1].append([0x0C, b"x"])), "tbs"),
    ("attribute_numeric_string", 0, lambda d: mutate(d, _name_value(0x12, b"123")), "attribute_value"),
    ("extensions_two_sequences", 0, lambda d: mutate(d, lambda t: node(t, TBS + (7,))[1].append([0x30, []])), "extension"),
    ("extension_without_value", 0, lambda d: mutate(d, lambda t: node(t, TBS + (7, 0, 0))[1].pop()), "extension"),
    ("tag_context_4_constructed", 0, lambda d: mutate(d, _alg_param([0xA4, []])), "tag"),
    ("tag_visible_string", 0, lambda d: mutate(d, _name_value(0x1A)), "tag"),
    ("depth_16_control", 0, lambda d: mutate(d, _nested(14)), None),     # the innermost inside 16 constructed elements
    ("depth_17", 0, lambda d: mutate(d, _nested(15)), "depth"),
    ("depth_1500", 0, lambda d: mutate(d, _nested(1498)), "depth"),      # a RecursionError in the reference before the bound
    ("boolean_01", 0, lambda d: mutate(d, _crit(b"\x01")), "boolean"),
    ("boolean_two_octets", 0, lambda d: mutate(d, _crit(b"\xff\xff")), "boolean"),
    ("critical_false_encoded", 0, lambda d: mutate(d, _crit(b"\x00")), "extension"),
    ("integer_leading_zero", 0, lambda d: mutate(d, _set(TBS + (1,), value=b"\x00\x01\x23\x45\x67")), "integer"),
    ("integer_leading_ff", 0, lambda d: mutate(d, _set(TBS + (1,), value=b"\xff\x81")), "integer"),
    ("integer_empty", 0, lambda d: mutate(d, _set(TBS + (1,), value=b"")), "integer"),
    ("serial_negative", 0, lambda d: mutate(d, _set(TBS + (1,), value=b"\x81")), "serial"),
    ("serial_zero", 0, lambda d: mutate(d, _set(TBS + (1,), value=b"\x00")), "serial"),
    ("version_v1_encoded", 0, lambda d: mutate(d, _set(TBS + (0, 0), value=b"\x00")), "version"),
    ("version_v2", 0, lambda d: mutate(d, _set(TBS + (0, 0), value=b"\x01")), "version"),
    ("version_v4", 0, lambda d: mutate(d, _set(TBS + (0, 0), value=b"\x03")), "version"),
    ("length_long_form", 0, _long_length, "length"),
    ("trailing_byte", 0, lambda d: d + b"\x00", "length"),
    ("trailing_element", 0, lambda d: d + b"\x05\x00", "tbs"),
    ("octet_string_constructed", 0, lambda d: mutate(d, lambda t: node(t, first(t, 0x04)).__setitem__(0, 0x24)), "tag"),
    ("set_primitive", 0, lambda d: mutate(d, _first(0x31, tag=0x11)), "tag"),
    ("tag_high_number", 0, lambda d: mutate(d, _name_value(0x1F, b"\x01a")), "tag"),
    ("tag_high_number_long_length", 0, lambda d: d.replace(bytes.fromhex("0c046c656166"), bytes.fromhex("1f8500000000"), 1), "tag"),
    ("unique_id_unused_8", 0, lambda d: mutate(d, lambda t: node(t, TBS)[1].insert(7, [0x81, b"\x08\x00"])), "bit_string"),
    ("unique_id_control", 0, lambda d: mutate(d, lambda t: node(t, TBS)[1].insert(7, [0x81, b"\x00\xff"])), None),
    ("tag_unknown_universal", 0, lambda d: mutate(d, _name_value(0x0E)), "tag"),
    ("attribute_octet_string", 0, lambda d: mutate(d, _name_value(0x04)), "attribute_value"),
    ("attribute_generalized_time", 0, lambda d: mutate(d, _name_value(0x18, b"20261121000000Z")), "attribute_value"),
    ("utf8_invalid", 0, lambda d: mutate(d, _name_value(0x0C, b"le\xffaf")), "string"),
    ("utf8_overlong", 0, lambda d: mutate(d, _name_value(0x0C, b"\xc0\xaf")), "string"),
    ("utf8_surrogate", 0, lambda d: mutate(d, _name_value(0x0C, b"\xed\xa0\x80")), "string"),
    ("printable_star", 0, lambda d: mutate(d, _name_value(0x13, b"le*af")), "string"),
    ("ia5_8bit", 0, lambda d: mutate(d, _name_value(0x16, b"le\x80f")), "string"),
    ("bmp_odd", 0, lambda d: mutate(d, _name_value(0x1E, b"\x00l\x00")), "string"),
    ("universal_not_4", 0, lambda d: mutate(d, _name_value(0x1C, b"\x00\x00\x00l\x00")), "string"),
    ("utctime_no_seconds", 0, lambda d: mutate(d, _validity(b"2611210000Z")), "time"),
    ("utctime_offset", 0, lambda d: mutate(d, _validity(b"261121000000+0100")), "time"),
    ("utctime_feb_30", 0, lambda d: mutate(d, _validity(b"260230000000Z")), "time"),
    ("utctime_hour_24", 0, lambda d: mutate(d, _validity(b"261121240000Z")), "time"),
    ("generalized_fraction", 0, lambda d: mutate(d, _validity(b"20261121000000.5Z", 0x18)), "time"),
    ("generalized_feb_29_2100", 0, lambda d: mutate(d, _validity(b"21000229000000Z", 0x18)), "time"),
    ("oid_leading_80", 0, lambda d: mutate(d, _first(0x06, value=b"\x80\x55\x04\x03")), "oid"),
    ("null_with_contents", 0, lambda d: mutate(d, lambda t: node(t, TBS + (2,))[1].append([0x05, b"\x00"])), "null"),
    ("bit_string_unused_key", 0, lambda d: mutate(d, lambda t: node(t, TBS + (6, 1)).__setitem__(1, b"\x01" + node(t, TBS + (6, 1))[1][1:-1] + b"\x00")), "bit_string"),
    ("set_order", 1, lambda d: mutate(d, _swap_rdn), "set_order"),
    ("tbs_field_missing", 2, lambda d: mutate(d, lambda t: node(t, TBS)[1].pop(1)), "tbs"),
    ("tbs_extensions_twice", 0, lambda d: mutate(d, lambda t: node(t, TBS)[1].append(copy.deepcopy(node(t, TBS)[1][-1]))), "tbs"),
]


_JS = """
import { x5cLeafDerProblem } from %s;
import { readFileSync } from "node:fs";
process.stdout.write(JSON.stringify(JSON.parse(readFileSync(0, "utf8")).map((h) => x5cLeafDerProblem(Buffer.from(h, "hex")))));
"""


def js_problems(ders):
    from urllib.parse import quote
    p = subprocess.run([NODE, "--input-type=module", "-e", _JS % json.dumps("file://" + quote(JS))],
                       input=json.dumps([d.hex() for d in ders]), capture_output=True, text=True, timeout=600)
    if p.returncode:
        raise AssertionError(p.stderr[-2000:])
    return json.loads(p.stdout)


class Rules(unittest.TestCase):
    def test_controls_well_formed_leaves(self):
        for d in BASES():
            self.assertIsNone(A.x5c_leaf_der_problem(d))
        for tag, value in ((0x0C, "leaf é".encode()), (0x13, b"Leaf (1)"), (0x16, b"a@b.example"), (0x14, b"leaf"),
                           (0x1E, "leaf".encode("utf-16-be")), (0x1C, "le".encode("utf-32-be"))):
            with self.subTest(hex(tag)):
                d = mutate(leaf(), _name_value(tag, value))
                self.assertIsNone(A.x5c_leaf_der_problem(d))
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    x509.load_der_x509_certificate(d).subject.rfc4514_string()   # cryptography reads it too

    def test_one_case_per_rule(self):
        bases = BASES()
        for name, b, fn, rule in CASES:
            with self.subTest(name):
                self.assertEqual(A.x5c_leaf_der_problem(fn(bases[b])), rule)

    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_same_rule_in_js(self):
        bases = BASES()
        ders = [fn(bases[b]) for _, b, fn, _ in CASES] + bases
        self.assertEqual(js_problems(ders), [A.x5c_leaf_der_problem(d) for d in ders])


def _py_cert(der):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            c = A._load_x5c_leaf([base64.b64encode(der).decode()])
            c.subject.rfc4514_string(); c.issuer.rfc4514_string(); c.not_valid_before_utc; c.not_valid_after_utc
            A._jwk_from_pubkey(c.public_key())
        return True
    except Exception:  # noqa: BLE001
        return False


_JS_CERT = """
import { X509Certificate, createPublicKey } from "node:crypto"; import { readFileSync } from "node:fs";
import { x5cLeafDerProblem } from %s;
process.stdout.write(JSON.stringify(JSON.parse(readFileSync(0, "utf8")).map((h) => { const d = Buffer.from(h, "hex");
  try { const c = new X509Certificate(d); if (!Buffer.from(c.raw).equals(d) || x5cLeafDerProblem(d)) return false;
    const j = createPublicKey({ key: c.publicKey.export({ format: "jwk" }), format: "jwk" }).export({ format: "jwk" });
    String(c.subject); String(c.issuer); new Date(c.validFrom).toISOString(); new Date(c.validTo).toISOString();
    return j.kty === "EC" && j.crv === "P-256"; } catch { return false; } })));
"""


@unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
class Generated(unittest.TestCase):
    def test_generated_changes(self):
        rnd = random.Random(1191)
        bases = BASES(); ders = []
        for _ in range(1500):
            b = bytearray(rnd.choice(bases)); i = rnd.randrange(len(b)); op = rnd.randrange(3)
            if op == 0:
                b[i] = rnd.getrandbits(8)
            elif op == 1:
                b[i] ^= 1 << rnd.randrange(8)
            else:
                name, bi, fn, _ = rnd.choice(CASES); b = bytearray(fn(bases[bi]))
            ders.append(bytes(b))
        self.assertEqual(js_problems(ders), [A.x5c_leaf_der_problem(d) for d in ders])
        from urllib.parse import quote
        p = subprocess.run([NODE, "--input-type=module", "-e", _JS_CERT % json.dumps("file://" + quote(JS))],
                           input=json.dumps([d.hex() for d in ders]), capture_output=True, text=True, timeout=600)
        js = json.loads(p.stdout); py = [_py_cert(d) for d in ders]
        self.assertEqual([i for i in range(len(ders)) if py[i] != js[i]], [])
        self.assertGreater(sum(py), 100); self.assertGreater(len(py) - sum(py), 100)   # both answers are reached


class WholePack(unittest.TestCase):
    """A pack whose x5c leaf (the key source) carries `critical` 01, assembled from parts (build refuses it): that
    artifact's error in both verifiers. Measured 2026-11-21 on 1.9.0: valid: true for the JS verifier, an artifact error
    for the reference. Control: the same assembly with the well-formed leaf is valid in both."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2leafder_")
        sys.path.insert(0, os.path.join(ROOT, "spec", "vectors", "ap2"))
        import make_vectors_closed_schema as cs
        cls.cs = cs
        cls.scope = cs._load("valid_signed")["honest_scope"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _pack(self, der, name):
        cs = self.cs
        jwk = A._jwk_from_pubkey(KEY.public_key())
        hdr = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": [base64.b64encode(der).decode("ascii")]}
        pay = {"iss": "issuer-bank", "mandate_type": "intent", "max_amount": "150.00 EUR"}
        art = cs._artifact("intent", cs._sign_jwt(KEY, hdr, pay) + "~", hdr, jwk, pay, False)
        art["key"] = {"jwk": jwk, "provenance_class": "x5c_header", "note": "key from the x5c leaf of the signed header"}
        path = os.path.join(self.d, name + ".json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cs._pack(self.scope, "test leaf DER", [art]), f)
        return path

    def _both(self, path):
        r = A.verify_evidence(path)
        out = [(r["valid"], json.dumps(r["artifacts"]))]
        if NODE:
            p = subprocess.run([NODE, JS, path], capture_output=True, text=True, timeout=120)
            js = json.loads(p.stdout); out.append((js["valid"], json.dumps(js["artifacts"])))
        return out

    def test_rule_named_when_the_library_refuses_too(self):
        """A leaf that breaks a rule AND that node:crypto refuses on its own (an INTEGER with a leading 00, X.690
        §8.3.2): the rule is named in both receipts. Measured 2026-11-21 on d44ca04, where the JS verifier asked its
        library first: `...the x5c leaf is unusable`, no rule, while the reference said `x5c leaf is not DER: integer`."""
        bad = self._both(self._pack(mutate(leaf(), _set(TBS + (1,), value=b"\x00\x01\x23\x45\x67")), "lib_refuses"))
        self.assertEqual([v for v, _ in bad], [False] * len(bad))
        for _, arts in bad:
            self.assertIn("x5c leaf is not DER: integer", arts)

    @unittest.skipUnless(NODE, "node absent: the JS verifier cannot be measured")
    def test_point_at_infinity_gets_a_receipt_from_js(self):
        """An EC subjectPublicKey that is the point at infinity (BIT STRING `00 00`): node:crypto 22.23.2 aborts the
        process when asked for its JWK (measured 2026-11-21 on 1.9.0 and on d44ca04: no receipt, SIGABRT). The JS
        verifier refuses a public key of less than two octets before asking: exit 1, a receipt, that artifact's
        error, as the reference. Control: the well-formed leaf through the same assembly is exit 0."""
        ok = subprocess.run([NODE, JS, self._pack(leaf(), "inf_control")], capture_output=True, text=True, timeout=120)
        self.assertEqual(ok.returncode, 0, ok.stderr[-500:])
        path = self._pack(mutate(leaf(), _set(TBS + (6, 1), value=b"\x00\x00")), "inf")
        p = subprocess.run([NODE, JS, path], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 1, p.stderr[-500:])
        r = json.loads(p.stdout)
        self.assertIs(r["valid"], False)
        self.assertIn("the x5c leaf is unusable", json.dumps(r["artifacts"]))
        self.assertIs(A.verify_evidence(path)["valid"], False)

    def test_controls_and_bad_leaf(self):
        good = leaf()
        for valid, _ in self._both(self._pack(good, "good")):
            self.assertTrue(valid)
        bad = self._both(self._pack(mutate(good, _crit(b"\x01")), "bad"))
        self.assertEqual([v for v, _ in bad], [False] * len(bad))   # on 1.9.0 the JS verifier said True
        for _, arts in bad:
            self.assertIn("x5c leaf is not DER: boolean", arts)


@unittest.skipUnless(shutil.which("openssl"), "openssl absent: the x5c chain cannot be checked")
class SerialOnlyForTheLeaf(unittest.TestCase):
    """1.10.0 (SPEC §2 (d)): the positive serial is asked of the x5c leaf only. Anchors and intermediates are read by
    openssl, not by this walk: a CA whose serial is 0 (several roots of common trust stores have one; pyca/cryptography
    50.0.2 does not refuse it for that reason) still anchors a chain. Control: the same leaf with serial 0 is that
    artifact's error."""

    @staticmethod
    def _resigned_with_serial(der, key, serial):   # cryptography's builder refuses serial 0: the TBS is rewritten and signed
        tree = parse(der, 0, len(der))
        node(tree, TBS + (1,))[1] = serial
        tbs = ser([node(tree, TBS)])
        sig = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        body = tbs + ser([node(tree, (0, 1))]) + bytes([0x03]) + _len(len(sig) + 1) + b"\x00" + sig
        return bytes([0x30]) + _len(len(body)) + body

    def _ca(self):
        k = ec.generate_private_key(ec.SECP256R1())
        c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zero ca")]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zero ca")])).public_key(k.public_key())
             .serial_number(1).not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True))
        return k, self._resigned_with_serial(c.sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.DER), k, b"\x00")

    def _leaf(self, ca_key, serial):
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "zero ca")])).public_key(KEY.public_key())
             .serial_number(7).not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=30)))
        der = b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        return der if serial is None else self._resigned_with_serial(der, ca_key, serial)

    def test_anchor_with_serial_zero_and_leaf_with_serial_zero(self):
        d = tempfile.mkdtemp(prefix="ap2serial_")
        try:
            ca_key, ca_der = self._ca()
            self.assertEqual(A.x5c_leaf_der_problem(ca_der), "serial")   # the bench: the anchor really has serial 0
            anchor = os.path.join(d, "ca.pem")
            with open(anchor, "wb") as f:
                f.write(b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(ca_der) + b"-----END CERTIFICATE-----\n")
            good = self._leaf(ca_key, None)
            self.assertIsNone(A.x5c_leaf_der_problem(good))
            self.assertIs(A._verify_x5c_chain([base64.b64encode(good).decode()], anchor), True)   # the anchor's serial 0 is not read
            zero = self._leaf(ca_key, b"\x00")
            self.assertEqual(A.x5c_leaf_der_problem(zero), "serial")
            with self.assertRaisesRegex(A.Ap2EvidenceError, "x5c leaf is not DER: serial"):
                A._load_x5c_leaf([base64.b64encode(zero).decode()])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
