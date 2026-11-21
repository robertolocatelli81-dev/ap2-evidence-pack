#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.1, SPEC §6 step 2, RFC 7515 §5.2 step 8: verify checks the issuer signature only under the alg the signed header
names, and this format knows ES256 only.

Up to 1.9.0 verify checked ES256 whatever the header said (build refused it): measured on 2026-11-20 on 1.9.0, a pack
whose issuer header, signed by the issuer, says "none", "HS256", "ES384" or "RS256" over an ES256 signature was
`valid: true` in both verifiers. Positive control: on 1.9.0 the generated cases below are valid in Python and in
JavaScript and these tests fail."""
import base64
import hashlib
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

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
except ImportError:  # pragma: no cover
    ec = None

JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")
PAYLOAD = {"iss": "w", "vct": "mandate.payment.1", "_sd": [], "_sd_alg": "sha-256"}


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _token(sk, header):
    si = _b64u(json.dumps(header).encode()) + "." + _b64u(json.dumps(PAYLOAD).encode())
    r, s = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return si + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~"


def _jwk(sk):
    n = sk.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}


def _alg_values(rnd):
    """the generated alg values: names of the JOSE registry, case and space variants of ES256, other JSON types, and
    random strings; plus "absent" (no alg member)"""
    out = ["none", "None", "NONE", "HS256", "HS384", "HS512", "ES384", "ES512", "ES256K", "RS256", "PS256", "EdDSA",
           "Ed25519", "es256", "Es256", "ES256 ", " ES256", "ES256\u0000", "ES2560", "", None, 0, 256, True, [], ["ES256"],
           {"alg": "ES256"}, "absent"]   # a float is refused before, by the number profile (SPEC §3.1, own test)
    for _ in range(40):
        n = rnd.randint(1, 12)
        out.append("".join(rnd.choice("ESHRP0123456789abcdz-_ ") for _ in range(n)))
    return [v for v in out if v != "ES256"]


@unittest.skipIf(ec is None, "needs cryptography")
class IssuerAlg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2alg_")
        cls.sk = ec.generate_private_key(ec.SECP256R1())
        cls.base = os.path.join(cls.d, "base.json")
        A.build_evidence([{"name": "m", "sd_jwt": _token(cls.sk, {"alg": "ES256", "typ": "ap2-mandate+sd-jwt"})}],
                         cls.base, keys={"m": _jwk(cls.sk)})
        with open(cls.base) as f:
            cls.ev = json.load(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _pack(self, header, name):
        ev = json.loads(json.dumps(self.ev))
        ev["artifacts"][0]["sd_jwt_compact"] = _token(self.sk, header)
        ev["artifacts"][0]["header"] = header
        ev["evidence_digest_sha256"] = hashlib.sha256(A._canon({k: v for k, v in ev.items()
                                                                if k not in A._DIGEST_EXCLUDED})).hexdigest()
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            json.dump(ev, f)
        return p

    def _header(self, alg):
        h = {"typ": "ap2-mandate+sd-jwt"}
        if alg != "absent":
            h["alg"] = alg
        return h

    def test_control_resealed_es256_is_valid(self):
        r = A.verify_evidence(self._pack({"alg": "ES256", "typ": "ap2-mandate+sd-jwt"}, "ctl.json"))
        self.assertTrue(r["valid"], r["artifacts"])

    def test_generated_algs_python(self):
        rnd = random.Random(20261120)
        for i, alg in enumerate(_alg_values(rnd)):
            with self.subTest(alg=alg):
                r = A.verify_evidence(self._pack(self._header(alg), "py%d.json" % i))
                self.assertFalse(r["valid"])
                self.assertIn("issuer_alg_not_es256", r["artifacts"][0].get("error", ""))
                self.assertIs(r["artifacts"][0].get("signature_ok"), None)

    def test_build_refuses_the_same_headers(self):
        for alg in ("none", "HS256", "ES384", "absent"):
            with self.subTest(alg=alg), self.assertRaises(A.Ap2EvidenceError):
                A.build_evidence([{"name": "m", "sd_jwt": _token(self.sk, self._header(alg))}],
                                 os.path.join(self.d, "b.json"), keys={"m": _jwk(self.sk)})

    def _js(self, p):
        q = subprocess.run(["node", JS, p], capture_output=True, text=True)
        return q.returncode, json.loads(q.stdout)

    def test_every_key_source_and_the_check_before_the_signature(self):
        """the rule does not depend on where the key came from (the tests above use a supplied key: here the header's
        own jwk), and it is asked before the signature is read: a token that says ES384 and carries 96 octets is
        issuer_alg_not_es256, not a remark about the length of an ES256 signature"""
        jwk = _jwk(self.sk)
        base = os.path.join(self.d, "hj.json")
        A.build_evidence([{"name": "m", "sd_jwt": _token(self.sk, {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk})}], base)
        with open(base) as f:
            ev = json.load(f)
        self.assertEqual(ev["artifacts"][0]["key"]["provenance_class"], "jwk_header")
        node = shutil.which("node")
        saved, self.ev = self.ev, ev
        try:
            ctl = self._pack({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk}, "hjctl.json")
            self.assertTrue(A.verify_evidence(ctl)["valid"])
            for i, alg in enumerate(("none", "HS256", "ES384", "RS256", "es256", None, "absent")):
                with self.subTest(source="jwk_header", alg=alg):
                    p = self._pack(dict(self._header(alg), jwk=jwk), "hj%d.json" % i)
                    r = A.verify_evidence(p)
                    self.assertFalse(r["valid"])
                    self.assertIn("issuer_alg_not_es256", r["artifacts"][0].get("error", ""))
                    if node:
                        rc, j = self._js(p)
                        self.assertEqual((rc, j["valid"]), (1, False))
                        self.assertIn("issuer_alg_not_es256", j["artifacts"][0].get("error", ""))
        finally:
            self.ev = saved
        p = self._pack({"alg": "ES384", "typ": "ap2-mandate+sd-jwt"}, "es384.json")
        with open(p) as f:
            ev = json.load(f)
        head = ev["artifacts"][0]["sd_jwt_compact"].rsplit(".", 1)[0]
        ev["artifacts"][0]["sd_jwt_compact"] = head + "." + _b64u(bytes(range(96))) + "~"
        ev["evidence_digest_sha256"] = hashlib.sha256(A._canon({k: v for k, v in ev.items()
                                                                if k not in A._DIGEST_EXCLUDED})).hexdigest()
        with open(p, "w") as f:
            json.dump(ev, f)
        with self.subTest(case="96 octets under ES384"):
            self.assertIn("issuer_alg_not_es256", A.verify_evidence(p)["artifacts"][0].get("error", ""))
            if node:
                self.assertIn("issuer_alg_not_es256", self._js(p)[1]["artifacts"][0].get("error", ""))

    @unittest.skipUnless(shutil.which("node"), "needs node")
    def test_generated_algs_js(self):
        rnd = random.Random(20261120)
        algs = _alg_values(rnd)[:30]
        paths = [self._pack(self._header(a), "js%d.json" % i) for i, a in enumerate(algs)]
        ctl = self._pack({"alg": "ES256", "typ": "ap2-mandate+sd-jwt"}, "jsctl.json")
        for a, p in [("ES256", ctl)] + list(zip(algs, paths)):
            with self.subTest(alg=a):
                q = subprocess.run(["node", JS, p], capture_output=True, text=True)
                r = json.loads(q.stdout)
                if a == "ES256":
                    self.assertEqual((q.returncode, r["valid"]), (0, True), q.stderr[-400:])
                else:
                    self.assertEqual((q.returncode, r["valid"]), (1, False))
                    self.assertIn("issuer_alg_not_es256", r["artifacts"][0].get("error", ""))
                    # the same message, whole, in both receipts: the reference writes the exception's name before it
                    self.assertEqual("Ap2EvidenceError: " + r["artifacts"][0]["error"],
                                     A.verify_evidence(p)["artifacts"][0]["error"])
                    self.assertTrue(r["artifacts"][0]["error"].endswith("(RFC 7515 §5.2 step 8, SPEC §6 step 2)"))


if __name__ == "__main__":
    unittest.main()
