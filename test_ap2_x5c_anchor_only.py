#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.1, SPEC §6 step 7: an x5c chain validates to the trust anchor the relying party supplies, and to nothing else.

Up to 1.8.0 `_verify_x5c_chain` ran `openssl verify -CAfile <anchor>` without `-no-CApath -no-CAstore`, so openssl added
its default certificate store (the system CAs, or SSL_CERT_FILE / SSL_CERT_DIR). Measured on 2026-11-18 on the PyPI wheel
1.8.0: an ES256 artifact whose x5c leaf is issued by a CA "rp-ca", verified with `--trust-anchor` an UNRELATED CA, gave
`issuer_identity verified / ca_certified` and `self_asserted_only: false` as soon as rp-ca was in the default store.

The default store is simulated with SSL_CERT_FILE and SSL_CERT_DIR (both read by OpenSSL's default paths). Positive
controls of the bench itself: `openssl verify -CAfile <unrelated>` without the two options answers OK under that
environment (so the environment does reach openssl), and the chain verifies when rp-ca IS the anchor. On v1.8.0 and on
the branch before this change `test_unrelated_anchor_with_ca_in_default_store` fails (verified / ca_certified)."""
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

OPENSSL = shutil.which("openssl")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _cert(subject_cn, issuer_cn, pub, signer, ca):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    return b.sign(signer, hashes.SHA256())


def _pem(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


@unittest.skipUnless(OPENSSL, "openssl absent: the x5c chain cannot be checked")
class AnchorOnly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2x5c_")
        rp_key, other_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        rp = _cert("rp-ca", "rp-ca", rp_key.public_key(), rp_key, True)
        other = _cert("unrelated-anchor", "unrelated-anchor", other_key.public_key(), other_key, True)
        leaf = _cert("issuer-leaf", "rp-ca", leaf_key.public_key(), rp_key, False)
        cls.rp_pem, cls.other_pem = os.path.join(cls.d, "rp.pem"), os.path.join(cls.d, "other.pem")
        cls.leaf_pem = os.path.join(cls.d, "leaf.pem")
        for p, c in ((cls.rp_pem, rp), (cls.other_pem, other), (cls.leaf_pem, leaf)):
            with open(p, "wb") as f:
                f.write(_pem(c))
        # the simulated default store: a file and a hashed directory, both holding rp-ca
        cls.store_dir = os.path.join(cls.d, "store")
        os.mkdir(cls.store_dir)
        h = subprocess.run([OPENSSL, "x509", "-hash", "-noout", "-in", cls.rp_pem], capture_output=True, text=True,
                           check=True, encoding="utf-8").stdout.strip()
        shutil.copy(cls.rp_pem, os.path.join(cls.store_dir, h + ".0"))
        cls.store_env = {"SSL_CERT_FILE": cls.rp_pem, "SSL_CERT_DIR": cls.store_dir}
        hdr = {"alg": "ES256", "typ": "example+sd-jwt",
               "x5c": [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()]}
        claims = {"vct": "mandate.payment.1", "transaction_id": "dGVzdC10cmFuc2FjdGlvbg",
                  "payee": {"id": "m", "name": "M"}, "payment_amount": {"amount": 1250, "currency": "EUR"},
                  "payment_instrument": {"id": "i", "type": "card"}}
        si = _b64u(json.dumps(hdr).encode()) + "." + _b64u(json.dumps(claims).encode())
        r, s = decode_dss_signature(leaf_key.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
        tok = si + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~"
        cls.pack = os.path.join(cls.d, "pack.json")
        A.build_evidence([{"name": "payment", "sd_jwt": tok}], cls.pack, tsa_url=None)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _issuer(self, anchor, env=None):
        with mock.patch.dict(os.environ, env or {}):
            r = A.verify_evidence(self.pack, trust_anchor=anchor)
        return r["states"]["issuer_identity"]["state"], r["states"]["issuer_identity"]["reasons"], r["self_asserted_only"]

    def test_bench_reaches_openssl(self):
        # positive control: under the simulated store, plain `openssl verify -CAfile <unrelated>` accepts the leaf
        env = dict(os.environ, **self.store_env)
        plain = subprocess.run([OPENSSL, "verify", "-CAfile", self.other_pem, self.leaf_pem], capture_output=True, env=env)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        closed = subprocess.run([OPENSSL, "verify", "-CAfile", self.other_pem, "-no-CApath", "-no-CAstore", self.leaf_pem],
                                capture_output=True, env=env)
        self.assertNotEqual(closed.returncode, 0)

    def test_rp_anchor_verifies(self):
        self.assertEqual(self._issuer(self.rp_pem), ("verified", ["ca_certified"], False))
        self.assertEqual(self._issuer(self.rp_pem, self.store_env), ("verified", ["ca_certified"], False))

    def test_unrelated_anchor_without_store(self):
        self.assertEqual(self._issuer(self.other_pem), ("not_evaluated", ["chain_unresolved"], True))

    def test_unrelated_anchor_with_ca_in_default_store(self):
        self.assertEqual(self._issuer(self.other_pem, self.store_env), ("not_evaluated", ["chain_unresolved"], True))
        with open(self.leaf_pem, "rb") as f:
            der = x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)
        with mock.patch.dict(os.environ, self.store_env):
            self.assertIs(A._verify_x5c_chain([base64.b64encode(der).decode()], self.other_pem), False)

    def test_openssl_before_3_is_a_check_not_run(self):
        # an openssl that does not know -no-CAstore (before 3.0) cannot keep the default store out: the check is not run
        # (instrument_failure), never reported as a chain that did not reach the anchor
        from _ap2_platform import fake_tool   # 1.11.0: a program on every system (Windows: a .cmd)
        fake = fake_tool(os.path.join(self.d, "fakebin"), "openssl",
                         "import sys\nsys.stderr.write('verify: Unknown option: -no-CAstore\\n')\nsys.exit(1)\n")
        with mock.patch.dict(os.environ, {"PATH": fake + os.pathsep + os.environ.get("PATH", "")}):
            with self.assertRaisesRegex(A.Ap2WriteError, "OpenSSL 3.0 or later") as cm:   # SPEC §6.10: exit 74, receipt
                A.verify_evidence(self.pack, trust_anchor=self.rp_pem)
        r = cm.exception.receipt
        st = r["states"]["issuer_identity"]
        self.assertEqual((st["state"], st["reasons"], r["self_asserted_only"]), ("not_evaluated", ["instrument_failure"], True))
        self.assertIsNone(r["artifacts"][0]["x5c_leaf"]["chain_verified"])

    def test_cli_unrelated_anchor_with_ca_in_default_store(self):
        env = dict(os.environ, **self.store_env)
        env.pop("PYTHONPATH", None)
        p = subprocess.run([sys.executable, os.path.join(ROOT, "ap2_evidence.py"), "verify", self.pack,
                            "--trust-anchor", self.other_pem], capture_output=True, text=True, env=env, encoding="utf-8")
        r = json.loads(p.stdout)
        self.assertEqual((r["states"]["issuer_identity"]["reasons"], r["self_asserted_only"]), (["chain_unresolved"], True))


if __name__ == "__main__":
    unittest.main()
