#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.10.0 vector of SPEC §6 step 2 (the issuer signature only under the `alg` the signed header names) —
provenance of the frozen files.

  issuer_alg_not_es256   an ES256 signature of the issuer under a signed header that says "alg": "none"
                         -> REJECT (that artifact's error, issuer_alg_not_es256)
  issuer_x5c_key_purpose_not_signing
                         an x5c leaf whose keyUsage is keyCertSign only and whose extendedKeyUsage is serverAuth only,
                         under --trust-anchor issuer_purpose_ca.crt (the CA that issued it, shipped beside)
                         -> valid, chain_verified true, self_asserted_only true, issuer_identity contradicted /
                            key_purpose_not_signing (SPEC §6 step 7, §6.9); needs openssl

Assembled from parts (`_artifact`, `_pack`), not through `build_evidence`, which refuses it at build. Measured
2026-11-20 on the tag v1.9.0: `valid: true` in both verifiers (ES256 checked whatever the header named). The error text
is not in the normative block; the `states` block is the SPEC §6.9 row of an artifact error.

  python3 make_vectors_191.py alg        write issuer_alg_not_es256 (a fresh key: rebuild only deliberately)
  python3 make_vectors_191.py purpose    write issuer_x5c_key_purpose_not_signing and issuer_purpose_ca.crt (fresh keys)

The second is measured on 2026-11-21: on 2e2556b (before 1.10.0's key-purpose rule) the reference gives issuer_identity
verified / ca_certified and self_asserted_only false on it.
"""
import base64
import datetime
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402
from make_vectors_sd_rules import STATES  # noqa: E402

SUBJECT = "ap2 conformance vector (issuer alg, 1.10.0)"


def alg() -> int:
    sk, jwk = cs._signer()
    scope = cs._load("valid_signed")["honest_scope"]
    hdr = {"alg": "none", "typ": "example+sd-jwt", "jwk": jwk}
    claims = {"iss": "user-wallet", "mandate_type": "intent", "max_amount": "150.00 EUR"}
    jwt = cs._sign_jwt(sk, hdr, claims)   # an ES256 signature over the header that names "none"
    name = "issuer_alg_not_es256"
    exp = cs._expected(
        name,
        "An issuer JWT whose signed protected header says \"alg\": \"none\" and whose signature is a valid ES256 "
        "signature of the header's own jwk over the JWS signing input. RFC 7515 §5.2 step 8: the signature is validated "
        "in the manner defined for the algorithm the alg header parameter names. Measured 2026-11-20 on v1.9.0: both "
        "verifiers valid: true. 1.10.0 (SPEC §6 step 2): that artifact's error, issuer_alg_not_es256.",
        {}, cs.ARTIFACT_ERROR)
    exp["states"] = STATES
    cs._write(name, cs._pack(scope, SUBJECT, [cs._artifact("intent", jwt + "~", hdr, jwk, claims, False)]), exp)
    return 0


def purpose() -> int:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import ap2_evidence as ap2
    nb, na = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc), datetime.datetime(2126, 1, 1, tzinfo=datetime.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def ku(**on):
        flags = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
                 "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
        return x509.KeyUsage(**{f: f in on for f in flags})
    ca_sk, leaf_sk = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("ap2 conformance purpose CA")).issuer_name(name("ap2 conformance purpose CA"))
          .public_key(ca_sk.public_key()).serial_number(11).not_valid_before(nb).not_valid_after(na)
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(ku(key_cert_sign=True, crl_sign=True), critical=True).sign(ca_sk, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(name("ap2 conformance TLS server, not a signer"))
            .issuer_name(name("ap2 conformance purpose CA")).public_key(leaf_sk.public_key()).serial_number(12)
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(ku(key_cert_sign=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_sk, hashes.SHA256()))
    with open(os.path.join(_HERE, "issuer_purpose_ca.crt"), "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    leaf_jwk = ap2._jwk_from_pubkey(leaf_sk.public_key())
    h = {"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "x5c": [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode("ascii")]}
    p = {"iss": "issuer-bank", "mandate_type": "intent", "max_amount": "150.00 EUR"}
    art = cs._artifact("intent", cs._sign_jwt(leaf_sk, h, p) + "~", h, leaf_jwk, p, False)
    art["key"] = {"jwk": leaf_jwk, "provenance_class": "x5c_header", "note": "key from the x5c leaf of the signed header"}
    name_ = "issuer_x5c_key_purpose_not_signing"
    exp = cs._expected(
        name_,
        "A mandate whose key is an x5c leaf issued by issuer_purpose_ca.crt with keyUsage keyCertSign only and "
        "extendedKeyUsage serverAuth only, under --trust-anchor issuer_purpose_ca.crt: the chain validates, the leaf is not "
        "issued for signing (RFC 5280 §4.2.1.3, §4.2.1.12) — issuer_identity contradicted/key_purpose_not_signing, "
        "self_asserted_only true; the pack stays valid, as for chain_broken (SPEC §6 step 7, §6.9). Measured 2026-11-21 "
        "on 2e2556b: verified/ca_certified and self_asserted_only false. Needs openssl.",
        {"trust_anchor": "issuer_purpose_ca.crt"}, dict(cs.ACCEPT_PLAIN, valid=True, self_asserted_only=True))
    exp["states"] = {"admission": "admitted", "refusal_class": None,
                     "subjects": {"sealed_content": {"state": "verified", "reasons": []},
                                  "holder_binding": {"state": "not_evaluated", "reasons": ["not_present"]},
                                  "time_anchor": {"state": "not_evaluated", "reasons": ["not_present"]},
                                  "producer_signature": {"state": "not_evaluated", "reasons": ["not_present"]},
                                  "issuer_identity": {"state": "contradicted", "reasons": ["key_purpose_not_signing"]}},
                     "policy": {"met": True, "unmet": []}}
    exp["requires"] = ["openssl"]
    cs._write(name_, cs._pack(scope_of(), "ap2 conformance vector (key purpose, 1.10.0)", [art]), exp)
    return 0


def scope_of():
    return cs._load("valid_signed")["honest_scope"]


if __name__ == "__main__":
    which = sys.argv[1:]
    if which == ["alg"]:
        raise SystemExit(alg())
    if which == ["purpose"]:
        raise SystemExit(purpose())
    raise SystemExit("usage: make_vectors_191.py alg|purpose")
