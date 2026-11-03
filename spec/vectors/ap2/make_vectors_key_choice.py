#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.7.3 vectors on the key sources of the protected header (SPEC §2 (d), §6 step 2, §9.2) — provenance
of the frozen files.

  key_header_jwk_differs    a `supplied` key that verifies the signature, beside a header `jwk` naming ANOTHER key  -> REJECT
  key_header_x5c_differs    a `jwks_fetched` key that verifies the signature, beside a header `x5c` whose leaf is
                            another key                                                                            -> REJECT
  key_material_not_used     a `supplied` key, beside a header `jwk` and `x5c` naming that same key and a `jku`: valid,
                            the three names reported in `artifacts[0].ignored.key_material`                        -> ACCEPT

A 1.7.2 verifier accepts the first two (it did not compare a header key source that was not the provenance source) and
reports `ignored: {}` on the third. 1.7.3 `build` refuses to write the first two (SPEC §2 (d)): they are made here by hand,
as a producer that does not follow §2 would write them; the third is the pack 1.7.3 `build` writes.

  python3 make_vectors_key_choice.py       write the vectors (fresh keys: rebuild only deliberately)
"""
import base64
import datetime
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402
import make_vectors_sd_rules as sdr  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ap2 = cs.ap2
SUBJECT = "ap2 conformance vector (key sources of the header)"
NP = {"state": "not_evaluated", "reasons": ["not_present"]}
VALID_STATES = {"admission": "admitted", "refusal_class": None,
                "subjects": {"sealed_content": {"state": "verified", "reasons": []}, "holder_binding": NP, "time_anchor": NP,
                             "producer_signature": NP, "issuer_identity": {"state": "not_evaluated", "reasons": ["self_asserted"]}},
                "policy": {"met": True, "unmet": []}}


def _leaf(sk):
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ap2 conformance vector leaf")])
    c = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(sk.public_key()).serial_number(1)
         .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1)).sign(sk, hashes.SHA256()))
    return base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()


def main() -> int:
    sk, jwk = cs._signer()
    sk_o, jwk_o = cs._signer()
    scope = cs._load("valid_signed")["honest_scope"]
    pay = {"iss": "user-wallet", "mandate_type": "intent"}

    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk_o}
    art = cs._artifact("intent", cs._sign_jwt(sk, hdr, pay) + "~", hdr, jwk, pay, False)
    art["key"] = {"jwk": jwk, "provenance_class": "supplied", "note": "key material supplied by the caller (caller vouches)"}
    exp = cs._expected("key_header_jwk_differs",
                       "The supplied key verifies the issuer signature; the signed header carries a jwk naming another key "
                       "(RFC 7515 §4.1.3 defines it as the key that signed). Measured 2026-11-03 on 1.7.2: valid in both "
                       "verifiers. 1.7.3 (SPEC §2 (d), §6 step 2): that artifact's error.", {}, cs.ARTIFACT_ERROR)
    exp["states"] = sdr.STATES
    cs._write("key_header_jwk_differs", cs._pack(scope, SUBJECT, [art]), exp)

    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "kid": "k1", "x5c": [_leaf(sk_o)]}
    art = cs._artifact("intent", cs._sign_jwt(sk, hdr, pay) + "~", hdr, dict(jwk, kid="k1"), pay, False)
    art["key"] = {"jwk": dict(jwk, kid="k1"), "provenance_class": "jwks_fetched", "jwks_url": "https://issuer.example/jwks.json",
                  "jwks_sha256": "00" * 32, "fetched_utc": "2026-11-03T00:00:00Z",
                  "note": "fetched over TLS at build time — a capture witness, not proof of issuer control of the key"}
    exp = cs._expected("key_header_x5c_differs",
                       "The JWKS key (kid k1) verifies the issuer signature; the signed header carries an x5c whose leaf is "
                       "another key (RFC 7515 §4.1.6). Measured 2026-11-03 on 1.7.2: valid in both verifiers. 1.7.3 (SPEC "
                       "§2 (d), §6 step 2): that artifact's error.", {}, cs.ARTIFACT_ERROR)
    exp["states"] = sdr.STATES
    cs._write("key_header_x5c_differs", cs._pack(scope, SUBJECT, [art]), exp)

    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk, "x5c": [_leaf(sk)], "jku": "https://issuer.example/jwks.json"}
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "p.json")
        ap2.build_evidence([{"name": "intent", "sd_jwt": cs._sign_jwt(sk, hdr, pay) + "~"}], out, keys={"intent": jwk},
                           subject=SUBJECT)
        pack = ap2.read_evidence_file(out)
    exp = cs._expected("key_material_not_used",
                       "A supplied key, beside a header jwk and x5c naming that same key and a jku (never fetched): valid, "
                       "and the three names are REPORTED in artifacts[0].ignored.key_material (SPEC §2 (d), §9.2). Measured "
                       "2026-11-03 on 1.7.2: valid, ignored {} in both verifiers.", {}, cs.ACCEPT_PLAIN,
                       report={"ignored": [{"key_material": ["jku", "jwk", "x5c"]}]})
    exp["states"] = VALID_STATES
    cs._write("key_material_not_used", pack, exp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
