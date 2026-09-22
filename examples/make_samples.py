#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generate sample SD-JWT mandates so the README's CLI is runnable end-to-end
by anyone (third-party verifiability of the documented commands):

    python3 examples/make_samples.py            # writes checkout.sdjwt, payment.sdjwt
    python3 ap2_evidence.py build evidence.json checkout=checkout.sdjwt payment=payment.sdjwt
    python3 ap2_evidence.py verify evidence.json

The samples are REAL ES256 SD-JWTs (fresh P-256 key, real signatures, real
selective disclosures, the payment mandate hash-binding the checkout one) — generated locally,
worthless outside this demo, never reused.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ap2_evidence as ap2  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def main() -> int:
    sk = ec.generate_private_key(ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": _b64u(nums.x.to_bytes(32, "big")),
           "y": _b64u(nums.y.to_bytes(32, "big"))}

    def sign_jwt(header: dict, payload: dict) -> str:
        si = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}"
        der = sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{si}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def sd_jwt(open_claims: dict, sd_claims: dict) -> str:
        discs = [_b64u(json.dumps([f"salt{i}", k, v]).encode())
                 for i, (k, v) in enumerate(sd_claims.items())]
        payload = dict(open_claims)
        payload["_sd"] = sorted(ap2._disclosure_digest(d) for d in discs)
        payload["_sd_alg"] = "sha-256"
        return (sign_jwt({"alg": "ES256", "typ": "ap2-mandate+sd-jwt", "jwk": jwk},
                         payload) + "~" + "~".join(discs) + "~")

    checkout = sd_jwt({"iss": "user-wallet-sample", "vct": "mandate.checkout.open.1"},
                    {"max_amount": "150.00 EUR", "merchant_scope": "books"})
    payment = sd_jwt({"iss": "shopping-agent-sample", "vct": "mandate.payment.1",
                   "intent_mandate_hash":
                       hashlib.sha256(checkout.encode("ascii")).hexdigest()},
                  {"items": ["book-123"]})
    open("checkout.sdjwt", "w").write(checkout)
    open("payment.sdjwt", "w").write(payment)
    print("written: checkout.sdjwt, payment.sdjwt  (sample ES256 SD-JWTs, demo-only key)")
    print("next:    python3 ap2_evidence.py build evidence.json "
          "checkout=checkout.sdjwt payment=payment.sdjwt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
