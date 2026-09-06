#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generate sample SD-JWT mandates so the README's CLI is runnable end-to-end
by anyone (third-party verifiability of the documented commands):

    python3 examples/make_samples.py            # writes intent.sdjwt, cart.sdjwt
    python3 ap2_evidence.py build evidence.json intent=intent.sdjwt cart=cart.sdjwt
    python3 ap2_evidence.py verify evidence.json

The samples are REAL ES256 SD-JWTs (fresh P-256 key, real signatures, real
selective disclosures, the cart hash-binding the intent) — generated locally,
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

    intent = sd_jwt({"iss": "user-wallet-sample", "mandate_type": "intent"},
                    {"max_amount": "150.00 EUR", "merchant_scope": "books"})
    cart = sd_jwt({"iss": "shopping-agent-sample", "mandate_type": "cart",
                   "intent_mandate_hash":
                       hashlib.sha256(intent.encode("ascii")).hexdigest()},
                  {"items": ["book-123"]})
    open("intent.sdjwt", "w").write(intent)
    open("cart.sdjwt", "w").write(cart)
    print("written: intent.sdjwt, cart.sdjwt  (sample ES256 SD-JWTs, demo-only key)")
    print("next:    python3 ap2_evidence.py build evidence.json "
          "intent=intent.sdjwt cart=cart.sdjwt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
