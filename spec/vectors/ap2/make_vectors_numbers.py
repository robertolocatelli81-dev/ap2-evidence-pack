#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.7.2 vectors on numbers in the SD-JWT layer (SPEC §3.1) — provenance of the frozen files.

  sd_number_integral_literal   a token in the AP2 SDK's shape (`delegate_payload`, one array-element disclosure) whose
                               signed JSON writes `"max":10.0`, `"max":250.00` and `"exp":1700003600.0`: literals with a
                               zero fractional part; default policy: that artifact's error                -> REJECT
  sd_number_integral_literal_accepted   the same pack under `accept_integral_floats`: read as 10, 250 and
                               1700003600, as recorded                                                     -> ACCEPT
  sd_number_fraction           the same token with `"max":0.29`: no integer value, that artifact's error  -> REJECT
  sd_number_fraction_accepted  the same pack under `accept_integral_floats`: still that artifact's error   -> REJECT

Why: the AP2 SDK at e1ea56d (`Budget.max: float`) writes every budget as a JSON float (`Budget(max=10)` -> `10.0`), and
AP2's schema types `payment.budget.max` as `number`; up to 1.7.1 both verifiers refused such a token (`float '10.0' in the
evidence file`), so no budget mandate the SDK made could be carried. The literals are written by hand below (json.dumps
would write 250.0), the signature covers them as written.

  python3 make_vectors_numbers.py       write the four vectors (a fresh key: rebuild only deliberately)
"""
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402
import make_vectors_sd_rules as sdr  # noqa: E402

SUBJECT = "ap2 conformance vector (numbers in the SD-JWT layer)"
STATES_VALID = {"admission": "admitted", "refusal_class": None,
                "subjects": {"sealed_content": {"state": "verified", "reasons": []}, "holder_binding": sdr.NP,
                             "time_anchor": sdr.NP, "producer_signature": sdr.NP,
                             "issuer_identity": {"state": "not_evaluated", "reasons": ["self_asserted"]}},
                "policy": {"met": True, "unmet": []}}


def _content_text(budget_literal: str) -> str:
    """The Mandate Content as the SDK lays it out, with the number literals spelled here, not by json.dumps."""
    return ('{"cnf":{"jwk":{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}},'
            '"constraints":[{"currency":"USD","max":%s,"type":"payment.budget"},'
            '{"currency":"USD","max":250.00,"type":"payment.amount_range"}],'
            '"exp":1700003600,"iat":1700000000,"vct":"mandate.payment.open.1"}' % (AGENT_X, AGENT_Y, budget_literal))


AGENT_X, AGENT_Y = "wBaJx1FoWIFIUWqqUVTmHTyj8fkiIRXYSJS2cP-flWw", "N8oAdVtWlJi9dr0y-meNnxgYTbsSHqbnAswbyz1e7g4"


def _token(sk, jwk, budget_literal):
    disc = cs._b64u(('["salt-number-1",%s]' % _content_text(budget_literal)).encode("ascii"))
    digest = cs._b64u(hashlib.sha256(disc.encode("ascii")).digest())
    hdr_txt = json.dumps({"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk}, separators=(",", ":"))
    pay_txt = '{"_sd_alg":"sha-256","delegate_payload":[{"...":"%s"}],"exp":1700003600.0,"iss":"user-wallet"}' % digest
    si = cs._b64u(hdr_txt.encode()) + "." + cs._b64u(pay_txt.encode())
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sk.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return si + "." + cs._b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~" + disc + "~"


def main() -> int:
    sk, jwk = cs._signer()
    scope = cs._load("valid_signed")["honest_scope"]
    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk}
    content = {"cnf": {"jwk": {"crv": "P-256", "kty": "EC", "x": AGENT_X, "y": AGENT_Y}},
               "constraints": [{"currency": "USD", "max": 10, "type": "payment.budget"},
                               {"currency": "USD", "max": 250, "type": "payment.amount_range"}],
               "exp": 1700003600, "iat": 1700000000, "vct": "mandate.payment.open.1"}
    recorded = {"delegate_payload": [content], "exp": 1700003600, "iss": "user-wallet"}
    lit = cs._pack(scope, SUBJECT, [cs._artifact("open_payment", _token(sk, jwk, "10.0"), hdr, jwk, recorded, False)])
    exp1 = cs._expected("sd_number_integral_literal",
                        "A token in the AP2 SDK's shape whose signed JSON writes \"max\":10.0 (budget), \"max\":250.00 "
                        "(amount_range) and \"exp\":1700003600.0 (payload): literals with a zero fractional part. 1.7.2 "
                        "(SPEC §3.1, the SD-JWT layer), default policy: that artifact's error (float '1700003600.0' in the "
                        "SD-JWT), both verifiers — JSON Schema Core 2020-12 §6.3: such a literal SHOULD NOT be written. "
                        "The same pack under accept_integral_floats is sd_number_integral_literal_accepted.", {}, cs.ARTIFACT_ERROR)
    exp1["states"] = sdr.STATES
    cs._write("sd_number_integral_literal", lit, exp1)
    exp1a = cs._expected("sd_number_integral_literal_accepted",
                         "The pack of sd_number_integral_literal, byte for byte, under accept_integral_floats (SPEC §3.1): "
                         "10.0, 250.00 and 1700003600.0 are read as 10, 250 and 1700003600, as recorded, both verifiers; "
                         "the signed bytes are checked as written. The AP2 SDK at e1ea56d (Budget.max: float) writes every "
                         "budget as a JSON float, 10 as 10.0 (measured 2026-11-02): such a mandate is carried only under this option.",
                         {"accept_integral_floats": True}, cs.ACCEPT_PLAIN)
    exp1a["states"] = STATES_VALID
    cs._write("sd_number_integral_literal_accepted", lit, exp1a)
    frac = cs._pack(scope, SUBJECT, [cs._artifact("open_payment", _token(sk, jwk, "0.29"), hdr, jwk, {"delegate_payload": []}, False)])
    exp2 = cs._expected("sd_number_fraction",
                        "The same token with \"max\":0.29. SPEC §3.1, default policy: that artifact's error in both verifiers — already on the token's first literal with a fraction, \"exp\":1700003600.0 in the payload, before the disclosure with 0.29 is read; sd_number_fraction_accepted is the case where 0.29 itself decides. Declared: a schema-valid AP2 budget with a fraction cannot be carried by this format.", {}, cs.ARTIFACT_ERROR)
    exp2["states"] = sdr.STATES
    cs._write("sd_number_fraction", frac, exp2)
    exp2a = cs._expected("sd_number_fraction_accepted",
                         "The pack of sd_number_fraction, byte for byte, under accept_integral_floats: 0.29 has no integer "
                         "value, so it stays that artifact's error (float '0.29' in the SD-JWT: not an integer within "
                         "+/-(2^53-1)), in both verifiers — the option reads only integral literals.",
                         {"accept_integral_floats": True}, cs.ARTIFACT_ERROR)
    exp2a["states"] = sdr.STATES
    cs._write("sd_number_fraction_accepted", frac, exp2a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
