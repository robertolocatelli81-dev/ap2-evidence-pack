#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.9.1 vector of SPEC §6 step 2 (the issuer signature only under the `alg` the signed header names) —
provenance of the frozen files.

  issuer_alg_not_es256   an ES256 signature of the issuer under a signed header that says "alg": "none"
                         -> REJECT (that artifact's error, issuer_alg_not_es256)

Assembled from parts (`_artifact`, `_pack`), not through `build_evidence`, which refuses it at build. Measured
2026-11-20 on the tag v1.9.0: `valid: true` in both verifiers (ES256 checked whatever the header named). The error text
is not in the normative block; the `states` block is the SPEC §6.9 row of an artifact error.

  python3 make_vectors_191.py       write the vector (a fresh key: rebuild only deliberately)
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402
from make_vectors_sd_rules import STATES  # noqa: E402

SUBJECT = "ap2 conformance vector (issuer alg, 1.9.1)"


def main() -> int:
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
        "verifiers valid: true. 1.9.1 (SPEC §6 step 2): that artifact's error, issuer_alg_not_es256.",
        {}, cs.ARTIFACT_ERROR)
    exp["states"] = STATES
    cs._write(name, cs._pack(scope, SUBJECT, [cs._artifact("intent", jwt + "~", hdr, jwk, claims, False)]), exp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
