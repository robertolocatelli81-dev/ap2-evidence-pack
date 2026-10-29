#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.7.1 vector on the depth of the resolved claims (SPEC §6 step 2, §3.1) — provenance of the frozen file.

  sd_disclosures_too_deep   a chain of 513 object disclosures, each nested in the one before: the resolved claims nest
                            513 deep, one more than the §3.1 bound of 512                                    -> REJECT

The file itself nests no deeper than the profile allows (the chain is inside the signed token), so the pack is admitted.
Its `resolved_claims` record the top-level claim only: no file within the §3.1 bound can hold claims 513 deep. A 1.7.0
verifier resolves the chain and reports `claims_match: false` (`issuer_identity` `self_asserted`); a 1.7.1 verifier
refuses the resolution, `disclosures_too_deep`, which is that artifact's error: `sealed_content` `contradicted`
`artifact_invalid`, the other subjects `not_present` (SPEC §6.9).

  python3 make_vectors_depth.py       write the vector (a fresh key: rebuild only deliberately)
"""
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402
import make_vectors_sd_rules as sdr  # noqa: E402

CHAIN = 513
SUBJECT = "ap2 conformance vector (depth of the resolved claims)"


def _disc(salt, *parts):
    return cs._b64u(json.dumps([salt, *parts], separators=(",", ":")).encode())


def _digest(disc):
    return cs._b64u(hashlib.sha256(disc.encode("ascii")).digest())


def main() -> int:
    sk, jwk = cs._signer()
    scope = cs._load("valid_signed")["honest_scope"]
    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk}
    inner = _disc("salt-depth-%d" % CHAIN, "c", "leaf"); discs = [inner]
    for k in range(CHAIN - 1, 0, -1):
        inner = _disc("salt-depth-%d" % k, "c", {"_sd": [_digest(inner)]}); discs.append(inner)
    pay = {"iss": "user-wallet", "mandate_type": "intent", "_sd": [_digest(inner)], "_sd_alg": "sha-256"}
    compact = cs._sign_jwt(sk, hdr, pay) + "~" + "~".join(reversed(discs)) + "~"
    recorded = {"iss": "user-wallet", "mandate_type": "intent"}
    exp = cs._expected("sd_disclosures_too_deep",
                       "A chain of 513 object disclosures, each nested in the one before: the resolved claims nest 513 deep, "
                       "one more than the SPEC §3.1 bound of 512; the file itself is within the bound. Measured 2026-10-29 on "
                       "1.7.0: both verifiers resolve the chain and report claims_match false (issuer_identity self_asserted). "
                       "1.7.1 (SPEC §6 step 2): disclosures_too_deep, that artifact's error.", {}, cs.ARTIFACT_ERROR)
    exp["states"] = sdr.STATES
    cs._write("sd_disclosures_too_deep", cs._pack(scope, SUBJECT, [cs._artifact("intent", compact, hdr, jwk, recorded, False)]), exp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
