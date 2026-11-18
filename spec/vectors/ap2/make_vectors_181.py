#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.8.1 SD-JWT grammar vectors (RFC 9901 §4, SPEC §6 step 2) — provenance of the frozen files.

  sd_jwt_no_separator        the issuer JWT alone, no '~'                       -> REJECT (sd_jwt_no_separator)
  sd_jwt_empty_component     <jwt>~~<d1>~<d2>~, an empty component              -> REJECT (sd_jwt_empty_component)
  sd_jwt_no_trailing_tilde   <jwt>~<d1>~<d2>, the trailing '~' omitted          -> REJECT (sd_jwt_final_component_not_kb_jwt)
  holder_sd_hash_mismatch_no_key  a KB-JWT, no cnf.jwk, sd_hash of another presentation -> REJECT (sd_hash_mismatch)

Assembled from parts (`_artifact`, `_pack`), not through `build_evidence`, which refuses them at build. Their
`resolved_claims` and `kb_jwt.present` record what the 1.8.0 reader produced: the first two `valid: true` under 1.8.0 in
both verifiers (no disclosure / the empty one dropped), the third an artifact error under 1.8.0 too, for another reason
(its last disclosure taken as the KB-JWT: "kb-jwt must have 3 dot-separated segments") — measured 2026-11-18 on the tag
v1.8.0. The error text is not in the normative block; the `states` block is the SPEC §6.9 row of an artifact error.

  python3 make_vectors_181.py       write the three vectors (fresh keys: rebuild only deliberately)
"""
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402
from make_vectors_sd_rules import STATES, _digest, _disc  # noqa: E402

SUBJECT = "ap2 conformance vector (SD-JWT grammar, 1.8.1)"


def main() -> int:
    sk, jwk = cs._signer()
    scope = cs._load("valid_signed")["honest_scope"]
    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk}
    d1, d2 = _disc("salt-181-1", "max_amount", "150.00 EUR"), _disc("salt-181-2", "merchant_scope", "books")
    open_claims = {"iss": "user-wallet", "mandate_type": "intent"}
    pay = dict(open_claims, _sd=sorted([_digest(d1), _digest(d2)]), _sd_alg="sha-256")
    jwt = cs._sign_jwt(sk, hdr, pay)
    both = dict(open_claims, max_amount="150.00 EUR", merchant_scope="books")
    rows = [
        ("sd_jwt_no_separator", jwt, open_claims, False,
         "The issuer-signed JWT alone, without '~'. RFC 9901 §4: SD-JWT = JWT \"~\" *(DISCLOSURE \"~\"). Measured "
         "2026-11-18 on v1.8.0: both verifiers valid: true (read as an SD-JWT with no disclosures). 1.8.1 (SPEC §6 "
         "step 2): that artifact's error, sd_jwt_no_separator."),
        ("sd_jwt_empty_component", jwt + "~~" + d1 + "~" + d2 + "~", both, False,
         "An empty component between two '~'. RFC 9901 §4: DISCLOSURE = BASE64URL, at least one character; only the last "
         "component may be empty. Measured 2026-11-18 on v1.8.0: both verifiers valid: true (the empty component dropped "
         "in silence). 1.8.1 (SPEC §6 step 2): that artifact's error, sd_jwt_empty_component."),
        ("sd_jwt_no_trailing_tilde", jwt + "~" + d1 + "~" + d2, dict(open_claims, max_amount="150.00 EUR"), True,
         "Two disclosures and the trailing '~' omitted. RFC 9901 §4: \"In the case that there is no Key Binding JWT, the "
         "last element MUST be an empty string and the last separating tilde character MUST NOT be omitted\". Measured "
         "2026-11-18 on v1.8.0: the last disclosure read as the KB-JWT (gone from the resolved claims), the artifact an "
         "error only as \"kb-jwt must have 3 dot-separated segments\". 1.8.1 (SPEC §6 step 2): that artifact's error, "
         "sd_jwt_final_component_not_kb_jwt, before anything is resolved."),
    ]
    hsk, _ = cs._signer()   # the holder's key: the issuer payload names none (no cnf.jwk)
    pres = jwt + "~" + d1 + "~"
    kb = cs._sign_jwt(hsk, {"alg": "ES256", "typ": "kb+jwt"},
                      {"iat": 1760054400, "aud": "merchant-books", "nonce": "n-7f3a",
                       "sd_hash": cs._b64u(hashlib.sha256(b"another presentation~").digest())})
    rows.append(("holder_sd_hash_mismatch_no_key", pres + kb, dict(open_claims, max_amount="150.00 EUR"), True,
                 "A KB-JWT whose sd_hash is the hash of another presentation, and no cnf.jwk in the issuer payload. RFC 9901 "
                 "§7.3 step 5.g asks the Verifier to check sd_hash, which needs no key (§4.3.1): the KB-JWT is not bound to "
                 "this presentation. Measured 2026-11-18 on v1.8.0: both verifiers valid: true, holder_binding "
                 "not_evaluated/holder_key_unknown, the same receipt as with the right sd_hash. 1.8.1 (SPEC §9.2): that "
                 "artifact's error, sd_hash_mismatch."))
    for name, compact, resolved, kb_present, desc in rows:
        exp = cs._expected(name, desc, {}, cs.ARTIFACT_ERROR)
        exp["states"] = STATES
        cs._write(name, cs._pack(scope, SUBJECT, [cs._artifact("intent", compact, hdr, jwk, resolved, kb_present)]), exp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
