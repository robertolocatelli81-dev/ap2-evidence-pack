#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.7.0 SD-JWT processing-rule vectors (RFC 9901 §7.1, SPEC §6 step 2) — provenance of the frozen files.

  sd_digest_repeated       the AP2 `delegate_payload` form with the same array placeholder twice  -> REJECT (§7.1 step 4)
  sd_digest_repeated_sd    the same object digest in the `_sd` array of two objects                 -> REJECT (§7.1 step 4)
  sd_claim_name_reserved   an object disclosure whose claim name is `_sd`                           -> REJECT (§7.1 step 3.c.ii.2)

The packs are sealed around an artifact the verifier must refuse, so they are assembled from parts (`_artifact`, `_pack`)
and not through `build_evidence`, which verifies at build. Their `resolved_claims` record what the 1.6.0 resolver produced
(the mandate twice; the claim in both objects; `_sd` as an ordinary claim), so that a 1.6.0 verifier says `valid: true` on
them — measured 2026-10-28 and 2026-10-29 on fffadff (1.6.0), both verifiers — and a 1.7.0 verifier says `valid: false`
with the artifact's error. The `states` block is the SPEC §6.9 table's row for an artifact error (`sealed_content`
`contradicted` `artifact_invalid`, the other subjects `not_present`); the conformance runner compares it with the
reference verifier.

  python3 make_vectors_sd_rules.py       write the three vectors (fresh keys: rebuild only deliberately)
"""
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402

NP = {"state": "not_evaluated", "reasons": ["not_present"]}
STATES = {"admission": "admitted", "refusal_class": None,
          "subjects": {"sealed_content": {"state": "contradicted", "reasons": ["artifact_invalid"]}, "holder_binding": NP,
                       "time_anchor": NP, "producer_signature": NP, "issuer_identity": NP},
          "policy": {"met": True, "unmet": []}}
SUBJECT = "ap2 conformance vector (SD-JWT processing rules)"


def _disc(salt, *parts):
    return cs._b64u(json.dumps([salt, *parts]).encode())


def _digest(disc):
    return cs._b64u(hashlib.sha256(disc.encode("ascii")).digest())


def main() -> int:
    sk, jwk = cs._signer()
    scope = cs._load("valid_signed")["honest_scope"]   # the §1 text every vector carries
    hdr = {"alg": "ES256", "typ": "example+sd-jwt", "jwk": jwk}

    content = {"vct": "mandate.payment.open.1", "constraints": [{"type": "payment.amount_range", "currency": "USD", "max": 20000, "min": 0}],
               "cnf": {"jwk": jwk}, "iat": 1777342357, "exp": 1777345957}
    d1 = _disc("salt-sd-rules-1", content)
    pay1 = {"delegate_payload": [{"...": _digest(d1)}, {"...": _digest(d1)}], "_sd_alg": "sha-256"}
    compact1 = cs._sign_jwt(sk, hdr, pay1) + "~" + d1 + "~"
    resolved1_160 = {"delegate_payload": [content, content]}   # what the 1.6.0 resolver produced: the mandate twice
    exp1 = cs._expected("sd_digest_repeated",
                        "The AP2 `delegate_payload` form (one array disclosure) with the same placeholder digest twice in the "
                        "signed payload. RFC 9901 §7.1 step 4: \"If any digest value is encountered more than once in the "
                        "Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected\". "
                        "Measured 2026-10-28 on 1.6.0: both verifiers valid: true, the mandate twice in resolved_claims. "
                        "1.7.0 (SPEC §6 step 2): that artifact's error, the pack is not valid.", {}, cs.ARTIFACT_ERROR)
    exp1["states"] = STATES
    cs._write("sd_digest_repeated", cs._pack(scope, SUBJECT, [cs._artifact("payment", compact1, hdr, jwk, resolved1_160, False)]), exp1)

    d3 = _disc("salt-sd-rules-3", "note", {"k": 1})
    pay3 = {"iss": "user-wallet", "mandate_type": "intent", "_sd": [_digest(d3)], "extra": {"_sd": [_digest(d3)]}, "_sd_alg": "sha-256"}
    compact3 = cs._sign_jwt(sk, hdr, pay3) + "~" + d3 + "~"
    resolved3_160 = {"iss": "user-wallet", "mandate_type": "intent", "note": {"k": 1}, "extra": {"note": {"k": 1}}}   # 1.6.0: in both objects
    exp3 = cs._expected("sd_digest_repeated_sd",
                        "The same object-disclosure digest in the `_sd` array of two objects (top level and `extra`). RFC 9901 "
                        "§7.1 step 4 (as sd_digest_repeated). Measured 2026-10-28 on 1.6.0: both verifiers valid: true, the "
                        "claim inserted in both objects. 1.7.0 (SPEC §6 step 2): that artifact's error.", {}, cs.ARTIFACT_ERROR)
    exp3["states"] = STATES
    cs._write("sd_digest_repeated_sd", cs._pack(scope, SUBJECT, [cs._artifact("intent", compact3, hdr, jwk, resolved3_160, False)]), exp3)

    d2 = _disc("salt-sd-rules-2", "_sd", ["not-a-digest"])
    pay2 = {"iss": "user-wallet", "mandate_type": "intent", "_sd": [_digest(d2)], "_sd_alg": "sha-256"}
    compact2 = cs._sign_jwt(sk, hdr, pay2) + "~" + d2 + "~"
    resolved2_160 = {"iss": "user-wallet", "mandate_type": "intent", "_sd": ["not-a-digest"]}   # 1.6.0: `_sd` as an ordinary claim
    exp2 = cs._expected("sd_claim_name_reserved",
                        "An object disclosure whose claim name is `_sd`. RFC 9901 §7.1 step 3.c.ii.2: \"If the claim name is "
                        "_sd or ..., the SD-JWT MUST be rejected\". Measured 2026-10-28 on 1.6.0: both verifiers valid: true, "
                        "`_sd` inserted as an ordinary claim of resolved_claims. 1.7.0 (SPEC §6 step 2): that artifact's error.",
                        {}, cs.ARTIFACT_ERROR)
    exp2["states"] = STATES
    cs._write("sd_claim_name_reserved", cs._pack(scope, SUBJECT, [cs._artifact("intent", compact2, hdr, jwk, resolved2_160, False)]), exp2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
