#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generator of the 1.11.0 vectors of SPEC §5 (a pinned set with an ml-dsa-65 key requires its signature) — provenance of
the frozen files.

  producer_pq_stripped_pinned          valid_signed.json with the ml-dsa-65 entry removed and `scheme` set to
                                       classical-only, under the pins of valid_signed (ed25519 AND ml-dsa-65), no other
                                       policy -> REJECT (policy.unmet trusted_producer_keys)
  producer_pq_stripped_classical_pin   the same bytes under the ed25519 pin alone (a classical-only producer's set)
                                       -> ACCEPT

Derived from the frozen valid_signed.json and its pins, no new key: running it again writes the same bytes. Measured on
2026-11-24 on the tag v1.10.0 and on the PyPI wheel 1.10.0: the first was `valid: true`, `policy.unmet: []` in both
verifiers; the second is the same under 1.10.0 and 1.11.0.

  python3 make_vectors_1110.py
"""
import copy
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import make_vectors_closed_schema as cs  # noqa: E402

NORMATIVE = {"valid": True, "digest_ok": True, "bindings_ok": True, "policy_ok": True, "pq_protected": False,
             "producer_present": True, "producer_ok": True, "producer_trusted": True, "rfc3161_claimed": False,
             "rfc3161_verified": None, "self_asserted_only": True}


def _states(unmet):
    return {"admission": "admitted", "refusal_class": None,
            "subjects": {"sealed_content": {"state": "verified", "reasons": []},
                         "holder_binding": {"state": "not_evaluated", "reasons": ["not_present"]},
                         "time_anchor": {"state": "not_evaluated", "reasons": ["not_present"]},
                         "producer_signature": {"state": "verified", "reasons": []},
                         "issuer_identity": {"state": "not_evaluated", "reasons": ["self_asserted", "self_asserted"]}},
            "policy": {"met": not unmet, "unmet": unmet}}


def main() -> int:
    pack = copy.deepcopy(cs._load("valid_signed"))
    blk = pack["producer_signatures"]
    blk["signatures"] = [s for s in blk["signatures"] if s["sig_alg"] != "ml-dsa-65"]
    blk["scheme"] = "classical-only"
    with open(os.path.join(_HERE, "valid_signed.expected.json"), encoding="utf-8") as f:
        pins = json.load(f)["policy"]["trusted_producer_keys"]
    base = {"require_pq": False, "require_producer": False, "require_anchor": False}

    name = "producer_pq_stripped_pinned"
    exp = cs._expected(
        name,
        "valid_signed with its ml-dsa-65 entry removed and scheme set to classical-only (the downgrade of SPEC §5), under "
        "the pins of valid_signed — its ed25519 AND its ml-dsa-65 key — and no other policy. What is left verifies (the "
        "ed25519 signature is over the same digest; scheme agrees with the entries). 1.11.0 (SPEC §5, §6 step 6): a pinned "
        "set that holds an ml-dsa-65 key requires a valid ml-dsa-65 signature under a pinned key — not valid, policy.unmet "
        "trusted_producer_keys. Measured 2026-11-24 on v1.10.0 and on the PyPI wheel 1.10.0: valid true, unmet [], in both "
        "verifiers.",
        dict(base, trusted_producer_keys=pins), dict(NORMATIVE, valid=False, policy_ok=False))
    exp["states"] = _states(["trusted_producer_keys"])
    cs._write(name, pack, exp)

    name = "producer_pq_stripped_classical_pin"
    exp = cs._expected(
        name,
        "The same bytes as producer_pq_stripped_pinned under the ed25519 pin alone: the set of a classical-only producer "
        "holds no ml-dsa-65 key, so a classical-only block whose key it pins meets it (SPEC §5) — valid. Control of the "
        "1.11.0 rule: unchanged from 1.10.0.",
        dict(base, trusted_producer_keys={"ed25519": pins["ed25519"]}), NORMATIVE)
    exp["states"] = _states([])
    cs._write(name, pack, exp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
