#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Write acvp_mldsa65_sigver_pure.jsonl from NIST's ACVP-Server, never by hand.

    python3 make_acvp_mldsa65.py <internalProjection.json> > acvp_mldsa65_sigver_pure.jsonl

Input: usnistgov/ACVP-Server at commit a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324 (2026-07-31, the latest commit of the
directory on 2026-11-17), gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json, sha256
47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437 (checked: a file that differs stops the script).
Selection: every test of every group whose parameterSet is ML-DSA-65, signatureInterface "external", preHash "pure"
and externalMu false (one group, tgId 3, 15 tests on that commit). Output: one JSON object per line, in the group's
order, with the keys tgId, tcId, testPassed, reason, pk, message, context, signature (hex in lower case; the secret
key `sk`, the `deferred` flag and `hashAlg` "none" are left out). Changes made to NIST's data, as its notice asks:
the selection, the key subset, the lower case hex, the one-object-per-line layout (2026-11-17)."""
import hashlib
import json
import sys

PIN = "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"


def cases(data: bytes):
    if hashlib.sha256(data).hexdigest() != PIN:
        raise SystemExit(f"internalProjection.json: sha256 {hashlib.sha256(data).hexdigest()}, the pinned one is {PIN}")
    doc = json.loads(data)
    if (doc.get("algorithm"), doc.get("mode"), doc.get("revision")) != ("ML-DSA", "sigVer", "FIPS204"):
        raise SystemExit("not the ML-DSA sigVer FIPS204 projection")
    out = []
    for g in doc["testGroups"]:
        if (g.get("parameterSet"), g.get("signatureInterface"), g.get("preHash"), g.get("externalMu")) != \
                ("ML-DSA-65", "external", "pure", False):
            continue
        for t in g["tests"]:
            if t.get("hashAlg") != "none" or t.get("deferred") is not False:
                raise SystemExit(f"tc {t.get('tcId')}: hashAlg or deferred outside the rule")
            out.append({"tgId": g["tgId"], "tcId": t["tcId"], "testPassed": t["testPassed"], "reason": t["reason"],
                        "pk": t["pk"].lower(), "message": t["message"].lower(), "context": t["context"].lower(),
                        "signature": t["signature"].lower()})
    return out


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        for c in cases(f.read()):
            sys.stdout.write(json.dumps(c, separators=(",", ":")) + "\n")
