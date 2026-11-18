#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.0, SPEC §7.3 and §13: the KB-JWT header's `typ` compared as RFC 7515 §4.1.9 says (ASCII case ignored,
`application/` implied when there is no '/'), in the reference and in the JavaScript verifier alike.

Positive control: on 1.7.3 and on the branch before this change the typ was compared byte for byte, and `KB+JWT`
(the same media type) was refused: measured on the branch before this change, 4 of the 6 tests fail (the KB-JWT typ
compared byte for byte, and check_jose_header taking U+212A as "K"); `test_wrong_typ_refused` and
`test_ascii_boundaries` pass on both. A wrong
typ stays refused, and U+212A KELVIN SIGN, which Python's `str.lower` and JavaScript's `toLowerCase` turn into "k", is
not "K" (only A-Z are folded). The JavaScript function is read from a copy of ap2-verify.mjs that exports it; the
same values go to both, a fixed list and 2 000 generated ones."""
import base64
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")
HAVE_NODE = shutil.which("node") is not None
ACCEPTED = ["kb+jwt", "KB+JWT", "Kb+Jwt", "kB+jWT", "application/kb+jwt", "APPLICATION/KB+JWT", "Application/Kb+Jwt"]
REFUSED = ["jwt", "JWT", "kb+jwt ", " kb+jwt", "kb+jwt\n", "KB+JWT", "kb+jwt; v=1", "text/kb+jwt", "application//kb+jwt",
           "application/", "", "kb-jwt", "kb+sd-jwt", "dc+sd-jwt", "application/jwt", "KB+JWTİ", "kıb+jwt",
           "ＫＢ+JWT", "kb​+jwt"]
NOT_STRING = [None, 5, True, ["kb+jwt"], {"t": "kb+jwt"}]
MISSING = object()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def kb_with(typ) -> str:
    header = {"alg": "ES256"}
    if typ is not MISSING:
        header["typ"] = typ
    payload = {"aud": "m", "nonce": "n1", "iat": 1760000000, "sd_hash": "x"}
    return ".".join([b64u(json.dumps(header).encode()), b64u(json.dumps(payload).encode()), b64u(b"\0" * 64)])


def py_outcome(typ):
    """'ok' (the typ check passed: no holder key, so the KB-JWT is present and not verified) or the refusal"""
    try:
        kb = kb_with(typ)   # 1.8.1: verify_kb_jwt reads the presentation (sd_hash) without the holder key too: a parsed SD-JWT
        r = A.verify_kb_jwt({"kb_jwt": kb, "compact": "h.p.s~" + kb}, {})
        return "ok" if (r["present"], r["verified"]) == (True, None) else f"other {r}"
    except A.Ap2EvidenceError as e:
        return str(e)


def js_outcomes(typs):
    d = tempfile.mkdtemp(prefix="ap2kbtyp_")
    try:
        with open(JS, encoding="utf-8") as f:
            src = f.read()
        with open(os.path.join(d, "m.mjs"), "w", encoding="utf-8") as f:
            f.write(src + "\nexport { verifyKbJwt as __verifyKbJwt };\n")
        with open(os.path.join(d, "in.json"), "w", encoding="utf-8") as f:
            json.dump([kb_with(t) for t in typs], f)
        with open(os.path.join(d, "run.mjs"), "w", encoding="utf-8") as f:
            f.write('import { __verifyKbJwt } from "./m.mjs";\nimport { readFileSync } from "node:fs";\n'
                    'const out = [];\nfor (const kb of JSON.parse(readFileSync(process.argv[2], "utf8"))) {\n'
                    '  try { const r = __verifyKbJwt({ kbJwt: kb, compact: "h.p.s~" + kb }, {});\n'
                    '    out.push(r.present === true && r.verified === null ? "ok" : "other " + JSON.stringify(r)); }\n'
                    '  catch (e) { out.push(e.message); } }\nprocess.stdout.write(JSON.stringify(out));\n')
        p = subprocess.run(["node", os.path.join(d, "run.mjs"), os.path.join(d, "in.json")], capture_output=True,
                           text=True, cwd=d)
        if p.returncode != 0:
            raise AssertionError(p.stderr[-800:])
        return json.loads(p.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def oracle(typ) -> bool:
    """RFC 7515 §4.1.9, written apart: a string that, A-Z folded and 'application/' added when no '/', is the type"""
    if not isinstance(typ, str):
        return False
    folded = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in typ)
    if "/" not in folded:
        folded = "application/" + folded
    return folded == "application/kb+jwt"


class KbTyp(unittest.TestCase):
    def test_case_and_prefix_accepted(self):
        for typ in ACCEPTED:
            self.assertEqual(py_outcome(typ), "ok", typ)

    def test_wrong_typ_refused(self):
        for typ in REFUSED + NOT_STRING + [MISSING]:
            self.assertIn('typ must be "kb+jwt"', py_outcome(typ), repr(typ))

    def test_check_jose_header_folds_only_ascii(self):
        for typ in ACCEPTED:
            self.assertTrue(A.check_jose_profile({"alg": "ES256", "typ": typ}, "kb-jwt", ["ES256"])["ok"], typ)
        for typ in REFUSED:
            self.assertEqual(A.check_jose_profile({"alg": "ES256", "typ": typ}, "kb-jwt", ["ES256"])["why"],
                             "typ_mismatch", repr(typ))
        self.assertEqual("KB+JWT".lower(), "kb+jwt")      # the trap: Python's own lowercasing

    def test_ascii_boundaries(self):
        """A-Z folded, and nothing else: '@' (0x40) and '[' (0x5B) stay; every letter, Z included"""
        self.assertEqual(A._media_type("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "application/abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(A._media_type("@[`{"), "application/@[`{")
        self.assertTrue(A.check_jose_header({"alg": "ES256", "typ": "ZZ+JWT"}, "zz+jwt", ["ES256"])["ok"])

    def test_generated_against_the_oracle_and_js(self):
        rnd = random.Random(20261117)
        alphabet = "kKbBjJwWtT+/aApPlLiIcCoOnN Kİı;=-"
        typs = list(ACCEPTED + REFUSED)
        for _ in range(2000):
            base = rnd.choice(["kb+jwt", "application/kb+jwt", "jwt", "kb+sd-jwt"])
            s = list(base)
            for _ in range(rnd.randint(0, 3)):
                op, i = rnd.randrange(4), rnd.randrange(len(s) + 1)
                if op == 0 and i < len(s):
                    s[i] = s[i].swapcase()
                elif op == 1:
                    s.insert(i, rnd.choice(alphabet))
                elif op == 2 and i < len(s):
                    del s[i]
                elif i < len(s):
                    s[i] = rnd.choice(alphabet)
            typs.append("".join(s))
        py = [py_outcome(t) for t in typs]
        for t, got in zip(typs, py):
            self.assertEqual(got == "ok", oracle(t), repr(t))
        self.assertGreater(sum(o == "ok" for o in py), 50)          # the generator reaches both sides
        self.assertGreater(sum(o != "ok" for o in py), 50)
        if HAVE_NODE:
            js = js_outcomes(typs + NOT_STRING + [MISSING])
            py_all = py + [py_outcome(t) for t in NOT_STRING + [MISSING]]
            diff = [(t, a, b) for t, a, b in zip(typs + NOT_STRING + ["<missing>"], py_all, js) if a != b]
            self.assertEqual(diff, [])

    def test_pack_end_to_end(self):
        """a pack whose KB-JWT says typ "KB+JWT", built and verified by the reference and the JavaScript verifier"""
        import hashlib
        import test_ap2_evidence as E
        sk, jwk = E._make_signer()
        hsk, hjwk = E._make_signer()
        sd = E._make_sd_jwt(sk, {"iss": "wallet", "cnf": {"jwk": hjwk}}, {"amount": "10.00"}, header_extra={"jwk": jwk})
        kb = E._sign_jwt(hsk, {"alg": "ES256", "typ": "KB+JWT"},
                         {"aud": "m", "nonce": "n1", "iat": 1760000000,
                          "sd_hash": E._b64u(hashlib.sha256(sd.encode("ascii")).digest())})
        d = tempfile.mkdtemp(prefix="ap2kbtyp_")
        try:
            out = os.path.join(d, "pack.json")
            A.build_evidence([{"name": "i", "sd_jwt": sd + kb}], out)
            v = A.verify_evidence(out)
            self.assertEqual((v["valid"], v["artifacts"][0]["kb_jwt"]["verified"]), (True, True), v)
            if HAVE_NODE:
                p = subprocess.run(["node", JS, out], capture_output=True, text=True)
                j = json.loads(p.stdout)
                self.assertEqual((p.returncode, j["valid"], j["artifacts"][0]["kb_jwt"]["verified"]), (0, True, True), p.stdout[-600:])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
