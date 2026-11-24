#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.1, SPEC §6 step 2 and §9.2 (2026-11-18): the SD-JWT grammar closed (RFC 9901 §4) and `sd_hash` checked without
the holder key (RFC 9901 §4.3.1), in the reference and in the JavaScript verifier alike.

Positive control: on v1.8.0 (d5601e4) `<jwt>~<d1>~<d2>` gave `parse_sd_jwt` one disclosure and `<d2>` as the KB-JWT, and
`resolve_disclosures` resolved without `<d2>`; `<jwt>` and `<jwt>~~<d1>~` parsed with no error (valid: true in a pack);
a KB-JWT without cnf.jwk gave the same object for a right and a wrong `sd_hash` (valid: true; now a wrong one is that
artifact's error, sd_hash_mismatch, in verify and build). Measured on v1.8.0 with this file, 7 of its 9 tests fail:
`test_generative_grammar_python`, `test_generative_grammar_js`, `test_named_cases`, `test_sd_hash_without_key_python`,
`test_sd_hash_without_key_js`, `test_build_does_not_seal_it` (the receipt has no `sd_hash_ok`) and
`test_build_refuses_a_wrong_sd_hash_without_key`;
`test_generator_reaches_every_class` and `test_with_key_unchanged` pass on both.

The expected outcome of each generated serialization comes from the generator's own labels of each component, matched
against the ABNF of RFC 9901 §4 (`SD-JWT = JWT "~" *(DISCLOSURE "~")`, `SD-JWT-KB = SD-JWT KB-JWT`), not from the code."""
import base64
import hashlib
import json
import os
import random
import re
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
NODE = shutil.which("node")
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
NEEDS_CRYPTO = unittest.skipUnless(HAVE_CRYPTO, "needs cryptography")
NEEDS_NODE = unittest.skipUnless(NODE, "needs node")
NAMES = ("sd_jwt_no_separator", "sd_jwt_empty_component", "sd_jwt_final_component_not_kb_jwt")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwt_of(h, p, sig=b"\0" * 64):
    return ".".join([b64u(json.dumps(h).encode()), b64u(json.dumps(p).encode()), b64u(sig)])


ISSUER = jwt_of({"alg": "ES256", "typ": "example+sd-jwt"}, {"iss": "w", "_sd_alg": "sha-256"})
KB = jwt_of({"alg": "ES256", "typ": "kb+jwt"}, {"iat": 1, "aud": "m", "nonce": "n", "sd_hash": "x"})


def disclosure(i):
    return b64u(json.dumps([f"salt{i}", f"c{i}", i]).encode())


# component kinds: D disclosure, E empty, K a KB-JWT, and the malformed last components (none of them three segments)
LAST_BAD = {"one_segment": "abc", "two_segments": "a.b", "four_segments": "a.b.c.d", "disclosure": None}


def generate(rnd):
    """(serialization, labels): labels = the list of component kinds after the issuer JWT, or None for no '~' at all"""
    if rnd.random() < 0.08:
        return ISSUER, None
    n = rnd.randrange(0, 5)
    comps = [("D", disclosure(i)) for i in range(n)]
    for _ in range(rnd.choice([0, 0, 0, 1, 2])):   # empty components anywhere before the last
        comps.insert(rnd.randrange(0, len(comps) + 1), ("E", ""))
    last = rnd.choice(["E", "E", "K", "bad"])
    if last == "E":
        comps.append(("E", ""))
    elif last == "K":
        comps.append(("K", KB))
    else:
        kind = rnd.choice(sorted(LAST_BAD))
        comps.append(("D", disclosure(99)) if kind == "disclosure" else ("X", LAST_BAD[kind]))
    return ISSUER + "~" + "~".join(c for _, c in comps), [k for k, _ in comps]


def expected(labels):
    """from the labels: ("ok", n disclosures, KB-JWT present) or ("refused", the set of rules broken)"""
    if labels is None:
        return ("refused", {"sd_jwt_no_separator"})
    seq = "".join(labels)
    if re.fullmatch(r"D*[EK]", seq):          # JWT "~" *(DISCLOSURE "~") [KB-JWT]
        return ("ok", seq.count("D"), seq.endswith("K"))
    broken = set()
    if "E" in seq[:-1]:
        broken.add("sd_jwt_empty_component")
    if seq[-1] in "DX":
        broken.add("sd_jwt_final_component_not_kb_jwt")
    return ("refused", broken)


def py_parse(compact):
    try:
        p = A.parse_sd_jwt(compact)
        return ("ok", len(p["disclosures"]), p["kb_jwt"] is not None)
    except A.Ap2EvidenceError as e:
        return ("refused", str(e).split(":")[0])


def js_parse_many(compacts):
    d = tempfile.mkdtemp(prefix="ap2grammar_")
    try:
        with open(JS, encoding="utf-8") as f:
            src = f.read()
        with open(os.path.join(d, "m.mjs"), "w", encoding="utf-8") as f:
            f.write(src + "\nexport { parseSdJwt as __parse, verifyKbJwt as __kb };\n")
        with open(os.path.join(d, "in.json"), "w", encoding="utf-8") as f:
            json.dump(compacts, f)
        with open(os.path.join(d, "run.mjs"), "w", encoding="utf-8") as f:
            f.write('import { __parse, __kb } from "./m.mjs";\nimport { readFileSync } from "node:fs";\nconst out = [];\n'
                    'for (const [c, resolved] of JSON.parse(readFileSync(process.argv[2], "utf8"))) {\n'
                    '  try { const p = __parse(c);\n'
                    '    if (resolved === null) { out.push(["ok", p.disclosures.length, p.kbJwt !== null]); continue; }\n'
                    '    const r = __kb(p, resolved); delete r._ignored; out.push(["kb", r]); }\n'
                    '  catch (e) { out.push(["refused", e.message.split(":")[0]]); } }\n'
                    'process.stdout.write(JSON.stringify(out));\n')
        p = subprocess.run([NODE, os.path.join(d, "run.mjs"), os.path.join(d, "in.json")], capture_output=True, text=True,
                           cwd=d, encoding="utf-8")
        if p.returncode != 0:
            raise AssertionError(p.stderr[-800:])
        return json.loads(p.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def check(test, got, want, compact):
    if want[0] == "ok":
        test.assertEqual(tuple(got), want, compact)
    else:
        test.assertEqual(got[0], "refused", compact)
        test.assertIn(got[1], want[1], compact)


class Grammar(unittest.TestCase):
    CASES = [generate(random.Random(seed)) for seed in range(1500)]

    def test_generator_reaches_every_class(self):
        seen = {expected(lab)[0] for _, lab in self.CASES} | \
               {n for _, lab in self.CASES for n in (expected(lab)[1] if expected(lab)[0] == "refused" else ())}
        self.assertTrue({"ok", *NAMES} <= seen, seen)

    def test_generative_grammar_python(self):
        for compact, labels in self.CASES:
            check(self, py_parse(compact), expected(labels), compact)

    @NEEDS_NODE
    def test_generative_grammar_js(self):
        got = js_parse_many([[c, None] for c, _ in self.CASES])
        for (compact, labels), g in zip(self.CASES, got):
            check(self, g, expected(labels), compact)
            self.assertEqual(tuple(g), py_parse(compact), compact)   # the two verifiers: the same outcome, the same name

    def test_named_cases(self):
        d1, d2 = disclosure(1), disclosure(2)
        table = {ISSUER: "sd_jwt_no_separator",
                 f"{ISSUER}~{d1}~{d2}": "sd_jwt_final_component_not_kb_jwt",
                 f"{ISSUER}~~{d1}~": "sd_jwt_empty_component",
                 f"{ISSUER}~{d1}~~": "sd_jwt_empty_component",
                 f"{ISSUER}~{d1}~a.b": "sd_jwt_final_component_not_kb_jwt",
                 f"{ISSUER}~{d1}~a.b.c.d": "sd_jwt_final_component_not_kb_jwt"}
        for compact, name in table.items():
            self.assertEqual(py_parse(compact), ("refused", name), compact)
        for compact in (f"{ISSUER}~", f"{ISSUER}~{d1}~{d2}~", f"{ISSUER}~{KB}", f"{ISSUER}~{d1}~{KB}"):
            self.assertEqual(py_parse(compact)[0], "ok", compact)
        with self.assertRaises(A.Ap2EvidenceError):   # a 3-segment last component is the KB-JWT: checked later, as before
            A.verify_kb_jwt(A.parse_sd_jwt(f"{ISSUER}~{d1}~a.b.c"), {})


def signer():
    sk = ec.generate_private_key(ec.SECP256R1()); n = sk.public_key().public_numbers()
    return sk, {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def sign(sk, h, p):
    si = b64u(json.dumps(h, separators=(",", ":")).encode()) + "." + b64u(json.dumps(p, separators=(",", ":")).encode())
    r, s = decode_dss_signature(sk.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
    return si + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


@NEEDS_CRYPTO
class SdHashWithoutKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.jwk = signer()
        cls.hsk, cls.hjwk = signer()

    def presentation(self, n, cnf):
        ds = [disclosure(i) for i in range(n)]
        pay = {"iss": "w", "_sd": sorted(A._disclosure_digest(d) for d in ds), "_sd_alg": "sha-256"}
        if cnf:
            pay["cnf"] = {"jwk": self.hjwk}
        pres = sign(self.sk, {"alg": "ES256", "typ": "example+sd-jwt", "jwk": self.jwk}, pay) + "~" + "".join(d + "~" for d in ds)
        return pres, A.resolve_disclosures(pay, ds)

    def kb(self, pres, how):
        target = {"right": pres, "other_presentation": pres + "x~", "no_tilde": pres[:-1], "empty": ""}[how]
        sh = b64u(hashlib.sha256(target.encode("ascii")).digest())
        return sign(self.hsk, {"alg": "ES256", "typ": "kb+jwt"}, {"iat": 1, "aud": "m", "nonce": "n", "sd_hash": sh})

    def cases(self, cnf):
        out = []
        for n in range(4):
            pres, resolved = self.presentation(n, cnf)
            for how in ("right", "other_presentation", "no_tilde", "empty"):
                out.append((pres + self.kb(pres, how), resolved, how == "right"))
        return out

    def py_kb(self, compact, resolved):
        r = A.verify_kb_jwt(A.parse_sd_jwt(compact), resolved)
        r.pop("_ignored", None)
        return r

    def test_sd_hash_without_key_python(self):
        """1.8.1 (SPEC §9.2, RFC 9901 §7.3 step 5.g): right -> verified null, sd_hash_ok true; wrong -> that artifact's
        error, sd_hash_mismatch, whatever the key"""
        for compact, resolved, right in self.cases(cnf=False):
            if not right:
                with self.assertRaisesRegex(A.Ap2EvidenceError, "^sd_hash_mismatch:", msg=compact):
                    self.py_kb(compact, resolved)
                continue
            r = self.py_kb(compact, resolved)
            self.assertEqual((r["present"], r["verified"], r["sd_hash_ok"]), (True, None, True), compact)
            self.assertNotIn("signature_ok", r)   # the signature is not checked without the key: nothing said about it

    def test_with_key_unchanged(self):
        for compact, resolved, right in self.cases(cnf=True):
            r = self.py_kb(compact, resolved)
            self.assertEqual((r["verified"], r["signature_ok"], r["sd_hash_ok"]), (right, True, right), compact)

    @NEEDS_NODE
    def test_sd_hash_without_key_js(self):
        cases = self.cases(cnf=False) + self.cases(cnf=True)
        got = js_parse_many([[c, res] for c, res, _ in cases])
        for (compact, resolved, right), g in zip(cases, got):
            if not right and "cnf" not in resolved:
                self.assertEqual(g, ["refused", "sd_hash_mismatch"], compact)
                continue
            self.assertEqual(g[1].get("sd_hash_ok"), right, compact)
            self.assertEqual(g, ["kb", json.loads(json.dumps(self.py_kb(compact, resolved)))], compact)

    def test_build_refuses_a_wrong_sd_hash_without_key(self):
        pres, _ = self.presentation(2, cnf=False)
        d = tempfile.mkdtemp(prefix="ap2sdh_")
        try:
            out = os.path.join(d, "p.json")
            with self.assertRaisesRegex(A.Ap2EvidenceError, "sd_hash_mismatch"):
                A.build_evidence([{"name": "m", "sd_jwt": pres + self.kb(pres, "other_presentation")}], out)
            self.assertFalse(os.path.exists(out))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_build_does_not_seal_it(self):
        """the member is the receipt's: a producer does not seal it in the holder-key-unknown branch, so a 1.8.0 verifier,
        which does not recompute it there, still reads the pack; a copy that carries it must equal the recomputation"""
        pres, _ = self.presentation(1, cnf=False)
        d = tempfile.mkdtemp(prefix="ap2sdh_")
        try:
            out = os.path.join(d, "p.json")
            A.build_evidence([{"name": "m", "sd_jwt": pres + self.kb(pres, "right")}], out)
            with open(out, encoding="utf-8") as f:
                ev = json.load(f)
            self.assertNotIn("sd_hash_ok", ev["artifacts"][0]["kb_jwt"])
            r = A.verify_evidence(out)
            self.assertEqual((r["valid"], r["artifacts"][0]["kb_jwt"]["sd_hash_ok"]), (True, True))
            self.assertEqual(r["states"]["holder_binding"], {"state": "not_evaluated", "reasons": ["holder_key_unknown"]})
            for claimed, ok in ((True, True), (False, False)):
                ev2 = json.loads(json.dumps(ev))
                ev2["artifacts"][0]["kb_jwt"]["sd_hash_ok"] = claimed
                e2 = {k: v for k, v in ev2.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
                ev2["evidence_digest_sha256"] = hashlib.sha256(A._canon(e2)).hexdigest()
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(ev2, f)
                r = A.verify_evidence(out)
                self.assertEqual(r["valid"], ok, claimed)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
