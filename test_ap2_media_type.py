#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.1, SPEC §13: `typ` compared as a media type, as RFC 7515 §4.1.9 says — "Per RFC 2045, all media type values,
subtype values, and parameter names are case insensitive. However, parameter values are case sensitive unless otherwise
specified" — with the grammar of RFC 9110 §8.3.1 and §5.6.6 (OWS around ';', no whitespace around '=', token or
quoted-string values, the two forms equivalent), in the reference and in the JavaScript verifier alike.

Positive control: on v1.8.0 (d5601e4) the whole value was folded, so `check_jose_header` found `x+jwt;p=A` equal to
`x+jwt;p=a`, and `kb+jwt; p=a`, `kb+jwt;p="a"`, `KB+JWT;P=a` different from `kb+jwt;p=a` (measured 2026-11-18). On
v1.8.0 `test_named_pairs` and `test_generated_pairs_python` fail; the JS test compares with a function v1.8.0 does not
have in that form and fails too.

The expected answer of every generated pair comes from `oracle`, written apart (a regular expression of the RFC 9110
grammar), not from the code under test."""
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
T = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
Q = r'"(?:[\t !#-\[\]-~]|\\[\t !-~])*"'
PARAM = rf"[ \t]*;[ \t]*({T})=({T}|{Q})"   # 1.8.1 (SPEC §13): this format's rule, a ';' needs a parameter
FULL = re.compile(rf"({T})(?:/({T}))?((?:{PARAM})*)")


def fold(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def oracle(typ):
    """RFC 9110 media type, written apart: (folded type/subtype, sorted (folded name, value)) or None"""
    m = FULL.fullmatch(typ)
    if not m:
        return None
    if m.group(2) is None and "/" in typ:
        return None
    full = m.group(1) + "/" + m.group(2) if m.group(2) is not None else "application/" + m.group(1)
    params = {}
    for pm in re.finditer(PARAM, m.group(3)):
        v = pm.group(2)
        if v.startswith('"'):
            v = re.sub(r"\\(.)", r"\1", v[1:-1], flags=re.S)
        k = fold(pm.group(1))
        if k in params:
            return None
        params[k] = v
    return fold(full), tuple(sorted(params.items()))


def same(norm, a, b):
    x, y = norm(a), norm(b)
    return x is not None and x == y


def generate(rnd):
    base = rnd.choice(["kb+jwt", "KB+JWT", "application/kb+jwt", "Application/Kb+Jwt", "x+jwt", "dc+sd-jwt", "KB+JWT",
                       "kb+jwt/", "", "a/b/c"])
    out = base
    for _ in range(rnd.choice([0, 0, 1, 1, 2, 3])):
        name = rnd.choice(["p", "P", "charset", "Charset", "q", "K", "a b", ""])
        val = rnd.choice(["a", "A", "utf-8", "UTF-8", '"a"', '"A"', '"a\\"b"', '"x y"', '"\\a"', '"unterminated', "", "x y",
                          "K", '"K"', "a/b", '"a;b"'])
        sp1, sp2 = rnd.choice(["", " ", "\t", "  "]), rnd.choice(["", " ", "\t"])
        eq = rnd.choice(["=", "=", "=", " =", "= "])
        out += f"{sp1};{sp2}{name}{eq}{val}"
    if rnd.random() < 0.1:
        out += rnd.choice([";", " ", "; ", ";;"])
    return out


def variant(rnd, typ):
    """another spelling of the same media type, or a near miss"""
    choices = [typ, typ.upper(), fold(typ), typ.replace(";", " ; "), typ.replace(";", ";\t"), typ.replace("=a", '="a"'),
               typ.replace('="a"', "=a"), typ.replace("=a", "=A"), typ.replace("application/", ""), typ + ";", typ + " ",
               "application/" + typ]
    return rnd.choice(choices)


PAIRS = []
_rnd = random.Random(20261118)
for _ in range(3000):
    a = generate(_rnd)
    PAIRS.append((a, variant(_rnd, a)))
NAMED = [("x+jwt;p=A", "x+jwt;p=a", False), ("kb+jwt;p=a", "kb+jwt; p=a", True), ("kb+jwt;p=a", 'kb+jwt;p="a"', True),
         ("kb+jwt;p=a", "KB+JWT;P=a", True), ("kb+jwt;charset=UTF-8", "kb+jwt;charset=utf-8", False),
         ("kb+jwt;a=1;b=2", "kb+jwt;b=2;a=1", True), ("kb+jwt;p=a;p=a", "kb+jwt;p=a", False),
         ("kb+jwt;p = a", "kb+jwt;p=a", False), ('kb+jwt;p="a\\"b"', 'kb+jwt;p="a\\"b"', True),
         ("kb+jwt;K=a", "kb+jwt;k=a", False), ("kb+jwt;p=K", "kb+jwt;p=k", False),
         ("kb+jwt;", "kb+jwt", False), ("kb+jwt ", "kb+jwt", False), ("kb+jwt", "application/kb+jwt", True),
         ('kb+jwt;p="\\a"', "kb+jwt;p=a", True),
         ('x+jwt;p="a/b"', 'application/x+jwt;p="a/b"', False),
         # 1.8.1, SPEC §13: a ';' not followed by a parameter is no media type in this format (RFC 9110 §5.6.6 allows an
         # empty parameter; this format refuses it, as 1.8.0 did, so the patch release widens nothing)
         ("kb+jwt ;", "kb+jwt", False), ("kb+jwt;;", "kb+jwt", False), ("kb+jwt; ;", "kb+jwt", False),
         ("kb+jwt;\t", "kb+jwt", False), ("application/kb+jwt;", "kb+jwt", False), ("x+jwt;", "x+jwt", False),
         ("kb+jwt;p=a;", "kb+jwt;p=a", False), ("kb+jwt;;p=a", "kb+jwt;p=a", False), ("kb+jwt\t;", "kb+jwt", False)]
EMPTY_PARAMETER = ["kb+jwt;", "kb+jwt ;", "kb+jwt;\t", "kb+jwt;;;", "kb+jwt; ;", "Application/KB+JWT;", "kb+jwt\t;",
                   "application/kb+jwt;", "x+jwt;", "kb+jwt;p=a;", "kb+jwt;;p=a", "kb+jwt;p=a; ;q=b"]   # RFC 7515 §4.1.9: a '/' anywhere, nothing prepended   # a quoted-pair is the character after the backslash (RFC 9110 §5.6.4)


class MediaType(unittest.TestCase):
    def test_named_pairs(self):
        for a, b, want in NAMED:
            self.assertEqual(same(oracle, a, b), want, (a, b))   # the oracle itself, on the cases the SPEC names
            self.assertEqual(A.check_jose_header({"alg": "ES256", "typ": a}, b, ["ES256"])["ok"], want, (a, b))

    def test_empty_parameter_is_no_media_type(self):
        # 1.8.1, SPEC §13: the cases measured as new greens on the branch before this rule (NEMESIS R7, 2026-11-18)
        for typ in EMPTY_PARAMETER:
            self.assertIsNone(oracle(typ), typ)
            self.assertIsNone(A._media_type(typ), typ)
            self.assertFalse(A.check_jose_header({"alg": "ES256", "typ": typ}, "kb+jwt", ["ES256"])["ok"], typ)
            with self.assertRaises(ValueError, msg=typ):
                A.check_jose_header({"alg": "ES256", "typ": "kb+jwt"}, typ, ["ES256"])

    def test_generator_reaches_both_answers(self):
        got = {same(oracle, a, b) for a, b in PAIRS}
        self.assertEqual(got, {True, False})
        self.assertGreater(sum(oracle(a) is None for a, _ in PAIRS), 100)
        self.assertGreater(sum(oracle(a) is not None and ";" in a for a, _ in PAIRS), 150)   # 221 measured with this seed

    def test_generated_pairs_python(self):
        for a, b in PAIRS:
            want = same(oracle, a, b)
            if oracle(b) is None:   # an expected_typ that is no media type is the caller's error
                with self.assertRaises(ValueError, msg=(a, b)):
                    A.check_jose_header({"alg": "ES256", "typ": a}, b, ["ES256"])
                continue
            self.assertEqual(A.check_jose_header({"alg": "ES256", "typ": a}, b, ["ES256"])["ok"], want, (a, b))

    def test_kb_jwt_typ_with_parameters_refused(self):
        for typ in ("kb+jwt;p=a", "KB+JWT; v=1", 'kb+jwt;p=""'):
            kb = ".".join(A._b64url(json.dumps(x).encode()) for x in
                          ({"alg": "ES256", "typ": typ}, {"aud": "m", "nonce": "n", "iat": 1, "sd_hash": "x"})) + "." + \
                A._b64url(b"\0" * 64)
            with self.assertRaisesRegex(A.Ap2EvidenceError, 'typ must be "kb\\+jwt"'):
                A.verify_kb_jwt({"kb_jwt": kb, "compact": "h.p.s~" + kb}, {})

    @unittest.skipUnless(NODE, "needs node")
    def test_generated_pairs_js(self):
        d = tempfile.mkdtemp(prefix="ap2mt_")
        try:
            with open(JS, encoding="utf-8") as f:
                src = f.read()
            with open(os.path.join(d, "m.mjs"), "w", encoding="utf-8") as f:
                f.write(src + "\nexport { mediaType as __mt };\n")
            with open(os.path.join(d, "in.json"), "w", encoding="utf-8") as f:
                json.dump([[a, b] for a, b in PAIRS + [(a, b) for a, b, _ in NAMED]], f)
            with open(os.path.join(d, "run.mjs"), "w", encoding="utf-8") as f:
                f.write('import { __mt } from "./m.mjs";\nimport { readFileSync } from "node:fs";\n'
                        'const out = JSON.parse(readFileSync(process.argv[2], "utf8")).map(([a, b]) => {\n'
                        '  const x = __mt(a), y = __mt(b); return [x !== null && x === y, y === null]; });\n'
                        'process.stdout.write(JSON.stringify(out));\n')
            p = subprocess.run([NODE, os.path.join(d, "run.mjs"), os.path.join(d, "in.json")], capture_output=True,
                               text=True, cwd=d)
            self.assertEqual(p.returncode, 0, p.stderr[-800:])
            for (a, b), (eq, b_none) in zip(PAIRS + [(a, b) for a, b, _ in NAMED], json.loads(p.stdout)):
                self.assertEqual((eq, b_none), (same(oracle, a, b), oracle(b) is None), (a, b))
                self.assertEqual(eq, same(A._media_type, a, b), (a, b))   # the two verifiers agree
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
