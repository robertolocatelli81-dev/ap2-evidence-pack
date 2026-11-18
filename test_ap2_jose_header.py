#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.0, SPEC §13: the JOSE header profile (decode_jose_header, check_jose_header, check_jose_profile) and the dots that
parse_sd_jwt names.

Real headers, from the files saved by the reviews of 16-17/11/2026 (never fetched here): EUDI TS3 (eudi-doc-standards
cfc383e) lines 427, 439 and 496 decode to {"kid": "did:example:…/keys/1", "alg": "ES256", "typ": "JWT"} where the
profiles ask `openid4vci-proof+jwt` (427) and `key-attestation+jwt` (439, 496): `typ_mismatch`. The ModI example
(lg-modellointeroperabilita-docs 9790b6a, 02_integrity_rest.rst line 179) shows a token whose first characters decode
to `{"alg":"RS256","ty` beside a JWS header with `"alg": "ES256"` (line 191). Generated headers are compared with an
oracle written apart. Positive control: on 1.7.3 the functions do not exist (this file fails at its import there)."""
import base64
import json
import os
import random
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ap2_evidence as A  # noqa: E402

TS3 = {"kid": "did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1", "alg": "ES256", "typ": "JWT"}
MODI_TOKEN_PREFIX = "eyJhbGciOiJSUzI1NiIsInR5c"          # 02_integrity_rest.rst:179, as shown (truncated)
MODI_SHOWN_HEADER = {"alg": "ES256", "typ": "JWT"}        # line 191 shows "alg": "ES256"


def seg(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


class Real(unittest.TestCase):
    def test_ts3_headers(self):
        for line, profile in ((427, "openid4vci-proof"), (439, "key-attestation"), (496, "key-attestation")):
            h = A.decode_jose_header(seg(TS3))
            r = A.check_jose_profile(h, profile, ["ES256"])
            self.assertEqual((r["ok"], r["why"], r["typ"]), (False, "typ_mismatch", "JWT"), line)

    def test_the_right_types_pass(self):
        for typ in ("key-attestation+jwt", "Key-Attestation+JWT", "application/key-attestation+jwt",
                    "APPLICATION/KEY-ATTESTATION+JWT"):
            self.assertTrue(A.check_jose_profile(dict(TS3, typ=typ), "key-attestation", ["ES256"])["ok"], typ)
        for typ in ("keyattestation+jwt", "application/jwt", "text/key-attestation+jwt", "key-attestation+jwt ",
                    "key-attestation+jwt; v=1"):
            self.assertEqual(A.check_jose_profile(dict(TS3, typ=typ), "key-attestation", ["ES256"])["why"], "typ_mismatch")
        self.assertTrue(A.check_jose_profile({"alg": "ES256", "typ": "dc+sd-jwt"}, "sd-jwt-vc", ["ES256"])["ok"])
        self.assertTrue(A.check_jose_profile({"alg": "ES256", "typ": "kb+jwt"}, "kb-jwt", ["ES256"])["ok"])

    def test_modi_prefix(self):
        with self.assertRaises(A.Ap2EvidenceError):                     # a truncated header is never a header
            A.decode_jose_header(MODI_TOKEN_PREFIX)
        prefix = A._b64url_decode(MODI_TOKEN_PREFIX[:24])
        self.assertTrue(prefix.startswith(b'{"alg":"RS256"'))
        token_alg = json.loads(prefix.split(b",")[0] + b"}")["alg"]
        self.assertNotEqual(token_alg, MODI_SHOWN_HEADER["alg"])
        r = A.check_jose_header({"alg": token_alg, "typ": "JWT"}, "JWT", [MODI_SHOWN_HEADER["alg"]])
        self.assertEqual(r["why"], "alg_not_allowed")

    def test_dots_are_named(self):
        for text, dots in (("abc", 0), ("a.b", 1), ("a.b.c.d", 3), ("a.b.c.d.e", 4)):
            with self.assertRaises(A.Ap2EvidenceError) as c:
                A.parse_sd_jwt(text + "~")   # 1.8.1: an SD-JWT has a '~' (sd_jwt_no_separator otherwise, SPEC §6 step 2)
            self.assertIn(f"(found {dots} dot(s))", str(c.exception))


class Rules(unittest.TestCase):
    def test_reasons_and_order(self):
        for h, why in (([], "header_not_object"), ("x", "header_not_object"), (None, "header_not_object"),
                       ({"alg": "ES256", "typ": "kb+jwt", "crit": ["b64"]}, "crit_not_understood"),
                       ({"crit": [], "typ": 1}, "crit_not_understood"),
                       ({"typ": "kb+jwt"}, "alg_missing"), ({"alg": 1, "typ": "kb+jwt"}, "alg_not_string"),
                       ({"alg": "none", "typ": "kb+jwt"}, "alg_not_allowed"), ({"alg": "RS256"}, "alg_not_allowed"),
                       ({"alg": "ES256"}, "typ_missing"), ({"alg": "ES256", "typ": None}, "typ_not_string"),
                       ({"alg": "ES256", "typ": ["kb+jwt"]}, "typ_not_string"), ({"alg": "ES256", "typ": "jwt"}, "typ_mismatch")):
            self.assertEqual(A.check_jose_header(h, "kb+jwt", ["ES256"])["why"], why, h)

    def test_arguments(self):
        for typ, algs in (("", ["ES256"]), (None, ["ES256"]), ("kb+jwt", []), ("kb+jwt", ["none"]), ("kb+jwt", "ES256"),
                          ("kb+jwt", [""]), ("kb+jwt", [None])):
            with self.assertRaises(ValueError):
                A.check_jose_header({"alg": "ES256"}, typ, algs)
        for p in ("openid4vci-proof", "key-attestation"):
            with self.assertRaises(ValueError):
                A.check_jose_profile(TS3, p, ["ES256", "HS256"])
        self.assertTrue(A.check_jose_profile({"alg": "HS256", "typ": "kb+jwt"}, "kb-jwt", ["HS256"])["ok"])
        self.assertEqual(A.check_jose_profile(TS3, "unknown", ["ES256"])["why"], "profile_unknown")

    def test_decode_is_strict(self):
        good = seg({"alg": "ES256"})
        self.assertEqual(A.decode_jose_header(good), {"alg": "ES256"})
        for bad in (good + "=", good + " ", "e" + good, base64.urlsafe_b64encode(b'{"alg":"ES256","alg":"x"}').decode().rstrip("="),
                    seg([1]), seg("x"), base64.urlsafe_b64encode(b'\xef\xbb\xbf{}').decode().rstrip("="),
                    base64.urlsafe_b64encode(b'{"a":\xff}').decode().rstrip("="), "", None):
            with self.assertRaises(A.Ap2EvidenceError, msg=repr(bad)):
                A.decode_jose_header(bad)


def oracle(header, expected, algs):
    """the rule of SPEC §13, written apart"""
    if not isinstance(header, dict):
        return "header_not_object"
    if "crit" in header:
        return "crit_not_understood"
    a = header.get("alg", KeyError)
    if a is KeyError:
        return "alg_missing"
    if type(a) is not str:
        return "alg_not_string"
    if a not in algs:
        return "alg_not_allowed"
    t = header.get("typ", KeyError)
    if t is KeyError:
        return "typ_missing"
    if type(t) is not str:
        return "typ_not_string"
    low = lambda x: "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in x)   # SPEC §13: A-Z only  # noqa: E731
    norm = [low(x) if "/" in x else "application/" + low(x) for x in (t, expected)]
    return None if norm[0] == norm[1] else "typ_mismatch"


class Generated(unittest.TestCase):
    def test_against_the_oracle(self):
        rnd = random.Random(20261117)
        typs = ["kb+jwt", "KB+JWT", "application/kb+jwt", "Application/Kb+Jwt", "jwt", "JWT", "kb+jwt ", "kbjwt", "",
                "application/", "/kb+jwt", "kb+jwt/x", "dc+sd-jwt", "KB+jwt"]
        algs = ["ES256", "ES384", "EdDSA", "none", "RS256", "", "es256"]
        seen = {}
        for _ in range(5000):
            h = {}
            keys = [k for k, pr in (("alg", 0.85), ("typ", 0.85), ("kid", 0.5), ("crit", 0.3), ("x5c", 0.2))
                    if rnd.random() < pr]
            for k in keys:
                if k == "alg":
                    h[k] = rnd.choice(algs + [1, None, ["ES256"]])
                elif k == "typ":
                    h[k] = rnd.choice(typs + [1, None, True])
                elif k == "crit":
                    h[k] = rnd.choice([[], ["b64"], "x"])
                else:
                    h[k] = "v"
            exp = rnd.choice(["kb+jwt", "application/kb+jwt", "KB+JWT"])
            allowed = rnd.choice([["ES256"], ["ES256", "EdDSA"], ["RS256"]])
            got = A.check_jose_header(h, exp, allowed)["why"]
            self.assertEqual(got, oracle(h, exp, allowed), (h, exp, allowed))
            seen[got] = seen.get(got, 0) + 1
        for why in (None, "crit_not_understood", "alg_missing", "alg_not_string", "alg_not_allowed", "typ_missing",
                    "typ_not_string", "typ_mismatch"):
            self.assertGreaterEqual(seen.get(why, 0), 20, seen)

    def test_decode_round_trip(self):
        rnd = random.Random(5)
        for _ in range(2000):
            h = {"alg": rnd.choice(["ES256", "EdDSA"]), "typ": rnd.choice(["kb+jwt", "dc+sd-jwt"]),
                 "kid": "".join(rnd.choice("abcé/:") for _ in range(rnd.randint(0, 9)))}
            s = base64.urlsafe_b64encode(json.dumps(h, ensure_ascii=rnd.random() < 0.5).encode()).decode().rstrip("=")
            self.assertEqual(A.decode_jose_header(s), h)


if __name__ == "__main__":
    unittest.main()
