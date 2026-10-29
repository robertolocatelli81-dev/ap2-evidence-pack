#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.7.1 — SPEC §6 step 2 and §3.1: the depth of the resolved claims, and `build` refusing what `verify` refuses.

A chain of disclosures nested one inside another resolves into claims as deep as the chain, while every JSON text it comes
from (payload, each disclosure) stays shallow. Up to 1.7.0 nothing bounded that depth: `build` wrote packs `verify` then
refused as `json_too_deep`, from about 1000 levels the library raised RecursionError, `build` exited with a traceback,
and `verify` reported the artifact's error as `RecursionError: maximum recursion depth exceeded` (Python) or `Maximum call
stack size exceeded` (JS). 1.7.1: the resolved claims nest no deeper than 512 (`disclosures_too_deep`, that artifact's
error), the walk is iterative in both verifiers, and `build` refuses a pack its own profile refuses.

The chains are GENERATED: each level is one of four forms (a plain object, a plain array, an object disclosure, an array
element disclosure), each adding exactly one level to the resolved claims, so the generator knows the depth and the claims
it meant. The oracle: depth <= 509 — `build` writes a pack both verifiers call valid; 510..512 — the library resolves it,
`build` refuses it (`json_too_deep`: the pack would nest the claims three levels further down), a pack holding the token
is not valid with no artifact error (its recorded claims cannot be the resolved ones); >= 513 — `disclosures_too_deep` in
the library, in `build`, in §11.3 step 5 and as the artifact's error of both verifiers.

Positive control (run by hand, not in the suite): this file on c1bc79e (1.7.0) must FAIL — measured 2026-10-29.
"""
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "verifiers"))
import ap2_evidence as ap2  # noqa: E402
import differential_oracle as O  # noqa: E402

_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_MANY = os.path.join(_HERE, "verifiers", "js", "verify_many.mjs")
_SK, _NUM = O._fresh_key()
_TOO_DEEP = "disclosures_too_deep"


def _b64u(b):
    return __import__("base64").urlsafe_b64encode(b).decode().rstrip("=")


def _disc(arr):
    return _b64u(json.dumps(arr, separators=(",", ":")).encode())


def _h(d):
    return _b64u(hashlib.sha256(d.encode("ascii")).digest())


def chain(forms, leaf="leaf"):
    """forms: the levels from the outside in. Returns (compact, resolved claims meant, their depth)."""
    raw, res, discs = leaf, leaf, []
    for i, f in enumerate(reversed(forms)):
        if f == "obj":
            raw, res = {"p": raw}, {"p": res}
        elif f == "arr":
            raw, res = [raw], [res]
        elif f == "dobj":
            d = _disc(["s%d" % i, "c", raw]); discs.append(d); raw, res = {"_sd": [_h(d)]}, {"c": res}
        else:
            d = _disc(["s%d" % i, raw]); discs.append(d); raw, res = [{"...": _h(d)}], [res]
    payload, resolved = {"iss": "x", "r": raw}, {"iss": "x", "r": res}
    compact = O._sign_compact(_SK, _NUM, json.dumps(payload, separators=(",", ":"))) + "~".join(reversed(discs)) + ("~" if discs else "")
    return compact, resolved, len(forms) + 1


def random_forms(rng, levels):
    """Random levels; a run of plain levels stays short, so no payload or disclosure text is itself deeper than §3.1 allows."""
    out, plain = [], 0
    while len(out) < levels:
        f = rng.choice(("obj", "arr", "dobj", "darr")) if plain < 60 else rng.choice(("dobj", "darr"))
        plain = plain + 1 if f in ("obj", "arr") else 0
        out.append(f)
    if all(f in ("obj", "arr") for f in out):
        out[-1] = "dobj"
    return out


def depth_of(v):
    d, stack = 0, [(v, 1)]
    while stack:
        x, k = stack.pop()
        if isinstance(x, (dict, list)):
            d = max(d, k)
            stack.extend((y, k + 1) for y in (x.values() if isinstance(x, dict) else x))
    return d


def _cases():
    """Fixed chains of one form at and around every threshold (alternating object and array disclosures), and random mixed
    chains in 495..530 levels (the threshold of `build`, 510, and of the resolver, 513, are inside), a seed per run."""
    rng = random.Random(171)
    fixed = [2, 40] + list(range(504, 516)) + list(range(984, 996)) + [1500, 20000]
    out = [["dobj" if i % 2 == 0 else "darr"] * n for i, n in enumerate(fixed)]
    out += [random_forms(rng, rng.randint(495, 530)) for _ in range(24)]
    return out


class TestResolvedDepth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = []
        for forms in _cases():
            compact, resolved, depth = chain(forms)
            cls.cases.append({"forms": forms, "compact": compact, "resolved": resolved, "depth": depth})
        cls.tmp = tempfile.mkdtemp(prefix="ap2depth-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_bench_reaches_both_sides_of_every_threshold(self):
        ds = {c["depth"] for c in self.cases}
        for d in (509, 510, 512, 513, 989, 991, 1501, 20001):
            self.assertIn(d, ds)
        self.assertTrue(any(len(set(c["forms"])) == 4 for c in self.cases if 505 <= c["depth"] <= 520))

    def test_library_and_census(self):
        for c in self.cases:
            p = ap2.parse_sd_jwt(c["compact"])   # every JSON text of the token is within the §3.1 profile
            with self.subTest(depth=c["depth"], lens="resolve_disclosures"):
                if c["depth"] <= ap2.MAX_JSON_DEPTH:
                    got = ap2.resolve_disclosures(p["payload"], p["disclosures"])
                    self.assertEqual(depth_of(got), c["depth"])
                    self.assertEqual(ap2._canon(got), ap2._canon(c["resolved"]))
                else:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, "^" + _TOO_DEEP + ": the resolved claims nest deeper than 512"):
                        ap2.resolve_disclosures(p["payload"], p["disclosures"])
            with self.subTest(depth=c["depth"], lens="_digest_census (SPEC §11.3 step 5)"):
                if c["depth"] <= ap2.MAX_JSON_DEPTH:
                    self.assertEqual(ap2._digest_census(p), 0)
                else:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, _TOO_DEEP):
                        ap2._digest_census(p)

    def test_the_walk_does_not_use_the_interpreter_stack(self):
        # the bound and its error are the same under a recursion limit far below the depth: the walk is iterative
        import inspect
        deep = next(c for c in self.cases if c["depth"] == 512)
        deeper = next(c for c in self.cases if c["depth"] == 20001)
        old = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(len(inspect.stack()) + 60)
            for c in (deep, deeper):
                p = ap2.parse_sd_jwt(c["compact"])
                if c is deep:
                    got = ap2.resolve_disclosures(p["payload"], p["disclosures"])
                else:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, _TOO_DEEP):
                        ap2.resolve_disclosures(p["payload"], p["disclosures"])
        finally:
            sys.setrecursionlimit(old)
        self.assertEqual(ap2._canon(got), ap2._canon(deep["resolved"]))

    def test_the_leaf_below_the_deepest_container(self):
        # NEMESIS1 1.7.1: a scalar is not a level, null included (JS `typeof null === "object"`), an empty container is one
        manifest, expect = [], {}
        for i, (form, leaf) in enumerate((f, l) for f in ("dobj", "darr")
                                         for l in (None, 0, False, "", "leaf", {}, [])):
            compact, resolved, depth = chain([form] * 511, leaf)
            too_deep = isinstance(leaf, (dict, list))   # the leaf itself at 513
            p = ap2.parse_sd_jwt(compact)
            with self.subTest(form=form, leaf=leaf, lens="resolve_disclosures"):
                if too_deep:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, _TOO_DEEP):
                        ap2.resolve_disclosures(p["payload"], p["disclosures"])
                else:
                    self.assertEqual(ap2._canon(ap2.resolve_disclosures(p["payload"], p["disclosures"])), ap2._canon(resolved))
            path = self._swap_pack(compact, "leaf%d.json" % i)
            manifest.append({"name": str(i), "path": path, "flags": []}); expect[str(i)] = too_deep
        if not shutil.which("node"):
            self.skipTest("node absent: the JS verifier is not measured")
        mpath = os.path.join(self.tmp, "manifest_leaf.json")
        with open(mpath, "w") as f:
            json.dump(manifest, f)
        pr = subprocess.run(["node", _MANY, _JS, mpath], capture_output=True, text=True, timeout=600)
        self.assertEqual(pr.returncode, 0, pr.stderr[-500:])
        for k, r in json.loads(pr.stdout).items():
            with self.subTest(case=k, lens="verify js"):
                a = r["artifacts"][0]
                if expect[k]:
                    self.assertIn(_TOO_DEEP, a.get("error", ""), a)
                else:
                    self.assertNotIn("error", a); self.assertIs(a["claims_match"], False)

    def _swap_pack(self, compact, name):
        """A pack built around a flat token, then given `compact` with the same key and header: the file stays shallow."""
        base = os.path.join(self.tmp, "base.json")
        if not os.path.exists(base):
            ap2.build_evidence([{"name": "m", "sd_jwt": O._sign_compact(_SK, _NUM, '{"iss":"x"}')}], base)
        with open(base) as f:
            ev = json.load(f)
        ev["artifacts"][0]["sd_jwt_compact"] = compact
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            json.dump(O.rehash(ev), f)
        return path

    def test_build_and_both_verifiers(self):
        manifest, expect = [], {}
        for i, c in enumerate(self.cases):
            out = os.path.join(self.tmp, "b%d.json" % i)
            with self.subTest(depth=c["depth"], lens="build_evidence"):
                if c["depth"] <= ap2.MAX_JSON_DEPTH - 3:   # the claims sit three levels down in the pack (§2)
                    ap2.build_evidence([{"name": "m", "sd_jwt": c["compact"]}], out)
                    r = ap2.verify_evidence(out)
                    self.assertTrue(r["valid"], r["artifacts"])
                    expect[str(i)] = "valid"
                else:
                    reason = "json_too_deep" if c["depth"] <= ap2.MAX_JSON_DEPTH else _TOO_DEEP
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, reason):
                        ap2.build_evidence([{"name": "m", "sd_jwt": c["compact"]}], out)
                    self.assertFalse(os.path.exists(out), "a refused build wrote a file")
                    out = self._swap_pack(c["compact"], "s%d.json" % i)
                    expect[str(i)] = "mismatch" if c["depth"] <= ap2.MAX_JSON_DEPTH else _TOO_DEEP
            manifest.append({"name": str(i), "path": out, "flags": []})
            if expect.get(str(i)) in ("mismatch", _TOO_DEEP):
                with self.subTest(depth=c["depth"], lens="verify python"):
                    a = ap2.verify_evidence(out)["artifacts"][0]
                    if expect[str(i)] == _TOO_DEEP:
                        self.assertIn(_TOO_DEEP, a.get("error", ""), a)
                    else:
                        self.assertNotIn("error", a); self.assertIs(a["claims_match"], False)
                with self.subTest(depth=c["depth"], lens="verify_restrictions"):
                    self.assertFalse(ap2.verify_restrictions(out)["met"])
        if not shutil.which("node"):
            self.skipTest("node absent: the JS verifier is not measured")
        mpath = os.path.join(self.tmp, "manifest.json")
        with open(mpath, "w") as f:
            json.dump(manifest, f)
        p = subprocess.run(["node", _MANY, _JS, mpath], capture_output=True, text=True, timeout=600)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        receipts = json.loads(p.stdout)
        for i, c in enumerate(self.cases):
            r = receipts[str(i)]
            with self.subTest(depth=c["depth"], lens="verify js"):
                self.assertNotIn("crash", r, r)
                a = r["artifacts"][0]
                if expect[str(i)] == "valid":
                    self.assertTrue(r["valid"], a)
                elif expect[str(i)] == _TOO_DEEP:
                    self.assertFalse(r["valid"]); self.assertIn(_TOO_DEEP, a.get("error", ""), a)
                else:
                    self.assertFalse(r["valid"]); self.assertNotIn("error", a); self.assertIs(a["claims_match"], False)


class TestBuildCommand(unittest.TestCase):
    """The `build` command: a refusal (exit 1, one JSON line on stderr, no file), or a usage error (exit 2) — never a
    traceback; and never a pack its own `verify` refuses."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2depth-cli-")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _build(self, compact, *extra):
        t = os.path.join(self.d, "t.sdjwt"); out = os.path.join(self.d, "p.json")
        with open(t, "w") as f:
            f.write(compact)
        if os.path.exists(out):
            os.unlink(out)
        p = subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "build", out, "m=" + t, *extra],
                           capture_output=True, text=True, timeout=300)
        return p, out

    def test_chains_around_the_thresholds(self):
        for n, rc, reason in ((508, 0, None), (509, 1, "json_too_deep"), (511, 1, "json_too_deep"), (512, 1, _TOO_DEEP),
                              (988, 1, _TOO_DEEP), (990, 1, _TOO_DEEP), (1500, 1, _TOO_DEEP), (20000, 1, _TOO_DEEP)):
            p, out = self._build(chain(["dobj"] * n)[0])
            with self.subTest(levels=n):
                self.assertNotIn("Traceback", p.stderr)
                self.assertEqual(p.returncode, rc, p.stderr[-300:])
                if rc == 0:
                    self.assertTrue(ap2.verify_evidence(out)["valid"])
                else:
                    self.assertFalse(os.path.exists(out))
                    self.assertIn(reason, json.loads(p.stderr.strip().splitlines()[-1])["error"])

    def test_a_supplied_key_the_profile_refuses(self):
        compact = O._sign_compact(_SK, _NUM, '{"iss":"x"}')
        jwk = json.loads(__import__("base64").urlsafe_b64decode(compact.split(".")[0] + "==="))["jwk"]
        p, out = self._build(compact)   # positive control: the same token builds
        self.assertEqual(p.returncode, 0, p.stderr)
        for name, text, rc, reason in (
                ("float member", json.dumps(dict(jwk, ext=1.5)), 1, "float"),
                ("member 600 deep", json.dumps(dict(jwk, ext=json.loads("[" * 600 + "]" * 600))), 1, "json_too_deep"),
                ("integer beyond 2^53", json.dumps(dict(jwk, ext=2 ** 60)), 1, "portable range"),
                ("file 100000 arrays deep", "[" * 100000 + "]" * 100000, 2, "nests too deep"),
                # NEMESIS1 1.7.1: parsed by json.load, then deeper than _canon's recursion (3.9/3.11: 987-990 = traceback)
                ("member 988 deep", json.dumps(jwk)[:-1] + ', "ext": ' + "[" * 988 + "]" * 988 + "}", None, "json_too_deep"),
                ("a list", "[" + json.dumps(jwk) + "]", 2, "not a non-empty JSON object"),
                ("null", "null", 2, "not a non-empty JSON object"),
                ("an empty object", "{}", 2, "not a non-empty JSON object")):
            k = os.path.join(self.d, "k.json")
            with open(k, "w") as f:
                f.write(text)
            p, out = self._build(compact, "--key", "m=" + k)
            with self.subTest(key=name):
                self.assertNotIn("Traceback", p.stderr)
                self.assertIn(p.returncode, (1, 2) if rc is None else (rc,), p.stderr[-300:])   # None: 1, or 2 where json.load gives up first
                self.assertFalse(os.path.exists(out))
                self.assertIn(reason if p.returncode == 1 or rc is not None else "nests too deep", p.stderr)

    def test_the_size_bound_before_and_after_the_tsa(self):
        # NEMESIS1 1.7.1: the bound is checked before any TSA is asked, and again with the TSA blocks the writer will write
        calls = []
        def stamp(digest, url):
            calls.append(url)
            return {"anchored": False, "note": "N" * (65 << 20)}   # a TSA block that alone pushes the pack over 64 MiB
        old = ap2._rfc3161_stamp_noted
        ap2._rfc3161_stamp_noted = stamp
        try:
            big = _disc(["s", "c", "A" * (50 * 1000 * 1000)])
            tok = O._sign_compact(_SK, _NUM, json.dumps({"iss": "x", "_sd": [_h(big)]}, separators=(",", ":"))) + big + "~"
            out = os.path.join(self.d, "p.json")
            with self.assertRaisesRegex(ap2.Ap2EvidenceError, "exceeds 67108864 bytes"):
                ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, tsa_url="http://tsa.invalid")
            self.assertEqual(calls, [], "a TSA was asked for a pack already over the bound")
            flat = O._sign_compact(_SK, _NUM, '{"iss":"x"}')
            with self.assertRaisesRegex(ap2.Ap2EvidenceError, "exceeds 67108864 bytes"):
                ap2.build_evidence([{"name": "m", "sd_jwt": flat}], out, tsa_url="http://tsa.invalid")
            self.assertEqual(calls, ["http://tsa.invalid"])
            self.assertFalse(os.path.exists(out))
        finally:
            ap2._rfc3161_stamp_noted = old

    def test_a_pack_over_64_mib_is_not_written(self):
        # NEMESIS1 1.7.1: SPEC §3.1 refuses a file over 64 MiB; measured before the check, exit 0 and a 116 670 431-byte pack
        big = _disc(["s", "c", "A" * (50 * 1000 * 1000)])
        compact = O._sign_compact(_SK, _NUM, json.dumps({"iss": "x", "_sd": [_h(big)]}, separators=(",", ":"))) + big + "~"
        p, out = self._build(compact)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 1, p.stderr[-300:])
        self.assertFalse(os.path.exists(out))
        self.assertIn("exceeds 67108864 bytes", json.loads(p.stderr.strip().splitlines()[-1])["error"])
        small = _disc(["s", "c", "A" * 1000])   # positive control: the same shape, small, builds
        p, out = self._build(O._sign_compact(_SK, _NUM, json.dumps({"iss": "x", "_sd": [_h(small)]}, separators=(",", ":"))) + small + "~")
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertTrue(ap2.verify_evidence(out)["valid"])


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestSizeBoundExact(unittest.TestCase):
    """NEMESIS2 1.7.1: the 64 MiB bound at the byte, on the text the writers write — ASCII and non-ASCII (written as UTF-8,
    escaped as \\uXXXX in the canonical form), and the two writers that add a block to an existing pack, `stamp` and
    `sign_evidence` (measured before this check: 200 bytes under the bound became 67 109 969 / 67 116 150, refused by both
    verifiers). The subject is the padding: one ASCII character is one byte of the file, an e-acute two."""

    MAX = ap2.MAX_EVIDENCE_BYTES

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2size-")
        cls.tok = O._sign_compact(_SK, _NUM, '{"iss":"x"}')
        p = os.path.join(cls.d, "base.json")
        ap2.build_evidence([{"name": "m", "sd_jwt": cls.tok}], p, subject="")
        cls.s0 = os.path.getsize(p)   # the file with an empty subject

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _build(self, size, wide=0):
        """A pack whose written text is exactly `size` bytes: `wide` e-acutes (2 bytes each), the rest ASCII."""
        out = os.path.join(self.d, "p.json")
        if os.path.exists(out):
            os.unlink(out)
        subject = "\u00e9" * wide + "x" * (size - self.s0 - 2 * wide)
        ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], out, subject=subject)
        return out

    def test_exactly_at_the_bound_is_written_and_valid_one_byte_over_is_not(self):
        wide = 20 << 20   # 40 MiB of the file are two-byte characters: their canonical form (\\u00e9) alone exceeds 64 MiB
        out = self._build(self.MAX, wide)
        self.assertEqual(os.path.getsize(out), self.MAX)
        with open(out, encoding="utf-8") as f:
            self.assertGreater(len(ap2._canon(json.load(f))), self.MAX)
        self.assertTrue(ap2.verify_evidence(out)["valid"])   # the JS verifier's bound at the byte: the oracle's hostile files
        for w in (wide, 0):   # one byte over: non-ASCII (fewer characters than bytes) and ASCII (canonical form shorter)
            with self.subTest(wide=w):
                with self.assertRaisesRegex(ap2.Ap2EvidenceError, r"exceeds 67108864 bytes \(67108865\) — not built"):
                    self._build(self.MAX + 1, w)
                self.assertFalse(os.path.exists(os.path.join(self.d, "p.json")))

    def test_stamp_and_sign_do_not_take_a_pack_over_the_bound(self):
        from test_ap2_anchors import LocalTSA
        if not shutil.which("openssl"):
            self.skipTest("openssl absent: the local TSA cannot run")
        tsa = LocalTSA(self.d, "tsaS")
        old = ap2._rfc3161_stamp
        ap2._rfc3161_stamp = lambda digest, url, timeout=20: tsa.stamp(digest, url)
        try:
            for which, call, outcome in (("stamp", lambda p: ap2.add_anchor(p, "https://a.example"), "not stamped"),
                                         ("sign", ap2.sign_evidence, "not signed")):
                with self.subTest(writer=which, near="the bound"):
                    out = self._build(self.MAX - 200)
                    before = _sha(out)
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, "exceeds 67108864 bytes .* — " + outcome):
                        call(out)
                    self.assertEqual(_sha(out), before, "the pack changed")
                    self.assertTrue(ap2.verify_evidence(out)["valid"])
                with self.subTest(writer=which, near="nothing"):   # positive control: a small pack takes the block
                    out = self._build(self.s0 + 10)
                    call(out)
                    self.assertTrue(ap2.verify_evidence(out)["valid"])
        finally:
            ap2._rfc3161_stamp = old

    def test_surrogate_code_points_are_a_refusal_not_a_traceback(self):
        # library input only (argv and the JSON parser cannot produce them): a str with a high and a low surrogate as two code
        # points passes the canonical check (escaped, they spell a valid pair) and cannot be encoded as UTF-8
        out = os.path.join(self.d, "s.json")
        with self.assertRaisesRegex(ap2.Ap2EvidenceError, "surrogate code point"):
            ap2.build_evidence([{"name": "m\ud800\udc00", "sd_jwt": self.tok}], out)
        self.assertFalse(os.path.exists(out))


class TestJwksBody(unittest.TestCase):
    """NEMESIS2 1.7.1: a JWKS body that parses but is not {"keys": [object, ...]} is a build refusal, not a traceback (the
    fetch is replaced in-process: no network). Positive control: the same token builds against a well-formed body."""

    def test_bodies(self):
        import io
        import urllib.request
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        si = _b64u(b'{"alg":"ES256","typ":"ap2-mandate+sd-jwt","kid":"k1"}') + "." + _b64u(b'{"iss":"x"}')
        r, s = decode_dss_signature(_SK.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256())))
        tok = si + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")) + "~"
        jwk = {"kty": "EC", "crv": "P-256", "x": _b64u(_NUM.x.to_bytes(32, "big")), "y": _b64u(_NUM.y.to_bytes(32, "big")), "kid": "k1"}

        class Body(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        d = tempfile.mkdtemp(prefix="ap2jwks-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        out = os.path.join(d, "p.json")
        old = urllib.request.urlopen
        self.addCleanup(setattr, urllib.request, "urlopen", old)
        for name, body in (("well-formed", {"keys": [jwk]}), ("a list", [jwk]), ("a string", "s"), ("null", None),
                           ("keys a number", {"keys": 5}), ("keys a string", {"keys": "abc"}), ("keys [5]", {"keys": [5]}),
                           ("keys [null]", {"keys": [None]}), ("keys [jwk, 5]", {"keys": [jwk, 5]}), ("no keys", {"k": [jwk]})):
            raw = json.dumps(body).encode()
            urllib.request.urlopen = lambda url, timeout=20, raw=raw: Body(raw)
            with self.subTest(body=name):
                if name == "well-formed":
                    ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, jwks_urls={"m": "https://jwks.invalid/k"})
                    self.assertTrue(ap2.verify_evidence(out)["valid"])
                    os.unlink(out)
                else:
                    with self.assertRaisesRegex(ap2.Ap2EvidenceError, "JWKS body is not a JSON object"):
                        ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, jwks_urls={"m": "https://jwks.invalid/k"})
                    self.assertFalse(os.path.exists(out))


class TestLibraryInputNotJson(unittest.TestCase):
    """NEMESIS2 1.7.1: a supplied key `json.dumps` cannot serialise (library input only: the CLI reads JSON) is a refusal, not
    the ValueError / TypeError it raised. Positive control: the same key without the member builds."""

    def test_keys(self):
        tok = O._sign_compact(_SK, _NUM, '{"iss":"x"}')
        jwk = json.loads(__import__("base64").urlsafe_b64decode(tok.split(".")[0] + "==="))["jwk"]
        d = tempfile.mkdtemp(prefix="ap2lib-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        out = os.path.join(d, "p.json")
        ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, keys={"m": dict(jwk)})
        self.assertTrue(ap2.verify_evidence(out)["valid"]); os.unlink(out)
        cyc = dict(jwk); cyc["ext"] = cyc
        for name, key in (("a cycle", cyc), ("an integer of 5001 digits", dict(jwk, ext=10 ** 5000)), ("a set", dict(jwk, ext={1})),
                          ("bytes", dict(jwk, ext=b"x"))):
            with self.subTest(key=name):
                with self.assertRaisesRegex(ap2.Ap2EvidenceError, r"^the pack would be refused by verify \(SPEC §3.1\)"):
                    ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, keys={"m": key})
                self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
