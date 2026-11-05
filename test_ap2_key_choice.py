#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.7.3 — the key the caller names is the policy (SPEC §2 (a)–(d), §6 step 2, §9.2).

Measured on 1.7.2 (2026-11-03): `--jwks-url name=https://…` for a token whose protected header carries `jwk` or `x5c` was
never fetched; the header key was snapshotted (`jwk_header` / `x5c_header`) and the build ended with exit 0. These tests
derive every expected outcome from the SPEC text (`_expect_build`, `_expect_verify`), not from the code, and run over the
whole space of {caller: none / supplied right / supplied wrong / JWKS} × {JWKS: thirteen sets, http, unreachable} × {header
x5c: absent / signer / other / [] / null} × {header jwk: absent / signer / other / null / string} × {kid: absent / k1 / k2
/ zz / "" (present, empty: compared as a string, not taken for absent)} × {jku, x5u: neither / one / both}, the header keys also as the NEGATED point of the signer's key (same x,
other y: a real, distinct P-256 key) and as a jwk mixing two keys' coordinates, with the fetch replaced in-process (no network). The verify side runs on hand-made packs
in both verifiers. Run: python3 test_ap2_key_choice.py
"""
import copy
import datetime
import http.server
import itertools
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402
import test_ap2_evidence as T  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_MANY = os.path.join(_HERE, "verifiers", "js", "verify_many.mjs")
_NODE = shutil.which("node")


def _cert(sk, cn="ap2 key-choice probe", san_ip=None):
    import base64
    import ipaddress
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(sk.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2046, 1, 1)))
    if san_ip:
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san_ip))]), critical=False)
    c = b.sign(sk, hashes.SHA256())
    return c, base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()


SK_S, JWK_S = T._make_signer()   # the signer
SK_O, JWK_O = T._make_signer()   # another key
_, LEAF_S = _cert(SK_S)
_, LEAF_O = _cert(SK_O)
# the negated point -P = (x, p - y): private key n - d. Same x as the signer's key, another y — a distinct valid key, so a
# comparison that reads one coordinate only is caught
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SK_NEG = ec.derive_private_key(_N - SK_S.private_numbers().private_value, ec.SECP256R1())
_, LEAF_NEG = _cert(SK_NEG)
JWK_NEG = {"kty": "EC", "crv": "P-256", "x": T._b64u(SK_NEG.public_key().public_numbers().x.to_bytes(32, "big")),
           "y": T._b64u(SK_NEG.public_key().public_numbers().y.to_bytes(32, "big"))}
assert JWK_NEG["x"] == JWK_S["x"] and JWK_NEG["y"] != JWK_S["y"]
JWK_MIX = {"kty": "EC", "crv": "P-256", "x": JWK_O["x"], "y": JWK_S["y"]}   # another x, the signer's y: not a key at all
RSA = {"kty": "RSA", "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw", "e": "AQAB"}
UNREACHABLE, HTTP = "https://jwks.unreachable.invalid/k", "http://jwks.plain.invalid/k"
JKU = "https://jku.never-fetched.invalid/jwks"
X5U = "https://x5u.never-fetched.invalid/chain.pem"
URLS = ((), ("jku",), ("x5u",), ("jku", "x5u"))


def _k(key, kid=None, **extra):
    d = dict(key); d.update(extra)
    if kid is not None:
        d["kid"] = kid
    return d


# thirteen JWK Sets: name -> (keys, list of (who, kid, usable) for the SPEC-derived oracle)
JWKS_SETS = {
    "empty": [],
    "S/k1": [_k(JWK_S, "k1")],
    "S/k1,O/k2": [_k(JWK_S, "k1"), _k(JWK_O, "k2")],
    "O/k1,S/k2": [_k(JWK_O, "k1"), _k(JWK_S, "k2")],
    "S/k1,S/k1": [_k(JWK_S, "k1"), _k(JWK_S, "k1")],
    "RSA/k1,S/k1": [_k(RSA, "k1"), _k(JWK_S, "k1")],
    "S/k1 use=enc": [_k(JWK_S, "k1", use="enc")],
    "S no kid": [_k(JWK_S)],
    "S/k1 alg=ES384": [_k(JWK_S, "k1", alg="ES384")],
    "S/k1 key_ops=sign": [_k(JWK_S, "k1", key_ops=["sign"])],
    "S/k1 key_ops=verify": [_k(JWK_S, "k1", key_ops=["verify"])],
    "S/k1 key_ops=null": [_k(JWK_S, "k1", key_ops=None)],
    "S/k1 kty=OKP": [_k(dict(JWK_S, kty="OKP"), "k1")],
}


def _who(jwk):
    return "S" if jwk.get("x") == JWK_S["x"] else "O" if jwk.get("x") == JWK_O["x"] else "?"


def _usable(e):   # SPEC §2 (c), written from the text
    if e.get("kty") != "EC" or e.get("crv") != "P-256" or not isinstance(e.get("x"), str) or not isinstance(e.get("y"), str):
        return False
    if "use" in e and e["use"] != "sig":
        return False
    if "alg" in e and e["alg"] != "ES256":
        return False
    if "key_ops" in e and not (isinstance(e["key_ops"], list) and "verify" in e["key_ops"]):
        return False
    return True


X5C = {"absent": None, "S": [LEAF_S], "O": [LEAF_O], "neg": [LEAF_NEG], "empty": [], "null": "NULL"}
JWK = {"absent": None, "S": JWK_S, "O": JWK_O, "neg": JWK_NEG, "mix": JWK_MIX, "null": "NULL", "str": "a-string"}


def _header(x5c, jwk, kid, urls):
    h = {"alg": "ES256", "typ": "example+sd-jwt"}
    if X5C[x5c] is not None:
        h["x5c"] = None if X5C[x5c] == "NULL" else X5C[x5c]
    if JWK[jwk] is not None:
        h["jwk"] = None if JWK[jwk] == "NULL" else JWK[jwk]
    if kid is not None:
        h["kid"] = kid
    for u in urls:
        h[u] = JKU if u == "jku" else X5U
    return h


def _expect_build(caller, jwks_set, url, x5c, jwk, kid, urls):
    """SPEC §2 (a)-(d), from the text. Returns ("refused", why) or (class, sorted names not used)."""
    if caller == "jwks":
        if url != "ok":
            return ("refused", "url")
        cand = [e for e in JWKS_SETS[jwks_set] if _usable(e)]
        if kid is not None:
            cand = [e for e in cand if e.get("kid") == kid]
        if len(cand) != 1:
            return ("refused", "jwks_select")
        chosen, cls = _who(cand[0]), "jwks_fetched"
    elif caller in ("S", "O"):
        chosen, cls = caller, "supplied"
    elif x5c != "absent":
        if x5c not in ("S", "O", "neg"):
            return ("refused", "header_source")
        chosen, cls = x5c, "x5c_header"
    elif jwk != "absent":
        if jwk not in ("S", "O", "neg", "mix"):
            return ("refused", "header_source")
        chosen, cls = jwk, "jwk_header"
    else:
        return ("refused", "no_key")
    if chosen != "S":
        return ("refused", "signature")   # the signature does not verify
    used = {"x5c_header": "x5c", "jwk_header": "jwk"}.get(cls)
    if jwk != "absent" and used != "jwk" and jwk != chosen:
        return ("refused", "unused_differs")
    if x5c != "absent" and used != "x5c" and x5c != chosen:
        return ("refused", "unused_differs")
    return cls, sorted([n for n, present in (("jwk", jwk != "absent"), ("x5c", x5c != "absent")) if present and n != used] + list(urls))


_WHY = (("signature", ("not a point of P-256",)),   # a header jwk that is not a key: no signature can verify under it
        ("url", ("JWKS URL must be", "JWKS fetch failed")), ("jwks_select", ("(SPEC §2 (c))",)),
        ("header_source", ("x5c chain absent", "the header jwk is not a JSON object")), ("no_key", ("no key material",)),
        ("signature", ("signature INVALID",)), ("unused_differs", ("(SPEC §2 (d)",)))


def _why(msg):
    """The reason of a refusal, read from its message (one tag, or the message itself when none or several match)."""
    tags = [t for t, needles in _WHY if any(x in msg for x in needles)]
    return tags[0] if len(tags) == 1 else msg


class _Body:
    def __init__(self, raw):
        self.raw = raw

    def read(self, n=-1):
        return self.raw if n < 0 else self.raw[:n]

    def geturl(self):   # the URL after redirects (urllib's response has it); the in-process fake is never redirected
        return "https://jwks.test/k"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class KeyChoiceLibrary(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2keychoice-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.fetched = []
        old = urllib.request.urlopen
        self.addCleanup(setattr, urllib.request, "urlopen", old)

        def fake(url, timeout=20):
            self.fetched.append(url)
            if url == UNREACHABLE or not url.startswith("https://jwks."):
                raise urllib.error.URLError("unreachable (test)")
            return _Body(json.dumps({"keys": JWKS_SETS[url[len("https://jwks."):-len(".test/k")]]}).encode())
        urllib.request.urlopen = fake

    @staticmethod
    def _url(name):
        return "https://jwks." + name + ".test/k"

    def test_generative_build_matches_the_spec_on_every_combination(self):
        tokens = {}
        for x5c, jwk, kid, urls in itertools.product(X5C, JWK, (None, "k1", "k2", "zz", ""), URLS):
            tokens[(x5c, jwk, kid, urls)] = T._sign_jwt(SK_S, _header(x5c, jwk, kid, urls), {"iss": "u", "n": 1}) + "~"
        callers = [("none", None, None), ("S", None, None), ("O", None, None)]
        callers += [("jwks", s, "ok") for s in JWKS_SETS] + [("jwks", "S/k1", "http"), ("jwks", "S/k1", "down")]
        n = ok = jwks_won_over_header = 0
        wrong = []
        built = []
        for (caller, jset, url), ((x5c, jwk, kid, urls), tok) in itertools.product(callers, tokens.items()):
            n += 1
            out = os.path.join(self.d, f"p{n}.json")
            kw = {}
            if caller in ("S", "O"):
                kw["keys"] = {"m": JWK_S if caller == "S" else JWK_O}
            elif caller == "jwks":
                kw["jwks_urls"] = {"m": self._url(jset) if url == "ok" else HTTP if url == "http" else UNREACHABLE}
            want = _expect_build(caller, jset, url, x5c, jwk, kid, urls)
            self.fetched.clear()
            try:
                r = ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, **kw)
                with open(out) as fh:
                    key = json.load(fh)["artifacts"][0]["key"]
                got = (key["provenance_class"], r.get("key_material_not_used", {}).get("m", []))
            except ap2.Ap2EvidenceError as e:
                got = ("refused", _why(str(e)))
                if os.path.exists(out):
                    wrong.append(((caller, jset, url, x5c, jwk, kid, urls), "refused but a file was written"))
            except Exception as e:  # noqa: BLE001 — a traceback is a defect, not a refusal
                got = ("TRACEBACK", type(e).__name__)
            if JKU in self.fetched or X5U in self.fetched:
                wrong.append(((caller, jset, url, x5c, jwk, kid, urls), "jku/x5u fetched"))
            if got != want:
                wrong.append(((caller, jset, url, x5c, jwk, kid, urls), want, got))
            elif want[0] != "refused":
                ok += 1; built.append((out, want))
                if caller == "jwks" and (x5c != "absent" or jwk != "absent"):
                    jwks_won_over_header += 1
        self.assertEqual(wrong[:8], [], f"{len(wrong)} of {n} combinations differ from the SPEC")
        self.assertEqual(n, 18 * 6 * 7 * 5 * 4)
        self.assertGreater(jwks_won_over_header, 0)   # the 1.7.2 defect's own cases are inside the space, and built
        self.__class__._built = built
        # every pack built verifies, in the reference, and names the same sources in ignored.key_material (SPEC §9.2)
        for out, (cls, names) in built:
            v = ap2.verify_evidence(out)
            self.assertTrue(v["valid"], (out, v["artifacts"]))
            self.assertEqual(v["artifacts"][0]["provenance_class"], cls)
            self.assertEqual(v["artifacts"][0]["ignored"].get("key_material", []), names, out)
        if _NODE:
            man = os.path.join(self.d, "manifest.json")
            with open(man, "w") as fh:
                json.dump([{"name": o, "path": o, "flags": []} for o, _ in built], fh)
            p = subprocess.run([_NODE, _MANY, _JS, man], capture_output=True, text=True, timeout=600)
            self.assertEqual(p.returncode, 0, p.stderr[-500:])
            got = json.loads(p.stdout)
            for out, (cls, names) in built:
                self.assertTrue(got[out].get("valid"), (out, got[out]))
                self.assertEqual(got[out]["artifacts"][0]["ignored"].get("key_material", []), names, out)

    def test_both_sources_for_one_artifact_is_a_refusal_before_any_fetch(self):
        tok = T._sign_jwt(SK_S, {"alg": "ES256", "kid": "k1"}, {"iss": "u"}) + "~"
        out = os.path.join(self.d, "both.json")
        with self.assertRaises(ap2.Ap2EvidenceError) as cm:
            ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, keys={"m": JWK_S}, jwks_urls={"m": self._url("S/k1")})
        self.assertIn("ambiguous", str(cm.exception)); self.assertEqual(self.fetched, []); self.assertFalse(os.path.exists(out))

    def test_empty_or_wrongly_typed_caller_values_are_refusals_not_a_fallback(self):
        tok = T._sign_jwt(SK_S, {"alg": "ES256", "jwk": JWK_S}, {"iss": "u"}) + "~"   # a header key a fallback would use
        for kw, why in (({"keys": {"m": {}}}, "non-empty JSON object"), ({"keys": {"m": []}}, "non-empty JSON object"),
                        ({"jwks_urls": {"m": ""}}, "starting https://"), ({"jwks_urls": {"m": 5}}, "starting https://"),
                        # 1.7.3: a value that is None or falsy was taken for "no key" and the header jwk was used
                        ({"keys": {"m": None}}, "non-empty JSON object"), ({"keys": {"m": 0}}, "non-empty JSON object"),
                        ({"jwks_urls": {"m": None}}, "starting https://"), ({"jwks_urls": {"m": False}}, "starting https://"),
                        ({"keys": [("m", JWK_S)]}, "must be objects"), ({"keys": []}, "must be objects"), ({"keys": ""}, "must be objects"),
                        ({"keys": 0}, "must be objects"), ({"jwks_urls": []}, "must be objects"), ({"jwks_urls": False}, "must be objects")):
            out = os.path.join(self.d, "e.json")
            with self.assertRaises(ap2.Ap2EvidenceError, msg=kw) as cm:
                ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, **kw)
            self.assertIn(why, str(cm.exception), kw)
            self.assertFalse(os.path.exists(out), kw)
        for kw in ({"supplied_jwk": {}}, {"supplied_jwk": []}, {"jwks_url": ""}, {"jwks_url": 0}):   # the private call on its own
            with self.assertRaises(ap2.Ap2EvidenceError, msg=kw):
                ap2._snapshot_key(ap2.parse_sd_jwt(tok), **kw)

    def test_usable_keys_and_same_key_edges(self):
        # SPEC §2 (c): x and y strings, `use`/`alg` present only with their value, `key_ops` a LIST containing "verify";
        # SPEC §2 (d): the header jwk equals the key on kty AND crv AND x AND y. Each case was a surviving mutant of the 1.7.3 draft
        tok = T._sign_jwt(SK_S, {"alg": "ES256"}, {"iss": "u"}) + "~"
        for name, keys, built in (("x not a string beside the signer", [JWK_S, dict(JWK_O, x=5)], True),
                                  ("use null", [dict(JWK_S, use=None)], False), ("alg null", [dict(JWK_S, alg=None)], False),
                                  ("key_ops the string verify", [dict(JWK_S, key_ops="verify")], False)):
            JWKS_SETS["edge"] = keys
            out = os.path.join(self.d, "u.json")
            try:
                r = ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, jwks_urls={"m": self._url("edge")})
                got = True
                self.assertNotIn("key_material_not_used", r, name)   # SPEC §2 (d): present only when one is not empty
            except ap2.Ap2EvidenceError as e:
                got = False; self.assertIn("(SPEC §2 (c))", str(e), name)
            finally:
                JWKS_SETS.pop("edge", None)
            self.assertEqual(got, built, name)
            if built:
                os.remove(out)
        for name, hj in (("kty OKP", dict(JWK_S, kty="OKP")), ("crv P-384", dict(JWK_S, crv="P-384"))):
            t = T._sign_jwt(SK_S, {"alg": "ES256", "jwk": hj}, {"iss": "u"}) + "~"
            with self.assertRaises(ap2.Ap2EvidenceError, msg=name) as cm:
                ap2.build_evidence([{"name": "m", "sd_jwt": t}], os.path.join(self.d, "s.json"), keys={"m": JWK_S})
            self.assertIn("(SPEC §2 (d)", str(cm.exception), name)
            p_ = os.path.join(self.d, "s.json")
            with open(p_, "w") as fh:
                json.dump(_pack_of({"alg": "ES256", "jwk": hj}, JWK_S, "supplied"), fh)
            self.assertIn("(SPEC §2 (d)", ap2.verify_evidence(p_)["artifacts"][0].get("error", ""), name)
            if _NODE:
                js = json.loads(subprocess.run([_NODE, _JS, p_], capture_output=True, text=True, timeout=120).stdout)
                self.assertIn("(SPEC §2 (d)", js["artifacts"][0].get("error", ""), name)

    def test_kid_not_a_string_is_a_refusal_before_the_fetch(self):
        for kid in (1, None, ["k1"], {"k": 1}):
            tok = T._sign_jwt(SK_S, {"alg": "ES256", "kid": kid}, {"iss": "u"}) + "~"
            self.fetched.clear()
            with self.assertRaises(ap2.Ap2EvidenceError, msg=kid):
                ap2.build_evidence([{"name": "m", "sd_jwt": tok}], os.path.join(self.d, "k.json"), jwks_urls={"m": self._url("S/k1")})
            self.assertEqual(self.fetched, [], kid)

    def test_the_note_names_what_was_not_used(self):
        tok = T._sign_jwt(SK_S, {"alg": "ES256", "jwk": JWK_S, "kid": "k1", "jku": JKU}, {"iss": "u"}) + "~"
        out = os.path.join(self.d, "n.json")
        r = ap2.build_evidence([{"name": "m", "sd_jwt": tok}], out, jwks_urls={"m": self._url("RSA/k1,S/k1")})
        self.assertEqual(r["key_material_not_used"], {"m": ["jku", "jwk"]})
        with open(out) as fh:
            note = json.load(fh)["artifacts"][0]["key"]["note"]
        self.assertIn("not used for the key: jku, jwk", note); self.assertIn("1 JWK(s) of the set not usable", note)


def _pack_of(header, key_jwk, pc, extra_key=None):
    tok = T._sign_jwt(SK_S, header, {"iss": "u", "n": 1}) + "~"
    key = {"jwk": key_jwk, "provenance_class": pc}
    key.update(extra_key or {})
    art = {"name": "m", "sd_jwt_compact": tok, "header": header, "key": key, "resolved_claims": {"iss": "u", "n": 1},
           "kb_jwt": {"present": False}, "verified_at_build": {"signature_ok": True, "disclosures_ok": True}}
    sys.path.insert(0, os.path.join(_HERE, "spec", "vectors", "ap2"))
    import make_vectors_closed_schema as cs  # noqa: PLC0415
    return cs._pack(cs._load("valid_signed")["honest_scope"], "ap2 key-choice probe", [art])


def _expect_verify(pc, x5c, jwk, urls):
    """SPEC §2 reconciliation + §2 (d) at verification, from the text: None = that artifact's error, else the names."""
    if pc == "jwk_header" and jwk != "S":
        return None
    if pc == "x5c_header" and x5c != "S":
        return None
    used = {"x5c_header": "x5c", "jwk_header": "jwk"}.get(pc)
    if jwk != "absent" and used != "jwk" and jwk != "S":
        return None
    if x5c != "absent" and used != "x5c" and x5c != "S":
        return None
    return sorted([n for n, present in (("jwk", jwk != "absent"), ("x5c", x5c != "absent")) if present and n != used] + list(urls))


class KeyChoiceVerify(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2keychoice-v-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_generative_verify_both_verifiers(self):
        import base64
        # trail: the signer's leaf followed by one byte — not a DER certificate; node:crypto parsed it (the JS verifier said
        # valid where the reference said error, measured 2026-11-03 on 1.7.2 for x5c_header and on the 1.7.3 draft for every class)
        X = dict(X5C, bad=["not base64!"], trail=[base64.b64encode(base64.b64decode(LEAF_S) + b"\x00").decode()]); J = JWK
        cases, n = [], 0
        for pc, x5c, jwk, urls in itertools.product(sorted(ap2.PROVENANCE_CLASSES), X, J, URLS):
            h = {"alg": "ES256", "typ": "example+sd-jwt"}
            if X[x5c] is not None:
                h["x5c"] = None if X[x5c] == "NULL" else X[x5c]
            if J[jwk] is not None:
                h["jwk"] = None if J[jwk] == "NULL" else J[jwk]
            for u in urls:
                h[u] = JKU if u == "jku" else X5U
            n += 1
            path = os.path.join(self.d, f"v{n}.json")
            with open(path, "w") as fh:
                json.dump(_pack_of(h, JWK_S, pc), fh)
            cases.append((path, (pc, x5c, jwk, urls), _expect_verify(pc, x5c, jwk, urls)))
        self.assertEqual(n, 4 * 8 * 7 * 4)
        wrong = []
        for path, combo, want in cases:
            v = ap2.verify_evidence(path); a = v["artifacts"][0]
            got = None if "error" in a else a["ignored"].get("key_material", [])
            if got != want or v["valid"] != (want is not None):
                wrong.append((combo, want, got, a.get("error")))
        self.assertEqual(wrong[:6], [], f"reference: {len(wrong)} of {n} differ from the SPEC")
        self.assertTrue(any(w is None for _, _, w in cases) and any(w is not None for _, _, w in cases))
        if not _NODE:
            self.skipTest("node absent: the JS verifier is not measured")
        man = os.path.join(self.d, "m.json")
        with open(man, "w") as fh:
            json.dump([{"name": p, "path": p, "flags": []} for p, _, _ in cases], fh)
        p = subprocess.run([_NODE, _MANY, _JS, man], capture_output=True, text=True, timeout=600)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        got_js = json.loads(p.stdout); wrong = []
        for path, combo, want in cases:
            a = got_js[path]["artifacts"][0]
            got = None if "error" in a else a["ignored"].get("key_material", [])
            if got != want or got_js[path]["valid"] != (want is not None):
                wrong.append((combo, want, got, a.get("error")))
        self.assertEqual(wrong[:6], [], f"JS: {len(wrong)} of {n} differ from the SPEC")


class _JwksHandler(http.server.BaseHTTPRequestHandler):
    body = b""
    hits = []
    redirect = None   # a URL to answer 302 with (test_a_redirect_off_https_is_a_refusal)

    def do_GET(self):  # noqa: N802
        type(self).hits.append(self.path)
        if type(self).redirect and self.path == "/jwks.json":
            self.send_response(302); self.send_header("Location", type(self).redirect); self.send_header("Content-Length", "0"); self.end_headers()
            return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *a):
        pass


class KeyChoiceCli(unittest.TestCase):
    """End to end through the CLI with a local https JWKS (127.0.0.1, a certificate made here, trusted via SSL_CERT_FILE):
    no network, no mock inside the process under test."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2keychoice-cli-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        sk = ec.generate_private_key(ec.SECP256R1())
        cert, _ = _cert(sk, cn="127.0.0.1", san_ip="127.0.0.1")
        self.ca = os.path.join(self.d, "srv.pem"); kp = os.path.join(self.d, "srv.key")
        with open(self.ca, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(kp, "wb") as fh:
            fh.write(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _JwksHandler.body = json.dumps({"keys": [_k(JWK_S, "k1")]}).encode(); _JwksHandler.hits = []; _JwksHandler.redirect = None
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), _JwksHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(self.ca, kp)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close); self.addCleanup(self.srv.shutdown)
        self.url = f"https://127.0.0.1:{self.srv.server_address[1]}/jwks.json"
        self.tok = os.path.join(self.d, "m.sdjwt")
        with open(self.tok, "w") as fh:
            fh.write(T._sign_jwt(SK_S, {"alg": "ES256", "kid": "k1", "jwk": JWK_S}, {"iss": "u"}) + "~")
        self.k = os.path.join(self.d, "k.json")
        with open(self.k, "w") as fh:
            json.dump(JWK_S, fh)
        self.out = os.path.join(self.d, "out.json")

    def _cli(self, *extra):
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "pythonpath")}
        env["SSL_CERT_FILE"] = self.ca; env["NO_PROXY"] = "127.0.0.1"
        p = subprocess.run([sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py"), "build", self.out, "m=" + self.tok, *extra],
                           capture_output=True, text=True, timeout=120, env=env)
        return p.returncode, p.stdout, p.stderr

    def test_jwks_url_is_fetched_and_wins_over_the_header_jwk(self):
        rc, out, err = self._cli("--jwks-url", "m=" + self.url)
        self.assertEqual(rc, 0, err)
        self.assertEqual(_JwksHandler.hits, ["/jwks.json"])   # 1.7.2: no request at all
        with open(self.out) as fh:
            key = json.load(fh)["artifacts"][0]["key"]
        self.assertEqual((key["provenance_class"], key["jwks_url"], key["jwk"]["kid"]), ("jwks_fetched", self.url, "k1"))
        self.assertEqual(json.loads(out)["key_material_not_used"], {"m": ["jwk"]})

    def test_a_jwk_off_the_curve_is_a_refusal_not_a_traceback(self):
        # measured on 1.7.2: a ValueError traceback (exit 1, no reason) for a --key file, a header jwk or a cnf.jwk whose
        # (x, y) is not a point of P-256
        with open(self.k, "w") as fh:
            json.dump(JWK_MIX, fh)
        rc, _, err = self._cli("--key", "m=" + self.k)
        self.assertEqual(rc, 1, err); self.assertNotIn("Traceback", err); self.assertIn("not a point of P-256", json.loads(err)["error"])
        with open(self.tok, "w") as fh:
            fh.write(T._sign_jwt(SK_S, {"alg": "ES256", "jwk": JWK_MIX}, {"iss": "u"}) + "~")
        rc, _, err = self._cli()
        self.assertEqual(rc, 1, err); self.assertNotIn("Traceback", err); self.assertIn("not a point of P-256", json.loads(err)["error"])
        holder = T._sign_jwt(SK_S, {"alg": "ES256", "jwk": JWK_S}, {"iss": "u", "cnf": {"jwk": JWK_MIX}}) + "~"
        kb = T._sign_jwt(SK_O, {"alg": "ES256", "typ": "kb+jwt"}, {"iat": 1, "aud": "a", "nonce": "n", "sd_hash": "x"})
        with self.assertRaises(ap2.Ap2EvidenceError):
            ap2.build_evidence([{"name": "m", "sd_jwt": holder + kb}], self.out)
        self.assertFalse(os.path.exists(self.out))

    def test_jwks_url_whose_key_is_not_the_header_jwk_is_refused_not_overridden(self):
        _JwksHandler.body = json.dumps({"keys": [_k(JWK_O, "k1")]}).encode()   # the caller's source names another key
        rc, _, err = self._cli("--jwks-url", "m=" + self.url)
        self.assertEqual(rc, 1, err); self.assertIn("signature INVALID", err); self.assertFalse(os.path.exists(self.out))
        self.assertEqual(_JwksHandler.hits, ["/jwks.json"])

    def test_a_redirect_off_https_is_a_refusal(self):
        # measured 2026-11-03 on 1.7.2 and on the 1.7.3 draft: urllib followed a 302 from the https JWKS URL to plain http, read the
        # set there and the pack recorded jwks_fetched under the https URL, exit 0
        class Plain(_JwksHandler):
            hits, redirect = [], None
        Plain.body = _JwksHandler.body
        plain = http.server.HTTPServer(("127.0.0.1", 0), Plain)
        threading.Thread(target=plain.serve_forever, daemon=True).start()
        self.addCleanup(plain.server_close); self.addCleanup(plain.shutdown)
        _JwksHandler.redirect = f"http://127.0.0.1:{plain.server_address[1]}/jwks.json"
        rc, _, err = self._cli("--jwks-url", "m=" + self.url)
        self.assertEqual(rc, 1, err); self.assertIn("not https://", json.loads(err)["error"]); self.assertFalse(os.path.exists(self.out))
        self.assertEqual((_JwksHandler.hits, Plain.hits), (["/jwks.json"], ["/jwks.json"]))   # the bench sees the downgrade
        _JwksHandler.redirect = self.url.replace("/jwks.json", "/moved.json"); _JwksHandler.hits = []   # https -> https: allowed
        rc, _, err = self._cli("--jwks-url", "m=" + self.url)
        self.assertEqual(rc, 0, err); self.assertEqual(_JwksHandler.hits, ["/jwks.json", "/moved.json"])

    def test_key_and_jwks_url_for_one_artifact_is_a_usage_error_before_anything(self):
        for args in (("--key", "m=" + self.k, "--jwks-url", "m=" + self.url), ("--jwks-url", "m=" + self.url, "--key", "m=/nonexistent/k.json")):
            rc, _, err = self._cli(*args)
            self.assertEqual(rc, 2, err); self.assertIn("ambiguous", err); self.assertFalse(os.path.exists(self.out))
        self.assertEqual(_JwksHandler.hits, [])


if __name__ == "__main__":
    unittest.main()
