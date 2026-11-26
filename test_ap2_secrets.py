#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.11.2 (SPEC §2): a secret given to this package does not come out of it. A canary — a real P-256 private key, or a
password in a URL — goes into every input of the command line and of the library that takes a key or a URL, in the place
it belongs to and in the places it could be put by mistake, and is searched in everything that comes out: the pack, any
file left in the folder, stdout, stderr, the value returned, the exception with its causes. It is searched raw and in
hex, base64, base64url (at each of the three offsets, so inside a longer text too) and decimal.

Positive control: a producer that leaks is found, in each of those forms; and on 1.11.1 (b00df7e) the tests that state the
new behaviour fail."""
import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402
import test_ap2_evidence as T  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

PRIVATE = ("d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv")


def forms(secret: bytes) -> dict:
    """The texts under which `secret` would be recognised in an output, by name (bytes to search for)."""
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(), "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):   # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        first, last = (k * 8 + 5) // 6, (k + len(secret)) * 8 // 6
        part = whole[first:last]
        out[f"base64+{k}"], out[f"base64url+{k}"] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    return out


def found(secret: bytes, *outputs) -> list:
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")   # JSON may escape the slash of base64
    return sorted(n for n, f in forms(secret).items() if f in blob)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2sec-"); self.addCleanup(shutil.rmtree, self.d, True)
        self.out = os.path.join(self.d, "out"); os.mkdir(self.out)
        self.sk, self.jwk = T._make_signer()
        self.secret = self.sk.private_numbers().private_value.to_bytes(32, "big")
        self.d64 = T._b64u(self.secret)
        self.password = "Pw" + self.d64[:30]
        self.tok = T._make_sd_jwt(self.sk, {"iss": "https://i.example", "vct": "mandate.x", "iat": 1700000000}, {"a": "b"})
        self.pack = os.path.join(self.out, "e.json")

    def left(self):
        data = []
        for base, _, files in os.walk(self.out):
            for n in files:
                data.append(n)
                with open(os.path.join(base, n), "rb") as f:
                    data.append(f.read())
        return data

    def clean(self):
        for n in os.listdir(self.out):
            os.unlink(os.path.join(self.out, n))

    def none(self, what, *outputs, secrets=None):
        for s in secrets or (self.secret, self.d64.encode(), self.password.encode()):
            self.assertEqual(found(s, *outputs, *self.left()), [], what)

    def call(self, f, *a, **kw):
        """(result or None, exception or None, every text of both and of the streams)"""
        so, se = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(so), contextlib.redirect_stderr(se):
            try:
                r, e = f(*a, **kw), None
            except (Exception, SystemExit) as ex:  # noqa: BLE001
                r, e = None, ex
        text = [so.getvalue(), se.getvalue(), repr(r)]
        while e is not None and len(text) < 20:   # the exception and what caused it, without the frames' source lines
            text += [type(e).__name__, str(e), repr(getattr(e, "args", "")), "".join(traceback.format_exception_only(type(e), e))]
            first = e if len(text) < 8 else None
            e = e.__cause__
            r = r if first is None else first
        return r, text

    def file(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def cli(self, *argv, js=False):
        cmd = ["node", os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")] if js else [sys.executable, "-B", os.path.join(_HERE, "ap2_evidence.py")]
        return subprocess.run(cmd + list(argv), capture_output=True, timeout=120, cwd=self.out)

    def pem(self, sk=None):
        return (sk or self.sk).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class TheSearchFinds(Base):
    """Positive control of the search, and of a producer that leaks."""

    def test_every_form(self):
        s = self.secret
        for name, text in (("raw", b"x" + s + b"y"), ("hex", b'"' + s.hex().encode()), ("HEX", s.hex().upper().encode()), ("decimal", str(int.from_bytes(s, "big")).encode()),
                           ("base64+0", base64.b64encode(s)), ("base64+1", base64.b64encode(b'{' + s + b'}')), ("base64+2", base64.b64encode(b'{"' + s + b'}')),
                           ("base64url+0", self.d64.encode()), ("base64url+1", base64.urlsafe_b64encode(b"a" + s)), ("base64url+2", base64.urlsafe_b64encode(b"ab" + s + b"c"))):
            self.assertIn(name, found(s, text), name)
        self.assertTrue(found(self.d64.encode(), base64.urlsafe_b64encode(b'{"jwk":{"d":"' + self.d64.encode() + b'"}}')))   # inside a token
        self.assertEqual(found(s, b"nothing", self.jwk), [])   # the public key is not the private one

    def test_a_producer_that_leaks_is_found(self):
        key = dict(self.jwk, ext={"d": self.d64}, n=str(int.from_bytes(self.secret, "big")), h=self.secret.hex())
        r = ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": key})
        self.none("the package", repr(r))
        self.clean()
        with mock.patch.object(ap2, "_JWK_SEALED", tuple(key)):   # the same build, its list of sealed members opened
            ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": key})
        with self.assertRaises(AssertionError):
            self.none("the leak")
        self.assertEqual([x for x in found(self.secret, *self.left()) if x[:6] != "base64"], ["decimal", "hex"])
        self.clean()
        with mock.patch.object(ap2, "_url_problem", lambda *a, **k: None), mock.patch.object(ap2, "_rfc3161_stamp", lambda d, u, timeout=20: {"anchored": False, "tsa_url": u, "note": "x"}):
            ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": self.jwk}, tsa_url="https://u:%s@h/" % self.password)
        self.assertTrue(found(self.password.encode(), *self.left()))
        with self.assertRaises(AssertionError):
            self.none("the URL")


class SuppliedKeys(Base):
    def keys(self):
        d, j = self.d64, self.jwk
        priv = [dict(j, **{m: v}) for m in PRIVATE for v in (d, [d], {"x": d}, int.from_bytes(self.secret, "big"))]
        other = [dict(j, **{m: v}) for m, v in (("D", d), ("secret", d), ("ext", {"d": d}), ("ext", [{"k": [d]}]), ("private_key_pem", self.pem().decode()), ("", d), ("kid", {"d": d}),
                                                ("kid", [d]), ("kid", int.from_bytes(self.secret, "big")), ("x5c", [d]), ("use", d), ("alg", d), ("key_ops", [d]), ("x5u", "https://u:%s@h/" % self.password), (d, 1),
                                                ("d ", d), ("d​", d), ("__proto__", {"d": d}))]
        return priv, other

    def test_the_library(self):
        priv, other = self.keys()
        for key in priv:
            r, text = self.call(ap2.build_evidence, [{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": key})
            self.assertIsInstance(r, ap2.Ap2EvidenceError); self.assertRegex(str(r), "^issuer_key_private: ")
            self.none(sorted(key), *text); self.assertEqual(os.listdir(self.out), [])
        for key in other:
            r, text = self.call(ap2.build_evidence, [{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": key})
            self.assertIsInstance(r, dict, (sorted(key), text))
            self.none(sorted(key), *text)
            self.assertEqual(len(r["key_members_not_sealed"]["m"]), 1)
            with open(self.pack, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["artifacts"][0]["key"]["jwk"], self.jwk)
            self.assertTrue(ap2.verify_evidence(self.pack)["valid"])
            self.clean()
        r = ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": dict(self.jwk, kid="k1", use="sig")})   # what is sealed, and named
        with open(self.pack, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["artifacts"][0]["key"]["jwk"], dict(self.jwk, kid="k1"))
        self.assertEqual(r["key_members_not_sealed"], {"m": ["use"]})
        self.clean()
        self.assertNotIn("key_members_not_sealed", ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": dict(self.jwk, kid="k1")}))

    def test_names_are_repeated_up_to_32_characters(self):
        self.assertEqual(ap2._nameable("n" * 32), repr("n" * 32))
        self.assertEqual(ap2._nameable("n" * 33), "(a name not repeated here)")
        self.assertEqual(ap2._nameable(5), "(a name not repeated here)")
        r = ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": dict(self.jwk, **{"n" * 32: 1, "o" * 33: 2})})
        self.assertEqual(r["key_members_not_sealed"], {"m": ["(a name not repeated here)", "n" * 32]})

    def test_library_misuse(self):
        for kw in ({"keys": {"m": self.d64}}, {"keys": {"m": [self.d64]}}, {"keys": {"m": self.pem()}}, {"keys": {"m": self.sk}}, {"keys": {"m": {"d": self.d64}}}, {"keys": {self.d64: self.jwk}},
                   {"keys": [self.d64]}, {"keys": {"m": {"kty": "OKP", "crv": "Ed25519", "x": self.jwk["x"], "d": self.d64}}}, {"keys": {"m": {"kty": "oct", "k": self.d64}}},
                   {"jwks_urls": {"m": self.d64}}, {"jwks_urls": {self.d64: "https://h/"}}):
            r, text = self.call(ap2.build_evidence, [{"name": "m", "sd_jwt": self.tok}], self.pack, **kw)
            self.assertIsInstance(r, Exception, kw); self.none(list(kw), *text)
            self.assertEqual(os.listdir(self.out), [])

    def test_the_command_line(self):
        tok = self.file("t.sdjwt", self.tok)
        k = self.file("k.json", json.dumps(self.jwk))
        priv, other = self.keys()
        for key, rc in [(x, 1) for x in priv[::9]] + [(x, 0) for x in other[::3]]:
            p = self.cli("build", self.pack, "m=" + tok, "--key", "m=" + self.file("p.json", json.dumps(key)))
            self.assertEqual(p.returncode, rc, (sorted(key), p.stderr))
            self.none(sorted(key), p.stdout, p.stderr); self.clean()
        priv_json = json.dumps(dict(self.jwk, d=self.d64))
        for args in (["--key", "m=" + self.file("a.pem", self.pem())], ["--key", "m=" + self.file("b.txt", self.d64)], ["--key", "m=" + self.file("c.bin", self.secret)],
                     ["--key", "m=" + self.file("l.json", json.dumps([dict(self.jwk, d=self.d64)]))], ["--key", "m=" + self.file("s.json", json.dumps(self.d64))],
                     ["--key", "m=" + priv_json], ["--key", priv_json], ["--key", self.d64], ["--key", self.d64 + "="], ["--key", self.d64 + "=" + k], ["--key", "=" + self.d64], ["--key", "-" + self.d64],
                     ["--key=" + self.d64], ["--key=-" + self.d64], ["--keyy", self.d64], ["--keyy=" + self.d64], ["--key", "m=" + k, "--key", "m=" + priv_json], ["--key", "m=" + k, self.d64 + "=" + k + "x"],
                     ["--key", "m=" + k, "--jwks-url", "m=https://u:%s@h/" % self.password]):
            p = self.cli("build", self.pack, "m=" + tok, *args)
            self.assertEqual(p.returncode, 2, (args[0], p.stderr)); self.assertIn(b"error:", p.stderr)
            self.assertNotIn(b"Traceback", p.stderr)
            if args[-1].endswith("x") and len(args) == 3:   # an ARTIFACT's name=path is not a key: its message names the file
                continue
            self.none(args[0], p.stdout, p.stderr); self.assertEqual(os.listdir(self.out), [])


class Tokens(Base):
    def test_a_private_key_in_a_token_is_not_copied(self):
        pub2 = T._make_signer()[1]
        cases = {"header": ({"alg": "ES256", "jwk": dict(self.jwk, d=self.d64)}, {"iss": "u"}), "cnf": ({"alg": "ES256", "jwk": self.jwk}, {"iss": "u", "cnf": {"jwk": dict(pub2, d=self.d64)}}),
                 "delegate": ({"alg": "ES256", "jwk": self.jwk}, {"iss": "u", "delegate_payload": [1, {"cnf": {"jwk": dict(pub2, priv=self.d64)}}]})}
        for n, (h, p) in cases.items():
            tok = T._sign_jwt(self.sk, h, p) + "~"
            self.assertTrue(found(self.d64.encode(), tok), "control: the token itself carries it")
            for kw in ({}, {"keys": {"m": self.jwk}}):
                r, text = self.call(ap2.build_evidence, [{"name": "m", "sd_jwt": tok}], self.pack, **kw)
                self.assertIsInstance(r, ap2.Ap2EvidenceError); self.assertIn("issuer_key_private", str(r), n)
                self.none(n, *text); self.assertEqual(os.listdir(self.out), [])
        ap2.build_evidence([{"name": "m", "sd_jwt": T._sign_jwt(self.sk, {"alg": "ES256", "jwk": self.jwk}, {"iss": "u", "cnf": {"jwk": pub2}}) + "~"}], self.pack)   # control


class Urls(Base):
    BAD = ("https://u:{p}@h/", "http://u:{p}@h/x", "https://{p}@h", "https://u:{p}@[::1]:8/", "HTTPS://u:{p}@h/", "https:/u:{p}@h/", "https:u:{p}@h/", "https:///u:{p}@h/", "//u:{p}@h/", "u:{p}@h", "{p}",
           "https://u:{p}%40h/", "https://u:{p}\\@h/", "https://h\\@u:{p}/", "https://h /{p}", "https://h/\t{p}", "https://h/\n{p}", "https://h/\x00{p}", "https://é/{p}", "https://h/é{p}", "https://u:{p}@h@i/",
           "ftp://u:{p}@h/", "file:///{p}", "https://", "https:///x", "https://h:99999{p}/", " https://h/{p}", "https://h/{p} ", "https://{p}%40h/", "https://h/\\{p}", "https://h/{p}\x7f", "https:{p}/", "https:/{p}/",
           "https://[u:{p}@h]/", "https://[{p}]/", "https://h?\\{p}", "https://h#\u00e9{p}", "https://h:123456/{p}")
    GOOD = ("http://h", "https://h/", "https://h:8080/a@b?c=d@e#f@g", "https://[::1]:8/", "HTTP://tsa.example/tsr", "https://127.0.0.1/%20x", "https://h_x.example:/", "https://h?x", "https://h:65535/")

    def bad(self):
        return [u.format(p=self.password) for u in self.BAD]

    def test_the_grammar(self):
        for u in self.bad():
            self.assertIsNotNone(ap2._url_problem(u), u)
            self.assertIsNotNone(ap2._url_problem(u, https_only=True), u)
            self.none("the reason", ap2._url_problem(u))
        for u in self.GOOD:
            self.assertIsNone(ap2._url_problem(u), u)
            self.assertEqual(ap2._url_problem(u, https_only=True) is None, u.startswith("https://"), u)
        for u in (None, 1, b"https://h/", [], {}):
            self.assertIsNotNone(ap2._url_problem(u))

    def test_the_library_before_the_network(self):
        asked = []
        with mock.patch.object(ap2.urllib.request, "urlopen", lambda *a, **k: asked.append(a) or (_ for _ in ()).throw(OSError("no"))):
            good = os.path.join(self.d, "good.json")
            ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], good, keys={"m": self.jwk})
            for u in self.bad():
                for f, a, kw in ((ap2.build_evidence, ([{"name": "m", "sd_jwt": self.tok}], self.pack), {"keys": {"m": self.jwk}, "tsa_url": u}),
                                 (ap2.build_evidence, ([{"name": "m", "sd_jwt": self.tok}], self.pack), {"keys": {"m": self.jwk}, "extra_tsa_urls": ["https://h/", u]}),
                                 (ap2.build_evidence, ([{"name": "m", "sd_jwt": self.tok}], self.pack), {"jwks_urls": {"m": u}}), (ap2.add_anchor, (good, u), {})):
                    r, text = self.call(f, *a, **kw)
                    self.assertIsInstance(r, ap2.Ap2EvidenceError, u); self.none(u, *text); self.assertEqual(os.listdir(self.out), [])
                    if "jwks_urls" in kw:
                        self.assertRegex(str(r), "^jwks_urls\\['m'\\]: ")   # with the other arguments, before any token is read
                    if f is ap2.add_anchor:
                        self.assertRegex(str(r), "^TSA: .*: not stamped$")   # stamp's own check, before the pack is read
                self.assertEqual(ap2._rfc3161_stamp("0" * 64, u)["anchored"], False)
                self.none(u, ap2._rfc3161_stamp("0" * 64, u))
                self.call(ap2._snapshot_key, ap2.parse_sd_jwt(self.tok), None, u)
            self.assertEqual(asked, [])
            r = ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": self.jwk}, tsa_url="https://h/")   # control: a good one is asked
            self.assertIs(r["rfc3161_anchored"], False)
        self.assertEqual(len(asked), 1 if shutil.which("openssl") else 0)
        with open(good, encoding="utf-8") as f:
            self.assertNotIn("anchors", json.load(f))

    def test_the_command_line(self):
        tok, k = self.file("t.sdjwt", self.tok), self.file("k.json", json.dumps(self.jwk))
        good = os.path.join(self.d, "good.json")
        ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], good, keys={"m": self.jwk})
        for u in [x for x in self.bad() if "\0" not in x][::2]:
            for argv in (["build", self.pack, "m=" + tok, "--key", "m=" + k, "--tsa", u], ["build", self.pack, "m=" + tok, "--key", "m=" + k, "--tsa", "https://h/", "--tsa=" + u],
                         ["build", self.pack, "m=" + tok, "--jwks-url", "m=" + u], ["build", self.pack, "m=" + tok, "--jwks-url", u], ["stamp", good, "--tsa", u], ["stamp", good, "--tsaa", u]):
                p = self.cli(*argv)
                self.assertEqual(p.returncode, 2, (argv[-2], u, p.stderr)); self.assertNotIn(b"Traceback", p.stderr)
                self.none((argv[0], u), p.stdout, p.stderr); self.assertEqual(os.listdir(self.out), [])


class Verifying(Base):
    """What the verifiers print about a pack that carries a secret (one built before 1.11.2), or about a key given to them."""

    def leaky(self):
        ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": self.jwk})
        with open(self.pack, encoding="utf-8") as f:
            e = json.load(f)
        os.unlink(self.pack)
        a = e["artifacts"][0]["key"]
        a["jwk"].update(d=self.d64, ext={"k": self.d64}); a["jwks_url"] = "https://u:%s@h/" % self.password
        e["rfc3161_timestamp"] = {"anchored": False, "tsa_url": "https://u:%s@h/" % self.password, "note": self.password}
        e["anchors"] = [{"mechanism": "rfc3161", "tsr_b64": "AAAA", "tsa_url": "https://u:%s@h/" % self.password, "note": self.password}]
        e["evidence_digest_sha256"] = __import__("hashlib").sha256(ap2._canon({k: v for k, v in e.items() if k not in ap2._DIGEST_EXCLUDED})).hexdigest()
        bad = json.loads(json.dumps(e)); bad["artifacts"][0]["key"]["zz"] = self.d64
        return [self.file("leaky.json", json.dumps(e)), self.file("bad.json", json.dumps(bad)), self.file("trunc.json", json.dumps(e)[:-9]), self.file("k.json", json.dumps(dict(self.jwk, d=self.d64)))]

    def verifiers(self):
        return [False] + ([True] if shutil.which("node") else [])

    def test_receipts_do_not_repeat_it(self):
        packs = self.leaky()
        for js in self.verifiers():
            for p in packs:
                r = self.cli(*([] if js else ["verify"]), p, js=js)
                self.assertIn(r.returncode, (0, 1), r.stderr); self.assertTrue(r.stdout)
                self.none((js, p), r.stdout, r.stderr)
        for p in packs:
            r = self.cli("restriction", p)
            self.none(p, r.stdout, r.stderr)

    def test_keys_given_to_a_verifier(self):
        good = os.path.join(self.d, "good.json")
        ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], good, keys={"m": self.jwk})
        pem = self.file("priv.pem", self.pem())
        b64 = base64.b64encode(self.secret).decode()
        for js in self.verifiers():
            cmd = [] if js else ["verify"]
            for flags in (["--trusted-producer-key", b64], ["--trusted-producer-key", "ed25519=" + b64], ["--trusted-producer-key", "ed25519=-" + b64], ["--trusted-producer-key", b64 + "="], ["--trusted-producer-key", "-" + b64],
                          ["--trusted-producer-key=" + self.d64], ["--trusted-producer-key", self.d64 + "=x"], ["--tsa-cert", pem], ["--trusted-producer-keyy", b64]) + (() if js else (["--trust-anchor", pem],)):
                r = self.cli(*cmd, good, *flags, js=js)
                self.assertIn(r.returncode, (1, 2), (js, flags[0], r.stderr)); self.assertNotIn(b"Traceback", r.stderr)
                self.none((js, flags[0]), r.stdout, r.stderr)
        for pins in ({"ed25519": b64}, {"ed25519": [b64, 1]}, {b64: "x"}, b64, [b64], {"ed25519": {"d": b64}}):
            _, text = self.call(ap2.verify_evidence, good, trusted_producer_keys=pins)
            self.none("pins", *text)


class Producer(Base):
    def test_signing_and_its_identity_file(self):
        suite = ap2._sigsuite
        ident = suite.ProducerIdentity.create()
        f = os.path.join(self.d, "id.json")
        shown = [ident.save(f), repr(ident), str(ident), ident.public_keys()]
        with open(f, "rb") as fh:
            saved = json.loads(fh.read())
        privs = [v for v in json.dumps(saved).split('"') if len(v) > 40]
        self.assertTrue(privs)
        ap2.build_evidence([{"name": "m", "sd_jwt": self.tok}], self.pack, keys={"m": self.jwk})
        shown.append(ap2.sign_evidence(self.pack, ident))
        pubs = list(ident.public_keys().values())
        secrets = [base64.b64decode(p)[-32:] for p in privs if p not in pubs]
        self.assertTrue(secrets)
        self.none("sign", *map(str, shown), secrets=secrets)
        self.assertIsNotNone(ap2.verify_evidence(self.pack)["producer_signatures"]["ok"])
        for data in (json.dumps(saved)[:-20], json.dumps({"keys": saved}), json.dumps([saved]), self.d64, json.dumps({k: (v[:-3] if isinstance(v, str) else v) for k, v in saved.items()})):
            p = self.file("bad_id.json", data)
            _, text = self.call(suite.ProducerIdentity.load, p)
            for s in secrets + [self.secret]:
                self.assertEqual(found(s, *text), [], text)

    def test_the_sample_writer(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("make_samples_under_test", os.path.join(_HERE, "examples", "make_samples.py"))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        so, cwd = io.StringIO(), os.getcwd()
        os.chdir(self.out)
        try:
            with mock.patch.object(mod.ec, "generate_private_key", lambda c: self.sk), contextlib.redirect_stdout(so):
                mod.main()
        finally:
            os.chdir(cwd)
        self.assertGreaterEqual(len(os.listdir(self.out)), 2)
        self.none("make_samples", so.getvalue())

    def test_no_private_key_is_in_the_repository(self):
        """Every JSON file of the repository: no JWK with a private member (a vector that states the refusal has the value "AA")."""
        hits, seen = [], 0

        def walk(v, where):
            if isinstance(v, dict):
                if "kty" in v:
                    hits.extend((where, m) for m in PRIVATE if m in v and v[m] != "AA")
                for x in v.values():
                    walk(x, where)
            elif isinstance(v, list):
                for x in v:
                    walk(x, where)
        for base, dirs, files in os.walk(_HERE):
            dirs[:] = [x for x in dirs if not x.startswith(".") and x not in ("node_modules", "__pycache__")]
            for n in files:
                if n.endswith((".json", ".jwk")):
                    with open(os.path.join(base, n), "rb") as f:
                        try:
                            walk(json.loads(f.read()), n); seen += 1
                        except ValueError:
                            pass
        self.assertGreater(seen, 100)
        self.assertEqual(hits, [])
        walk({"a": [{"kty": "EC", "d": "x"}]}, "control")
        self.assertEqual(hits, [("control", "d")])



class TheTsaNoteCarriesNoText(unittest.TestCase):
    """1.11.2: an error asking a TSA is sealed by its kinds, errno and HTTP status: its text can carry the URL."""

    def test_no_text_of_the_error(self):
        import http.client
        import urllib.error
        from unittest import mock
        canary = "pw-CANARY-7f3e"
        cases = [(http.client.InvalidURL("nonnumeric port: '%s@host'" % canary), "InvalidURL"),
                 (urllib.error.URLError(ConnectionRefusedError(111, canary)), "URLError: ConnectionRefusedError [Errno 111]"),
                 (urllib.error.URLError(canary), "URLError"),
                 (urllib.error.HTTPError("https://h/" + canary, 503, canary, {}, None), "HTTPError: 503"),
                 (ValueError(canary), "ValueError")]
        for exc, want in cases:
            with self.subTest(exc=type(exc).__name__), mock.patch("urllib.request.urlopen", side_effect=exc):
                r = ap2._rfc3161_stamp("00" * 32, "https://tsa.example/")
                self.assertEqual((r["anchored"], r["note"]), (False, want))
                self.assertNotIn(canary, json.dumps(r))

if __name__ == "__main__":
    unittest.main()
