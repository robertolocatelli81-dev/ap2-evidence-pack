#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.7.2 — a supplied key names an artifact (SPEC §2): `--key name=…` / `--jwks-url name=…` whose name is not an artifact
of this build, or given twice, is a usage error (exit 2, no file, before any file under it is read or URL fetched);
`build_evidence` refuses a stray `keys` / `jwks_urls` name. Measured on 1.7.1 (2026-11-02): both were ignored in silence
(`--key nope=k.json` -> exit 0, header keys used; `--key a=K1 --key a=K2` -> K2 alone). Run: python3 test_ap2_supplied_key_names.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402
import test_ap2_evidence as T  # noqa: E402


class SuppliedKeyNames(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2keys-"); self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.sk, self.jwk = T._make_signer(); self.sk2, self.jwk2 = T._make_signer()
        self.tok = os.path.join(self.d, "a.sdjwt"); self.tok_b = os.path.join(self.d, "b.sdjwt")
        with open(self.tok, "w") as fh:
            fh.write(T._make_sd_jwt(self.sk, {"iss": "u"}, {"x": "1"}, header_extra={"jwk": self.jwk}))
        with open(self.tok_b, "w") as fh:
            fh.write(T._make_sd_jwt(self.sk2, {"iss": "v"}, {"y": "2"}, header_extra={"jwk": self.jwk2}))
        self.k, self.k2 = os.path.join(self.d, "k.json"), os.path.join(self.d, "k2.json")
        for path, jwk in ((self.k, self.jwk), (self.k2, self.jwk2)):
            with open(path, "w") as fh:
                json.dump(jwk, fh)
        self.out = os.path.join(self.d, "out.json")

    def _cli(self, *extra):
        p = subprocess.run([sys.executable, os.path.join(_HERE, "ap2_evidence.py"), "build", self.out, "a=" + self.tok, "b=" + self.tok_b, *extra],
                           capture_output=True, text=True, timeout=120)
        return p.returncode, p.stderr

    def test_control_a_named_key_is_used_and_recorded_as_supplied(self):
        rc, err = self._cli("--key", "a=" + self.k); self.assertEqual(rc, 0, err)
        with open(self.out) as fh:
            arts = {a["name"]: a["key"]["provenance_class"] for a in json.load(fh)["artifacts"]}
        self.assertEqual(arts, {"a": "supplied", "b": "jwk_header"})

    def test_control_a_wrong_key_for_a_right_name_is_a_build_refusal(self):
        rc, err = self._cli("--key", "a=" + self.k2); self.assertEqual(rc, 1, err); self.assertIn("signature INVALID", err)
        self.assertFalse(os.path.exists(self.out))

    def test_key_naming_no_artifact_is_a_usage_error_no_file(self):
        rc, err = self._cli("--key", "nope=" + self.k)
        self.assertEqual(rc, 2, err); self.assertIn("--key: no artifact named 'nope'", err); self.assertIn("artifacts: a, b", err)
        self.assertFalse(os.path.exists(self.out))

    def test_key_repeated_for_one_artifact_is_a_usage_error_whatever_the_order(self):
        for first, second in ((self.k, self.k2), (self.k2, self.k)):   # on 1.7.1 the second won in silence: K2 then K failed, K then K2 passed
            rc, err = self._cli("--key", "a=" + first, "--key", "a=" + second)
            self.assertEqual(rc, 2, err); self.assertIn("--key: 'a' given more than once", err); self.assertFalse(os.path.exists(self.out))

    def test_key_name_checked_before_its_file_is_read(self):
        rc, err = self._cli("--key", "nope=" + os.path.join(self.d, "absent.json"))
        self.assertEqual(rc, 2, err); self.assertIn("no artifact named 'nope'", err); self.assertNotIn("cannot read", err)

    def test_jwks_url_naming_no_artifact_is_a_usage_error_before_any_fetch(self):
        rc, err = self._cli("--jwks-url", "nope=https://127.0.0.1:9/jwks")   # port 9: a fetch would fail differently
        self.assertEqual(rc, 2, err); self.assertIn("--jwks-url: no artifact named 'nope'", err); self.assertFalse(os.path.exists(self.out))
        rc, err = self._cli("--jwks-url", "a=https://127.0.0.1:9/x", "--jwks-url", "a=https://127.0.0.1:9/y")
        self.assertEqual(rc, 2, err); self.assertIn("--jwks-url: 'a' given more than once", err)

    def test_two_different_artifacts_may_each_have_a_key(self):
        rc, err = self._cli("--key", "a=" + self.k, "--key", "b=" + self.k2); self.assertEqual(rc, 0, err)
        with open(self.out) as fh:
            self.assertEqual({a["key"]["provenance_class"] for a in json.load(fh)["artifacts"]}, {"supplied"})

    def test_library_refuses_a_stray_name(self):
        with open(self.tok) as fh:
            arts = [{"name": "a", "sd_jwt": fh.read()}]
        for kw in ({"keys": {"nope": self.jwk}}, {"jwks_urls": {"nope": "https://127.0.0.1:9/jwks"}},
                   {"keys": {"a": self.jwk, "zz": self.jwk}}):
            with self.assertRaises(ap2.Ap2EvidenceError) as cm:
                ap2.build_evidence(arts, self.out, **kw)
            self.assertIn("no artifact named", str(cm.exception)); self.assertIn("SPEC §2", str(cm.exception))
            self.assertFalse(os.path.exists(self.out))
        ap2.build_evidence(arts, self.out, keys={"a": self.jwk})   # the control: a named key builds
        self.assertTrue(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
