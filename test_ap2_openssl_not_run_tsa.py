#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.1, SPEC §3.2, §6.10: checks of the RFC 3161 path that ran outside the rules of the rest of the file.

1. The key-identifier step (`key_id_token_problem`, a token whose SignerInfo names its signer by subjectKeyIdentifier)
   called openssl with a bare subprocess.run: measured on 2026-11-20 on 1.9.0, an openssl killed by SIGKILL in
   `cms -verify` or in `verify -purpose timestampsign` gave `tsa_verified: false` ("openssl ... : refused"), and one that
   did not answer within 30 s gave `tsa_verified: false` (TimeoutExpired) — a finding about the token where the check had
   not run. Now through `_run_openssl`: `tsa_verified` null and the reason in `tsa_note`, as for `openssl ts -verify`.
Positive control: on 1.9.0 the three tests of a check not run fail (false where null is expected)."""
import base64
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl") and os.name == "posix", "needs openssl and a POSIX shell")


@NEEDS
class KeyIdStepNotRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_ap2_tsa_key_id as K
        cls.K = K
        cls.td = tempfile.mkdtemp(prefix="ap2kid_")
        cls.lab = K.Lab(cls.td, "lab")
        cls.tsr = base64.b64encode(K.reply(cls.lab.resign(cls.lab.token()))).decode()
        cls.real = shutil.which("openssl")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def _verify(self):
        return A._verify_rfc3161(self.tsr, self.K.DIGEST.hex(), tsa_cert=self.lab.j("ca.crt"))

    def _with_fake(self, name, case):
        d = os.path.join(self.td, name)
        os.makedirs(d)
        with open(os.path.join(d, "openssl"), "w") as f:
            f.write('#!/bin/sh\n%s\nexec "%s" "$@"\n' % (case, self.real))
        os.chmod(os.path.join(d, "openssl"), 0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + old
        try:
            return self._verify()
        finally:
            os.environ["PATH"] = old

    def test_control_real_openssl_verifies(self):
        self.assertTrue(A.signer_named_by_key_id(base64.b64decode(self.tsr)))
        self.assertIs(self._verify()["tsa_verified"], True)

    def test_killed_in_cms_verify_is_not_run(self):
        r = self._with_fake("kill_cms", 'case "$1 $2" in "cms -verify") kill -KILL $$;; esac')
        self.assertIsNone(r["tsa_verified"], r)
        self.assertIn("not run here", r["tsa_note"])
        self.assertIn("_not_run", r)

    def test_killed_in_verify_purpose_is_not_run(self):
        r = self._with_fake("kill_verify", 'case "$1 $2" in "verify -purpose") kill -KILL $$;; esac')
        self.assertIsNone(r["tsa_verified"], r)
        self.assertIn("terminated by signal", r["tsa_note"])

    def test_no_answer_is_not_run(self):
        r = self._with_fake("slow", 'case "$1 $2" in "verify -purpose") exec sleep 45;; esac')
        self.assertIsNone(r["tsa_verified"], r)
        self.assertIn("no answer within", r["tsa_note"])

    def test_a_refusal_stays_false(self):   # the other direction: a real "no" of openssl is still a finding
        r = A._verify_rfc3161(self.tsr, self.K.DIGEST.hex(), tsa_cert=self.lab.j("tsa.crt"))
        self.assertIs(r["tsa_verified"], False, r)


if __name__ == "__main__":
    unittest.main()
