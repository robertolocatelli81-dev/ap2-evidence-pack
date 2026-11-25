#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.11.0, security: the openssl the reference runs is never one in the current folder.

shutil.which looks in the current folder first on Windows (CPython 3.9 and 3.11 always, 3.13 unless
NoDefaultCurrentDirectoryInExePath is set), and on every system an empty or relative PATH entry is the current folder.
Up to 1.10.0 ap2_evidence ran what shutil.which("openssl") answered, and key_id_token_problem ran a bare "openssl": an
openssl planted beside the evidence was run. Now `_which_absolute` (from omega-nucleo-comune which_absolute) keeps only
an absolute answer and searches only the absolute folders of PATH.

The planted program writes a marker file when it runs. POSIX: the current folder reached through an empty PATH entry
(real, nothing simulated). Windows: shutil.which's own current-folder rule (real there). The positive control puts
shutil.which back in place of _which_absolute: the planted program runs."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
import _ap2_platform as P  # noqa: E402

VEC = os.path.join(ROOT, "spec", "vectors", "ap2")


class NeverTheCurrentFolder(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2which_")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.marker = os.path.join(self.d, "RAN")
        # the planted openssl: in the folder that will be current, it leaves a marker and answers nothing useful
        P.fake_tool(self.d, "openssl", "open(%r, 'w').close()\nimport sys; sys.exit(1)\n" % self.marker)
        here = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, here)
        # POSIX: an empty PATH entry is the current folder; Windows looks there first anyway
        self.path = os.pathsep + os.environ.get("PATH", "")

    def _verify(self):
        with mock.patch.dict(os.environ, {"PATH": self.path}):
            return A.verify_evidence(os.path.join(VEC, "anchor_valid.json"), tsa_cert=os.path.join(VEC, "anchor_probe_tsa.crt"))

    def test_shutil_which_would_answer_the_planted_one(self):   # the premise, measured here
        with mock.patch.dict(os.environ, {"PATH": self.path}):
            found = shutil.which("openssl")
        self.assertIsNotNone(found)
        self.assertFalse(os.path.isabs(found), found)   # a relative answer: the current folder

    def test_the_planted_openssl_is_not_run(self):
        try:
            self._verify()
        except A.Ap2WriteError:
            pass
        self.assertFalse(os.path.exists(self.marker), "the openssl in the current folder was run")
        with mock.patch.dict(os.environ, {"PATH": self.path}):
            exe = A._which_absolute("openssl")
        self.assertTrue(exe is None or (os.path.isabs(exe) and os.path.dirname(exe) != self.d), exe)

    def test_positive_control_shutil_which_runs_it(self):
        with mock.patch.object(A, "_which_absolute", shutil.which):
            try:
                self._verify()
            except A.Ap2WriteError:
                pass
        self.assertTrue(os.path.exists(self.marker), "the bench cannot see a planted openssl being run")

    def test_key_id_step_default_is_not_the_bare_name(self):
        calls = []
        real = A._run_openssl

        def spy(cmd, timeout, **kw):
            calls.append(cmd[0])
            return real(cmd, timeout, **kw)
        import test_ap2_tsa_key_id as K
        if not K.shutil.which("openssl"):
            self.skipTest("openssl needed for the key-identifier lab")
        lab = K.Lab(tempfile.mkdtemp(dir=self.d), "lab")
        tok = K.reply(lab.resign(lab.token()))
        with mock.patch.dict(os.environ, {"PATH": self.path}), mock.patch.object(A, "_run_openssl", spy):
            try:
                A.key_id_token_problem(tok, K.DIGEST.hex(), lab.j("ca.crt"), __import__("time").time(), tempfile.mkdtemp(dir=self.d))
            except A.Ap2WriteError:
                pass
        self.assertTrue(calls and all(os.path.isabs(c) for c in calls), calls)
        self.assertFalse(os.path.exists(self.marker))

    def test_absolute_on_windows_names_a_drive_or_a_share(self):
        import ntpath
        with mock.patch.object(A.os, "name", "nt"), mock.patch.object(A.os, "path", ntpath):
            got = {p: A._is_absolute(p) for p in ("\\tools", "/tools", "tools", "C:tools", "", "C:\\tools", "c:/tools",
                                                  "\\\\host\\share\\tools")}
        self.assertEqual([p for p in got if got[p]], ["C:\\tools", "c:/tools", "\\\\host\\share\\tools"])
        if os.name != "nt":
            self.assertTrue(A._is_absolute("/tools"))   # POSIX: as before

    def test_a_name_with_a_separator_is_refused(self):
        for bad in ("", ".", "..", "a/openssl", "a\\openssl", "open\0ssl"):
            with self.subTest(name=bad), self.assertRaises(ValueError):
                A._which_absolute(bad)


if __name__ == "__main__":
    unittest.main()
