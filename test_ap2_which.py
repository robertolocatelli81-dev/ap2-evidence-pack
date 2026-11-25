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

    def _verify(self, site="tsa-cert"):
        """One call for each place that runs openssl: verify with a TSA certificate, verify with a trust anchor (x5c),
        and the timestamp query of build --tsa and stamp (the TSA is never reached: a URL that refuses)."""
        with mock.patch.dict(os.environ, {"PATH": self.path}):
            if site == "tsa-cert":
                return A.verify_evidence(os.path.join(VEC, "anchor_valid.json"), tsa_cert=os.path.join(VEC, "anchor_probe_tsa.crt"))
            if site == "trust-anchor":
                return A.verify_evidence(os.path.join(VEC, "issuer_x5c_ca_certified.json"), trust_anchor=os.path.join(VEC, "issuer_ca.crt"))
            with mock.patch.object(A.urllib.request, "urlopen", side_effect=OSError("no TSA in this test")):
                return A._rfc3161_stamp("00" * 32, "http://tsa.invalid/")

    SITES = ("tsa-cert", "trust-anchor", "stamp")

    def test_shutil_which_would_answer_the_planted_one(self):   # the premise, measured here
        with mock.patch.dict(os.environ, {"PATH": self.path}):
            found = shutil.which("openssl")
        self.assertIsNotNone(found)
        self.assertFalse(os.path.isabs(found), found)   # a relative answer: the current folder

    def test_the_planted_openssl_is_not_run(self):
        for site in self.SITES:
            with self.subTest(site=site):
                try:
                    self._verify(site)
                except A.Ap2WriteError:
                    pass
                self.assertFalse(os.path.exists(self.marker), "the openssl in the current folder was run")
        with mock.patch.dict(os.environ, {"PATH": self.path}):
            exe = A._which_absolute("openssl")
        self.assertTrue(exe is None or (os.path.isabs(exe) and os.path.dirname(exe) != self.d), exe)

    def test_positive_control_shutil_which_runs_it(self):
        for site in self.SITES:
            with self.subTest(site=site), mock.patch.object(A, "_which_absolute", shutil.which):
                try:
                    self._verify(site)
                except A.Ap2WriteError:
                    pass
                self.assertTrue(os.path.exists(self.marker), "the bench cannot see a planted openssl being run")
                os.remove(self.marker)

    def test_an_absolute_folder_of_path_is_searched_once_the_current_one_is_dropped(self):
        """PATH: the current folder (the planted openssl), then an absolute folder with another openssl. The answer is
        the second, by its absolute path; a file there that is not a program (no execute bit on POSIX, no extension of
        PATHEXT on Windows) is not an answer."""
        good = P.fake_tool(os.path.join(self.d, "abs"), "openssl", "import sys; sys.exit(0)\n")
        with mock.patch.dict(os.environ, {"PATH": os.pathsep + good}):
            exe = A._which_absolute("openssl")
        self.assertIsNotNone(exe)
        self.assertTrue(A._is_absolute(exe), exe)
        self.assertEqual(os.path.normcase(os.path.dirname(exe)), os.path.normcase(good))
        plain = os.path.join(self.d, "plain")
        os.mkdir(plain)
        with open(os.path.join(plain, "openssl"), "w", encoding="utf-8") as f:
            f.write("not a program\n")
        os.chmod(os.path.join(plain, "openssl"), 0o644)
        os.mkdir(os.path.join(good, "sub"))
        os.mkdir(os.path.join(good, "sub", "openssl"))   # a folder of that name is not one either
        for path in (os.pathsep + plain, os.pathsep + os.path.join(good, "sub"), ""):
            with self.subTest(PATH=path), mock.patch.dict(os.environ, {"PATH": path}):
                self.assertIsNone(A._which_absolute("openssl"))

    def test_a_name_with_a_drive_is_refused_on_windows(self):
        # `C:openssl` is the current folder of drive C, and os.path.join(folder, "C:openssl") drops the folder
        with mock.patch.object(A.os, "name", "nt"), self.assertRaises(ValueError):
            A._which_absolute("C:openssl")

    def test_key_id_step_without_openssl_is_the_write_error_and_a_bare_name_is_looked_up(self):
        with mock.patch.dict(os.environ, {"PATH": ""}):   # no folder to search: the planted one is all there is
            for exe in (None, "openssl"):
                with self.subTest(exe=exe), self.assertRaises(A.Ap2WriteError) as e:
                    A.key_id_token_problem(b"", "00" * 32, os.path.join(VEC, "issuer_ca.crt"), 0, self.d, exe)
                self.assertIn("cannot run openssl here", str(e.exception))
        # a bare name other than openssl is the one looked up (not replaced by "openssl")
        seen = []
        with mock.patch.object(A, "_which_absolute", lambda name: seen.append(name)), self.assertRaises(A.Ap2WriteError):
            A.key_id_token_problem(b"", "00" * 32, os.path.join(VEC, "issuer_ca.crt"), 0, self.d, "openssl3")
        self.assertEqual(seen, ["openssl3"])

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
        # the same answers on every Python: ntpath's change (\\tools, \\\\server, \\\\server\\share, any character as a drive)
        yes = ("C:\\tools", "c:/tools", "\\\\host\\share\\tools", "//host/share/tools", "\\\\host\\share", "\\\\?\\C:\\tools")
        no = ("\\tools", "/tools", "tools", "C:tools", "", "\\\\host", "\\\\host\\", "1:\\tools", "::\\tools", "\u00e9:\\tools",
              "\\\\\\tools", "C:")
        with mock.patch.object(A.os, "name", "nt"):
            got = {p: A._is_absolute(p) for p in yes + no}
        self.assertEqual([p for p in got if got[p]], list(yes))
        if os.name != "nt":
            self.assertTrue(A._is_absolute("/tools"))   # POSIX: as before

    def test_the_names_of_pathext(self):
        """Windows: a bare name is looked up with each extension of PATHEXT, a name that has one already as it is."""
        for name, file in (("tool", "tool.EXE"), ("other.exe", "other.exe")):
            d = tempfile.mkdtemp(dir=self.d)
            with open(os.path.join(d, file), "wb"):
                pass
            os.chmod(os.path.join(d, file), 0o755)
            with self.subTest(name=name), mock.patch.dict(os.environ, {"PATH": d, "PATHEXT": ".EXE"}), \
                    mock.patch.object(A.os, "name", "nt"), mock.patch.object(A, "_is_absolute", os.path.isabs), \
                    mock.patch.object(shutil, "which", lambda n: None):
                self.assertEqual(A._which_absolute(name), os.path.join(d, file))

    def test_a_name_with_a_separator_is_refused(self):
        for bad in ("", ".", "..", "a/openssl", "a\\openssl", "open\0ssl"):
            with self.subTest(name=bad), self.assertRaises(ValueError):
                A._which_absolute(bad)


if __name__ == "__main__":
    unittest.main()
