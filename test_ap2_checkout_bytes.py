# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""1.11.1: a checkout has the committed bytes whatever core.autocrlf says (the default of Git for Windows is true).
Before, with no .gitattributes, such a checkout turned the line ends of the text files, so the tsa_cert_sha256 a
receipt states was another one (reported by a reader on 2026-11-22); the verdict under it was the same."""
import glob
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CRT = os.path.join(HERE, "spec", "vectors", "ap2", "anchor_probe_tsa.crt")


@unittest.skipUnless(shutil.which("git"), "git absent: no checkout can be made")
class CheckoutBytes(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def _git(self, *args):
        # nothing of this machine's git decides the outcome: no GIT_* variable of the caller (a hook's GIT_DIR, a
        # configuration given through GIT_CONFIG_COUNT or GIT_CONFIG_PARAMETERS, GIT_TEMPLATE_DIR), no system or user
        # configuration, no system or user attributes file (a user's `* -text` made the control below fail)
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1")
        none = os.path.join(self.d, "no-attributes")
        open(none, "ab").close()
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                        "-c", "core.attributesFile=" + none, *args], check=True, capture_output=True, env=env, timeout=120)

    def _checkout(self, attributes: bool) -> bytes:
        """The bytes of a committed certificate in a clone with core.autocrlf=true."""
        src, dst = os.path.join(self.d, "src%d" % attributes), os.path.join(self.d, "dst%d" % attributes)
        os.mkdir(src)
        self._git("init", "-q", src)
        shutil.copy(CRT, os.path.join(src, "x.crt"))
        if attributes:
            shutil.copy(os.path.join(HERE, ".gitattributes"), src)
        self._git("-C", src, "-c", "core.autocrlf=false", "add", "-A")
        self._git("-C", src, "commit", "-q", "-m", "t")
        self._git("clone", "-q", "-c", "core.autocrlf=true", src, dst)
        with open(os.path.join(dst, "x.crt"), "rb") as f:
            return f.read()

    def test_a_checkout_has_the_committed_bytes(self):
        with open(CRT, "rb") as f:
            committed = f.read()
        self.assertNotIn(b"\r", committed)
        self.assertEqual(self._checkout(attributes=True), committed)
        self.assertEqual(self._checkout(attributes=False), committed.replace(b"\n", b"\r\n"))   # the control: 1.10.0

    def test_this_checkout_has_them(self):
        """The files of this very checkout (the CI asks for the conversion on every system)."""
        names = glob.glob(os.path.join(HERE, "spec", "vectors", "ap2", "*.crt"))
        self.assertTrue(names)
        for name in names:
            with open(name, "rb") as f:
                self.assertNotIn(b"\r", f.read(), name)


if __name__ == "__main__":
    unittest.main()
