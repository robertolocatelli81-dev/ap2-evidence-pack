#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.0: the wheel carries the ACVP vectors and NIST's notice beside the test that reads them, and that test passes
from an installed wheel. Measured on 2026-11-17: the 1.7.3 wheel on PyPI (sha256 109227df…) shipped
ap2_pqcrypto/test_acvp_mldsa65.py without its vectors file (FileNotFoundError when run installed; the signature suite
registered ML-DSA-65 all the same). Builds the wheel from a copy of the tracked files (needs the `build` and
`setuptools` modules and a git work tree, else skipped); positive control: the same build without the package-data table
lacks the file. 1.9.1: the work tree is asked of git (`rev-parse --is-inside-work-tree`) — measured 2026-11-21, on a
`git archive` with `build` installed both tests ERRORED (`git ls-files` exit 128) instead of skipping; and ci.yml runs this
file on the checkout after installing `build` and `setuptools`, so the positive control runs in CI (before, the jobs that
run the suites have no `build` module and the file was skipped everywhere)."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
WANT = ["ap2_pqcrypto/vectors/acvp_mldsa65_sigver_pure.jsonl", "ap2_pqcrypto/vectors/NIST-ACVP-NOTICE.txt"]


def _can_build():
    try:
        import build  # noqa: F401
        import setuptools  # noqa: F401
        return True
    except ImportError:
        return False


def build_wheel(td, drop_package_data=False):
    src = os.path.join(td, "src")
    files = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"], capture_output=True, check=True).stdout.split(b"\0")
    for f in filter(None, files):
        f = f.decode()
        if os.path.isfile(os.path.join(ROOT, f)):
            os.makedirs(os.path.dirname(os.path.join(src, f)) or src, exist_ok=True)
            shutil.copy2(os.path.join(ROOT, f), os.path.join(src, f))
    shutil.copy2(os.path.join(ROOT, "pyproject.toml"), os.path.join(src, "pyproject.toml"))
    if drop_package_data:
        p = os.path.join(src, "pyproject.toml")
        with open(p, encoding="utf-8") as f:
            text = f.read()
        i = text.index("[tool.setuptools.package-data]")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text[:i])
    out = os.path.join(td, "dist")
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", out, src],
                   capture_output=True, check=True)
    return os.path.join(out, [n for n in os.listdir(out) if n.endswith(".whl")][0])


def _in_work_tree():
    if not shutil.which("git"):
        return False
    r = subprocess.run(["git", "-C", ROOT, "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


@unittest.skipUnless(_can_build() and _in_work_tree(), "needs the build and setuptools modules, and a git work tree")
class WheelContents(unittest.TestCase):
    def test_vectors_in_the_wheel_and_the_installed_test_passes(self):
        with tempfile.TemporaryDirectory() as td:
            whl = build_wheel(td)
            names = zipfile.ZipFile(whl).namelist()
            for w in WANT:
                self.assertIn(w, names)
            site = os.path.join(td, "site")
            zipfile.ZipFile(whl).extractall(site)
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            env["PYTHONPATH"] = site
            r = subprocess.run([sys.executable, "-m", "unittest", "ap2_pqcrypto.test_acvp_mldsa65"], cwd=td,
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr[-600:])
            self.assertNotIn("FileNotFoundError", r.stderr)
            try:
                from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
                self.assertIn("Ran 2 tests", r.stderr)
                self.assertNotIn("skipped", r.stderr)      # it ran, not skipped for a missing backend
            except ImportError:
                pass

    def test_positive_control_without_package_data(self):
        with tempfile.TemporaryDirectory() as td:
            names = zipfile.ZipFile(build_wheel(td, drop_package_data=True)).namelist()
            self.assertNotIn(WANT[0], names)


if __name__ == "__main__":
    unittest.main()
