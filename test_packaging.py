#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.3.0: the wheel installs the signature suite as `ap2_pqcrypto/`, never as `pqcrypto/`.

PyPI's `pqcrypto` (1.0.0, a PQClean binding) owns the `pqcrypto/` directory in site-packages. Measured 2026-10-05: installing
1.2.2 on top of it replaced its `__init__.py` with our empty one, and `from pqcrypto import ml_kem_512` (its documented API)
stopped working; uninstalling 1.2.2 then removed that file for good. The clone keeps `pqcrypto/` (every documented
`python3 <file>.py` command is unchanged); setuptools maps it to `ap2_pqcrypto` in the wheel, and `ap2_evidence` looks for
`sigsuite.py` in `pqcrypto/` first, then `ap2_pqcrypto/` — the FILE, not the directory, because PyPI's `pqcrypto/` may sit
beside the installed module (the first prototype checked the directory and failed exactly there).

Positive controls: the 1.2.2 layout fails `test_pyproject_maps_pqcrypto_to_ap2_pqcrypto`; a layout with a foreign
`pqcrypto/` and no `ap2_pqcrypto/` fails to import. The floor test and the wheel test have no control here: the floor is
measured by the CI `floor` job (cryptography 48.0.0), and a wheel built from a tree with a stale `build/lib/pqcrypto/` was
measured (2026-10-05) to carry `pqcrypto/` — that is why the release procedure removes `build/` first and the test builds
from a clean copy."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None


def _load_pyproject(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


@unittest.skipIf(tomllib is None, "tomllib: Python >= 3.11")
class TestPyproject(unittest.TestCase):
    def test_pyproject_maps_pqcrypto_to_ap2_pqcrypto(self):
        st = _load_pyproject(os.path.join(HERE, "pyproject.toml"))["tool"]["setuptools"]
        self.assertEqual(st["packages"], ["ap2_pqcrypto"])
        self.assertEqual(st["package-dir"], {"ap2_pqcrypto": "pqcrypto"})
        self.assertNotIn("pqcrypto", st["packages"])

    def test_positive_control_the_1_2_2_layout_fails(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "pyproject.toml"), "w") as f:
            f.write('[tool.setuptools]\npy-modules = ["ap2_evidence"]\npackages = ["pqcrypto"]\n')
        st = _load_pyproject(os.path.join(d, "pyproject.toml"))["tool"]["setuptools"]
        self.assertIn("pqcrypto", st["packages"])
        self.assertNotIn("package-dir", st)
        shutil.rmtree(d)

    def test_cryptography_floor_is_48(self):
        deps = _load_pyproject(os.path.join(HERE, "pyproject.toml"))["project"]["dependencies"]
        self.assertEqual(deps, ["cryptography>=48"])   # ML-DSA-65 works from 48.0.0; 47.0.0 raises UnsupportedAlgorithm


class TestImportHookFindsTheFileNotTheDirectory(unittest.TestCase):
    """ap2_evidence.py copied next to (a) a foreign pqcrypto/ without sigsuite.py and (b) ap2_pqcrypto/ with it: the
    import succeeds and sigsuite comes from ap2_pqcrypto/. Control: without (b) it fails."""

    def _layout(self, with_ap2_pqcrypto):
        d = tempfile.mkdtemp()
        shutil.copy(os.path.join(HERE, "ap2_evidence.py"), d)
        os.makedirs(os.path.join(d, "pqcrypto"))
        with open(os.path.join(d, "pqcrypto", "__init__.py"), "w") as f:
            f.write("__version__ = '1.0.0'  # a foreign pqcrypto package, no sigsuite here\n")
        if with_ap2_pqcrypto:
            shutil.copytree(os.path.join(HERE, "pqcrypto"), os.path.join(d, "ap2_pqcrypto"))
        return d

    def _run(self, d):
        code = "import os, sys, ap2_evidence; print(os.path.basename(os.path.dirname(sys.modules['sigsuite'].__file__)))"
        return subprocess.run([sys.executable, "-c", code], cwd=d, capture_output=True, text=True, timeout=60)

    def test_sigsuite_resolved_from_ap2_pqcrypto_beside_a_foreign_pqcrypto(self):
        d = self._layout(True)
        out = self._run(d)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "ap2_pqcrypto")
        shutil.rmtree(d)

    def test_positive_control_without_ap2_pqcrypto_the_import_fails(self):
        d = self._layout(False)
        out = self._run(d)
        self.assertEqual(out.returncode, 1)
        self.assertIn("No module named 'sigsuite'", out.stderr)
        shutil.rmtree(d)


class TestWheelContents(unittest.TestCase):
    """The wheel built from a clean copy of this tree ships ap2_pqcrypto/sigsuite.py and no pqcrypto/ entry at all."""

    def test_wheel_has_ap2_pqcrypto_and_no_pqcrypto(self):
        try:
            import build  # noqa: F401  (python -m build, as the release procedure does; isolated: needs setuptools>=68 reachable)
        except ImportError:
            self.skipTest("the `build` package is not installed: the wheel is not measured here")
        src = tempfile.mkdtemp(); out = tempfile.mkdtemp()
        shutil.copytree(HERE, os.path.join(src, "t"), ignore=shutil.ignore_patterns("build", "*.egg-info", ".git", "__pycache__", "dist"))
        r = subprocess.run([sys.executable, "-m", "build", "-q", "-w", "-o", out, os.path.join(src, "t")],
                           capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        whl = [n for n in os.listdir(out) if n.endswith(".whl")]
        self.assertEqual(len(whl), 1, whl)
        names = zipfile.ZipFile(os.path.join(out, whl[0])).namelist()
        self.assertIn("ap2_pqcrypto/sigsuite.py", names)
        self.assertIn("ap2_evidence.py", names)
        self.assertEqual([n for n in names if n.startswith("pqcrypto/")], [])
        shutil.rmtree(src); shutil.rmtree(out)


if __name__ == "__main__":
    unittest.main()
