#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.0-draft — SPEC §12: the JavaScript verifier reads and checks the `not_before` block exactly as the reference: the
not_before cases of verifiers/differential_oracle.py (a pack built with real NIST pulses and its generated variants, the
window rule with an upper bound and the disclosures called directly) must give 0 disagreements. Positive control: with
AP2_ORACLE_JS pointing at the JS verifier as it was before it read the block (2026-11-16), this test fails (measured 2026-11-16: 278 disagreements of 281)."""
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


@unittest.skipUnless(shutil.which("node"), "node absent: the JS verifier cannot be measured")
class TestJsNotBefore(unittest.TestCase):
    def test_zero_disagreements_on_the_not_before_cases(self):
        env = dict(os.environ, AP2_ORACLE_ONLY_NB="1")
        out = subprocess.run([sys.executable, "-B", os.path.join(HERE, "verifiers", "differential_oracle.py")], capture_output=True,
                             text=True, env=env, timeout=1800)
        last = [ln for ln in out.stdout.splitlines() if ln.startswith("disagreements:")]
        self.assertEqual(out.returncode, 0, out.stdout[-3000:] + out.stderr[-2000:])
        self.assertTrue(last and last[0].startswith("disagreements: 0/"), last)
        n = int(last[0].split("/")[1].split()[0])
        self.assertGreaterEqual(n, 250, last)   # the cases are all there (232 packs + 1 positive control + 48 function cases on 2026-11-16)


if __name__ == "__main__":
    unittest.main()
