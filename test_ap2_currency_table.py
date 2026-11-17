#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""SPEC §12.3: MINOR_UNITS (and the JS verifier's NB_MINOR_UNITS) are the `digits` Unicode CLDR 49 gives the five
currencies; tools/currency_table_from_cldr.py prints the CLDR table from the CLDR files (not shipped: CV_CLDR_DIR names a
directory holding supplementalData.xml and currency.xml). Positive control: a table with one value changed is
refused by the comparison (test_a_changed_value_is_caught)."""
import os
import re
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402


def cldr_table():
    d = os.environ.get("CV_CLDR_DIR")
    if not d:
        raise unittest.SkipTest("CV_CLDR_DIR not set (the CLDR 49 files are not shipped)")
    out = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "currency_table_from_cldr.py"),
                          os.path.join(d, "supplementalData.xml"), os.path.join(d, "currency.xml")],
                         capture_output=True, text=True, check=True).stdout
    return {c: n for n, codes in eval(out).items() for c in codes.split()}   # noqa: S307 — the script's own literal


def disagreements(table, cldr):
    return {c: (v, cldr.get(c)) for c, v in table.items() if cldr.get(c) != v}


class CurrencyTable(unittest.TestCase):
    def test_python_table_is_cldr(self):
        self.assertEqual(disagreements(A.MINOR_UNITS, cldr_table()), {})

    def test_js_table_is_the_python_one(self):
        with open(os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs"), encoding="utf-8") as f:
            m = re.search(r"const NB_MINOR_UNITS = \{([^}]*)\}", f.read())
        js = {k: int(v) for k, v in re.findall(r"([A-Z]{3}): (\d)", m.group(1))}
        self.assertEqual(js, A.MINOR_UNITS)

    def test_a_changed_value_is_caught(self):
        cldr = cldr_table()
        self.assertEqual(disagreements(dict(A.MINOR_UNITS, JPY=2), cldr), {"JPY": (2, 0)})
        self.assertEqual(disagreements(dict(A.MINOR_UNITS, CLF=4), cldr), {"CLF": (4, None)})


if __name__ == "__main__":
    unittest.main()
