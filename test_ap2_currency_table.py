#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""SPEC §12.3: MINOR_UNITS (and the JS verifier's NB_MINOR_UNITS) are the ISO 4217 minor units of five currencies. No
currency list is shipped; with CV_ISO4217_LIST (the caller's own download of ISO 4217 list one) the five are compared
with it. Positive control: a table with one value changed is caught by the same comparison."""
import os
import re
import sys
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402


def list_one():
    p = os.environ.get("CV_ISO4217_LIST")
    if not p:
        raise unittest.SkipTest("CV_ISO4217_LIST not set (ISO 4217 list one is not shipped)")
    out = {}
    for e in ET.parse(p).getroot().iter("CcyNtry"):
        c, u = (e.findtext("Ccy") or "").strip(), (e.findtext("CcyMnrUnts") or "").strip()
        if c and u.isdigit():
            out[c] = int(u)
    return out


def disagreements(table, iso):
    return {c: (v, iso.get(c)) for c, v in table.items() if iso.get(c) != v}


class CurrencyTable(unittest.TestCase):
    def test_python_table_is_iso_4217(self):
        self.assertEqual(disagreements(A.MINOR_UNITS, list_one()), {})

    def test_js_table_is_the_python_one(self):
        with open(os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs"), encoding="utf-8") as f:
            m = re.search(r"const NB_MINOR_UNITS = \{([^}]*)\}", f.read())
        js = {k: int(v) for k, v in re.findall(r"([A-Z]{3}): (\d)", m.group(1))}
        self.assertEqual(js, A.MINOR_UNITS)

    def test_a_changed_value_is_caught(self):
        iso = list_one()
        self.assertEqual(disagreements(dict(A.MINOR_UNITS, JPY=2), iso), {"JPY": (2, 0)})


if __name__ == "__main__":
    unittest.main()
