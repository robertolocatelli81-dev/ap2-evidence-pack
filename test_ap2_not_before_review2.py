# SPDX-License-Identifier: Apache-2.0
"""SPEC §12 (1.8.0-draft), tests added after the second review (16/11/2026): the Unicode version of committed values and
the exact comparison of a genTime with many fraction digits, in the reference and in the JavaScript verifier."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "verifiers"))
import ap2_evidence as ap2  # noqa: E402
import differential_oracle as O  # noqa: E402

NOT_PORTABLE = ("a\U0001e08f̖", "Ra\U000105d2̇", "x͸")
GEN = ("20261116131059.9999995Z", "20261116131059.9999999Z", "20261116131059.99999999999Z", "20261116131059.999Z",
       "20261116131100Z", "20261116131100.0000001Z")
WANT = ["failed:window_inverted"] * 4 + ["verified", "verified"]


class Review2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.path, cls.ev = O._nb_pack(cls.td)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td)

    def js(self, window, disclosures):
        job = os.path.join(self.td, "job.json")
        with open(job, "w", encoding="utf-8") as fh:
            json.dump({"pack": self.path, "window": window, "disclosures": disclosures}, fh)
        out = subprocess.run(["node", os.path.join(ROOT, "verifiers", "js", "nb_parity.mjs"), job], capture_output=True,
                             text=True, timeout=120)
        return json.loads(out.stdout)

    def test_value_outside_unicode_13_refused_in_both(self):
        salt = O.NB_SALTS["payee_name_commitment"]
        for v in NOT_PORTABLE:
            with self.assertRaises(ValueError, msg=ascii(v)):
                ap2.payment_commitment("payee_name_commitment", salt, v)
        disc = [{"member": "payee_name_commitment", "salt": salt.hex(), "value": v} for v in NOT_PORTABLE]
        disc.append({"member": "payee_name_commitment", "salt": salt.hex(), "value": "Oracle Café Merchant"})
        py = []
        for d in disc:
            try:
                py.append(ap2.check_disclosure(self.path, d))
            except (ap2.Ap2EvidenceError, ValueError):
                py.append("refused")
        self.assertEqual(py[:3], ["refused"] * 3)
        self.assertEqual(py[3]["outcome"], "matches")
        if shutil.which("node"):
            self.assertEqual(self.js([], disc)["disclosures"], py)

    def test_gen_time_fraction_compared_exactly(self):
        arts = [{"signature_ok": True, "claims_match": True} for _ in self.ev["artifacts"]]
        py = [ap2.check_not_before(self.ev["not_before"], self.ev, arts, g)["checks"]["NB3"] for g in GEN]
        self.assertEqual(py, WANT)
        if shutil.which("node"):
            self.assertEqual([w["checks"]["NB3"] for w in self.js(list(GEN), [])["window"]], WANT)


if __name__ == "__main__":
    unittest.main()
