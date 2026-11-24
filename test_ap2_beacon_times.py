#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.8.1, SPEC §12.2 and §12.3: every time read on the `not_before` path is a verdict with a named reason, never a
traceback.

Measured on 2026-11-18 on the PyPI wheel 1.8.0 by an external review: a `not_before` pack with the real NIST pulses and
certificate, the certificate's notBefore (UTCTime) carried to month 13 and the pack resealed, ended `verify` with
`ValueError: time data '20261321000000Z' does not match format`, exit 1, empty stdout (`ap2_nist_beacon._gtime` called
`strptime` outside any try). The JavaScript verifier refused it as `certificate_time`. In the same class, found by reading
the code: a TSA-verified genTime with second 60 or 61 passes `time.strptime` (used for `-attime`) and stops
`datetime.strptime` in `check_not_before`.

The expected answer of every generated time comes from `oracle`, written apart (calendar.monthrange), not from the code
under test; the JS function `nbTime` is read from a copy of ap2-verify.mjs that exports it. On the previous commit 5 of
the 9 tests fail: the generated times, the month-13 pack (CLI and build) and the leap second (Python, and JS, where a
genTime that is no calendar time gave failed:window_inverted, a null compared as 0)."""
import base64
import calendar
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402
import ap2_nist_beacon as NB  # noqa: E402
import test_ap2_not_before as T  # noqa: E402

JS = os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")
NODE = shutil.which("node")


def oracle(raw: bytes, tag: int):
    """RFC 5280 §4.1.2.5: the instant (seconds since the epoch) or None"""
    if tag not in (0x17, 0x18) or any(b < 0x30 or b > 0x39 for b in raw[:-1]) or raw[-1:] != b"Z":
        return None
    if len(raw) != (13 if tag == 0x17 else 15):
        return None
    s = raw[:-1].decode()
    if tag == 0x17:
        s = ("19" if int(s[:2]) >= 50 else "20") + s
    y, mo, d, h, mi, se = int(s[:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]), int(s[12:14])
    if y < 1 or not 1 <= mo <= 12 or not 1 <= d <= calendar.monthrange(y, mo)[1] or h > 23 or mi > 59 or se > 59:
        return None
    return calendar.timegm((y, mo, d, h, mi, se))


def generate(rnd):
    tag = rnd.choice([0x17, 0x17, 0x18, 0x18, 0x18, 0x02, 0x13])
    good = rnd.random() < 0.5   # half the fields drawn from valid values, so both answers are reached often
    y = rnd.choice(["2026", "2024", "2000", "2049", "1950"] if good else ["2100", "1900", "0000", "0001", "9999"])
    mo = rnd.choice(["01", "02", "04", "12", "10"] if good else ["00", "13", "99", "02", "04"])
    d = rnd.choice(["01", "15", "28"] if good else ["29", "30", "31", "00", "32"])
    h = rnd.choice(["00", "12", "23"] if good else ["00", "23", "24", "99"])
    mi = rnd.choice(["00", "30", "59"] if good else ["00", "59", "60"])
    se = rnd.choice(["00", "30", "59"] if good else ["00", "59", "60", "61", "99"])
    s = (y[2:] if tag == 0x17 and rnd.random() < 0.9 else y) + mo + d + h + mi + se
    raw = s.encode() + (b"Z" if good else rnd.choice([b"Z", b"Z", b"Z", b"z", b"", b"+0100", b".5Z", b" Z", b"Z\x00"]))
    r = rnd.random()
    if r < 0.05:
        raw = raw.replace(b"1", "١".encode(), 1)   # ARABIC-INDIC DIGIT ONE, UTF-8
    elif r < 0.08:
        raw = raw[:3] + b"\xff" + raw[4:]
    elif r < 0.10:
        raw = raw[:-2]
    return raw, tag


CASES = [generate(random.Random(20261118 + i)) for i in range(4000)] + [
    (b"261321000000Z", 0x17), (b"20261321000000Z", 0x18), (b"261021000000Z", 0x17), (b"20240229000000Z", 0x18),
    (b"20250229000000Z", 0x18), (b"19000229000000Z", 0x18), (b"20001231235960Z", 0x18), (b"", 0x18), (b"\xff" * 15, 0x18)]


def py(raw, tag):
    try:
        return int(NB._gtime(raw, tag).timestamp())
    except NB.PulseError as e:
        return "PulseError:" + str(e)


class Times(unittest.TestCase):
    def test_generator_reaches_both_answers(self):
        got = [oracle(r, t) for r, t in CASES]
        self.assertGreater(sum(x is not None for x in got), 300)
        self.assertGreater(sum(x is None for x in got), 1500)

    def test_generated_times_python(self):
        for raw, tag in CASES:
            want = oracle(raw, tag)
            self.assertEqual(py(raw, tag), want if want is not None else "PulseError:certificate_time", (raw, tag))

    @unittest.skipUnless(NODE, "needs node")
    def test_generated_times_js(self):
        d = tempfile.mkdtemp(prefix="ap2nbt_")
        try:
            with open(JS, encoding="utf-8") as f:
                src = f.read()
            with open(os.path.join(d, "m.mjs"), "w", encoding="utf-8") as f:
                f.write(src + "\nexport { nbTime as __nbTime, PulseError as __PulseError };\n")
            with open(os.path.join(d, "in.json"), "w", encoding="utf-8") as f:
                json.dump([[base64.b64encode(r).decode(), t] for r, t in CASES], f)
            with open(os.path.join(d, "run.mjs"), "w", encoding="utf-8") as f:
                f.write('import { __nbTime, __PulseError } from "./m.mjs";\nimport { readFileSync } from "node:fs";\n'
                        'const out = JSON.parse(readFileSync(process.argv[2], "utf8")).map(([b, t]) => {\n'
                        '  try { return __nbTime(Buffer.from(b, "base64"), t) / 1000; }\n'
                        '  catch (e) { return e instanceof __PulseError ? "PulseError:" + e.message : "other:" + e; } });\n'
                        'process.stdout.write(JSON.stringify(out));\n')
            p = subprocess.run([NODE, os.path.join(d, "run.mjs"), os.path.join(d, "in.json")], capture_output=True,
                               text=True, cwd=d, encoding="utf-8")
            self.assertEqual(p.returncode, 0, p.stderr[-800:])
            for (raw, tag), got in zip(CASES, json.loads(p.stdout)):
                want = oracle(raw, tag)
                self.assertEqual(got, want if want is not None else "PulseError:certificate_time", (raw, tag))
        finally:
            shutil.rmtree(d, ignore_errors=True)


def _month13(pem: str) -> str:
    der = bytearray(base64.b64decode("".join(ln for ln in pem.splitlines() if "-----" not in ln)))
    i = der.find(b"\x17\x0d")   # notBefore, a UTCTime
    assert i > 0 and oracle(bytes(der[i + 2:i + 15]), 0x17) is not None
    der[i + 4:i + 6] = b"13"
    b = base64.b64encode(bytes(der)).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[j:j + 64] for j in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


class Packs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2nbp_")
        cls.ctl = os.path.join(cls.d, "ctl.json")
        A.build_evidence([{"name": "payment", "sd_jwt": T.mandate()}], cls.ctl, tsa_url=None, not_before=T.block())
        with open(cls.ctl, encoding="utf-8") as f:
            ev = json.load(f)
        ev["not_before"]["pulses"]["certificate"] = _month13(ev["not_before"]["pulses"]["certificate"])
        cls.bad = os.path.join(cls.d, "month13.json")
        T.reseal(cls.bad, ev)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _py_cli(self, path):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        return subprocess.run([sys.executable, "-B", os.path.join(ROOT, "ap2_evidence.py"), "verify", path],
                              capture_output=True, text=True, env=env, encoding="utf-8")

    def test_control_verifies(self):
        p = self._py_cli(self.ctl)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertTrue(json.loads(p.stdout)["valid"])

    def test_month_13_pack_python_cli(self):
        p = self._py_cli(self.bad)
        self.assertNotIn("Traceback", p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(p.returncode, 1)
        self.assertFalse(r["valid"])
        self.assertIn("certificate_time", json.dumps(r))

    def test_month_13_block_refused_at_build(self):
        nb = T.block()
        nb["pulses"]["certificate"] = _month13(nb["pulses"]["certificate"])
        with self.assertRaisesRegex(A.Ap2EvidenceError, "certificate_time"):
            A.build_evidence([{"name": "payment", "sd_jwt": T.mandate()}], os.path.join(self.d, "x.json"), tsa_url=None,
                             not_before=nb)

    @unittest.skipUnless(NODE, "needs node")
    def test_month_13_pack_js_cli(self):
        p = subprocess.run([NODE, JS, self.bad], capture_output=True, text=True, encoding="utf-8")
        r = json.loads(p.stdout)
        self.assertEqual(p.returncode, 1, p.stderr[-800:])
        self.assertFalse(r["valid"])
        self.assertIn("certificate_time", json.dumps(r))

    def test_leap_second_proven_time(self):
        with open(self.ctl, encoding="utf-8") as f:
            ev = json.load(f)
        r = A.verify_evidence(self.ctl)
        for proven, want in (("20991231235959Z", "verified"), ("20991231235959.5Z", "verified"),
                             ("20991231235960Z", "not_evaluated:verified_time_not_a_time"),
                             ("20991231235961.25Z", "not_evaluated:verified_time_not_a_time"),
                             ("20001231235959Z", "failed:window_inverted")):
            got = A.check_not_before(ev["not_before"], ev, r["artifacts"], proven)["checks"]["NB3"]
            self.assertEqual(got, want, proven)

    @unittest.skipUnless(NODE, "needs node")
    def test_leap_second_proven_time_js(self):
        # the JS verifier never has a TSA-verified genTime (no openssl); its window rule is still the same function
        d = tempfile.mkdtemp(prefix="ap2nbl_")
        try:
            with open(JS, encoding="utf-8") as f:
                src = f.read()
            with open(os.path.join(d, "m.mjs"), "w", encoding="utf-8") as f:
                f.write(src.replace('if (process.argv[1] && /ap2-verify\\.mjs$/', 'if (false && /x/') +
                        "\nexport { checkNotBefore as __cnb, verifyEvidence as __ve };\n")
            with open(os.path.join(d, "run.mjs"), "w", encoding="utf-8") as f:
                f.write('import { __cnb, __ve } from "./m.mjs";\nimport { readFileSync } from "node:fs";\n'
                        'const ev = JSON.parse(readFileSync(process.argv[2], "utf8")); const r = __ve(process.argv[2]);\n'
                        'process.stdout.write(JSON.stringify(["20991231235959Z", "20991231235960Z", "20001231235959Z"]'
                        '.map((t) => __cnb(ev.not_before, ev, r.artifacts, t).checks.NB3)));\n')
            p = subprocess.run([NODE, os.path.join(d, "run.mjs"), self.ctl], capture_output=True, text=True, cwd=d, encoding="utf-8")
            self.assertEqual(p.returncode, 0, p.stderr[-800:])
            self.assertEqual(json.loads(p.stdout), ["verified", "not_evaluated:verified_time_not_a_time",
                                                    "failed:window_inverted"])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
