#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.0: `ap2-evidence -h` / `--help` alone prints the commands and their options on stdout, exit 0; no argument at all
is a usage error naming the commands, exit 2; after a command -h/--help stays a usage error (the grammar of `verify` is
shared with the JavaScript verifier). Measured on the PyPI wheel 1.8.0 (2026-11-18): `ap2-evidence --help` answered
"error: unexpected argument", exit 2, and no help existed anywhere. On the previous commit test_help_alone fails."""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))


def cli(*args):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, "-B", os.path.join(ROOT, "ap2_evidence.py"), *args], capture_output=True,
                          text=True, env=env)


class Help(unittest.TestCase):
    def test_help_alone(self):
        for flag in ("-h", "--help"):
            p = cli(flag)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stderr, "")
            for word in ("usage: ap2-evidence", "ap2-evidence build", "ap2-evidence stamp", "ap2-evidence verify",
                         "ap2-evidence restriction", "--trust-anchor", "--tsa-cert", "--key", "--min-anchors"):
                self.assertIn(word, p.stdout, (flag, word))

    def test_no_argument_names_the_commands(self):
        p = cli()
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, "")
        self.assertIn("build, stamp, verify or restriction", p.stderr)

    def test_help_after_a_command_stays_a_usage_error(self):
        for args in (("verify", "--help"), ("verify", "-h"), ("build", "-h"), ("-h", "verify"), ("--help", "--help")):
            p = cli(*args)
            self.assertEqual(p.returncode, 2, args)
            self.assertEqual(p.stdout, "", args)


if __name__ == "__main__":
    unittest.main()
