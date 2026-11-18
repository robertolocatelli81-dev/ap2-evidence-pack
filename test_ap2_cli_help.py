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

    def test_help_lists_the_1_9_0_option(self):
        self.assertIn("--require-binding", cli("--help").stdout)

    def test_help_that_cannot_be_written_is_74(self):
        """The help goes through the receipt's writer: stdout on /dev/full or closed is exit 74 (EX_IOERR), never 0 with
        nothing written (measured on the first 1.9.0 draft, which used print(): exit 0 in both cases). A lost stderr does
        not matter to the help: exit 0, the text on stdout."""
        env = dict(os.environ); env.pop("PYTHONPATH", None)
        cmd = [sys.executable, "-B", os.path.join(ROOT, "ap2_evidence.py"), "--help"]
        if os.path.exists("/dev/full"):
            with open("/dev/full", "wb") as full:
                p = subprocess.run(cmd, stdout=full, stderr=subprocess.PIPE, env=env)
            self.assertEqual(p.returncode, 74, p.stderr)
            self.assertIn(b"help not written", p.stderr)
            with open("/dev/full", "wb") as full:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=full, env=env)
            self.assertEqual(p.returncode, 0)
            self.assertIn(b"usage: ap2-evidence", p.stdout)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, preexec_fn=lambda: os.close(1))
        self.assertEqual(p.returncode, 74, p.stderr)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, preexec_fn=lambda: os.close(2))
        self.assertEqual(p.returncode, 0)
        self.assertIn(b"usage: ap2-evidence", p.stdout)

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
