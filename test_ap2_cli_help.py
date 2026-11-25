#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.0: `ap2-evidence -h` / `--help` alone prints the commands and their options on stdout, exit 0; no argument at all
is a usage error naming the commands, exit 2; after a command -h/--help stays a usage error (the grammar of `verify` is
shared with the JavaScript verifier). Measured on the PyPI wheel 1.8.0 (2026-11-18): `ap2-evidence --help` answered
"error: unexpected argument", exit 2, and no help existed anywhere. On the previous commit test_help_alone fails."""
import os
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))


def cli(*args):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, "-B", os.path.join(ROOT, "ap2_evidence.py"), *args], capture_output=True,
                          text=True, env=env, encoding="utf-8")



def _closed(cmd, fd, env):
    """Run cmd with descriptor `fd` (1 or 2) closed at its start. POSIX: os.close in the child before exec. Windows has no
    preexec_fn (1.11.0); the equivalent is Git's bash closing it before it starts the program (`exec "$@" >&-`), which then
    starts with no handle there (sys.stdout or sys.stderr None)."""
    if os.name != "nt":
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, preexec_fn=lambda: os.close(fd))
    bash = shutil.which("bash")   # PATH's bash (Git's): System32's bash.exe is the WSL launcher
    return subprocess.run([bash, "-c", 'exec "$@" %d>&-' % fd, "_"] + [c.replace("\\", "/") for c in cmd],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

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
        from _ap2_platform import full_sink   # 1.11.0: /dev/full, or a file on a full volume (macOS, Windows)
        sink = full_sink()
        if sink is not None:
            with open(sink, "wb") as full:
                p = subprocess.run(cmd, stdout=full, stderr=subprocess.PIPE, env=env)
            self.assertEqual(p.returncode, 74, p.stderr)
            self.assertIn(b"help not written", p.stderr)
            with open(sink, "wb") as full:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=full, env=env)
            self.assertEqual(p.returncode, 0)
            self.assertIn(b"usage: ap2-evidence", p.stdout)
        p = _closed(cmd, 1, env)
        self.assertEqual(p.returncode, 74, p.stderr)
        p = _closed(cmd, 2, env)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b"usage: ap2-evidence", p.stdout)

    def test_every_option_with_a_value_refuses_a_flag_like_value(self):
        """One CLI grammar (1.1.0): a value that is empty or starts with "-" is a usage error, in the `--opt value` and
        the `--opt=value` form. The options with a value are read from the parsers themselves, so one added later is
        asked the same (found on 2026-11-18: --require-binding was missing from the pre-check, and `--require-binding=-x->y`
        was read as a pair, exit 1, where the JavaScript verifier said usage, exit 2)."""
        import re
        text = cli("--help").stdout
        found = set()
        for cmd in ("build", "stamp", "verify", "restriction"):
            block = text.split("usage: ap2-evidence " + cmd, 1)[1].split("usage: ap2-evidence ", 1)[0]
            usage = block.split("\n\n", 1)[0]
            for opt in re.findall(r"(--[a-z-]+) [A-Za-z]", usage):   # in a usage line, an option followed by its metavar
                found.add((cmd, opt))
        self.assertEqual(sorted({o for _c, o in found}),
                         ["--jwks-url", "--key", "--min-anchors", "--require-binding", "--subject", "--trust-anchor",
                          "--trusted-producer-key", "--tsa", "--tsa-cert"], found)
        for cmd, opt in sorted(found):
            for args in ([opt, "-x"], [opt + "=-x"], [opt, ""], [opt + "="], [opt], [opt, "--require-pq"], [opt + "=-a->b"]):
                with self.subTest(cmd=cmd, args=args):
                    p = cli(cmd, "x.json", *args)
                    self.assertEqual((p.returncode, p.stdout), (2, ""), p.stderr[-200:])

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

    def test_a_path_that_names_no_file_is_two_lines_on_stderr(self):
        """SPEC §3.1 (1.11.1): a message on stderr, nothing on stdout. The reference writes its usage and the reason; up to
        1.11.0 the SPEC said one line. Two lines at 80 columns, the width argparse takes when COLUMNS is not set and
        stderr is not a terminal; in a narrower one it wraps the usage (at 40 columns: three or four lines, by Python)."""
        from unittest import mock
        missing = os.path.join(ROOT, "no-such-file.json")
        for args in (("verify", missing), ("restriction", missing)):
            with mock.patch.dict(os.environ, {"COLUMNS": "80"}):
                p = cli(*args)
            self.assertEqual((p.returncode, p.stdout), (2, ""), args)
            lines = p.stderr.splitlines()
            self.assertEqual(len(lines), 2, p.stderr)
            self.assertTrue(lines[0].startswith("usage: ") and lines[1].startswith("ap2-evidence: error: "), p.stderr)
            with mock.patch.dict(os.environ, {"COLUMNS": "40"}):
                narrow = cli(*args)
            self.assertEqual((narrow.returncode, narrow.stdout), (2, ""), args)
            self.assertGreater(len(narrow.stderr.splitlines()), 2, narrow.stderr)   # the count is the width's, not the format's


if __name__ == "__main__":
    unittest.main()
