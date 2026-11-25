#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""A receipt that was not written whole is exit 74 (EX_IOERR), never the verdict's 0/1 (1.5.2).

Measured on 1.5.1 (2026-10-12): with stdout on /dev/full or on a pipe whose reader had gone, `ap2_evidence.py` exited 120
("Exception ignored" from the interpreter's final flush, a code no contract names) for the vectors' receipts and 1 with a
traceback for a receipt larger than the stream buffer (a valid pack included), and with stdout closed (`>&-`) it exited
0 or 1 with nothing on stderr; the Node verifier exited 0 or 1 with nothing on stderr on /dev/full and on the closed pipe;
`build` into a path it cannot write raised a traceback (exit 1, the "not valid" code). Every case here runs the real CLI in
a child process with a real file descriptor: /dev/full (ENOSPC), a pipe whose read end is already closed (EPIPE), fd 1
closed before exec, and a regular file as the control (verdict code and receipt unchanged)."""
import errno
import hashlib
import http.server
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ap2_evidence as ap2  # noqa: E402

_PY = [sys.executable, os.path.join(_HERE, "ap2_evidence.py")]
_NODE = shutil.which("node")
_JS = os.path.join(_HERE, "verifiers", "js", "ap2-verify.mjs")
_VEC = os.path.join(_HERE, "spec", "vectors", "ap2")
_VALID = os.path.join(_VEC, "anchor_valid.json")
_INVALID = os.path.join(_VEC, "digest_mismatch.json")
_OPENSSL = shutil.which("openssl")
from _ap2_platform import full_sink, NO_FULL  # noqa: E402  (1.11.0: /dev/full, or a full volume on macOS/Windows)
import _ap2_platform as P  # noqa: E402  (1.11.0: closed descriptors, RLIMIT_NPROC, CPU time: each system's equivalent)
_WIN = os.name == "nt"
_CUT = b"No space left on device" if _WIN else b"File too large"   # the full volume (Windows) for RLIMIT_FSIZE
_FULL = full_sink()
_DEVFULL = _FULL is not None


def _run(cmd, mode, cwd=None, stderr_mode="capture"):
    """Run cmd with stdout in `mode`: "file" (a regular file), "devfull" (/dev/full), "pipe" (a pipe whose read end is
    closed before the child starts: EPIPE on the first write), "closed" (fd 1 closed before exec). Returns
    (exit code, bytes on stdout in "file" mode else None, stderr bytes)."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        stdout, close, close_after = out, [], None
        if mode == "devfull":
            stdout = close_after = open(full_sink(), "wb")
        elif mode == "pipe":
            r, w = os.pipe()
            os.close(r)
            stdout = close_after = os.fdopen(w, "wb")
        elif mode == "closed":
            stdout = None
            close.append(1)
        se = err
        if stderr_mode == "devfull":
            se = open(full_sink(), "wb")
        elif stderr_mode == "closed":   # fd 2 closed before exec
            se = None
            close.append(2)
        try:   # 1.11.0: P.run closes them in a preexec_fn on POSIX, through Git's bash on Windows
            p = P.run(cmd, close=tuple(close), stdin=subprocess.DEVNULL, stdout=stdout, stderr=se, cwd=cwd, timeout=300)
        finally:
            if close_after is not None:
                close_after.close()
            if se is not err and se is not None:
                se.close()
        out.seek(0)
        err.seek(0)
        return p.returncode, (out.read() if mode == "file" else None), err.read()


@unittest.skipUnless(_DEVFULL, "a full device (" + NO_FULL + ")")
class TestPythonVerify(unittest.TestCase):
    def test_file_mode_is_the_control(self):   # verdict code and the receipt byte for byte, as before 1.5.2
        for path, code in ((_VALID, 0), (_INVALID, 1)):
            rc, out, err = _run(_PY + ["verify", path], "file")
            self.assertEqual(rc, code, err)
            self.assertEqual(out, (json.dumps(ap2.verify_evidence(path), indent=1) + "\n").encode("ascii"))
            self.assertEqual(err, b"")

    def test_lost_receipt_is_74_with_one_line_on_stderr(self):
        # Windows: a write to a pipe whose reader is gone is ERROR_NO_DATA, which CPython reports as EINVAL there
        for mode, why in (("devfull", b"No space left on device"), ("pipe", b"Invalid argument" if _WIN else b"Broken pipe"),
                          ("closed", b"stdout is closed")):
            for path in (_VALID, _INVALID):
                with self.subTest(mode=mode, input=os.path.basename(path)):
                    rc, _, err = _run(_PY + ["verify", path], mode)
                    self.assertEqual(rc, 74, err)
                    self.assertTrue(err.startswith(b"receipt not written: "), err)
                    self.assertIn(why, err)
                    self.assertEqual(err.count(b"\n"), 1, err)   # one line, no "Exception ignored", no traceback

    def test_stderr_failing_too_is_still_74(self):
        for mode in ("devfull", "pipe", "closed"):
            for emode in ("devfull", "closed"):
                with self.subTest(mode=mode, stderr=emode):
                    rc, _, _ = _run(_PY + ["verify", _VALID], mode, stderr_mode=emode)
                    self.assertEqual(rc, 74)

    def test_receipt_over_64_kib_reaches_a_slow_reader_whole(self):   # the flush must not cut what a pipe delivers late
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(_VEC, "anchors_unknown_key.json"), encoding="utf-8") as f:
                ev = json.load(f)
            ev["x" * 100000] = 1
            p = os.path.join(d, "ev.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(ev, f)
            prod = subprocess.Popen(_PY + ["verify", p], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            cat = subprocess.Popen(["sh", "-c", "sleep 0.5; exec cat"], stdin=prod.stdout, stdout=subprocess.PIPE)
            prod.stdout.close()
            raw, _ = cat.communicate(timeout=120)
            self.assertEqual(prod.wait(timeout=120), 1)
            self.assertGreater(len(raw), 65536)
            self.assertIs(json.loads(raw.decode("utf-8"))["valid"], False)
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(_NODE and _DEVFULL, "node and a full device (" + NO_FULL + ")")
class TestJsVerify(unittest.TestCase):
    def test_file_mode_is_the_control(self):
        for path, code in ((_VALID, 0), (_INVALID, 1)):
            rc, out, err = _run([_NODE, _JS, path], "file")
            self.assertEqual(rc, code, err)
            self.assertIs(json.loads(out.decode("utf-8"))["valid"], code == 0)
            self.assertEqual(out, subprocess.run([_NODE, _JS, path], capture_output=True).stdout)
            self.assertEqual(err, b"")

    def test_lost_receipt_is_74_with_one_line_on_stderr(self):
        for mode, why in (("devfull", b"ENOSPC"), ("pipe", b"EPIPE")):
            for path in (_VALID, _INVALID):
                with self.subTest(mode=mode, input=os.path.basename(path)):
                    rc, _, err = _run([_NODE, _JS, path], mode)
                    self.assertEqual(rc, 74, err)
                    self.assertEqual(err, b"receipt not written: " + why + b"\n")

    def test_stderr_failing_too_is_still_74(self):
        for mode in ("devfull", "pipe"):
            with self.subTest(mode=mode):
                rc, _, _ = _run([_NODE, _JS, _VALID], mode, stderr_mode="devfull")
                self.assertEqual(rc, 74)

    def test_usage_with_stderr_full_is_74_and_with_stderr_closed_is_2(self):
        # 1.5.2 review: console.error dropped ENOSPC and exited 2 (the Python CLI: 120 on 1.5.1). Closed stderr: Node
        # reopens fd 2 on /dev/null (the same limit as a closed stdout), so the usage exit 2 stays.
        for args in ([], ["--bogus", _VALID]):
            with self.subTest(args=args):
                self.assertEqual(_run_err([_NODE, _JS] + args, "full"), (74, b""))
                self.assertEqual(_run_err([_NODE, _JS] + args, "closed"), (2, b""))
                rc, out, err = _run([_NODE, _JS] + args, "file")
                self.assertEqual((rc, out), (2, b"")); self.assertTrue(err.startswith(b"usage: "), err)

    def test_closed_stdout_is_not_visible_to_node(self):
        # the README's stated limit: Node reopens a closed fd 1 on /dev/null, so the write succeeds and the exit is the
        # verdict's. If a Node release changes that, this test goes red and the README sentence has to change with it.
        for path, code in ((_VALID, 0), (_INVALID, 1)):
            rc, _, err = _run([_NODE, _JS, path], "closed")
            self.assertEqual((rc, err), (code, b""))


def _big_valid_pack(d):
    """valid_signed's two mandates copied 200 times under new names, re-sealed: a VALID pack whose receipt is ~84 KB."""
    import test_js_receipt_pipe as T
    cls = [c for c in vars(T).values() if isinstance(c, type) and issubclass(c, unittest.TestCase)][0]
    t = cls("test_valid_receipt_over_64_kib_is_whole_and_exits_0")
    t.setUp()
    try:
        p = os.path.join(d, "big_valid.json")
        shutil.copy(t._valid_with_copies(200), p)
        return p
    finally:
        t.tearDown()


class TestShortWriteToAFile(unittest.TestCase):   # 1.11.0: Windows, without RLIMIT_FSIZE, writes to a full volume instead
    """1.5.2 review: stdout on a regular file that stops growing (RLIMIT_FSIZE, as `ulimit -f 4`): Node wrote 4 096 bytes of
    the receipt and exited 0 (no error reported); it must be 74 with the reason, as the Python CLI (EFBIG, "File too large")."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_fsz_")
        cls.big = _big_valid_pack(cls.d)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _run_limited(self, cmd, limit):
        if limit is not None and _WIN:   # a file that cannot grow: on a full volume (ENOSPC), Windows' equivalent
            o = P.full_volume_with(self, "short")
            with open(o, "wb") as out, tempfile.TemporaryFile() as err:
                p = P.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=300)
                err.seek(0)
                e = err.read()
            with open(o, "rb") as f:
                return p.returncode, f.read(), e
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            p = P.run(cmd, fsize=limit, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=300)
            out.seek(0); err.seek(0)
            return p.returncode, out.read(), err.read()

    def _check(self, cmd, why):
        rc, out, err = self._run_limited(cmd, None)   # the control: the whole receipt, exit 0
        self.assertEqual((rc, err), (0, b""))
        self.assertIs(json.loads(out.decode("utf-8"))["valid"], True)
        self.assertGreater(len(out), 4096)
        rc, out, err = self._run_limited(cmd, 4096)
        self.assertEqual(rc, 74, err)
        self.assertLessEqual(len(out), 4096)
        self.assertTrue(err.startswith(b"receipt not written: ") and why in err and err.count(b"\n") == 1, err)

    def test_python(self):
        self._check(_PY + ["verify", self.big], _CUT)

    @unittest.skipUnless(_NODE, "node needed")
    def test_js(self):
        self._check([_NODE, _JS, self.big], b"ENOSPC" if _WIN else b"EFBIG")


class _Tsa:
    """A local RFC 3161 TSA (openssl ts -reply) behind a local HTTP server; "html" answers a 503 page instead."""

    CNF = ("[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {d}/serial\ncrypto_device = builtin\nsigner_cert = {d}/tsa.crt\n"
           "certs = {d}/ca.crt\nsigner_key = {d}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\n"
           "accuracy = secs:1\nordering = yes\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n"
           "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n")

    def __init__(self):
        self.d = d = tempfile.mkdtemp(prefix="tsa_")
        j = lambda n: os.path.join(d, n)  # noqa: E731
        with open(j("tsa.cnf"), "w", encoding="utf-8") as f:
            f.write(self.CNF.format(d=d.replace("\\", "/")))  # OpenSSL reads a backslash in a .cnf as an escape: Windows paths with forward slashes (1.11.0)
        with open(j("serial"), "w", encoding="utf-8") as f:
            f.write("01\n")
        ssl = lambda *a: subprocess.run([_OPENSSL] + list(a), check=True, capture_output=True)  # noqa: E731
        ssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("ca.key"),
            "-out", j("ca.crt"), "-subj", "/CN=test-ca", "-days", "2")
        ssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
            "-out", j("tsa.csr"), "-subj", "/CN=test-tsa")
        ssl("x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
            "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")
        lock = threading.Lock()

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                q = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/html":
                    body = b"<html><body>503 Service Unavailable</body></html>"
                else:
                    with lock:
                        with open(j("q.tsq"), "wb") as f:
                            f.write(q)
                        ssl("ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1", "-out", j("r.tsr"))
                        with open(j("r.tsr"), "rb") as f:
                            body = f.read()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.d, ignore_errors=True)


@unittest.skipUnless(_DEVFULL, "a full device (" + NO_FULL + ")")
class TestBuildAndStamp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_74_")
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=cls.d, check=True,
                       capture_output=True)
        with open(os.path.join(cls.d, "not_sdjwt.txt"), "w", encoding="utf-8") as f:
            f.write("this is not an SD-JWT\n")
        cls.tsa = _Tsa() if _OPENSSL else None

    @classmethod
    def tearDownClass(cls):
        if cls.tsa:
            cls.tsa.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def _build(self, out, mode, art="checkout=checkout.sdjwt"):
        return _run(_PY + ["build", out, art, "payment=payment.sdjwt"], mode, cwd=self.d)

    def test_build_file_mode_is_the_control(self):
        out = os.path.join(self.d, "ctl.json")
        rc, raw, err = self._build(out, "file")
        self.assertEqual((rc, err), (0, b""))
        r = json.loads(raw.decode("ascii"))
        with open(out, encoding="utf-8") as f:
            self.assertEqual(r["evidence_digest_sha256"], json.load(f)["evidence_digest_sha256"])
        self.assertTrue(ap2.verify_evidence(out)["valid"])

    def test_build_lost_receipt_is_74(self):
        for mode in ("devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                rc, _, err = self._build(os.path.join(self.d, "b_%s.json" % mode), mode)
                self.assertEqual(rc, 74, err)
                self.assertTrue(err.startswith(b"receipt not written: ") and err.count(b"\n") == 1, err)

    def test_build_refused_stays_1_in_every_mode(self):   # the refusal goes to stderr: nothing on stdout to lose
        for mode in ("file", "devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                rc, raw, err = self._build(os.path.join(self.d, "r.json"), mode, art="checkout=not_sdjwt.txt")
                self.assertEqual(rc, 1, err)
                self.assertIn(b'"error"', err)
                if mode == "file":
                    self.assertEqual(raw, b"")

    def test_the_write_error_is_an_ap2_error_and_an_oserror(self):   # CHANGELOG 1.5.2: both, for callers of either
        self.assertTrue(issubclass(ap2.Ap2WriteError, ap2.Ap2EvidenceError))
        self.assertTrue(issubclass(ap2.Ap2WriteError, OSError))
        with self.assertRaises(ap2.Ap2WriteError):
            ap2.build_evidence([{"name": "checkout", "sd_jwt": open(os.path.join(self.d, "checkout.sdjwt"), encoding="utf-8").read().strip()}],
                               os.path.join(self.d, "no_such_dir", "x.json"))

    def test_build_into_a_pack_path_it_cannot_write_is_74(self):
        for out in [x for x in (os.path.join(self.d, "no_such_dir", "ev.json"), _FULL) if x]:
            with self.subTest(out=out):
                rc, raw, err = self._build(out, "file")
                self.assertEqual(rc, 74, err)
                self.assertEqual(raw, b"")   # no receipt claiming a pack that is not there
                self.assertTrue(err.startswith(b"receipt not written: cannot write the pack ") and err.count(b"\n") == 1, err)

    def _pack(self, name):
        out = os.path.join(self.d, name)
        rc, _, err = self._build(out, "file")
        self.assertEqual(rc, 0, err)
        return out

    def _anchors(self, path):
        with open(path, encoding="utf-8") as f:
            return len(json.load(f).get("anchors", []))

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_file_mode_is_the_control(self):
        p = self._pack("s_ctl.json")
        rc, raw, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url], "file")
        self.assertEqual((rc, err), (0, b""))
        self.assertEqual(json.loads(raw.decode("ascii"))["anchors"], 1)
        self.assertEqual(self._anchors(p), 1)

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_lost_receipt_is_74_and_the_pack_holds_the_anchor(self):
        for mode in ("devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                p = self._pack("s_%s.json" % mode)
                rc, _, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url], mode)
                self.assertEqual(rc, 74, err)
                self.assertTrue(err.startswith(b"receipt not written: ") and err.count(b"\n") == 1, err)
                self.assertEqual(self._anchors(p), 1)   # the CHANGELOG says so: the pack was stamped, the receipt was lost
                self.assertTrue(ap2.verify_evidence(p, require_anchor=True, min_anchors=1)["valid"])

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_refused_stays_1_in_every_mode(self):
        p = self._pack("s_ref.json")
        with open(p, "rb") as f:
            before = hashlib.sha256(f.read()).hexdigest()
        for mode in ("file", "devfull", "pipe", "closed"):
            with self.subTest(mode=mode):
                rc, _, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url + "html"], mode)
                self.assertEqual(rc, 1, err)
                self.assertIn(b"no anchor obtained", err)
        with open(p, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), before)

    @unittest.skipUnless(_OPENSSL, "openssl absent: no local TSA")
    def test_stamp_into_a_directory_it_cannot_write_is_74_and_the_pack_is_unchanged(self):
        sub = os.path.join(self.d, "ro")
        os.mkdir(sub)
        p = os.path.join(sub, "ev.json")
        shutil.copy(self._pack("s_ro_src.json"), p)
        with open(p, "rb") as f:
            before = f.read()
        P.deny_writes_in(self, sub)   # 1.11.0: mode 0555, or a deny ACE on Windows
        rc, raw, err = _run(_PY + ["stamp", p, "--tsa", self.tsa.url], "file")
        self.doCleanups()
        self.assertEqual(rc, 74, err)
        self.assertEqual(raw, b"")
        self.assertTrue(err.startswith(b"receipt not written: cannot write the stamped pack") and err.count(b"\n") == 1, err)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), before)


def _run_err(cmd, emode, cwd=None):
    """stdout on a regular file, stderr "full" (/dev/full) or "closed" (fd 2 closed before exec)."""
    with tempfile.TemporaryFile() as out:
        se, close = None, ()
        if emode == "full":
            se = open(full_sink(), "wb")
        else:
            close = (2,)
        try:
            p = P.run(cmd, close=close, stdin=subprocess.DEVNULL, stdout=out, stderr=se, cwd=cwd, timeout=300)
        finally:
            if se is not None:
                se.close()
        out.seek(0)
        return p.returncode, out.read()


@unittest.skipUnless(_DEVFULL, "a full device (" + NO_FULL + ")")
class TestStderrLost(unittest.TestCase):
    """1.5.2 review: a usage message or a refusal that cannot reach stderr is EX_IOERR (74), never the interpreter's 120
    (stderr full) and never on stdout (stderr closed: argparse and print() fell back to stdout, exit 1 or 2)."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_74e_")
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=cls.d, check=True,
                       capture_output=True)
        with open(os.path.join(cls.d, "not_sdjwt.txt"), "w", encoding="utf-8") as f:
            f.write("this is not an SD-JWT\n")
        cls.bad = os.path.join(cls.d, "bad_digest.json")   # stamp refuses it before any TSA is asked
        shutil.copy(_INVALID, cls.bad)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_usage_and_refusal_with_stderr_lost_are_74_and_stdout_stays_empty(self):
        # 1.9.0: `-h` alone is the help, on stdout (test_ap2_cli_help.py); after a command it is still a usage error
        cases = (["verify"], ["verify", "--bogus", "x"], ["verify", "-h"], [],
                 ["build", os.path.join(self.d, "r.json"), "checkout=not_sdjwt.txt", "payment=payment.sdjwt"],
                 ["stamp", self.bad, "--tsa", "http://127.0.0.1:9/"])
        for emode in ("full", "closed"):
            for args in cases:
                with self.subTest(stderr=emode, args=args):
                    rc, out = _run_err(_PY + args, emode, cwd=self.d)
                    self.assertEqual((rc, out), (74, b""))

    def test_control_stderr_lost_with_nothing_to_say_keeps_the_verdict(self):
        for emode in ("full", "closed"):
            for path, code in ((_VALID, 0), (_INVALID, 1)):
                with self.subTest(stderr=emode, input=os.path.basename(path)):
                    rc, out = _run_err(_PY + ["verify", path], emode)
                    self.assertEqual(rc, code)
                    self.assertEqual(json.loads(out.decode("ascii"))["valid"], code == 0)

    def test_control_usage_and_refusal_codes_with_a_working_stderr(self):
        rc, out, err = _run(_PY + ["verify"], "file")
        self.assertEqual((rc, out), (2, b"")); self.assertIn(b"usage", err)
        rc, out, err = _run(_PY + ["build", os.path.join(self.d, "r2.json"), "checkout=not_sdjwt.txt", "payment=payment.sdjwt"],
                            "file", cwd=self.d)
        self.assertEqual((rc, out), (1, b"")); self.assertTrue(err.startswith(b'{"error": '), err)
        rc, out, err = _run(_PY + ["stamp", self.bad, "--tsa", "http://127.0.0.1:9/"], "file")
        self.assertEqual((rc, out), (1, b"")); self.assertIn(b"not stamped", err)


def _cpu_seconds(pid):
    """utime + stime of a live process, all its threads: /proc on Linux, its equivalent elsewhere (P.cpu_seconds)."""
    return P.cpu_seconds(pid)


def _run_prefilled(cmd, which=1, env=None, cwd=None, other_devfull=False, other_limit=None):
    """fd `which` (1 = stdout, 2 = stderr) is a NON-BLOCKING pipe that is already full when the process starts, and
    nobody reads it for a while: the process must wait asleep, as on a blocking pipe — still alive, and in some 1-second
    window (looked at from the 1st to the 10th second, so a slow start is not taken for a spin) using under 0.2 s of CPU,
    which a loop retrying EAGAIN never does — and once the pipe is drained what it had to say must arrive whole. The other
    stream goes to a regular file (or /dev/full). Returns (idle, rc, bytes after the filler or None, the other stream's bytes)."""
    r, w = os.pipe()
    P.set_nonblocking(w)   # 1.11.0: O_NONBLOCK on POSIX, PIPE_NOWAIT on Windows
    filled = 0
    while True:
        try:
            n = os.write(w, b"P" * 4096)
        except BlockingIOError:
            break
        except OSError as e:   # Windows before Python 3.12: a full PIPE_NOWAIT pipe is ENOSPC
            if not (_WIN and e.errno == errno.ENOSPC):
                raise
            break
        if not n:   # Windows: a PIPE_NOWAIT pipe that is full can take 0 bytes instead of raising
            break
        filled += n
    other = tempfile.TemporaryFile()
    if _WIN and other_limit is not None:   # no per-process file-size limit there: the full volume is its equivalent
        other_devfull, other_limit = True, None
    dest = open(full_sink(), "wb") if other_devfull else other
    try:   # other_limit: the other stream is a regular file that stops growing at that many bytes
        p = P.popen(cmd, fsize=other_limit, stdin=subprocess.DEVNULL, stdout=w if which == 1 else dest,
                    stderr=w if which == 2 else dest, cwd=cwd, env=dict(os.environ, **(env or {})))
    finally:
        os.close(w)
        if dest is not other:
            dest.close()
    idle, t0 = False, time.time()
    time.sleep(1.0)
    while p.poll() is None and time.time() - t0 < 10:
        try:
            c0 = _cpu_seconds(p.pid)
            time.sleep(1.0)
            c1 = _cpu_seconds(p.pid)
        except OSError:   # exited during the window
            break
        if p.poll() is not None:
            break
        if c1 - c0 < 0.2:
            idle = True
            break
    chunks = []
    while True:
        b = os.read(r, 1 << 16)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    rc = p.wait(timeout=120)
    other.seek(0)
    rest = other.read()
    other.close()
    data = b"".join(chunks)
    return idle, rc, (data[filled:] if data[:filled] == b"P" * filled else None), rest


class TestWholeOrWaited(unittest.TestCase):   # 1.11.0: every system (non-blocking pipes, CPU time: _ap2_platform)
    """1.5.2, second pass (13/10/2026, measured on a410964 with real processes): with PYTHONUNBUFFERED=1 (or -u) the
    receipt went to a raw FileIO whose short write the text layer dropped in silence (exit 0 or 1 with 24 bytes of it on a
    file of 1 000 bytes under `ulimit -f 1`; exit 0 through `| head -c 100` with a receipt of 84 620 bytes); a full
    non-blocking stdout read 1 s late gave 74 with 65 536 bytes in the pipe (buffered) or 0 with them (unbuffered); a
    refusal, a usage message or the "receipt not written" line on a full non-blocking stderr was lost (74, or 120 on
    1.5.1), the JS usage line too. Now every one of them is written whole or waited for."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_wow_")
        cls.big = _big_valid_pack(cls.d)
        with open(os.path.join(cls.d, "not_sdjwt.txt"), "w", encoding="utf-8") as f:
            f.write("this is not an SD-JWT\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _fsize_cut(self, cmd, env):
        """stdout appended to a file that already holds 1 000 bytes, under RLIMIT_FSIZE 1 024: 24 bytes, then EFBIG.
        Windows (1.11.0), which has no per-process file-size limit: the file on a full volume, so it cannot grow (ENOSPC)."""
        data = b"x" * 1000
        if _WIN:
            o, limit = P.full_volume_with(self, "cut", data), None
        else:
            o, limit = os.path.join(self.d, "cut"), 1024
            with open(o, "wb") as f:
                f.write(data)
        with open(o, "ab") as f, tempfile.TemporaryFile() as err:
            p = P.run(cmd, fsize=limit, stdin=subprocess.DEVNULL, stdout=f, stderr=err, env=dict(os.environ, **env), timeout=300)
            err.seek(0)
            return p.returncode, err.read()

    def test_unbuffered_short_write_is_74(self):
        u = {"PYTHONUNBUFFERED": "1"}
        for path in (_VALID, _INVALID, self.big):
            with self.subTest(input=os.path.basename(path)):
                rc, err = self._fsize_cut(_PY + ["verify", path], u)
                self.assertEqual(rc, 74, err)
                self.assertTrue(err.startswith(b"receipt not written: ") and _CUT in err and err.count(b"\n") == 1, err)
        rc, err = self._fsize_cut(_PY + ["verify", _VALID], {})   # the control: buffered was 74 already
        self.assertEqual(rc, 74, err)

    def test_unbuffered_big_receipt_to_a_reader_that_left_is_74(self):
        p = subprocess.run([shutil.which("bash"), "-c", '{ sleep 0.2; exec "$@"; } | head -c 100 >/dev/null; exit "${PIPESTATUS[0]}"', "_"]
                           + [c.replace("\\", "/") for c in _PY + ["verify", self.big]], env=dict(os.environ, PYTHONUNBUFFERED="1"),
                           stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
        self.assertEqual(p.returncode, 74, p.stderr)
        self.assertTrue(p.stderr.startswith(b"receipt not written: "), p.stderr)

    def _whole_when_drained(self, cmd, env=None):
        with tempfile.TemporaryFile() as f:
            ctl = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.DEVNULL,
                                 env=dict(os.environ, **(env or {})), timeout=300)
            f.seek(0)
            whole = f.read()
        idle, rc, got, err = _run_prefilled(cmd, 1, env)
        self.assertTrue(idle, "no 1-second window under 0.2 s of CPU: a spin, or it never waited")
        self.assertEqual((rc, err), (ctl.returncode, b""))
        self.assertEqual(got, whole)

    def test_full_non_blocking_stdout_is_waited_for_python(self):
        for env in ({}, {"PYTHONUNBUFFERED": "1"}):
            for path in (_VALID, self.big):
                with self.subTest(env=env, input=os.path.basename(path)):
                    self._whole_when_drained(_PY + ["verify", path], env)

    @unittest.skipUnless(_NODE, "node needed")
    def test_full_non_blocking_stdout_is_waited_for_js(self):   # libuv waited already: a guard
        for path in (_VALID, self.big):
            with self.subTest(input=os.path.basename(path)):
                self._whole_when_drained([_NODE, _JS, path])

    def _stderr_waited(self, cmd, code, start, stdout_devfull=False, stdout_limit=None):
        idle, rc, got, out = _run_prefilled(cmd, 2, cwd=self.d, other_devfull=stdout_devfull, other_limit=stdout_limit)
        self.assertTrue(idle, "no 1-second window under 0.2 s of CPU: a spin, or it never waited")
        self.assertEqual(rc, code, got)
        self.assertTrue(got is not None and got.startswith(start) and got.endswith(b"\n")
                        and (got.count(b"\n") == 1 or not start.startswith(b"receipt not written")), got)
        if stdout_limit is None or _WIN:   # Windows: the full volume stands for the limit, nothing gets there
            self.assertEqual(out, b"")
        else:
            self.assertEqual(len(out), stdout_limit)

    def test_full_non_blocking_stderr_is_waited_for_python(self):
        bad = os.path.join(_VEC, "digest_mismatch.json")
        self._stderr_waited(_PY + ["verify"], 2, b"usage: ")
        self._stderr_waited(_PY + ["build", os.path.join(self.d, "r.json"), "checkout=not_sdjwt.txt"], 1, b'{"error": ')
        self._stderr_waited(_PY + ["stamp", bad, "--tsa", "http://127.0.0.1:9/"], 1, b'{"error": ')
        self._stderr_waited(_PY + ["verify", _VALID], 74, b"receipt not written: ", stdout_devfull=True)

    @unittest.skipUnless(_NODE, "node needed")
    def test_full_non_blocking_stderr_is_waited_for_js(self):
        self._stderr_waited([_NODE, _JS], 2, b"usage: ")
        self._stderr_waited([_NODE, _JS, "--bogus", _VALID], 2, b"usage: ")
        self._stderr_waited([_NODE, _JS, _VALID], 74, b"receipt not written: ", stdout_devfull=True)
        # stdout a regular file that stops growing (the receipt written in a loop of writeSync, EFBIG): the line that
        # says so goes through the same loop, so a full non-blocking stderr is waited for there too
        self._stderr_waited([_NODE, _JS, self.big], 74, b"receipt not written: " + (b"ENOSPC" if _WIN else b"EFBIG"), stdout_limit=4096)

    def test_the_74_line_after_a_file_that_stops_growing_waits_for_a_full_stderr_python(self):
        self._stderr_waited(_PY + ["verify", self.big], 74, b"receipt not written: ", stdout_limit=4096)

    def test_text_the_caller_left_in_the_buffer_is_waited_for_too(self):
        """main() called in process after the caller wrote text that is still in sys.stdout's buffer, with stdout a
        non-blocking pipe that is full: the caller's text and then the receipt arrive whole once the pipe is drained, and
        the exit is the verdict's (on c2734a0 to cb36d56 the first flush sat outside the wait: exit 74, nothing written)."""
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a; sys.stdout.write('before\\n'); "
                "sys.exit(a.main(['verify', sys.argv[2]]))")
        with tempfile.TemporaryFile() as f:
            subprocess.run(_PY[:1] + [os.path.join(_HERE, "ap2_evidence.py"), "verify", _VALID], stdin=subprocess.DEVNULL,
                           stdout=f, timeout=300, check=True)
            f.seek(0)
            receipt = f.read()
        # buffered only: under -u the caller's own write goes to the raw pipe at once and Python drops it there, before
        # main() is called — not text left in the buffer
        idle, rc, got, err = _run_prefilled([sys.executable, "-c", code, _HERE, _VALID], 1)
        self.assertTrue(idle, "no 1-second window under 0.2 s of CPU: a spin, or it never waited")
        self.assertEqual((rc, err), (0, b""))
        # the caller's own line goes through its own text layer: "\r\n" on Windows (the receipt keeps "\n" everywhere)
        self.assertEqual(got, b"before" + os.linesep.encode("ascii") + receipt)

    def test_encodings_are_the_text_layers(self):
        """The receipt's bytes are the ones Python's own stdout text layer writes for the same text, in five encodings (a
        byte order mark included or not as that layer decides: utf-16 and utf-32 write one on a new file, none on a pipe or
        after bytes already in the file) and one error handler, to a new file, appended to a file and to a pipe, buffered
        and unbuffered. The reference is a second process writing the same text with sys.stdout.write."""
        text_path = os.path.join(self.d, "receipt.txt")
        with open(text_path, "w", encoding="utf-8", newline="") as f:
            f.write(json.dumps(ap2.verify_evidence(_VALID), indent=1) + "\n")
        # the reference keeps "\n" (1.11.0: so does the package, on every system; Windows' text layer would write "\r\n")
        ref = [sys.executable, "-c", "import sys; sys.stdout.reconfigure(newline='\\n'); "
               "sys.stdout.write(open(sys.argv[1], encoding='utf-8', newline='').read())", text_path]

        def out_of(argv, enc, dest, env):
            e = dict(os.environ, PYTHONIOENCODING=enc, **env)
            if dest == "pipe":
                return subprocess.run(argv, env=e, capture_output=True, timeout=120).stdout
            o = os.path.join(self.d, "o")
            with open(o, "wb") as f:
                f.write(b"PRE" if dest == "append" else b"")
            with open(o, "ab" if dest == "append" else "wb") as f:
                subprocess.run(argv, env=e, stdout=f, timeout=120)
            with open(o, "rb") as f:
                return f.read()
        for enc in ("utf-8", "utf-16", "utf-32", "utf-8-sig", "latin-1", "ascii:backslashreplace"):
            for dest in ("file", "append", "pipe"):
                for env in ({}, {"PYTHONUNBUFFERED": "1"}):
                    with self.subTest(enc=enc, dest=dest, env=env):
                        a, b = out_of(_PY + ["verify", _VALID], enc, dest, env), out_of(ref, enc, dest, env)
                        self.assertGreater(len(b), 10)
                        self.assertEqual(a, b)

    def test_in_process_streams(self):
        """main() in process with sys.stdout replaced: a StringIO (no bytes below it), a TextIOWrapper over io.BytesIO
        (pytest's capsys: bytes below, no descriptor) with and without write_through, and one the caller wrote to first."""
        import io
        for make in (io.StringIO, lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True),
                     lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            s = make()
            saved = sys.stdout
            sys.stdout = s
            try:
                rc = ap2.main(["verify", _VALID])
            finally:
                sys.stdout = saved
            text = s.getvalue() if isinstance(s, io.StringIO) else s.buffer.getvalue().decode("utf-8")
            self.assertEqual((rc, json.loads(text)["valid"]), (0, True), type(s).__name__)
        s = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        s.write("before\n")
        saved = sys.stdout
        sys.stdout = s
        try:
            rc = ap2.main(["verify", _VALID])
        finally:
            sys.stdout = saved
        head, _, rest = s.buffer.getvalue().decode("utf-8").partition("\n")
        # "before\n" went through the caller's own wrapper, which writes os.linesep ("\r\n" on Windows)
        self.assertEqual((rc, head + "\n", json.loads(rest)["valid"]), (0, "before" + os.linesep, True))


class TestPackWrittenWholeOrNotAtAll(unittest.TestCase):
    """1.5.2, second pass: `build` (and `sign_evidence`) opened the pack path with "w" and wrote into it, so a write that
    failed part way (a full disk, `ulimit -f`) truncated an earlier pack at that path (measured on 1.5.1 and a410964:
    5 891 bytes became 2 048 and the pack no longer verified). Now the pack goes to a temporary file in the same directory
    and is renamed onto the path only when whole."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_atomic_")
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=cls.d, check=True,
                       capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _sub(self):
        """A directory for the pack: a temporary one; on Windows (1.11.0) one on the full volume, which _build fills
        when a test asks for a limit — no per-process file-size limit there, a full volume is the equivalent."""
        return P.volume_dir(self) if _WIN else tempfile.mkdtemp(dir=self.d)

    def _build(self, out, limit=None, tsa=None):
        if limit is not None and _WIN:
            P.fill_volume(P.volume_root())
            limit = None
        cmd = _PY + ["build", out, "checkout=checkout.sdjwt", "payment=payment.sdjwt"] + (["--tsa", tsa] if tsa else [])
        with tempfile.TemporaryFile() as o, tempfile.TemporaryFile() as e:
            p = P.run(cmd, fsize=limit, cwd=self.d, stdin=subprocess.DEVNULL, stdout=o, stderr=e, timeout=300)
            o.seek(0); e.seek(0)
            return p.returncode, o.read(), e.read()

    def _leftovers(self, d):
        return [n for n in os.listdir(d) if n.endswith(".tmp")]

    def test_a_failed_build_leaves_the_earlier_pack_as_it_was(self):
        sub = self._sub()
        out = os.path.join(sub, "ev.json")
        rc, _, err = self._build(out)
        self.assertEqual(rc, 0, err)
        with open(out, "rb") as f:
            before = f.read()
        self.assertGreater(len(before), 2048)
        rc, raw, err = self._build(out, limit=2048)
        self.assertEqual(rc, 74, err)
        self.assertEqual(raw, b"")
        self.assertTrue(err.startswith(b"receipt not written: cannot write the pack ") and _CUT in err, err)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self._leftovers(sub), [])
        self.assertTrue(ap2.verify_evidence(out)["valid"])

    def test_a_failed_first_build_leaves_nothing(self):
        sub = self._sub()
        rc, _, err = self._build(os.path.join(sub, "ev.json"), limit=2048)
        self.assertEqual(rc, 74, err)
        self.assertEqual(os.listdir(sub), [])

    def test_mode_symlink_and_read_only(self):
        sub = tempfile.mkdtemp(dir=self.d)
        new = os.path.join(sub, "new.json")
        with open(os.path.join(sub, "ref"), "w", encoding="utf-8"):
            pass
        rc, _, err = self._build(new)
        self.assertEqual(rc, 0, err)
        self.assertEqual(stat.S_IMODE(os.stat(new).st_mode), stat.S_IMODE(os.stat(os.path.join(sub, "ref")).st_mode))
        if _WIN:   # 1.11.0: the access list is what the pack keeps there (a mode is only the read-only attribute)
            ap2._sigsuite.win_owner_only(new)
            kept = P.acl(new)
            self.assertNotEqual(kept, P.acl(os.path.join(sub, "ref")))   # control: a new file gets another list
            rc, _, err = self._build(new)
            self.assertEqual(rc, 0, err)
            self.assertEqual(P.acl(new), kept)
        else:
            os.chmod(new, 0o640)
            rc, _, err = self._build(new)
            self.assertEqual(rc, 0, err)
            self.assertEqual(stat.S_IMODE(os.stat(new).st_mode), 0o640)   # the pack it replaces keeps its permissions
        link = os.path.join(sub, "link.json")
        os.symlink("new.json", link)
        rc, raw, err = self._build(link)
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.islink(link))   # the file it names is replaced, the link stays
        self.assertEqual(json.loads(raw.decode("ascii"))["out"], link)
        if not (hasattr(os, "geteuid") and os.geteuid() == 0):   # Windows: 0o444 is the read-only attribute, which refuses too
            os.chmod(new, 0o444)
            self.addCleanup(os.chmod, new, 0o644)
            with open(new, "rb") as f:
                before = f.read()
            rc, _, err = self._build(new)
            self.assertEqual(rc, 74, err)
            self.assertIn(b"PermissionError", err)
            with open(new, "rb") as f:
                self.assertEqual(f.read(), before)
        self.assertEqual(self._leftovers(sub), [])

    def test_a_path_that_is_not_a_regular_file_is_written_directly(self):
        rc, raw, err = self._build(os.devnull)
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(raw.decode("ascii"))["out"], os.devnull)
        self.assertTrue(os.path.exists(os.devnull) and not os.path.isfile(os.devnull))

    def test_a_directory_is_refused_before_any_tsa_is_asked(self):
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(1)
                self.send_response(503)
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            sub = tempfile.mkdtemp(dir=self.d)
            rc, raw, err = self._build(sub, tsa="http://127.0.0.1:%d/" % srv.server_address[1])
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual((rc, raw, hits), (74, b"", []), err)
        self.assertEqual(err, ("receipt not written: cannot write the pack %r: IsADirectoryError: Is a directory\n" % sub).encode())

    def test_the_stderr_line_keeps_the_streams_error_handler(self):
        """stderr's own error handler (backslashreplace) decides how a character it cannot encode is written: a pack path
        with a non-ASCII character under PYTHONIOENCODING=ascii still gives the whole line, escaped as the text layer
        escapes it, and 74 — never a line lost to a strict encoder."""
        out = os.path.join(self.d, "no_such_d\u00fcr", "ev.json")
        p = subprocess.run(_PY + ["build", out, "checkout=checkout.sdjwt", "payment=payment.sdjwt"], cwd=self.d,
                           stdin=subprocess.DEVNULL, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="ascii"), timeout=300)
        self.assertEqual((p.returncode, p.stdout), (74, b""), p.stderr)
        line = "receipt not written: cannot write the pack %r: FileNotFoundError: No such file or directory\n" % out
        self.assertEqual(p.stderr, line.encode("ascii", "backslashreplace"))

    def test_the_temporary_name_is_created_exclusively(self):
        """The temporary file's name is drawn at random and created O_EXCL: whatever is already at the drawn name — a
        regular file, a FIFO, a symlink to a file — is neither written, nor followed, nor waited on; the next name is
        drawn. secrets.token_hex is made to return a planted name first."""
        for what in ("file", "fifo", "symlink"):
            with self.subTest(planted=what):
                sub = tempfile.mkdtemp(dir=self.d)
                out, victim = os.path.join(sub, "ev.json"), os.path.join(sub, "victim")
                with open(victim, "wb") as f:
                    f.write(b"victim")
                for prefix, call in ((".ap2-pack-", "a.build_evidence(arts, sys.argv[2])"),
                                     (".identity-", "s.ProducerIdentity.create().save(sys.argv[2])")):
                    planted = os.path.join(sub, prefix + "0" * 16 + ".tmp")
                    if what == "file":
                        with open(planted, "wb") as f:
                            f.write(b"planted")
                    elif what == "fifo":
                        if not hasattr(os, "mkfifo"):
                            self.skipTest("a FIFO at a name in a directory: Windows has named pipes only under \\\\.\\pipe\\")
                        os.mkfifo(planted)
                    else:
                        os.symlink(victim, planted)
                    code = ("import itertools, secrets, sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a; "
                            "from pqcrypto import sigsuite as s; n = itertools.count(0); "
                            "secrets.token_hex = lambda k=None: format(next(n), '016x'); "
                            "arts = [{'name': x, 'sd_jwt': open(x + '.sdjwt').read()} for x in ('checkout', 'payment')]\n"
                            + call + "\n")
                    p = subprocess.run([sys.executable, "-c", code, _HERE, out], cwd=self.d, capture_output=True, timeout=60)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    with open(victim, "rb") as f:
                        self.assertEqual(f.read(), b"victim")
                    self.assertTrue(os.path.lexists(planted))
                    if what == "file":
                        with open(planted, "rb") as f:
                            self.assertEqual(f.read(), b"planted")
                    os.unlink(planted)
                    self.assertEqual(self._leftovers(sub), [])

    def test_identity_save_whole_or_not_at_all(self):
        """pqcrypto ProducerIdentity.save wrote a private key file O_TRUNC in place: under RLIMIT_FSIZE a failed save left an
        earlier key file cut and no longer loadable (measured on 732705d: 223 bytes became 100), and a re-save kept an
        existing file's mode (0644 stayed 0644). Now: the earlier file intact and loadable, no temporary file left, 0600."""
        # 1.11.0, Windows: the key on the full volume (filled after the first save) stands for RLIMIT_FSIZE, and the
        # owner-only access list for mode 0600
        sub = P.volume_dir(self) if _WIN else tempfile.mkdtemp(dir=self.d)
        k = os.path.join(sub, "id.json")
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from pqcrypto import sigsuite as s\n"
                "if sys.argv[3] == 'first':\n s.ProducerIdentity.create().save(sys.argv[2])\n"
                "if sys.argv[3] == 'cut':\n"
                " if sys.argv[4] == 'rlimit':\n"
                "  import resource, signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); resource.setrlimit(resource.RLIMIT_FSIZE, (100, 100))\n"
                " try:\n  s.ProducerIdentity.create().save(sys.argv[2])\n except OSError as e:\n  print(type(e).__name__); sys.exit(3)\n")
        how = "volume" if _WIN else "rlimit"
        p = subprocess.run([sys.executable, "-c", code, _HERE, k, "first", how], capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        if not _WIN:
            self.assertEqual(stat.S_IMODE(os.stat(k).st_mode), 0o600)
        with open(k, "rb") as f:
            before = f.read()
        self.assertGreater(len(before), 100)
        if _WIN:
            P.fill_volume(P.volume_root())
        p = subprocess.run([sys.executable, "-c", code, _HERE, k, "cut", how], capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 3, p.stderr)
        with open(k, "rb") as f:
            self.assertEqual(f.read(), before)
        from pqcrypto import sigsuite
        sigsuite.ProducerIdentity.load(k)
        self.assertEqual(os.listdir(sub), ["id.json"])
        if _WIN:   # the access list (the FAT volume has none): a key saved in an NTFS directory has one entry, this user
            nt = os.path.join(tempfile.mkdtemp(dir=self.d), "id.json")
            sigsuite.ProducerIdentity.create().save(nt)
            lines = [x for x in P.acl(nt).splitlines() if ":" in x]
            self.assertEqual(len(lines), 1, P.acl(nt))
            self.assertIn(os.environ["USERNAME"].lower(), lines[0].lower())
            return
        os.chmod(k, 0o644)
        link = os.path.join(sub, "link.json")
        os.symlink("id.json", link)
        sigsuite.ProducerIdentity.create().save(link)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(stat.S_IMODE(os.stat(k).st_mode), 0o600)
        with open(k, "rb") as f:
            self.assertNotEqual(f.read(), before)

    def test_sign_evidence_leaves_the_pack_as_it_was_when_it_cannot_write(self):
        sub = self._sub()
        out = os.path.join(sub, "ev.json")
        rc, _, err = self._build(out)
        self.assertEqual(rc, 0, err)
        with open(out, "rb") as f:
            before = f.read()
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a\n"
                "if sys.argv[3] == 'rlimit':\n"
                " import resource, signal; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); resource.setrlimit(resource.RLIMIT_FSIZE, (2048, 2048))\n"
                "try:\n a.sign_evidence(sys.argv[2])\nexcept OSError as e:\n print(type(e).__name__); sys.exit(3)\n")
        if _WIN:   # 1.11.0: the full volume stands for RLIMIT_FSIZE
            P.fill_volume(P.volume_root())
        p = subprocess.run([sys.executable, "-c", code, _HERE, out, "volume" if _WIN else "rlimit"], capture_output=True, timeout=300)
        self.assertEqual(p.returncode, 3, p.stderr)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self._leftovers(sub), [])


@unittest.skipUnless(_OPENSSL, "openssl needed")
class TestOpensslTemporaryFiles(unittest.TestCase):
    """1.5.2, second pass: `verify --tsa-cert` and `verify --trust-anchor` hand openssl files in a temporary directory, and
    `stamp` / `build --tsa` wrote the query there. Measured on a410964 (13/10/2026) with no writable temporary file
    (`ulimit -f 0`): `verify --tsa-cert` on a valid pack raised a traceback (exit 1, the "not valid" code), `--trust-anchor`
    reported the artifact as an error (a valid pack "not valid", exit 1) and `stamp` raised a traceback (exit 1). Now a check
    that cannot be run here is exit 74 with one line, and the TSA query is read from openssl's stdout."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(_HERE, "verifiers"))
        import differential_oracle as O
        cls.d = tempfile.mkdtemp(prefix="ap2_tmpf_")
        with open(os.path.join(_VEC, "valid_signed.json"), encoding="utf-8") as f:
            base = json.load(f)
        cases = dict(O._x5c_cases(base))
        cls.x5c = os.path.join(cls.d, "x5c.json")
        with open(cls.x5c, "w", encoding="utf-8") as f:
            json.dump(O.rehash(cases["ca-issued-leaf"]), f)
        cls.ca = os.path.join(cls.d, "ca.pem")
        with open(cls.ca, "wb") as f:
            f.write(O._x5c_cases.ca_pem)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _run(self, cmd, limit):
        if limit is not None and _WIN:
            self.skipTest(P.NO_TEMP_LIMIT)
        p = P.run(cmd, fsize=limit, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        return p.returncode, p.stdout, p.stderr

    def _line_74(self, err, posix_line):
        """The exact line on POSIX; on Windows the reason is the system's (no fork, no signals): the same opening, one line."""
        if _WIN:
            self.assertTrue(err.startswith(posix_line.split(b": ")[0]) and err.endswith(b"\n") and err.count(b"\n") == 1, err)
        else:
            self.assertEqual(err, posix_line)

    def _full_receipt_74(self, rc, out, err, subject, err_line):
        """1.6.0 — SPEC §6.10: a check that could not be RUN here is exit 74 WITH the complete receipt: that subject
        not_evaluated/instrument_failure, every other subject evaluated (1.5.2–1.5.4: exit 74 and no receipt at all)."""
        self.assertEqual(rc, 74, err)
        if _WIN:   # the system's own reason after the same opening (Windows: no fork, no signals)
            self.assertTrue(err.startswith(b"check not run here: cannot run openssl here: ") and err.count(b"\n") == 1, err)
        else:
            self.assertEqual(err, err_line)
        r = json.loads(out.decode("utf-8"))   # complete JSON: the reader's rule (SPEC §10) — a receipt = the instrument
        self.assertEqual(r["admission"], "admitted")
        self.assertEqual(r["states"][subject]["state"], "not_evaluated")
        self.assertTrue(r["states"][subject]["reasons"])
        self.assertEqual(r["states"][subject]["reasons"], ["instrument_failure"] * len(r["states"][subject]["reasons"]))
        self.assertIn("check not run here", r["states"][subject]["detail"])
        self.assertEqual(r["states"]["sealed_content"]["state"], "verified")   # the other subjects are still evaluated
        return r

    def _check(self, cmd, field, subject):
        rc, out, err = self._run(cmd, None)   # the control: the check runs and passes
        self.assertEqual((rc, err), (0, b""))
        self.assertIn(field, out)
        self.assertEqual(json.loads(out)["states"][subject]["state"], "verified")
        # 0: no temporary directory passes tempfile's probe; 100: the probe passes, the file openssl reads does not fit
        for limit, why in ((0, b"no usable temporary directory"), (100, b"OSError: File too large")):
            rc, out, err = self._run(cmd, limit)   # stdout is a pipe: RLIMIT_FSIZE does not bind it, the receipt is written
            self._full_receipt_74(rc, out, err, subject, b"check not run here: cannot write a temporary file for openssl: " + why + b"\n")

    def test_verify_tsa_cert(self):
        self._check(_PY + ["verify", os.path.join(_VEC, "anchor_valid.json"), "--tsa-cert",
                           os.path.join(_VEC, "anchor_probe_tsa.crt"), "--require-anchor"], b'"tsa_verified": true', "time_anchor")

    def test_verify_trust_anchor(self):
        self._check(_PY + ["verify", self.x5c, "--trust-anchor", self.ca], b'"chain_verified": true', "issuer_identity")

    def test_check_not_run_and_receipt_not_written_are_two_branches(self):
        """1.6.0 — SPEC §6.10/§10: the two 74s are told apart by the receipt. A check not run here: the complete JSON on
        stdout. The receipt itself not written (stdout a regular file under RLIMIT_FSIZE 0, or /dev/full): no complete
        JSON, and "receipt not written" on stderr."""
        cmd = _PY + ["verify", os.path.join(_VEC, "anchor_valid.json"), "--tsa-cert", os.path.join(_VEC, "anchor_probe_tsa.crt")]
        # stdout a file that cannot grow: RLIMIT_FSIZE 0, or (Windows) a file on a full volume
        out_path = P.full_volume_with(self, "receipt.json") if _WIN else os.path.join(self.d, "receipt.json")
        with open(out_path, "wb") as fo:
            p = P.run(cmd, fsize=None if _WIN else 0, stdin=subprocess.DEVNULL, stdout=fo, stderr=subprocess.PIPE, timeout=300)
        with open(out_path, "rb") as f:
            written = f.read()
        self.assertEqual(p.returncode, 74, p.stderr)
        self.assertTrue(p.stderr.startswith(b"receipt not written: "), p.stderr)
        with self.assertRaises(ValueError):
            json.loads(written.decode("utf-8", "replace"))   # nothing (or a cut) — never a complete receipt
        if _FULL is None:
            self.skipTest(NO_FULL)
        with open(full_sink(), "wb") as fo:   # the control: no openssl failure, only the write — the same branch
            p = subprocess.run(_PY + ["verify", os.path.join(_VEC, "anchor_valid.json")], stdin=subprocess.DEVNULL, stdout=fo,
                               stderr=subprocess.PIPE, timeout=300)
        self.assertEqual(p.returncode, 74, p.stderr)
        self.assertTrue(p.stderr.startswith(b"receipt not written: "), p.stderr)

    def test_library_raises_the_write_error(self):   # never a check reported as failed
        if _WIN:
            self.skipTest(P.NO_TEMP_LIMIT)
        code = ("import resource, sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a; "
                "resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))\n"
                "try:\n a.verify_evidence(sys.argv[2], trust_anchor=sys.argv[3])\n"
                "except a.Ap2WriteError as e:\n print(str(e)); sys.exit(3 if e.receipt['states']['issuer_identity']['reasons'] == ['instrument_failure'] else 4)\n")
        p = subprocess.run([sys.executable, "-c", code, _HERE, self.x5c, self.ca], capture_output=True, timeout=300)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertTrue(p.stdout.startswith(b"cannot write a temporary file for openssl"), p.stdout)

    def _nproc(self, cmd):
        # RLIMIT_NPROC 1 (this user runs more than one process: fork is refused); Windows: a Job Object whose
        # ActiveProcessLimit is 1, the child alone in it (1.11.0)
        p = P.run(cmd, nproc=1, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        return p.returncode, p.stdout, p.stderr

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "RLIMIT_NPROC does not bind root")
    def test_openssl_that_cannot_be_started_here_is_74_not_a_failed_check(self):
        """openssl that cannot be started (fork refused: RLIMIT_NPROC 1) was a failed check: measured on 732705d and
        cb36d56, `--tsa-cert --require-anchor` on a valid pack gave `tsa_verified: false`, `valid: false`, exit 1, and
        `--trust-anchor` gave `chain_verified: false`. Now the check could not be run here: exit 74, one line."""
        line = b"check not run here: cannot run openssl here: BlockingIOError: Resource temporarily unavailable\n"
        for cmd, subject in ((_PY + ["verify", os.path.join(_VEC, "anchor_valid.json"), "--tsa-cert",
                                     os.path.join(_VEC, "anchor_probe_tsa.crt"), "--require-anchor"], "time_anchor"),
                             (_PY + ["verify", os.path.join(_VEC, "anchor_valid.json"), "--tsa-cert", os.path.join(_VEC, "anchor_probe_tsa.crt")], "time_anchor"),
                             (_PY + ["verify", self.x5c, "--trust-anchor", self.ca], "issuer_identity")):
            with self.subTest(cmd=cmd[3:]):
                rc, out, err = self._run(cmd, None)   # the control: the check runs and passes
                self.assertEqual((rc, err), (0, b""))
                rc, out, err = self._nproc(cmd)   # 1.6.0: 74 WITH the complete receipt (SPEC §6.10)
                r = self._full_receipt_74(rc, out, err, subject, line)
                if "--require-anchor" in cmd:   # the anchor was not counted: the policy is not met, and says why
                    self.assertEqual((r["valid"], r["policy"]["unmet"]), (False, ["require_anchor"]))
        rc, out, err = self._nproc(_PY + ["verify", os.path.join(_VEC, "anchor_valid.json")])   # no openssl asked for:
        self.assertEqual((rc, err), (0, b""))                                                  # the limit changes nothing

    def test_openssl_killed_by_a_signal_is_74_not_a_finding(self):
        """1.6.0 review — openssl killed by a signal (a crashed dependency, krausz §3.1) gave no answer: measured
        18/10/2026, with an openssl that kills itself with SIGSEGV, `time_anchor: not_evaluated/tsa_invalid` and exit 1 on a
        valid pack under --require-anchor, and `issuer_identity: chain_unresolved` — a statement about the input. Now: exit
        74 WITH the complete receipt, that subject instrument_failure (SPEC §6.10). The control: an openssl that answers
        "no" (exit 1, no signal) stays a check that ran."""
        fake = tempfile.mkdtemp(dir=self.d)
        # 1.11.0: a program on every system (_ap2_platform.fake_tool). The crash: SIGSEGV on POSIX; on Windows, which has
        # no signals, a real access violation (a read at address 0), exit code 0xC0000005
        crash = (P.WIN_CRASH if _WIN else "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)\n")
        P.fake_tool(os.path.join(fake, "crash"), "openssl", crash)
        P.fake_tool(os.path.join(fake, "no"), "openssl", "import sys; print('Verification: FAILED'); sys.exit(1)\n")
        cases = ((_PY + ["verify", os.path.join(_VEC, "anchor_valid.json"), "--tsa-cert", os.path.join(_VEC, "anchor_probe_tsa.crt"),
                         "--require-anchor"], "time_anchor", "tsa_invalid"),
                 (_PY + ["verify", self.x5c, "--trust-anchor", self.ca], "issuer_identity", "chain_unresolved"))
        for cmd, subject, answered in cases:
            with self.subTest(cmd=cmd[3:]):
                env = dict(os.environ, PATH=os.path.join(fake, "crash") + os.pathsep + os.environ.get("PATH", ""))
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=300)
                self._full_receipt_74(p.returncode, p.stdout, p.stderr, subject,
                                      b"check not run here: cannot run openssl here: terminated by signal 11\n")
                if _WIN:
                    self.assertTrue(p.stderr.endswith(b"ended by exception 0xC0000005\n"), p.stderr)
                env["PATH"] = os.path.join(fake, "no") + os.pathsep + os.environ.get("PATH", "")
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=300)
                r = json.loads(p.stdout)
                self.assertNotEqual(p.returncode, 74, p.stderr)
                self.assertEqual(r["states"][subject], {"state": "not_evaluated", "reasons": [answered]})

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "RLIMIT_NPROC does not bind root")
    def test_stamp_whose_openssl_cannot_be_started_is_74_and_the_pack_is_unchanged(self):
        """1.5.3 — measured on 1.5.2 under RLIMIT_NPROC 1: `stamp` gave "no anchor obtained: BlockingIOError …", a refusal,
        exit 1. The query was never made here: exit 74, one line ending "not stamped", the pack as it was. `build` keeps
        writing the pack with the reason as its unanchored note, and a TSA that answers with no token stays a refusal."""
        tsa = _Tsa()
        try:
            sub = tempfile.mkdtemp(dir=self.d)
            subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=sub, check=True,
                           capture_output=True)
            p = os.path.join(sub, "ev.json")
            rc, _, err = _run(_PY + ["build", p, "checkout=checkout.sdjwt", "payment=payment.sdjwt"], "file", cwd=sub)
            self.assertEqual(rc, 0, err)
            with open(p, "rb") as f:
                before = f.read()
            rc, out, err = self._nproc(_PY + ["stamp", p, "--tsa", tsa.url])
            self.assertEqual((rc, out), (74, b""), err)
            self._line_74(err, b"receipt not written: cannot run openssl here: BlockingIOError: Resource temporarily unavailable: not stamped\n")
            self.assertTrue(err.endswith(b": not stamped\n"), err)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), before)
            rc, out, err = self._nproc(_PY + ["stamp", p, "--tsa", tsa.url + "html"])   # refused before: still 74, the
            self.assertEqual(rc, 74, err)                                                # query comes first
            rc, out, err = self._run(_PY + ["stamp", p, "--tsa", tsa.url + "html"], None)   # the control: a TSA reply
            self.assertEqual(rc, 1, err)                                                    # with no token stays 1
            self.assertIn(b"no anchor obtained", err)
            q = os.path.join(sub, "ev2.json")
            rc, _, err = self._nproc(_PY + ["build", q, "checkout=" + os.path.join(sub, "checkout.sdjwt"),
                                            "payment=" + os.path.join(sub, "payment.sdjwt"), "--tsa", tsa.url])
            self.assertEqual(rc, 0, err)   # build under the same limit: the pack, with the reason as its note
            with open(q, encoding="utf-8") as f:
                ts = json.load(f)["rfc3161_timestamp"]
            self.assertEqual(ts["anchored"], False)
            self.assertTrue(ts["note"].startswith("Ap2WriteError: cannot run openssl here: "), ts)
            if not _WIN:
                self.assertEqual(ts["note"], "Ap2WriteError: cannot run openssl here: BlockingIOError: Resource temporarily unavailable")
            r3 = os.path.join(sub, "ev3.json")   # a further --tsa goes through the same note (anchors_failed), never 74
            rc, out, err = self._nproc(_PY + ["build", r3, "checkout=" + os.path.join(sub, "checkout.sdjwt"),
                                              "payment=" + os.path.join(sub, "payment.sdjwt"), "--tsa", tsa.url,
                                              "--tsa", tsa.url])
            self.assertEqual(rc, 0, err)
            failed = json.loads(out.decode("ascii"))["anchors_failed"]
            self.assertEqual([(x["tsa_url"], x["note"].startswith("Ap2WriteError: cannot run openssl here: ")) for x in failed],
                             [(tsa.url, True)])
            if not _WIN:
                self.assertEqual(failed, [{"tsa_url": tsa.url, "note": "Ap2WriteError: "
                                 "cannot run openssl here: BlockingIOError: Resource temporarily unavailable"}])
            import socket   # the control: a TSA that cannot be reached is still the refusal, exit 1, not a traceback
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                closed = "http://127.0.0.1:%d/" % s.getsockname()[1]
            rc, out, err = self._run(_PY + ["stamp", p, "--tsa", closed], None)
            self.assertEqual(rc, 1, err)
            self.assertTrue(err.startswith(b'{"error": "no anchor obtained: URLError: '), err)
            rc, out, err = self._run(_PY + ["stamp", p, "--tsa", tsa.url], None)   # the control: unlimited, it stamps
            self.assertEqual((rc, err), (0, b""))
            self.assertEqual(json.loads(out.decode("ascii"))["anchors"], 1)
        finally:
            tsa.close()

    def test_a_temporary_directory_that_cannot_be_made_is_the_write_error(self):
        """The private directory failing after gettempdir passed (no inode left, a directory that stopped taking entries) is
        the same "cannot write a temporary file for openssl", with the reason and no path in it; made to fail here in
        process. 1.11.0: the directory is made by os.mkdir (ap2_evidence._private_tmpdir), no longer tempfile.mkdtemp —
        patching mkdtemp now proves nothing, so the call that makes it fails."""
        import errno
        real = os.mkdir
        calls = []

        def full(path, *a, **k):
            if os.path.basename(path).startswith("ap2-openssl-"):
                calls.append(path)
                raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)
            return real(path, *a, **k)
        os.mkdir = full
        try:
            with self.assertRaises(ap2.Ap2WriteError) as cm:
                ap2.verify_evidence(self.x5c, trust_anchor=self.ca)
        finally:
            os.mkdir = real
        self.assertEqual(len(calls), 1)   # ENOSPC is not a name already taken: no second try
        self.assertEqual(str(cm.exception), "cannot write a temporary file for openssl: OSError: " + os.strerror(errno.ENOSPC))

    def test_stamp_query_needs_no_temporary_file(self):
        tsa = _Tsa()
        try:
            sub = P.volume_dir(self) if _WIN else tempfile.mkdtemp(dir=self.d)
            subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=sub, check=True,
                           capture_output=True)
            p = os.path.join(sub, "ev.json")
            rc, _, err = _run(_PY + ["build", p, "checkout=checkout.sdjwt", "payment=payment.sdjwt"], "file", cwd=sub)
            self.assertEqual(rc, 0, err)
            with open(p, "rb") as f:
                before = f.read()
            # under RLIMIT_FSIZE 0 the token is obtained (no temporary file), then the pack cannot be written: 74, unchanged.
            # Windows (1.11.0): the pack on a full volume, the equivalent of a file this process cannot make grow
            if _WIN:
                P.fill_volume(P.volume_root())
                p0 = P.run(_PY + ["stamp", p, "--tsa", tsa.url], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=300)
                rc, out, err = p0.returncode, p0.stdout, p0.stderr
                P.unfill_volume(P.volume_root())
            else:
                rc, out, err = self._run(_PY + ["stamp", p, "--tsa", tsa.url], 0)
            self.assertEqual((rc, out), (74, b""), err)
            self.assertTrue(err.startswith(b"receipt not written: cannot write the stamped pack"), err)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), before)
            rc, out, err = self._run(_PY + ["stamp", p, "--tsa", tsa.url], None)
            self.assertEqual((rc, err), (0, b""))
            self.assertEqual(json.loads(out.decode("ascii"))["anchors"], 1)
        finally:
            tsa.close()


_SHIM_C = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
static int done = 0;
ssize_t write(int fd, const void *b, size_t n) {
  static ssize_t (*real)(int, const void *, size_t) = 0;
  if (!real) real = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
  const char *z = getenv("AP2_TEST_ZERO_FD");
  if (z && !done && n > 0 && fd == atoi(z)) { done = 1; return 0; }
  return real(fd, b, n);
}
int fsync(int fd) {
  static int (*real)(int) = 0;
  if (!real) real = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
  if (getenv("AP2_TEST_FSYNC_EIO")) { errno = EIO; return -1; }
  return real(fd);
}
"""


def _shim(d):
    """A shared object loaded with LD_PRELOAD: write(2) on fd AP2_TEST_ZERO_FD returns 0 once (no error, nothing taken),
    fsync(2) fails with EIO when AP2_TEST_FSYNC_EIO is set. None when there is no C compiler (the tests then skip)."""
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc or not sys.platform.startswith("linux"):
        return None
    src, so = os.path.join(d, "shim.c"), os.path.join(d, "shim.so")
    with open(src, "w", encoding="utf-8") as f:
        f.write(_SHIM_C)
    p = subprocess.run([cc, "-shared", "-fPIC", "-o", so, src, "-ldl"], capture_output=True, timeout=120)
    return so if p.returncode == 0 else None


_SITE_FAULTS = r"""
# 1.11.0: the equivalent of the LD_PRELOAD shim where there is none (macOS, Windows): the same two faults injected at the
# start of the Python process, in the calls the package makes (os.fsync; the raw stdout's write under -u)
import errno, io, os, sys
if os.environ.get("AP2_TEST_FSYNC_EIO"):
    def _fsync(fd):
        raise OSError(errno.EIO, os.strerror(errno.EIO))
    os.fsync = _fsync
if os.environ.get("AP2_TEST_ZERO_FD") == "1":
    class _Zero(io.FileIO):
        done = False

        def write(self, b):
            if not _Zero.done and len(b):
                _Zero.done = True
                return 0
            return super().write(b)
    sys.stdout = io.TextIOWrapper(_Zero(1, "wb", closefd=False), encoding=sys.stdout.encoding, errors=sys.stdout.errors,
                                  write_through=True)
"""


class TestNemesisFinal(unittest.TestCase):   # 1.11.0: every system (faults: LD_PRELOAD on Linux, a sitecustomize elsewhere)
    """Cases the 1.5.2 tests did not reach (final review, 13/10/2026): a write that takes 0 bytes, an fsync that fails, a
    read-only key file, a key path that is not a regular file, a working directory that cannot be written, openssl gone
    since `which`, openssl that does not answer, and the JS pause on a full stderr that never grows past 50 ms."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="ap2_nemfin_")
        cls.so = _shim(cls.d)
        cls.site = None
        if cls.so is None and not sys.platform.startswith("linux"):
            cls.site = os.path.join(cls.d, "site")
            os.makedirs(cls.site)
            with open(os.path.join(cls.site, "sitecustomize.py"), "w", encoding="utf-8") as f:
                f.write(_SITE_FAULTS)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _env(self, **kw):
        if self.so is not None:
            return dict(os.environ, LD_PRELOAD=self.so, **kw)
        return dict(os.environ, PYTHONPATH=self.site + os.pathsep + os.environ.get("PYTHONPATH", ""), **kw)

    def _faults(self):
        if self.so is None and self.site is None:
            self.skipTest("no C compiler for the LD_PRELOAD shim (Linux)")

    def test_a_write_that_takes_0_bytes_is_74(self):
        """write(2) that returns 0 for a non-empty buffer took nothing and reported no error: the loop treats it as an error
        (a short write), it does not spin on it and does not exit with the verdict's code."""
        self._faults()
        cmds = [_PY[:1] + ["-u"] + _PY[1:] + ["verify", _VALID]]
        if _NODE and self.so is not None:   # Node's write(2) is reached by LD_PRELOAD only (Linux): see the next test
            cmds.append([_NODE, _JS, _VALID])
        for cmd in cmds:
            with self.subTest(cmd=cmd[:2]):
                with tempfile.TemporaryFile() as out:
                    p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.PIPE, timeout=60,
                                       env=self._env(AP2_TEST_ZERO_FD="1"))
                    self.assertEqual(p.returncode, 74, p.stderr)
                    self.assertIn(b"short write", p.stderr)
                    self.assertEqual(p.stderr.count(b"\n"), 1)

    def test_an_fsync_that_fails_leaves_the_earlier_pack_and_key(self):
        """fsync(2) reports errors a write did not (EIO, a delayed ENOSPC): the pack and the key file are renamed onto the
        path only after it succeeds; on failure 74 (build) or OSError (save), and what was there stays."""
        self._faults()
        sub = tempfile.mkdtemp(dir=self.d)
        subprocess.run([sys.executable, os.path.join(_HERE, "examples", "make_samples.py")], cwd=sub, check=True,
                       capture_output=True)
        pk = os.path.join(sub, "p.json")
        rc, _, err = _run(_PY + ["build", pk, "checkout=checkout.sdjwt"], "file", cwd=sub)
        self.assertEqual(rc, 0, err)
        with open(pk, "rb") as f:
            before = f.read()
        p = subprocess.run(_PY + ["build", pk, "checkout=checkout.sdjwt", "payment=payment.sdjwt"], cwd=sub, timeout=120,
                           stdin=subprocess.DEVNULL, capture_output=True, env=self._env(AP2_TEST_FSYNC_EIO="1"))
        self.assertEqual((p.returncode, p.stdout), (74, b""), p.stderr)
        self.assertIn(b"Input/output error", p.stderr)
        with open(pk, "rb") as f:
            self.assertEqual(f.read(), before)
        k = os.path.join(sub, "id.json")
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from pqcrypto import sigsuite as s\n"
                "try:\n s.ProducerIdentity.create().save(sys.argv[2])\nexcept OSError as e:\n print(e.errno); sys.exit(3)\n")
        subprocess.run([sys.executable, "-c", code, _HERE, k], check=True, timeout=60)
        with open(k, "rb") as f:
            key = f.read()
        p = subprocess.run([sys.executable, "-c", code, _HERE, k], capture_output=True, timeout=60,
                           env=self._env(AP2_TEST_FSYNC_EIO="1"))
        self.assertEqual((p.returncode, p.stdout.strip()), (3, str(errno.EIO).encode()), p.stderr)
        with open(k, "rb") as f:
            self.assertEqual(f.read(), key)
        self.assertEqual(sorted(x for x in os.listdir(sub) if x.startswith(".")), [])

    def test_a_write_that_takes_0_bytes_is_74_js(self):
        """macOS and Windows: no LD_PRELOAD reaches Node's write(2). The equivalent at the next layer down that the JS
        verifier calls: fs.writeSync replaced, before the verifier loads, by one that takes 0 bytes once on fd 1 (node
        --import, module.syncBuiltinESMExports so the verifier's own `import { writeSync }` sees it)."""
        if not _NODE:
            self.skipTest("node needed")
        pre = os.path.join(self.d, "zero_write.mjs")
        with open(pre, "w", encoding="utf-8") as f:
            f.write("import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';\n"
                    "const real = fs.writeSync; let done = false;\n"
                    "fs.writeSync = (fd, b, ...a) => { if (!done && fd === 1 && b.length) { done = true; return 0; } return real(fd, b, ...a); };\n"
                    "syncBuiltinESMExports();\n")
        import pathlib
        with tempfile.TemporaryFile() as out:
            p = subprocess.run([_NODE, "--import", pathlib.Path(pre).as_uri(), _JS, _VALID], stdin=subprocess.DEVNULL,
                               stdout=out, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(p.returncode, 74, p.stderr)
        self.assertIn(b"short write", p.stderr)
        self.assertEqual(p.stderr.count(b"\n"), 1)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes a read-only file")
    def test_identity_save_refuses_a_read_only_key_file(self):
        """A key file its owner made read-only (chmod 400) was refused by 1.5.1 (PermissionError) and must not be replaced
        by a new key now that the file is renamed onto: the private key it holds would be lost."""
        from pqcrypto import sigsuite
        sub = tempfile.mkdtemp(dir=self.d)
        k = os.path.join(sub, "id.json")
        sigsuite.ProducerIdentity.create().save(k)
        os.chmod(k, 0o400)
        with open(k, "rb") as f:
            before = f.read()
        self.addCleanup(os.chmod, k, 0o600)
        with self.assertRaises(PermissionError):
            sigsuite.ProducerIdentity.create().save(k)
        with open(k, "rb") as f:
            self.assertEqual(f.read(), before)
        # Windows: 0o400 is the read-only attribute (the mode reads 0o444 there), which refuses the write the same way
        self.assertEqual(stat.S_IMODE(os.stat(k).st_mode), 0o444 if _WIN else 0o400)
        self.assertEqual(os.listdir(sub), ["id.json"])

    def test_identity_save_to_a_path_that_is_not_a_regular_file_and_from_another_directory(self):
        from pqcrypto import sigsuite
        sigsuite.ProducerIdentity.create().save(os.devnull)   # written directly: no temporary file in /dev
        self.assertTrue(os.path.exists(os.devnull) and not os.path.isfile(os.devnull))
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return
        ro, keys = tempfile.mkdtemp(dir=self.d), tempfile.mkdtemp(dir=self.d)
        P.deny_writes_in(self, ro)   # 1.11.0: mode 0555, or a deny ACE on Windows
        here = os.getcwd()
        os.chdir(ro)   # the temporary file goes next to the key, not in the working directory
        try:
            sigsuite.ProducerIdentity.create().save(os.path.join(keys, "id.json"))
        finally:
            os.chdir(here)
        sigsuite.ProducerIdentity.load(os.path.join(keys, "id.json"))

    @unittest.skipUnless(_OPENSSL, "openssl needed")
    def test_openssl_gone_since_which_and_openssl_without_an_answer_are_the_write_error(self):
        """The binary named by `which` no longer there (ENOENT at exec), and an openssl that gives no answer within the
        time limit: the check did not run here, so Ap2WriteError, never `tsa_verified: false` / "not valid"."""
        tsa = os.path.join(_VEC, "anchor_probe_tsa.crt")
        slow = P.fake_tool(os.path.join(self.d, "slowbin"), "openssl", "import time; time.sleep(30)\n")   # 1.11.0: every system
        code = ("import shutil, sys; sys.path.insert(0, sys.argv[1]); import ap2_evidence as a\n"
                "if sys.argv[4] == 'gone':\n w = shutil.which; shutil.which = lambda n, *x, **k: '/nonexistent/openssl' if n == 'openssl' else w(n, *x, **k)\n"
                "else:\n a._verify_rfc3161.__defaults__ = (1, None)\n"
                "try:\n r = a.verify_evidence(sys.argv[2], tsa_cert=sys.argv[3], require_anchor=True)\n print('verdict', r['valid'], r['rfc3161'].get('tsa_verified'))\n"
                "except a.Ap2WriteError as e:\n print(e)\n")
        for how, env, want in (("gone", None, b"cannot run openssl here: FileNotFoundError: No such file or directory"),
                               ("slow", dict(os.environ, PATH=slow + os.pathsep + os.environ.get("PATH", "")),
                                b"cannot run openssl here: no answer within 1 s")):
            with self.subTest(how=how):
                p = subprocess.run([sys.executable, "-c", code, _HERE, _VALID, tsa, how], capture_output=True, timeout=120,
                                   env=env)
                self.assertEqual(p.stdout.strip(), want, p.stderr)
        p = subprocess.run([sys.executable, "-c", code, _HERE, _VALID, tsa, "none"], capture_output=True, timeout=120)
        self.assertEqual(p.stdout.strip(), b"verdict True True", p.stderr)   # the control: the check runs and passes

    @unittest.skipUnless(_NODE, "node needed")
    def test_js_pause_on_a_full_stderr_stays_under_50_ms(self):
        """The JS loop waits 1 to 50 ms between retries of EAGAIN: once the reader drains a full non-blocking stderr, the
        usage line arrives within a few pauses, whenever that happens (three phases, so a doubling pause with no ceiling
        cannot pass by chance)."""
        lags = []
        for phase in (0.7, 1.0, 1.3):
            r, w = os.pipe()
            P.set_nonblocking(w)   # 1.11.0: O_NONBLOCK, or PIPE_NOWAIT on Windows
            while True:
                try:
                    if not os.write(w, b"P" * 4096):   # Windows: a full PIPE_NOWAIT pipe takes 0 bytes
                        break
                except BlockingIOError:
                    break
                except OSError as e:   # Windows before Python 3.12: ENOSPC
                    if not (_WIN and e.errno == errno.ENOSPC):
                        raise
                    break
            p = subprocess.Popen([_NODE, _JS], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=w)
            os.close(w)
            time.sleep(phase)
            t0, data = time.monotonic(), b""
            while True:
                b = os.read(r, 1 << 16)
                if not b:
                    break
                data += b
            lags.append(time.monotonic() - t0)
            os.close(r)
            self.assertEqual(p.wait(timeout=60), 2)
            self.assertTrue(data.lstrip(b"P").startswith(b"usage: "), data[-80:])
        self.assertLess(max(lags), 0.4, lags)


if __name__ == "__main__":
    unittest.main()
