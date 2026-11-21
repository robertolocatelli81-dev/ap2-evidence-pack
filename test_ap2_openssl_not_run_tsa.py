#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.9.1, SPEC §3.2, §6.10: two checks of the RFC 3161 path that ran outside the rules of the rest of the file.

1. The key-identifier step (`key_id_token_problem`, a token whose SignerInfo names its signer by subjectKeyIdentifier)
   called openssl with a bare subprocess.run: measured on 2026-11-20 on 1.9.0, an openssl killed by SIGKILL in
   `cms -verify` or in `verify -purpose timestampsign` gave `tsa_verified: false` ("openssl ... : refused"), and one that
   did not answer within 30 s gave `tsa_verified: false` (TimeoutExpired) — a finding about the token where the check had
   not run. Now through `_run_openssl`: `tsa_verified` null and the reason in `tsa_note`, as for `openssl ts -verify`.
2. The reply of a TSA (`stamp`, `build --tsa-url`) was read whole: measured on 2026-11-20 on 1.9.0, an 8 MiB reply was
   read to the last byte. Now at most MAX_TSA_REPLY_BYTES + 1 are read and a larger reply is not anchored, as the JWKS
   fetch already was (1 MiB).

Positive control: on 1.9.0 the four tests that need openssl fail (three false where null is expected, 8 388 608 bytes
read)."""
import base64
import http.server
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl") and os.name == "posix", "needs openssl and a POSIX shell")


@NEEDS
class KeyIdStepNotRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_ap2_tsa_key_id as K
        cls.K = K
        cls.td = tempfile.mkdtemp(prefix="ap2kid_")
        cls.lab = K.Lab(cls.td, "lab")
        cls.tsr = base64.b64encode(K.reply(cls.lab.resign(cls.lab.token()))).decode()
        cls.real = shutil.which("openssl")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def _verify(self):
        return A._verify_rfc3161(self.tsr, self.K.DIGEST.hex(), tsa_cert=self.lab.j("ca.crt"))

    def _with_fake(self, name, case):
        d = os.path.join(self.td, name)
        os.makedirs(d)
        with open(os.path.join(d, "openssl"), "w") as f:
            f.write('#!/bin/sh\n%s\nexec "%s" "$@"\n' % (case, self.real))
        os.chmod(os.path.join(d, "openssl"), 0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + old
        try:
            return self._verify()
        finally:
            os.environ["PATH"] = old

    def test_control_real_openssl_verifies(self):
        self.assertTrue(A.signer_named_by_key_id(base64.b64decode(self.tsr)))
        self.assertIs(self._verify()["tsa_verified"], True)

    def test_killed_in_cms_verify_is_not_run(self):
        r = self._with_fake("kill_cms", 'case "$1 $2" in "cms -verify") kill -KILL $$;; esac')
        self.assertIsNone(r["tsa_verified"], r)
        self.assertIn("not run here", r["tsa_note"])
        self.assertIn("_not_run", r)

    def test_killed_in_verify_purpose_is_not_run(self):
        r = self._with_fake("kill_verify", 'case "$1 $2" in "verify -purpose") kill -KILL $$;; esac')
        self.assertIsNone(r["tsa_verified"], r)
        self.assertIn("terminated by signal", r["tsa_note"])

    def test_no_answer_is_not_run(self):
        r = self._with_fake("slow", 'case "$1 $2" in "verify -purpose") exec sleep 45;; esac')
        self.assertIsNone(r["tsa_verified"], r)
        self.assertIn("no answer within", r["tsa_note"])

    def test_a_refusal_stays_false(self):   # the other direction: a real "no" of openssl is still a finding
        r = A._verify_rfc3161(self.tsr, self.K.DIGEST.hex(), tsa_cert=self.lab.j("tsa.crt"))
        self.assertIs(r["tsa_verified"], False, r)


class _Big(http.server.BaseHTTPRequestHandler):
    size = 8 << 20

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(self.size))
        self.end_headers()
        try:
            for _ in range(self.size // 65536):
                self.wfile.write(b"\x30" * 65536)
            self.wfile.write(b"\x30" * (self.size % 65536))   # the exact size, also when it is not a multiple of 64 KiB
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *a):
        pass


@NEEDS
class TsaReplyBounded(unittest.TestCase):
    def setUp(self):
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Big)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d/" % self.srv.server_address[1]
        self.read = []
        real = urllib.request.urlopen
        test = self

        class Spy:
            def __init__(self, r):
                self.r = r

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.r.close()

            def read(self, *a):
                b = self.r.read(*a)
                test.read.append(len(b))
                return b

        self.orig = A.urllib.request.urlopen
        A.urllib.request.urlopen = lambda *a, **k: Spy(real(*a, **k))

    def tearDown(self):
        A.urllib.request.urlopen = self.orig
        self.srv.shutdown()
        self.srv.server_close()

    def test_large_reply_not_read_whole(self):
        r = A._rfc3161_stamp("ab" * 32, self.url)
        self.assertFalse(r["anchored"])
        self.assertIn("larger than", r["note"])
        self.assertLessEqual(sum(self.read), A.MAX_TSA_REPLY_BYTES + 1)

    def test_the_bound_is_one_mebibyte(self):   # a literal, not the constant: a bound moved to 2 MiB must turn this red
        _Big.size = (1 << 20) + 1
        try:
            r = A._rfc3161_stamp("ab" * 32, self.url)
        finally:
            _Big.size = 8 << 20
        self.assertFalse(r["anchored"])
        self.assertEqual(r["note"], "TSA reply larger than 1048576 bytes: not read further, not anchored")
        self.assertEqual(sum(self.read), (1 << 20) + 1)

    def test_reply_at_the_bound_is_read(self):   # the other direction: a reply of exactly the bound is read and parsed
        _Big.size = A.MAX_TSA_REPLY_BYTES
        try:
            r = A._rfc3161_stamp("ab" * 32, self.url)
        finally:
            _Big.size = 8 << 20
        self.assertEqual(sum(self.read), A.MAX_TSA_REPLY_BYTES)
        self.assertEqual(r["note"], "TSA reply is not a granted token for this digest")


if __name__ == "__main__":
    unittest.main()
