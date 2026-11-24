#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""1.11.0: the same bytes on every system, and the same nesting verdict on every Python.

1. Files. The pack (`build`, `sign`, `stamp`, the private copy of `restriction`) and the producer identity were written
   in text mode with no `newline=`, so on Windows every "\\n" became "\\r\\n" (reported by cryptovalid-opencore's Windows
   port on 2026-11-24): the file's bytes, and the SHA-256 of the whole file that SPEC §10 tells a relying party to
   record, differed from the same pack written elsewhere. Now every text write of the package names `newline="\\n"`.
   `test_every_text_write_names_newline` reads the code (fails on v1.10.0: six writes); `test_written_files_have_no_cr`
   reads the bytes (meaningful on Windows, which the CI runs).
2. Receipts and messages. `_text_layer_bytes` turned "\\n" into os.linesep; now "\\n" stays, as the JS verifier writes
   it. `test_receipt_bytes_keep_lf` patches os.linesep to "\\r\\n" (fails on v1.10.0).
3. Nesting. A `--key` file and a fetched JWKS were bounded by json's RecursionError, whose depth differs by Python
   (measured 2026-11-24: 5000 levels raise it on 3.9 and 3.11 and parse on 3.12 to 3.14; 20000 parse on 3.14 only), so a
   `--key` JWK with a member 5000 deep was exit 2 on 3.9 and exit 1 on 3.13 (measured on v1.10.0). Now the nesting is
   counted on the text before the parser, bound 512 (SPEC §3.1): exit 1, the refusal build gives a pack that deep, on every
   Python. On v1.10.0 `test_key_file_past_the_bound_*` fails on every Python (on 3.14 at 100000 levels, elsewhere from
   5000 or 20000) and `test_jwks_past_the_bound_*` on every Python (600 levels parse on all of them)."""
import ast
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import ap2_evidence as A  # noqa: E402

PACKAGE_FILES = ("ap2_evidence.py", "ap2_nist_beacon.py", os.path.join("pqcrypto", "sigsuite.py"))
VECTOR = os.path.join(ROOT, "spec", "vectors", "ap2", "key_material_not_used.json")   # valid, no producer block


def _text_writes_without_newline(path):
    """open()/os.fdopen() in a text mode that writes ("w", "a", "x", "+"; not "b") without newline=."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    bad = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        if name not in ("open", "fdopen"):
            continue
        if isinstance(f, ast.Attribute) and name == "open" and not (isinstance(f.value, ast.Name) and f.value.id in ("io", "builtins")):
            continue   # os.open (flags, not a mode) and the like
        kws = {k.arg: k.value for k in n.keywords}
        mode = n.args[1] if len(n.args) >= 2 else kws.get("mode")
        m = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else ("r" if mode is None else "?")
        if "b" in m or not any(c in m for c in "wax+?"):
            continue
        if "newline" not in kws:
            bad.append(f"{os.path.basename(path)}:{n.lineno}")
    return bad


def _text_calls_without_encoding(path):
    """open() in text mode, and subprocess calls with text=True / universal_newlines=True, without encoding=: on Windows
    each reads or writes in the ANSI code page (CI run of 2026-11-24: the tests' own packs were written as cp1252 there
    and refused as not UTF-8, 193 errors in two test files)."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    bad = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        kws = {k.arg for k in n.keywords}
        if None in kws or "encoding" in kws:
            continue
        if name == "open" and not (isinstance(f, ast.Attribute) and getattr(f.value, "id", "") == "os"):
            mode = n.args[1] if len(n.args) >= 2 else next((k.value for k in n.keywords if k.arg == "mode"), None)
            m = mode.value if isinstance(mode, ast.Constant) and isinstance(mode.value, str) else ("r" if mode is None else "b?")
            if "b" not in m:
                bad.append(f"{os.path.relpath(path, ROOT)}:{n.lineno}")
        elif name in ("run", "Popen", "check_output", "check_call") and kws & {"text", "universal_newlines"}:
            bad.append(f"{os.path.relpath(path, ROOT)}:{n.lineno}")
    return bad


class Bytes(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2bytes_")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_every_text_write_names_newline(self):
        bad = [b for p in PACKAGE_FILES for b in _text_writes_without_newline(os.path.join(ROOT, p))]
        self.assertEqual(bad, [])

    def test_every_text_call_in_the_repository_names_its_encoding(self):
        import glob
        files = [p for pat in ("*.py", "pqcrypto/*.py", "verifiers/*.py", "spec/vectors/ap2/*.py", "examples/*.py", "interop/*.py")
                 for p in glob.glob(os.path.join(ROOT, pat))]
        self.assertGreater(len(files), 40)
        self.assertEqual([b for p in files for b in _text_calls_without_encoding(p)], [])

    def test_the_encoding_check_sees_a_call_without_one(self):   # positive control of the reader above
        p = os.path.join(self.d, "probe.py")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write('import subprocess\nopen("x")\nopen("y", "w")\nopen("z", "rb")\nopen("v", encoding="utf-8")\n'
                    'subprocess.run(["a"], text=True)\nsubprocess.run(["a"], text=True, encoding="utf-8")\n')
        self.assertEqual([b.split(":")[-1] for b in _text_calls_without_encoding(p)], ["2", "3", "6"])

    def test_the_check_sees_a_write_without_newline(self):   # positive control of the reader above
        p = os.path.join(self.d, "probe.py")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write('import os\nopen("x", "w", encoding="utf-8")\nos.fdopen(3, "w")\nopen("y", "wb")\nos.open("z", 1)\n'
                    'open("v", "w", newline="")\nopen("r")\n')
        self.assertEqual(_text_writes_without_newline(p), ["probe.py:2", "probe.py:3"])

    def test_written_files_have_no_cr(self):
        pack = os.path.join(self.d, "pack.json")
        shutil.copy(VECTOR, pack)
        with open(pack, "rb") as f:   # the vector as checked out: a Git that converts line ends would put CR here
            raw = f.read()
        with open(pack, "wb") as f:
            f.write(raw.replace(b"\r\n", b"\n"))
        ident = A._sigsuite.ProducerIdentity.create()
        A.sign_evidence(pack, identity=ident)          # _write_pack_file
        key = os.path.join(self.d, "identity.json")
        ident.save(key)                                 # ProducerIdentity.save
        for p in (pack, key):
            with open(p, "rb") as f:
                data = f.read()
            self.assertIn(b"\n", data if p == pack else data + b"\n")
            self.assertNotIn(b"\r", data, p)
        self.assertTrue(A.verify_evidence(pack)["digest_ok"])

    def test_receipt_bytes_keep_lf(self):
        buf = io.BytesIO()
        stream = io.TextIOWrapper(buf, encoding="utf-8", newline="\n")
        with mock.patch.object(A.os, "linesep", "\r\n"):
            self.assertEqual(A._text_layer_bytes(stream, buf, '{\n "a": 1\n}\n'), b'{\n "a": 1\n}\n')

    def test_message_bytes_are_utf8_on_an_ansi_code_page(self):
        """Windows gives a pipe cp1252: "§" was written as 0xA7 there (CI run of 2026-11-24), not as the JS verifier writes it.
        Under PYTHONIOENCODING the encoding it names is kept (test_receipt_not_written covers those)."""
        buf = io.BytesIO()
        stream = io.TextIOWrapper(buf, encoding="cp1252", newline="\n")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONIOENCODING"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(A._text_layer_bytes(stream, buf, "SPEC \u00a79.1\n"), "SPEC \u00a79.1\n".encode("utf-8"))
        with mock.patch.dict(os.environ, dict(env, PYTHONIOENCODING="cp1252"), clear=True):
            self.assertEqual(A._text_layer_bytes(stream, buf, "\u00a7"), b"\xa7")

    def test_a_crashed_openssl_is_known_on_each_system(self):
        """SPEC §6.10: openssl that crashed gave no answer. POSIX: a signal, a negative exit. Windows has no signals: an
        NTSTATUS error as the exit code (0xC0000005), read up to 1.10.0 as openssl's answer."""
        self.assertTrue(A._crashed(-11))
        self.assertFalse(A._crashed(1) or A._crashed(127))
        with mock.patch.object(A.os, "name", "nt"):
            self.assertTrue(A._crashed(0xC0000005) and A._crashed(0xC0000409))
            self.assertFalse(A._crashed(1))
        with mock.patch.object(A.os, "name", "posix"):
            self.assertFalse(A._crashed(0xC0000005))
        self.assertEqual(A._crash_text(0xC0000005), "ended by exception 0xC0000005")
        self.assertEqual(A._crash_text(-11), "terminated by signal 11")

    def test_cli_receipt_has_no_cr(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "ap2_evidence.py"), "verify", VECTOR], capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(b"\r", p.stdout)
        self.assertTrue(json.loads(p.stdout.decode("ascii"))["valid"])


def _nested(n):
    return "[" * n + "]" * n


class Nesting(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ap2depth_")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        with open(os.path.join(ROOT, "spec", "vectors", "ap2", "key_material_not_used.json"), encoding="utf-8") as f:
            a0 = json.load(f)["artifacts"][0]
        self.compact, self.jwk = a0["sd_jwt_compact"], json.dumps(a0["key"]["jwk"])
        self.art = os.path.join(self.d, "a.sdjwt")
        with open(self.art, "w", encoding="utf-8", newline="\n") as f:
            f.write(self.compact)

    def _build_with_key(self, text):
        k = os.path.join(self.d, "k.json")
        with open(k, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        return subprocess.run([sys.executable, os.path.join(ROOT, "ap2_evidence.py"), "build", os.path.join(self.d, "o.json"),
                               "a=" + self.art, "--key", "a=" + k], capture_output=True, timeout=300)

    def test_key_file_past_the_bound_is_one_refusal_on_every_python(self):
        for n in (513, 600, 5000, 20000, 100000):
            with self.subTest(levels=n):
                p = self._build_with_key(self.jwk[:-1] + ', "zz": ' + _nested(n) + "}")
                self.assertEqual(p.returncode, 1, p.stderr[-300:])
                self.assertEqual(json.loads(p.stderr.decode("ascii")), {"error": "the pack would be refused by verify (SPEC "
                                 "\u00a73.1): json_too_deep: nesting exceeds 512 \u2014 not built"})
                self.assertFalse(os.path.exists(os.path.join(self.d, "o.json")))

    def test_key_file_within_the_bound_is_read(self):   # control: 511 levels pass the count and are parsed; the pack would
        p = self._build_with_key(self.jwk[:-1] + ', "zz": ' + _nested(511) + "}")   # nest deeper, so build refuses it as before
        self.assertEqual(p.returncode, 1, p.stderr[-300:])
        self.assertIn(b"json_too_deep", p.stderr)
        p = self._build_with_key(self.jwk)   # and the key itself builds
        self.assertEqual(p.returncode, 0, p.stderr[-300:])

    def test_jwks_past_the_bound_is_refused_with_one_reason(self):
        for n in (600, 5000, 100000):
            with self.subTest(levels=n):
                body = ('{"keys": ' + _nested(n) + "}").encode()
                with self.assertRaises(A.Ap2EvidenceError) as c:
                    self._resolve(body)
                self.assertIn("json_too_deep: nesting exceeds 512", str(c.exception))

    def test_jwks_not_json_control(self):   # control: the refusal of a body that is not JSON is unchanged
        with self.assertRaises(A.Ap2EvidenceError) as c:
            self._resolve(b"{not json")
        self.assertIn("JWKS body is not JSON: JSONDecodeError", str(c.exception))

    def _resolve(self, body):
        class _Body(io.BytesIO):
            def geturl(self):
                return "https://jwks.test/k"

            def __enter__(self):
                return self
        with mock.patch.object(urllib.request, "urlopen", lambda url, timeout=20: _Body(body)):
            return A._snapshot_key(A.parse_sd_jwt(self.compact), jwks_url="https://jwks.test/k")


if __name__ == "__main__":
    unittest.main()
