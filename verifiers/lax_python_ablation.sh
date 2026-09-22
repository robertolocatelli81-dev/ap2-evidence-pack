#!/bin/bash
# Ablation (README): a copy of the reference with the strict layers removed — file/JWT JSON via plain json.loads, lenient
# base64url (whitespace stripped, padding added), JWK coordinate length not checked — must turn test_ap2_conformance.py RED.
# If the suite stayed green the strictness would be untested. Exit 0 = ablation red (as required), 1 = suite still green.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); cp -r "$ROOT"/. "$T"; cd "$T"
python3 - <<'PY'
import re
s = open("ap2_evidence.py").read()
s = s.replace("def loads_strict(text: str):", "def loads_strict(text: str):\n    return json.loads(text)\n\ndef _loads_strict_unused(text):")
s = s.replace("def _loads_segment(raw: bytes, what: str):", "def _loads_segment(raw: bytes, what: str):\n    return json.loads(raw.decode('utf-8-sig'))\n\ndef _loads_segment_unused(raw, what):")
s = s.replace("def _b64url_decode(s: str) -> bytes:", "def _b64url_decode(s: str) -> bytes:\n    s = ''.join(str(s).split()).rstrip('='); return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))\n\ndef _b64url_decode_unused(s):")
s = s.replace("    if len(xb) != 32 or len(yb) != 32:", "    if False:")
open("ap2_evidence.py", "w").write(s)
PY
python3 -B -m unittest test_ap2_conformance > "$T/ablation.log" 2>&1; rc=$?
grep -E "^(FAIL|ERROR):" "$T/ablation.log" | sort | uniq -c
tail -1 "$T/ablation.log"; rm -rf "$T"
if [ $rc -ne 0 ]; then echo "ablation RED as required (the strict layers are what the tests measure)"; exit 0; else echo "ablation GREEN: the tests do not measure the strict layers"; exit 1; fi
