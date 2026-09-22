#!/bin/bash
# Ablation (README): each strict layer of the reference removed ALONE from a copy — (1) file-level strict JSON (at its use site in
# read_evidence_file, so the JWT layer stays strict), (2) JWT-level strict
# JSON, (3) strict base64url, (4) JWK coordinate length — must turn test_ap2_conformance.py RED by itself (causality per layer,
# not a joint ablation). Exit 0 = every layer red as required; exit 1 = some layer left the suite green (that layer is untested).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd); rc_all=0
for L in file_json jwt_json b64url jwk_len; do
  T=$(mktemp -d); cp -r "$ROOT"/. "$T"; cd "$T"
  python3 - "$L" <<'PY'
import sys; L = sys.argv[1]; s = open("ap2_evidence.py").read(); n = len(s)
if L == "file_json": s = s.replace("    ev = loads_strict(text)", "    ev = json.loads(text)")   # r5: at the USE SITE — patching loads_strict itself also ablated the JWT layer (_loads_segment delegates to it), so the layers were not isolated
if L == "jwt_json": s = s.replace("def _loads_segment(raw: bytes, what: str):", "def _loads_segment(raw: bytes, what: str):\n    return json.loads(raw.decode('utf-8-sig'))\n\ndef _ablated_2(raw, what):")
if L == "b64url": s = s.replace("def _b64url_decode(s: str) -> bytes:", "def _b64url_decode(s: str) -> bytes:\n    s = ''.join(str(s).split()).rstrip('=').replace('+', '-').replace('/', '_'); return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))\n\ndef _ablated_3(s):")
if L == "jwk_len": s = s.replace("    if len(xb) != 32 or len(yb) != 32:", "    if False:")
assert len(s) != n, "ablation anchor not found: " + L
open("ap2_evidence.py", "w").write(s)
PY
  python3 -B -m unittest test_ap2_conformance > "$T/ablation.log" 2>&1; rc=$?
  printf "%-10s %s  %s\n" "$L" "$(tail -1 "$T/ablation.log")" "$(grep -E '^(FAIL|ERROR):' "$T/ablation.log" | sed 's/ (.*//' | sort -u | tr '\n' ' ')"
  if [ $rc -eq 0 ]; then echo "  -> GREEN: layer $L is not measured by the suite"; rc_all=1; fi
  cd "$ROOT"; rm -rf "$T"
done
if [ $rc_all -eq 0 ]; then echo "ablation: every strict layer RED alone, as required"; else echo "ablation: a layer stayed GREEN"; fi
exit $rc_all
