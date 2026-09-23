#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Every malformed input must produce a VERDICT, never a crash — checked by substituting types into every field.

Why this exists. The third-verifier cross-check (`sdk_crosscheck.py`) measured that when the `sd-jwt` reference
implementation refuses one of these hostile packs, 10 of its 17 refusals are uncaught internal errors — a
`JSONDecodeError`, a `'str' object has no attribute 'get'`, a failed tuple unpack — rather than a refusal it meant to
make. Those fail closed in effect, and they are not this repository's code to fix. What IS this repository's business
is whether the same class lives here: a verifier that raises instead of answering hands the caller a stack trace where
a receipt was promised, and an operator who sees a traceback learns nothing about the evidence.

The property: for every field of a valid pack, replaced by each of eight hostile types, both verifiers must print a
JSON verdict on stdout (or a bare usage, exit 2 with nothing on stdout). A traceback, a silent exit, a partial write:
all failures.

The positive control runs first and is not optional. A deliberately broken verifier — one that calls `.get()` on
whatever `subject` happens to be — must be caught by this same harness; if it is not, the harness proves nothing about
the real ones and exits 2 without even measuring them.

    python3 verifiers/type_fuzz.py [--quick]
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTOR = os.path.join(ROOT, "spec", "vectors", "ap2", "valid_signed.json")
PY = [sys.executable, os.path.join(ROOT, "ap2_evidence.py"), "verify"]
JS = ["node", os.path.join(ROOT, "verifiers", "js", "ap2-verify.mjs")]

# Four of these are the shapes that actually crashed the third stack, measured on its ten uncaught errors: `null`
# ('NoneType' object is not iterable), a string and a list ('str'/'list' object has no attribute 'get', plus the two
# failed tuple unpacks). The other four — a number, a boolean, a float where an integer belongs, a lone surrogate —
# are added here because they are this format's own edge cases, not because they were observed to crash anything.
HOSTILE_TYPES = [None, 0, "", [], {}, True, 1.5, "\ud800"]

CRASHY = '''import json, sys
ev = json.load(open(sys.argv[-1], encoding="utf-8"))
print(json.dumps({"valid": ev["subject"].get("x", False)}))
'''


def field_paths(obj, prefix=""):
    """Every addressable field of the pack. Arrays are probed at their first two positions: the third adds no shape."""
    out = [prefix] if prefix else []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += field_paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:2]):
            out += field_paths(v, f"{prefix}[{i}]")
    return out


def set_path(obj, path, value):
    parts = []
    for tok in path.split("."):
        m = re.match(r"([^\[]*)((\[\d+\])*)$", tok)
        if m.group(1):
            parts.append(m.group(1))
        for idx in re.findall(r"\[(\d+)\]", m.group(2) or ""):
            parts.append(int(idx))
    cur = obj
    for step in parts[:-1]:
        cur = cur[step]
    cur[parts[-1]] = value


def answered(cmd, path):
    """True when the command produced a verdict or a bare usage; False when it crashed or said nothing."""
    try:
        r = subprocess.run(list(cmd) + [path], capture_output=True, text=True, timeout=120)
    except Exception:   # noqa: BLE001
        return False, "the process did not finish"
    try:
        verdict = json.loads(r.stdout)
    except Exception:   # noqa: BLE001
        if r.returncode == 2 and r.stdout == "":
            return True, "usage"
        last = (r.stderr or "").strip().splitlines()
        return False, (last[-1][:100] if last else f"exit {r.returncode}, nothing on stdout")
    # Parsed stdout is not yet a verdict: `null` and `"x"` parse too. And a process can print the whole receipt and
    # THEN raise, leaving the traceback on stderr — counting that as an answer is what this docstring forbids.
    if not (isinstance(verdict, dict) and isinstance(verdict.get("valid"), bool)):
        return False, f"stdout parsed but carries no boolean `valid`: {str(verdict)[:60]}"
    if (r.stderr or "").strip():
        return False, f"verdict printed, but stderr is not empty: {r.stderr.strip().splitlines()[-1][:80]}"
    return True, ""


def run(cmds, base, types, tmp):
    bad, n, skipped, unchanged, usage = [], 0, 0, 0, 0
    for p in field_paths(base):
        for v in types:
            ev = copy.deepcopy(base)
            try:
                set_path(ev, p, v)
            except Exception:   # noqa: BLE001
                skipped += 1   # a path this harness cannot address is a mutation never attempted, never dropped in silence
                continue
            if ev == base:
                unchanged += 1   # `True` where `true` already stood is a run on the valid pack, not a hostile mutation
                continue
            f = os.path.join(tmp, "mutated.json")
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(ev))
            n += 1
            for label, cmd in cmds:
                ok, why = answered(cmd, f)
                if why == "usage":
                    usage += 1
                if not ok:
                    bad.append((label, p, repr(v)[:16], why))
    return n, bad, skipped, unchanged, usage


def main(argv):
    base = json.load(open(VECTOR, encoding="utf-8"))
    types = HOSTILE_TYPES[:3] if "--quick" in argv else HOSTILE_TYPES
    tmp = tempfile.mkdtemp()
    try:
        crashy = os.path.join(tmp, "crashy.py")
        with open(crashy, "w", encoding="utf-8") as fh:
            fh.write(CRASHY)
        # The ablated verifier raises exactly when `subject` is not an object, so the control mutates that one field:
        # a control that also fires on 700 unrelated mutations would say less, not more.
        control = {"subject": base["subject"]}
        n_c, caught = run([("ablated", [sys.executable, crashy])], control, HOSTILE_TYPES, tmp)[:2]
        print(f"positive control: a deliberately crashing verifier is caught on {len(caught)} of {n_c} mutations "
              f"of `subject` (the one field it mishandles)")
        # EXACT, not "at least one": a harness degraded to seeing a single crash out of eight would pass `if not caught`
        # while having lost most of its sight.
        if len(caught) != n_c - 1:
            print(f"the control caught {len(caught)}, not the {n_c - 1} that verifier must produce: this harness "
                  "cannot be trusted to see a crash, so nothing is measured")
            return 2

        n, bad, skipped, unchanged, usage = run([("python", PY), ("node", JS)], base, types, tmp)
        print(f"{n} hostile mutations of {len(field_paths(base))} fields x {len(types)} types, two verifiers each "
              f"({unchanged} substitutions left the pack identical to the valid one and are not counted, "
              f"{skipped} paths could not be addressed, {usage} answers were a bare usage)")
        if skipped:
            print("a path this harness cannot address is a hole in its own denominator")
            return 1
        for label, p, v, why in bad:
            print(f"  [CRASH] {label:7} {p} := {v}  -> {why}")
        print(f"inputs answered with a verdict instead of a crash: {2 * n - len(bad)}/{2 * n}")
        return 1 if bad else 0
    finally:
        import shutil    # noqa: PLC0415
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
