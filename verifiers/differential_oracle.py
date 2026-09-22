#!/usr/bin/env python3
"""Differential oracle over the ap2-evidence-pack verifiers: the Python reference (`ap2_evidence.py verify`) and the
independent Node verifier (`verifiers/js/ap2-verify.mjs`) must give the same (valid, digest_ok, bindings_ok, producer_ok,
pq_protected, rfc3161_verified, policy_ok) on every case: the shipped conformance vectors under their declared policy,
hostile files that a lenient verifier would accept (every one carries a digest recomputed the way that verifier would),
and a CLI-grammar table (usage exit 2, no verdict, in both). Exit 1 on any disagreement. 1.1.0 (2026-09-22): the cases
were measured red on the 1.0.2 reference first (see README)."""
import base64, copy, glob, hashlib, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
PY = [sys.executable, "-B", os.path.join(ROOT, "ap2_evidence.py"), "verify"]
JS = ["node", os.path.join(HERE, "js", "ap2-verify.mjs")]
KEYS = ("valid", "digest_ok", "bindings_ok", "producer_ok", "pq_protected", "rfc3161_verified", "policy_ok")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def rehash(ev, canon_fn=canon):
    e2 = {k: v for k, v in ev.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    ev = dict(ev); ev["evidence_digest_sha256"] = hashlib.sha256(canon_fn(e2)).hexdigest(); ev.pop("producer_signatures", None); return ev


def _der(tag, body):
    n = len(body); lb = bytes([n]) if n < 128 else bytes([0x82, n >> 8, n & 0xFF]); return bytes([tag]) + lb + body


def _forged_tsr(digest):
    tst = _der(0x30, _der(0x02, b"\x01") + _der(0x06, bytes.fromhex("2a03")) + _der(0x30, _der(0x30, _der(0x06, bytes.fromhex("608648016503040201"))) + _der(0x04, digest)) + _der(0x02, b"\x01") + _der(0x18, b"20260922100000Z"))
    eci = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010904")) + _der(0xA0, _der(0x04, tst)))
    sd = _der(0x30, _der(0x02, b"\x03") + _der(0x31, b"") + eci + _der(0x31, b""))
    return _der(0x30, _der(0x30, _der(0x02, b"\x00")) + _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010702")) + _der(0xA0, sd)))


# Declared divergence: TSA signature/chain verification needs openssl (Python only); the JS verifier reports tsa_verified null
# and under --require-anchor --tsa-cert does NOT pass (policy_ok false) — the same verdict, one different field.
DECLARED = {"vector-anchor_valid-tsa-cert": {"py": (True, True, True, True, True, True, True), "js": (False, True, True, True, True, True, False)}}   # only the REAL token differs: Python proves the TSA, JS cannot


def flags_for(policy):
    fl = []
    for alg, keys in (policy.get("trusted_producer_keys") or {}).items():
        for k in ([keys] if isinstance(keys, str) else keys):
            fl += ["--trusted-producer-key", f"{alg}={k}"]
    for name in ("require_producer", "require_pq", "require_anchor"):
        if policy.get(name):
            fl.append("--" + name.replace("_", "-"))
    return fl


def run(cmd, path, flags):
    try:
        out = subprocess.run(list(cmd) + [path] + flags, capture_output=True, text=True, timeout=120)
        r = json.loads(out.stdout); prod = r.get("producer_signatures") or {}
        return (r.get("valid"), r.get("digest_ok"), r.get("bindings_ok"), prod.get("ok"), r.get("pq_protected"), (r.get("rfc3161") or {}).get("verified"), r.get("policy_ok"))
    except Exception:  # noqa: BLE001
        return ("NONJSON/CRASH:" + os.path.basename(cmd[-1] if cmd[-1] != "verify" else cmd[-2]),) * 7   # distinct per verifier: two crashes never agree


def build_cases(d):
    cases = {}
    vdir = os.path.join(ROOT, "spec", "vectors", "ap2")
    for exp_path in sorted(glob.glob(os.path.join(vdir, "*.expected.json"))):
        exp = json.load(open(exp_path)); name = exp["vector"]
        cases["vector-" + name] = (os.path.join(vdir, name + ".json"), flags_for(exp.get("policy", {})))
    base_text = open(os.path.join(vdir, "valid_signed.json"), encoding="utf-8").read(); base = json.loads(base_text)
    def w(name, data):
        p = os.path.join(d, name + ".json"); open(p, "wb").write(data if isinstance(data, bytes) else data.encode("utf-8")); return p
    # 1.1.0 profile cases: each hostile file carries the digest a lenient verifier would recompute, so the profile rule decides
    cases["proto-key-digest-untouched"] = (w("proto", '{"__proto__": {"evil": 1}, ' + base_text.lstrip()[1:]), [])
    ev = rehash(dict(base, subject="x�")); cases["raw-byte-hashed-as-fffd"] = (w("fffd", json.dumps(ev, ensure_ascii=False).encode("utf-8").replace("�".encode("utf-8"), b"\xff", 1)), [])
    cases["non-ascii-subject-rehashed"] = (w("nonascii", json.dumps(rehash(dict(base, subject="café ≥ 1 😀")), ensure_ascii=False)), [])   # in profile: PASS both
    cases["float-1.0-rehashed"] = (w("float", json.dumps(rehash(dict(base, extra=1.0)))), [])
    cases["int-2^53+1-rehashed"] = (w("bigint", json.dumps(rehash(dict(base, extra=9007199254740993)))), [])
    cases["deep-100000"] = (w("deep", "[" * 100000), [])
    cases["nan-constant"] = (w("nan", base_text.replace('"created_utc"', '"x": NaN, "created_utc"', 1)), [])
    lone = dict(base, subject="\ud800"); e2 = {k: v for k, v in lone.items() if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    lone["evidence_digest_sha256"] = hashlib.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode("utf-8", "surrogatepass")).hexdigest(); lone.pop("producer_signatures", None)
    cases["lone-surrogate-rehashed"] = (w("lone", json.dumps(lone)), [])
    dup = rehash(base); txt = json.dumps(dup); cases["dup-key-same-value"] = (w("dup", txt[:-1] + ',"subject":' + json.dumps(dup["subject"]) + "}"), [])
    cases["digest-uppercase"] = (w("upper", json.dumps(dict(base, evidence_digest_sha256=base["evidence_digest_sha256"].upper()))), [])
    cases["artifacts-empty"] = (w("empty", json.dumps(rehash(dict(base, artifacts=[], bindings=[])))), [])
    cases["bom-prefixed"] = (w("bom", "﻿" + base_text), [])
    cases["not-an-object"] = (w("list", "[1]"), [])
    # SD-JWT segment shapes on the BINDER artifact (`cart`, index 1 — mutating the bound `intent` would flip bindings_ok for
    # every verifier and hide the base64url rule, review r1); digest recomputed so only the artifact layer decides
    binder = next(i for i, a in enumerate(base["artifacts"]) if a["name"] == "cart")
    c = base["artifacts"][binder]["sd_jwt_compact"]; parts = c.split("~"); h, p_, s_ = parts[0].split(".")
    for nm, sig in (("sig-b64url-space", s_[:10] + " " + s_[10:]), ("sig-b64url-padded", s_ + "=="), ("sig-b64url-plus", s_.replace("-", "+", 1) if "-" in s_ else s_[:-1] + "+")):
        e = copy.deepcopy(base); pp = parts[:]; pp[0] = ".".join([h, p_, sig]); e["artifacts"][binder]["sd_jwt_compact"] = "~".join(pp); cases[nm] = (w(nm, json.dumps(rehash(e))), [])
    # review r1: top-level field SHAPES (Python raised TypeError/AttributeError; JS answered), empty producer block, lenient
    # tsr_b64 / JWK coordinates, deep JWT header, non-object payload, trailing NBSP on the compact serialization
    for nm, mut in (("artifacts-null", lambda e: e.__setitem__("artifacts", None)), ("artifacts-string", lambda e: e.__setitem__("artifacts", "x")),
                    ("artifacts-list-of-null", lambda e: e.__setitem__("artifacts", [None])), ("key-null", lambda e: e["artifacts"][0].__setitem__("key", None)),
                    ("jwk-list", lambda e: e["artifacts"][0]["key"].__setitem__("jwk", [1])), ("rfc3161-null", lambda e: e.__setitem__("rfc3161_timestamp", None)),
                    ("rfc3161-string", lambda e: e.__setitem__("rfc3161_timestamp", "x")), ("producer-string", lambda e: e.__setitem__("producer_signatures", "x")),
                    ("producer-empty-object", lambda e: e.__setitem__("producer_signatures", {})), ("producer-list", lambda e: e.__setitem__("producer_signatures", [])),
                    ("producer-signatures-list-of-null", lambda e: e.__setitem__("producer_signatures", {"signatures": [None]}))):
        e = copy.deepcopy(base); mut(e); cases[nm] = (w(nm, json.dumps(e)), [])
    e = copy.deepcopy(base); e["bindings"] = None; cases["bindings-null-rehashed"] = (w("bnull", json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); pp = parts[:]; pp[0] = ".".join([h, "W10", s_]); e["artifacts"][binder]["sd_jwt_compact"] = "~".join(pp); cases["payload-list-rehashed"] = (w("plist", json.dumps(rehash(e))), [])
    deep = base64.urlsafe_b64encode(("[" * 100000).encode()).decode().rstrip("="); e = copy.deepcopy(base); pp = parts[:]; pp[0] = ".".join([deep, p_, s_]); e["artifacts"][binder]["sd_jwt_compact"] = "~".join(pp); cases["header-deep-rehashed"] = (w("hdeep", json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["artifacts"][binder]["sd_jwt_compact"] = c + "\u00a0"; cases["compact-trailing-nbsp-rehashed"] = (w("nbsp", json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["artifacts"][binder]["key"]["jwk"]["x"] = e["artifacts"][binder]["key"]["jwk"]["x"] + "="; cases["jwk-x-padded-rehashed"] = (w("jwkpad", json.dumps(rehash(e))), [])
    av = json.load(open(os.path.join(vdir, "anchor_valid.json"))); e = copy.deepcopy(av); t = e["rfc3161_timestamp"]["tsr_b64"]; e["rfc3161_timestamp"]["tsr_b64"] = t[:10] + " " + t[10:]; cases["tsr-b64-space"] = (w("tsrsp", json.dumps(e)), [])
    # a self-forged TimeStampResp (status 0, imprint = digest, no signer): binding holds, TSA does not — declared divergence under --tsa-cert
    forged = _forged_tsr(bytes.fromhex(base["evidence_digest_sha256"]))
    e = dict(base); e["rfc3161_timestamp"] = {"anchored": True, "tsa_url": "forged", "tsr_b64": base64.b64encode(forged).decode()}
    cases["tsr-self-forged-binding-only"] = (w("forged", json.dumps(e)), ["--require-anchor"])
    cases["tsr-self-forged-tsa-cert"] = (w("forged2", json.dumps(e)), ["--require-anchor", "--tsa-cert", os.path.join(vdir, "anchor_probe_tsa.crt")])
    cases["vector-anchor_valid-tsa-cert"] = (os.path.join(vdir, "anchor_valid.json"), ["--require-anchor", "--tsa-cert", os.path.join(vdir, "anchor_probe_tsa.crt")])
    e = copy.deepcopy(base); e["artifacts"][0]["resolved_claims"]["extra"] = "x"; cases["claims-mismatch-rehashed"] = (w("claims", json.dumps(rehash(e))), [])
    e = copy.deepcopy(base); e["bindings"] = []; cases["bindings-dropped-rehashed"] = (w("bind", json.dumps(rehash(e))), [])
    # producer block shapes
    e = copy.deepcopy(base); e["producer_signatures"]["signatures"][0]["signature_b64"] = e["producer_signatures"]["signatures"][0]["signature_b64"][:8] + " " + e["producer_signatures"]["signatures"][0]["signature_b64"][8:]; cases["producer-sig-b64-space"] = (w("psp", json.dumps(e)), [])
    e = copy.deepcopy(base); e["producer_signatures"]["signatures"].append({"sig_alg": "rsa-pss", "public_key_b64": "AA==", "signature_b64": "AA==", "post_quantum": False}); cases["producer-unknown-alg"] = (w("punk", json.dumps(e)), [])
    e = copy.deepcopy(base); e["producer_signatures"]["signatures"] = e["producer_signatures"]["signatures"][:1]; cases["producer-pq-stripped-required"] = (w("pstr", json.dumps(e)), ["--require-pq", "--trusted-producer-key", "ed25519=" + e["producer_signatures"]["signatures"][0]["public_key_b64"]])
    return cases


CLI = {"cli-no-path": [], "cli-unknown-flag": ["V", "--no-such"], "cli-two-positionals": ["V", "V"], "cli-empty-path": [""], "cli-help": ["--help"], "cli-h": ["-h"],
       "cli-double-dash": ["--", "V"], "cli-bool-with-value": ["V", "--require-pq=1"], "cli-key-empty": ["V", "--trusted-producer-key", ""], "cli-key-missing-value": ["V", "--trusted-producer-key"],
       "cli-key-flag-as-value": ["V", "--trusted-producer-key", "--require-pq"], "cli-key-no-alg": ["V", "--trusted-producer-key", "abc"], "cli-tsa-cert-empty": ["V", "--tsa-cert", ""], "cli-repeated-key-empty-first": ["V", "--trusted-producer-key", "", "--trusted-producer-key", "ed25519=AA=="],
       "cli-eq-form-verdict": ["V", "--trusted-producer-key=ed25519=AA=="]}


def main():
    if not shutil.which("node"):
        print("node absent: the JS verifier cannot be measured"); return 2
    tmp = tempfile.mkdtemp(); diffs = 0; n = 0
    try:
        cases = build_cases(tmp)
        declared = 0
        for name, (path, flags) in cases.items():
            py, js = run(PY, path, flags), run(JS, path, flags); n += 1
            if name in DECLARED and (py, js) == (DECLARED[name]["py"], DECLARED[name]["js"]):
                declared += 1; print(f"  [DECL] {name:34} py={py} js={js}  <- declared: TSA verification is openssl-only"); continue
            ok = py == js; diffs += 0 if ok else 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:34} py={py} js={js}")
        valid = os.path.join(ROOT, "spec", "vectors", "ap2", "valid_signed.json")
        for name, argv in CLI.items():
            args = [valid if a == "V" else a for a in argv]; row = {}
            for k, cmd in (("py", PY[:-1]), ("js", JS)):
                full = list(cmd) + (["verify"] if k == "py" else []) + args
                try:
                    out = subprocess.run(full, capture_output=True, text=True, timeout=60)
                    try: row[k] = "verdict:" + str(json.loads(out.stdout).get("valid"))
                    except Exception: row[k] = "usage" if out.returncode == 2 else f"exit{out.returncode}"
                except Exception: row[k] = "CRASH"
            want = "verdict:False" if name.endswith("-verdict") else "usage"   # the eq-form pins an unknown key: a verdict (not authentic), not usage
            ok = all(v == want for v in row.values()); diffs += 0 if ok else 1; n += 1
            print(f"  [{'OK ' if ok else 'DIFF'}] {name:34} expect {want}: {row}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"disagreements: {diffs}/{n} (declared: {declared})"); return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
