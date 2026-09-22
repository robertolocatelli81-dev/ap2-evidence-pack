#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ap2-evidence-pack — dispute evidence for agentic-payment mandates (standalone).

SPDX-License-Identifier: Apache-2.0
Copyright 2026 Roberto Locatelli

Relicensed by the copyright holder from the AGPL original in the OMEGA/CryptoValid
repository, to match the Apache-2.0 licensing of the AP2 ecosystem.

WHY (measured, 2026-08-21): the AP2 spec (Agent Payments Protocol, ap2-protocol.org) tells
implementers WHAT to keep for dispute resolution — "storing the SD-JWTs, along with their
disclosures, for the Mandates in their compact serialization" — but not HOW: no retention
mechanics, no issuer-key snapshotting, no long-term validation, no tamper-evidence; mandate
retrieval is declared outside the scope. An ECDSA JWT is verifiable at dispute time ONLY if
the issuer's key material is still resolvable; years later JWKS endpoints die and keys rotate.

WHAT THIS IS (deliberately thin — an adversarial review killed the "full vault" idea):
a library + CLI that turns a set of AP2-style SD-JWT mandates into ONE self-contained
evidence file that verifies OFFLINE years later:
  - parses SD-JWT compact serialization (issuer-JWT ~ disclosure* ~ [kb-jwt]) and resolves
    selective disclosures fail-closed (unmatched/duplicate/malformed disclosure -> reject);
  - verifies the ES256 (ECDSA P-256) signature and SNAPSHOTS the key material used, tagging
    it with an explicit PROVENANCE CLASS instead of pretending all captures are equal:
      x5c_header          key from the JWT's x5c leaf cert (chain recorded, PKI path NOT
                          validated to a trust anchor here — declared)
      jwk_header          key embedded in the protected header (self-asserted)
      supplied            key material handed in by the caller (caller vouches)
      jwks_fetched        key fetched from an https JWKS URL at build time (TLS witness
                          at capture — a witness, not a proof of issuer control)
  - discovers hash BINDINGS between artifacts (e.g. a cart mandate committing to the
    checkout_jwt) by recomputing sha-256 over each artifact's exact compact serialization
    and matching it against every string claim of the others — the primary quantity,
    not a proxy field;
  - seals everything into a canonical JSON evidence file with a SHA-256 digest and an
    OPTIONAL RFC 3161 timestamp (inlined TSA client; re-check = binding, plus the TSA's
    signature/chain with `--tsa-cert`), so the "key material existed and verified at
    time T" claim can be anchored to a third party.

HONEST SCOPE: proves that these exact artifacts, with this key material, verified at
build time, and (if stamped and the TSA verified against its certificate) that all of
it existed at the TSA's time — offline,
vendor-free, years later. It does NOT prove the issuer authorised the key (that is the
provenance class's job to DECLARE), does NOT confer eIDAS art. 45j qualified-archive legal
presumption (a QTSP service does), and does NOT validate x5c chains to a trust anchor.
ES256 only, by design; other algs are rejected loudly, never half-verified.

Usage:
  python3 ap2_evidence.py build out.json intent=intent.sdjwt cart=cart.sdjwt \
          [--key name=jwk.json] [--jwks-url name=https://...] [--tsa URL]
  python3 ap2_evidence.py verify out.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "pqcrypto"))
import sigsuite as _sigsuite  # noqa: E402  (crypto-agile hybrid classical + ML-DSA-65 producer signatures)

EVIDENCE_FORMAT = "ap2-evidence-pack/1.0"

HONEST_SCOPE = (
    "Proves: these exact SD-JWT artifacts, with the snapshotted key material (see each "
    "key's provenance_class), verified at build time; the RFC 3161 token (if present) "
    "anchors their existence to the TSA's clock. Does NOT prove the issuer authorised "
    "the key beyond what the provenance class states, does NOT confer eIDAS qualified-"
    "archive legal presumption, does NOT validate x5c chains to a trust anchor, and "
    "never proves the truth of the recorded transaction itself. When a producer signature is present, it protects THIS pack integrity, and authenticity ONLY for a relying party that has PINNED the producer public key out of band (an embedded key alone proves consistency, not authenticity), across the retention window (hybrid: a classical signature + FIPS-204 ML-DSA-65, surviving the quantum transition per NIST IR 8547); it does NOT retro-protect the underlying ES256 mandate signature - for the existed-before-a-quantum-adversary claim you still need a trusted time anchor (RFC 3161 / RFC 4998 renewal). 'valid' means each "
    "artifact verifies and the file is intact — NOT that the mandates form a bound "
    "chain (read `bindings`) nor that self-asserted keys prove issuer identity (read "
    "`provenance_classes`/`self_asserted_only`). KB-JWT holder binding is verified "
    "when the issuer payload carries cnf.jwk; without cnf.jwk it is recorded as "
    "present-but-unverifiable, never painted green. KB-JWT aud/nonce/iat are RECORDED "
    "for the auditor, not validated — their expected values are transaction context "
    "this tool cannot know offline.")


class Ap2EvidenceError(ValueError):
    """Fail-closed parse/verify error (message is auditor-readable, never a traceback)."""


# ────────────────────────────────────────────────────────── b64url / hashing

def _no_dup_pairs(pairs):
    """Reject duplicate JSON object keys: a crafted pack could otherwise carry two
    values for one key (parser keeps the last) so its meaning diverges from its digest."""
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Ap2EvidenceError(f"duplicate JSON key {k!r} (rejected fail-closed)")
        seen[k] = v
    return seen


# ── acceptance profile of the evidence file (1.1.0; SPEC §3): what cannot be re-serialised byte for byte by every
# JSON implementation is refused, so a third-party verifier computes the same canonical bytes or refuses the same file.
MAX_JSON_DEPTH = 512
MAX_EVIDENCE_BYTES = 64 << 20
_SAFE_INT = (1 << 53) - 1


def _no_float(text: str):
    raise Ap2EvidenceError(f"float {text!r} in the evidence file (not portable: use a string)")


def _bounded_int(text: str) -> int:
    v = int(text)
    if abs(v) > _SAFE_INT:
        raise Ap2EvidenceError("integer outside the portable range +/-(2^53-1)")
    return v


def _no_constant(name: str):
    raise Ap2EvidenceError(f"non-JSON constant {name}")


def _nesting_depth(text: str) -> int:
    depth = mx = 0; in_str = esc = False
    for ch in text:
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == '"': in_str = False
        elif ch == '"': in_str = True
        elif ch in "[{":
            depth += 1; mx = max(mx, depth)
        elif ch in "]}": depth -= 1
    return mx


def _hex4(s: str, i: int):
    h = s[i:i + 4]
    return int(h, 16) if len(h) == 4 and all(c in "0123456789abcdefABCDEF" for c in h) else None


def _has_lone_surrogate(text: str) -> bool:
    i, n = 0, len(text)
    while i < n:
        if text[i] != "\\":
            i += 1; continue
        if i + 1 < n and text[i + 1] == "u" and i + 5 < n:
            cp = _hex4(text, i + 2)
            if cp is None:
                i += 2; continue
            if 0xD800 <= cp <= 0xDBFF:
                if i + 7 >= n or text[i + 6] != "\\" or text[i + 7] != "u": return True
                lo = _hex4(text, i + 8)
                if lo is None or not (0xDC00 <= lo <= 0xDFFF): return True
                i += 12; continue
            if 0xDC00 <= cp <= 0xDFFF: return True
            i += 6; continue
        i += 2
    return False


def loads_strict(text: str):
    """Strict JSON for the evidence file: no duplicate keys, no floats, integers within +/-(2^53-1), no NaN/Infinity,
    nesting <= 512 by linear pre-scan, no lone UTF-16 surrogate escape. Raises Ap2EvidenceError."""
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise Ap2EvidenceError(f"json_too_deep: nesting exceeds {MAX_JSON_DEPTH}")
    if _has_lone_surrogate(text):
        raise Ap2EvidenceError("lone_surrogate: unpaired UTF-16 surrogate escape")
    try:
        return json.loads(text, object_pairs_hook=_no_dup_pairs, parse_float=_no_float, parse_int=_bounded_int, parse_constant=_no_constant)
    except RecursionError as e:
        raise Ap2EvidenceError("json_too_deep") from e
    except ValueError as e:
        if isinstance(e, Ap2EvidenceError): raise
        raise Ap2EvidenceError(f"not JSON: {str(e)[:80]}") from e


def read_evidence_file(path: str):
    """Read + decode + parse the evidence file under the profile. UTF-8 strict (a raw byte is a refusal, never U+FFFD),
    a size bound before reading, an unreadable path is a refusal — all Ap2EvidenceError, never a traceback."""
    try:
        if os.path.getsize(path) > MAX_EVIDENCE_BYTES:
            raise Ap2EvidenceError(f"evidence file exceeds {MAX_EVIDENCE_BYTES} bytes")
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise Ap2EvidenceError(f"unreadable evidence file: {type(e).__name__}") from e
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Ap2EvidenceError("evidence file is not valid UTF-8") from e
    if text.startswith("\ufeff"):
        raise Ap2EvidenceError("evidence file starts with a BOM")
    ev = loads_strict(text)
    if not isinstance(ev, dict):
        raise Ap2EvidenceError("evidence file is not a JSON object")
    return ev


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _loads_segment(raw: bytes, what: str):
    """JWT-level JSON (header, payload, disclosure, KB-JWT) under the SAME profile as the evidence file (SPEC §3.1): strict
    UTF-8, no BOM, no duplicate keys, no floats/NaN, bounded integers, bounded depth. 1.1.0 r2: the reference used
    `json.loads` here (last duplicate key wins, BOM skipped) while the JS verifier was strict — a signed payload
    `{"amount":"1","amount":"999"}` certified "999" in one verifier and was refused in the other."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Ap2EvidenceError(f"{what} is not valid UTF-8") from e
    if text.startswith("\ufeff"):
        raise Ap2EvidenceError(f"{what} starts with a BOM")
    return loads_strict(text)


def _b64url_decode(s: str) -> bytes:
    """RFC 7515 base64url, strict: alphabet only, no padding, no whitespace, canonical trailing bits (1.1.0: whitespace was
    stripped and padding added silently, so a segment could be spelled several ways for one meaning)."""
    if not isinstance(s, str) or not s or any(c not in _B64URL for c in s) or len(s) % 4 == 1:
        raise Ap2EvidenceError("invalid base64url segment")
    pad = -len(s) % 4
    try:
        raw = base64.urlsafe_b64decode(s + "=" * pad)
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"invalid base64url segment: {type(e).__name__}") from e
    if _b64url(raw) != s:
        raise Ap2EvidenceError("non-canonical base64url segment (trailing bits)")
    return raw


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sha256_b64url(data: bytes) -> str:
    return _b64url(hashlib.sha256(data).digest())


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ────────────────────────────────────────────────────────── SD-JWT parsing

def parse_sd_jwt(compact: str) -> Dict:
    """Split an SD-JWT compact serialization: <jwt>~<disclosure>*~[<kb-jwt>].
    A trailing '~' means no key-binding JWT. Returns raw parts, decoded header/payload."""
    compact = compact.strip()
    if "~" in compact:
        parts = compact.split("~")
        jwt, middle, kb = parts[0], parts[1:-1], parts[-1] or None
    else:
        jwt, middle, kb = compact, [], None
    seg = jwt.split(".")
    if len(seg) != 3:
        raise Ap2EvidenceError("issuer JWT must have 3 dot-separated segments")
    try:
        header = _loads_segment(_b64url_decode(seg[0]), "JWT header")
        payload = _loads_segment(_b64url_decode(seg[1]), "JWT payload")
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"JWT header/payload not valid JSON/base64url: {e}") from e
    return {"compact": compact, "jwt": jwt, "header": header, "payload": payload,
            "signature": _b64url_decode(seg[2]),
            "signing_input": f"{seg[0]}.{seg[1]}".encode("ascii"),
            "disclosures": [d for d in middle if d], "kb_jwt": kb}


def _disclosure_digest(disclosure_b64: str) -> str:
    # SD-JWT: digest = b64url(sha-256(ASCII of the base64url-encoded disclosure))
    return _sha256_b64url(disclosure_b64.encode("ascii"))


def resolve_disclosures(payload: Dict, disclosures: List[str]) -> Dict:
    """Replace _sd digests / '...' array placeholders with the disclosed claims.
    Fail-closed: duplicate digests, malformed disclosures, or disclosures that match
    nothing are ERRORS (per SD-JWT processing rules), never silently ignored."""
    # 1.1.0 r2: the SHAPE of the SD-JWT fields is imposed (present-with-null is not absent — `dict.get(k, default)` and
    # JS `??` disagreed): `_sd_alg` absent or exactly "sha-256"; `_sd` absent or a list of strings; `{"...": x}` with x a string
    if "_sd_alg" in payload and payload["_sd_alg"] != "sha-256":
        raise Ap2EvidenceError(f"_sd_alg {payload['_sd_alg']!r} unsupported (sha-256 only, declared)")
    by_digest: Dict[str, Tuple[str, list]] = {}
    for d in disclosures:
        try:
            arr = _loads_segment(_b64url_decode(d), "disclosure")
        except (ValueError, Ap2EvidenceError) as e:
            raise Ap2EvidenceError(f"malformed disclosure: {e}") from e
        if not isinstance(arr, list) or len(arr) not in (2, 3):
            raise Ap2EvidenceError("disclosure must be [salt,name,value] or [salt,value]")
        dig = _disclosure_digest(d)
        if dig in by_digest:
            raise Ap2EvidenceError("duplicate disclosure digest (rejected fail-closed)")
        by_digest[dig] = (d, arr)
    used = set()

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k in ("_sd", "_sd_alg"):
                    continue
                out[k] = walk(v)
            sd = node.get("_sd", [])
            if not isinstance(sd, list) or any(not isinstance(x, str) for x in sd):
                raise Ap2EvidenceError("_sd must be a list of digest strings")
            for dig in sd:
                if dig in by_digest:
                    d, arr = by_digest[dig]
                    if len(arr) != 3:
                        raise Ap2EvidenceError("object disclosure must be [salt,name,value]")
                    if not isinstance(arr[1], str):
                        raise Ap2EvidenceError("disclosed claim name must be a string")
                    if arr[1] in out:
                        raise Ap2EvidenceError(f"disclosed claim {arr[1]!r} collides")
                    out[arr[1]] = walk(arr[2])
                    used.add(dig)
            return out
        if isinstance(node, list):
            out_l = []
            for item in node:
                if isinstance(item, dict) and set(item.keys()) == {"..."}:
                    dig = item["..."]
                    if not isinstance(dig, str):
                        raise Ap2EvidenceError("array disclosure placeholder must be a digest string")
                    if dig in by_digest:
                        d, arr = by_digest[dig]
                        if len(arr) != 2:
                            raise Ap2EvidenceError("array disclosure must be [salt,value]")
                        out_l.append(walk(arr[1]))
                        used.add(dig)
                    # undisclosed array element: omitted (that is selective disclosure)
                else:
                    out_l.append(walk(item))
            return out_l
        return node

    resolved = walk(payload)
    unused = set(by_digest) - used
    if unused:
        raise Ap2EvidenceError(f"{len(unused)} disclosure(s) match no digest in the "
                               "payload (rejected fail-closed)")
    return resolved


# ────────────────────────────────────────────────────────── ES256 verification

def _pubkey_from_jwk(jwk: Dict):
    from cryptography.hazmat.primitives.asymmetric import ec
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise Ap2EvidenceError("only EC/P-256 JWKs are supported (ES256, declared)")
    xb, yb = _b64url_decode(jwk.get("x")), _b64url_decode(jwk.get("y"))
    if len(xb) != 32 or len(yb) != 32:   # RFC 7518 §6.2.1.2-3: the full octet length of the coordinate (r2: 31/33 bytes verified here, refused by JS)
        raise Ap2EvidenceError("JWK x/y must be exactly 32 bytes")
    x = int.from_bytes(xb, "big")
    y = int.from_bytes(yb, "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _pubkey_from_x5c_leaf(x5c: List[str]):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    leaf = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise Ap2EvidenceError("x5c leaf key is not EC P-256 (ES256 only, declared)")
    return pub


def _jwk_from_pubkey(pub) -> Dict:
    nums = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": _b64url(nums.x.to_bytes(32, "big")),
            "y": _b64url(nums.y.to_bytes(32, "big"))}


def verify_es256(signing_input: bytes, signature: bytes, jwk: Dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(signature) != 64:
        raise Ap2EvidenceError(f"ES256 signature must be 64 bytes, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        _pubkey_from_jwk(jwk).verify(encode_dss_signature(r, s), signing_input,
                                     ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _snapshot_key(parsed: Dict, supplied_jwk: Optional[Dict] = None,
                  jwks_url: Optional[str] = None, timeout: int = 20) -> Dict:
    """Choose the verification key and record WHERE it came from (provenance class).
    Precedence: SUPPLIED key first (the caller's explicit trust decision MUST override
    self-asserted header material — otherwise a self-consistent forgery with an embedded
    jwk would outrank the genuine key an auditor provides; found by pro-level self-attack
    2026-08-21), then x5c header > jwk header > fetched JWKS. Fail-closed if none."""
    header = parsed["header"]
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"alg {header.get('alg')!r} unsupported: ES256 only "
                               "(other algs are rejected, never half-verified)")
    if supplied_jwk:
        return {"jwk": supplied_jwk, "provenance_class": "supplied",
                "note": "key material supplied by the caller (caller vouches); "
                        "overrides any self-asserted header key by design"}
    if header.get("x5c"):
        if not isinstance(header["x5c"], list) or len(header["x5c"]) > 10:
            raise Ap2EvidenceError("x5c chain absent or too long (>10 certs): refused "
                                   "(a huge chain is a DoS vector, not a key)")
        pub = _pubkey_from_x5c_leaf(header["x5c"])
        chain_fp = [hashlib.sha256(base64.b64decode(c)).hexdigest() for c in header["x5c"]]
        return {"jwk": _jwk_from_pubkey(pub), "provenance_class": "x5c_header",
                "x5c_chain_sha256": chain_fp,
                "note": "leaf cert key verified the signature; chain recorded, PKI path "
                        "NOT validated to a trust anchor here (declared)"}
    if header.get("jwk"):
        return {"jwk": {k: header["jwk"][k] for k in ("kty", "crv", "x", "y")
                        if k in header["jwk"]},
                "provenance_class": "jwk_header",
                "note": "key embedded in the protected header (self-asserted)"}
    if jwks_url:
        if not jwks_url.startswith("https://"):
            raise Ap2EvidenceError("JWKS URL must be https:// (TLS is the whole witness)")
        with urllib.request.urlopen(jwks_url, timeout=timeout) as r:  # nosec B310 - https enforced above
            raw = r.read(1024 * 1024 + 1)          # cap: un JWKS gigante = DoS, non una chiave
        if len(raw) > 1024 * 1024:
            raise Ap2EvidenceError("JWKS response exceeds 1MB cap (refused fail-closed)")
        jwks = json.loads(raw.decode())
        kid = parsed["header"].get("kid")
        keys = jwks.get("keys", [])
        match = [k for k in keys if not kid or k.get("kid") == kid]
        if not match:
            raise Ap2EvidenceError(f"no key in JWKS matches kid={kid!r}")
        return {"jwk": {k: match[0][k] for k in ("kty", "crv", "x", "y", "kid")
                        if k in match[0]},
                "provenance_class": "jwks_fetched",
                "jwks_url": jwks_url, "jwks_sha256": hashlib.sha256(raw).hexdigest(),
                "fetched_utc": _utcnow(),
                "note": "fetched over TLS at build time — a capture witness, "
                        "not proof of issuer control of the key"}
    raise Ap2EvidenceError("no key material: JWT has neither x5c nor jwk header, and no "
                           "supplied key or JWKS URL was given (fail-closed)")


def verify_kb_jwt(parsed: Dict, resolved_claims: Dict) -> Dict:
    """Holder binding (SD-JWT KB-JWT): verified against the holder key in the issuer
    payload's cnf.jwk, plus the sd_hash commitment over the exact presentation
    (<jwt>~<disclosures>*~). Three honest states: absent / verified true-false /
    present-but-unverifiable (no cnf.jwk — declared, never a fake green)."""
    kb = parsed.get("kb_jwt")
    if not kb:
        return {"present": False}
    seg = kb.split(".")
    if len(seg) != 3:
        raise Ap2EvidenceError("kb-jwt must have 3 dot-separated segments")
    try:
        header = _loads_segment(_b64url_decode(seg[0]), "kb-jwt header")
        payload = _loads_segment(_b64url_decode(seg[1]), "kb-jwt payload")
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"kb-jwt header/payload invalid: {e}") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise Ap2EvidenceError("kb-jwt header and payload must be objects")
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"kb-jwt alg {header.get('alg')!r} unsupported (ES256 only)")
    # 1.1.0 r2: `cnf` absent or an object, `cnf.jwk` absent or an object (an empty object is a holder key that fails to
    # parse, not "unknown"): present-with-null used to be an AttributeError here and "absent" in JS
    rc = resolved_claims if isinstance(resolved_claims, dict) else {}
    if "cnf" in rc and not isinstance(rc["cnf"], dict):
        raise Ap2EvidenceError("cnf must be an object")
    cnf = rc.get("cnf", {})
    if "jwk" not in cnf:
        return {"present": True, "verified": None,
                "note": "no cnf.jwk in issuer payload — holder key unknown (declared)"}
    jwk = cnf["jwk"]
    if not isinstance(jwk, dict):
        raise Ap2EvidenceError("cnf.jwk must be an object")
    sig_ok = verify_es256(f"{seg[0]}.{seg[1]}".encode("ascii"),
                          _b64url_decode(seg[2]), jwk)
    presentation = parsed["compact"].rsplit("~", 1)[0] + "~"
    sd_hash_ok = payload.get("sd_hash") == _sha256_b64url(presentation.encode("ascii"))
    return {"present": True, "verified": bool(sig_ok and sd_hash_ok),
            "signature_ok": sig_ok, "sd_hash_ok": sd_hash_ok,
            "claims_recorded_not_validated": {k: payload.get(k)
                                              for k in ("aud", "nonce", "iat")
                                              if k in payload}}


# ────────────────────────────────────────────────────────── bindings

def find_bindings(artifacts: List[Dict]) -> List[Dict]:
    """Cross-artifact hash commitments, recomputed from the PRIMARY quantity: sha-256 over
    each artifact's exact compact serialization (hex and b64url forms), matched against
    every string claim of the other artifacts. Deterministic; found-or-absent, never guessed."""
    digests = {}
    for a in artifacts:
        raw = a["compact"].encode("ascii")
        digests[a["name"]] = {"hex": hashlib.sha256(raw).hexdigest(),
                              "b64url": _sha256_b64url(raw)}
    found = []

    def scan(node, path, holder):
        if isinstance(node, dict):
            for k, v in node.items():
                scan(v, f"{path}.{k}" if path else k, holder)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                scan(v, f"{path}[{i}]", holder)
        elif isinstance(node, str):
            for other, d in digests.items():
                if other == holder:
                    continue
                if node == d["hex"] or node == d["b64url"]:
                    found.append({"in": holder, "claim": path, "commits_to": other,
                                  "encoding": "hex" if node == d["hex"] else "b64url"})

    for a in artifacts:
        scan(a["resolved_claims"], "", a["name"])
    return found


# ────────────────────────────────────────────────────────── RFC 3161 time anchor

def _rfc3161_stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """OPTIONAL RFC 3161 timestamp via openssl (graceful when absent). Its absence
    never invalidates the evidence — signatures and digests stand on their own."""
    import shutil
    import subprocess
    import tempfile
    from urllib.parse import urlparse
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL scheme not allowed (http/https only)"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    d = tempfile.mkdtemp()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = subprocess.run(
            [exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts-query failed"}
        with open(tsq, "rb") as f:
            req = f.read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        resp = urllib.request.urlopen(http, timeout=timeout).read()
        return {"anchored": True, "tsa": tsa_url, "tsr_b64": base64.b64encode(resp).decode()}
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        import shutil as _sh
        _sh.rmtree(d, ignore_errors=True)


def _der_tlv(buf: bytes, off: int) -> Tuple[int, int, int]:
    """(tag, start, end) of the DER element at `off`; raises Ap2EvidenceError on malformation."""
    if off + 2 > len(buf):
        raise Ap2EvidenceError("der: truncated")
    tag, ln, hl = buf[off], buf[off + 1], 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + 2 + n > len(buf):
            raise Ap2EvidenceError("der: bad length")
        ln = int.from_bytes(buf[off + 2:off + 2 + n], "big"); hl = 2 + n
    if off + hl + ln > len(buf):
        raise Ap2EvidenceError("der: overrun")
    return tag, off + hl, off + hl + ln


def _der_children(buf: bytes, start: int, end: int) -> List[Tuple[int, int, int]]:
    out, o = [], start
    while o < end:
        t = _der_tlv(buf, o); out.append(t); o = t[2]
    return out


def parse_timestamp_resp(tsr: bytes) -> Dict:
    """Minimal DER walk of an RFC 3161 TimeStampResp: PKIStatus and the TSTInfo messageImprint hash (hex). No signature
    or certificate processing — the same two facts the JS verifier reads (SPEC §3.2)."""
    tag, st, en = _der_tlv(tsr, 0)
    if tag != 0x30:
        raise Ap2EvidenceError("not a TimeStampResp")
    kids = _der_children(tsr, st, en)
    if not kids:
        raise Ap2EvidenceError("empty TimeStampResp")
    stag, sst, sen = kids[0]
    sk = _der_children(tsr, sst, sen)
    if not sk or sk[0][0] != 0x02:
        raise Ap2EvidenceError("no PKIStatus")
    status_bytes = tsr[sk[0][1]:sk[0][2]]
    granted = len(status_bytes) == 1 and status_bytes[0] in (0, 1)
    if len(kids) < 2:
        return {"granted": granted, "imprint": None}
    ci = _der_children(tsr, kids[1][1], kids[1][2])           # ContentInfo: OID, [0] SignedData
    if len(ci) < 2:
        raise Ap2EvidenceError("no SignedData")
    sdl = _der_children(tsr, ci[1][1], ci[1][2])
    if not sdl:
        raise Ap2EvidenceError("empty SignedData")
    sd = sdl[0]
    sdc = _der_children(tsr, sd[1], sd[2])                    # version, digestAlgorithms, encapContentInfo, ...
    if len(sdc) < 3:
        raise Ap2EvidenceError("SignedData too short")
    eci = _der_children(tsr, sdc[2][1], sdc[2][2])
    if len(eci) < 2:
        raise Ap2EvidenceError("no eContent")
    wl = _der_children(tsr, eci[1][1], eci[1][2])
    if not wl:
        raise Ap2EvidenceError("empty eContent")
    wrap = wl[0]
    if wrap[0] != 0x04:
        raise Ap2EvidenceError("eContent is not an OCTET STRING")
    tst = _der_tlv(tsr, wrap[1])
    tstc = _der_children(tsr, tst[1], tst[2])                 # version, policy, messageImprint, serial, genTime, ...
    if len(tstc) < 3:
        raise Ap2EvidenceError("TSTInfo too short")
    mic = _der_children(tsr, tstc[2][1], tstc[2][2])
    if len(mic) < 2 or mic[1][0] != 0x04:
        raise Ap2EvidenceError("no messageImprint hash")
    gen_time = None   # r4: TSTInfo.genTime (GeneralizedTime, UTC) — reported, and the TSA chain is validated AT that time
    if len(tstc) >= 5 and tstc[4][0] == 0x18:
        gt = tsr[tstc[4][1]:tstc[4][2]].decode("ascii", "replace")
        if re.fullmatch(r"\d{14}(\.\d+)?Z", gt):
            gen_time = gt
    return {"granted": granted, "imprint": tsr[mic[1][1]:mic[1][2]].hex(), "gen_time": gen_time}


def _verify_rfc3161(tsr_b64: str, expected_digest_hex: str, timeout: int = 15, tsa_cert: Optional[str] = None) -> Dict:
    """RFC 3161 token check (SPEC §3.2). `verified` = the token parses, its status is granted and the TSTInfo
    messageImprint equals the recomputed pack digest — BINDING, not TSA authenticity: the TSA signature and certificate
    chain are validated only when the relying party supplies the TSA certificate (`tsa_cert`, PEM), through
    `openssl ts -verify -CAfile`; then `tsa_verified` is True/False (None when not requested or openssl is absent).
    1.1.0 r1: a self-forged TimeStampResp with status 0 and the right imprint used to pass the JS verifier and to
    fail this one only because `openssl ts -reply -text` refused the minimal DER — neither was a check of the TSA."""
    import shutil
    import subprocess
    import tempfile
    try:
        tsr = _sigsuite._unb64(tsr_b64)                       # strict base64 (a space inside the token used to be skipped)
    except (ValueError, TypeError):
        return {"verified": False, "note": "tsr_b64 is not canonical base64"}
    try:
        info = parse_timestamp_resp(tsr)
    except Exception as e:  # noqa: BLE001 — any malformed DER is "not parseable" (r2: an empty EXPLICIT [0] was an IndexError traceback)
        return {"verified": False, "note": f"token not parseable: {type(e).__name__}: {str(e)[:80]}"}
    imprint_ok = info["imprint"] == expected_digest_hex.lower()
    out = {"verified": bool(info["granted"] and imprint_ok), "granted": info["granted"], "imprint_ok": imprint_ok, "gen_time": info.get("gen_time"), "tsa_verified": None}
    if tsa_cert is None:
        return out
    exe = shutil.which("openssl")
    if not exe:
        out["tsa_note"] = "openssl absent — TSA signature/chain NOT verified"; return out
    d = tempfile.mkdtemp()
    try:
        path = os.path.join(d, "t.tsr")
        with open(path, "wb") as f:
            f.write(tsr)
        cmd = [exe, "ts", "-verify", "-digest", expected_digest_hex, "-sha256", "-in", path, "-CAfile", tsa_cert]
        if info.get("gen_time"):   # r4: validate the chain at the token's own genTime (`-attime`), so a TSA certificate that expired
            # AFTER issuing does not turn `tsa_verified` False years later; revocation is not checked (declared)
            import calendar, time as _t
            cmd += ["-attime", str(calendar.timegm(_t.strptime(info["gen_time"].split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")))]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out["tsa_verified"] = r.returncode == 0 and "Verification: OK" in (r.stdout or "")
        if not out["tsa_verified"]:   # `verified` keeps its §3.2 meaning (binding); the TSA outcome is its own field, in both verifiers
            out["tsa_note"] = (r.stderr or r.stdout).strip()[-160:]
    except Exception as e:  # noqa: BLE001
        out["tsa_verified"] = False; out["tsa_note"] = f"{type(e).__name__}: {str(e)[:80]}"
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return out

def _verify_one(parsed: Dict, key: Dict) -> Dict:
    sig_ok = verify_es256(parsed["signing_input"], parsed["signature"], key["jwk"])
    resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
    return {"signature_ok": sig_ok, "resolved_claims": resolved,
            "disclosures_ok": True}     # resolve_disclosures raised otherwise


def build_evidence(artifacts: List[Dict], out_path: str,
                   keys: Optional[Dict[str, Dict]] = None,
                   jwks_urls: Optional[Dict[str, str]] = None,
                   tsa_url: Optional[str] = None,
                   subject: str = "agentic-payment mandate evidence") -> Dict:
    """artifacts: [{name, sd_jwt}]. Verifies every artifact NOW, snapshots the key material
    used, records bindings, and writes ONE self-contained evidence file. Any artifact that
    fails to verify aborts the build (an evidence file must never contain a red light
    dressed as evidence — fail-closed at the source)."""
    keys, jwks_urls = keys or {}, jwks_urls or {}
    names = [a["name"] for a in artifacts]
    if len(set(names)) != len(names):
        raise Ap2EvidenceError("duplicate artifact names (bindings would silently "
                               "overwrite each other — refused fail-closed)")
    entries, for_bindings = [], []
    for a in artifacts:
        parsed = parse_sd_jwt(a["sd_jwt"])
        key = _snapshot_key(parsed, supplied_jwk=keys.get(a["name"]),
                            jwks_url=jwks_urls.get(a["name"]))
        v = _verify_one(parsed, key)
        if not v["signature_ok"]:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: ES256 signature INVALID "
                                   "(build refused — no evidence file for a red light)")
        kb = verify_kb_jwt(parsed, v["resolved_claims"])
        if kb.get("verified") is False:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: KB-JWT holder binding "
                                   "INVALID (build refused — no evidence file for a red light)")
        entries.append({"name": a["name"], "sd_jwt_compact": parsed["compact"],
                        "header": parsed["header"], "key": key,
                        "resolved_claims": v["resolved_claims"],
                        "kb_jwt": kb,
                        "verified_at_build": {"signature_ok": True,
                                              "disclosures_ok": True}})
        for_bindings.append({"name": a["name"], "compact": parsed["compact"],
                             "resolved_claims": v["resolved_claims"]})
    evidence = {
        "evidence_format": EVIDENCE_FORMAT, "subject": subject,
        "created_utc": _utcnow(), "artifacts": entries,
        "bindings": find_bindings(for_bindings),
        "honest_scope": HONEST_SCOPE,
    }
    evidence["evidence_digest_sha256"] = hashlib.sha256(_canon(evidence)).hexdigest()
    evidence["rfc3161_timestamp"] = (
        _rfc3161_stamp(evidence["evidence_digest_sha256"], tsa_url)
        if tsa_url else {"anchored": False, "note": "no TSA provided"})
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=1, sort_keys=True)
    return {"out": out_path, "artifacts": len(entries),
            "bindings": len(evidence["bindings"]),
            "evidence_digest_sha256": evidence["evidence_digest_sha256"],
            "rfc3161_anchored": evidence["rfc3161_timestamp"].get("anchored", False)}


def sign_evidence(path, identity=None, classical_alg="ed25519"):
    """Add an OMEGA PRODUCER SIGNATURE to an evidence pack: a HYBRID block (a classical
    signature + ML-DSA-65 when available) over evidence_digest_sha256, so the pack's
    integrity/authenticity survives the quantum transition (NIST IR 8547). The signature
    scheme is a DECLARED class per the auditor's request: each signature records
    its sig_alg. Backward-compatible: producer_signatures is excluded from the digest,
    exactly like the RFC 3161 timestamp. Honest scope: this protects THIS pack; it does not
    retro-protect the underlying ES256 mandate signature (still classical) - for that, the
    durable claim rests on the time anchor proving the mandate existed pre-quantum."""
    ev = read_evidence_file(path)
    digest = ev.get("evidence_digest_sha256")
    if not digest:
        raise Ap2EvidenceError("evidence pack has no digest to sign")
    if identity is None:
        identity = _sigsuite.ProducerIdentity.create(classical_alg=classical_alg)
    ev["producer_signatures"] = identity.sign_block(digest.encode("ascii"))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=1, sort_keys=True)
    algs = [x["sig_alg"] for x in ev["producer_signatures"]["signatures"]]
    return {"out": path, "scheme": ev["producer_signatures"]["scheme"], "sig_algs": algs,
            "pq_protected": any(a in _sigsuite.POST_QUANTUM for a in algs),
            "producer_public_keys": identity.public_keys()}


def verify_evidence(path: str, trusted_producer_keys=None, require_pq: bool = False,
                    require_producer: bool = False, require_anchor: bool = False, tsa_cert: Optional[str] = None) -> Dict:
    """OFFLINE re-verification from the evidence file alone: digest, every signature with
    the SNAPSHOTTED key, every disclosure, every binding, and the RFC 3161 token's binding
    (status + imprint; the TSA itself only with `tsa_cert`, via openssl). Fail-closed."""
    try:
        ev = read_evidence_file(path)
    except Ap2EvidenceError as e:   # 1.1.0: a hostile or unreadable file is a refusal receipt, never a traceback
        return {"digest_ok": False, "artifacts": [], "producer_signatures": {"present": False, "pq_protected": False, "trusted": None},
                "pq_protected": False, "bindings_ok": False, "rfc3161": {"claimed": False, "verified": None}, "provenance_classes": [],
                "self_asserted_only": False, "policy_ok": False, "valid": False, "honest_scope": None, "refused": str(e)}
    def refusal(msg):
        return {"digest_ok": False, "artifacts": [], "producer_signatures": {"present": False, "pq_protected": False, "trusted": None},
                "pq_protected": False, "bindings_ok": False, "rfc3161": {"claimed": False, "verified": None}, "provenance_classes": [],
                "self_asserted_only": False, "policy_ok": False, "valid": False, "honest_scope": None, "refused": msg}
    # 1.1.0 (review r1): the SHAPE of the top-level fields is checked before anything touches them — `artifacts` a list of
    # objects, `bindings` a list, `rfc3161_timestamp` an object or absent, `producer_signatures` an object or absent. A wrong
    # type used to be a TypeError/AttributeError traceback (the JS verifier answered); `producer_signatures: {}` was "absent".
    if not isinstance(ev.get("artifacts"), list) or any(not isinstance(a, dict) for a in ev["artifacts"]):
        return refusal("artifacts must be a list of objects")
    names = [a.get("name") for a in ev["artifacts"]]   # r3: the name keys the binding table — a non-string crashed the JS table, "__proto__" vanished from it
    if any(not isinstance(n, str) or not n for n in names):
        return refusal("artifacts[].name must be a non-empty string")
    if len(set(names)) != len(names):
        return refusal("artifacts[].name must be unique within the pack")
    if not isinstance(ev.get("bindings", []), list):
        return refusal("bindings must be a list")
    if "rfc3161_timestamp" in ev and not isinstance(ev["rfc3161_timestamp"], dict):
        return refusal("rfc3161_timestamp must be an object")
    if "rfc3161_timestamp" in ev and not isinstance(ev["rfc3161_timestamp"].get("anchored"), bool):   # r2: [] / {} were "not anchored" here and "anchored, unverified" in JS
        return refusal("rfc3161_timestamp.anchored must be a boolean")
    if "producer_signatures" in ev and not isinstance(ev["producer_signatures"], dict):
        return refusal("producer_signatures must be an object")
    e2 = {k: v for k, v in ev.items()
          if k not in ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures")}
    recomputed_digest = hashlib.sha256(_canon(e2)).hexdigest()
    digest_ok = recomputed_digest == ev.get("evidence_digest_sha256")

    art_results, all_ok = [], True
    for_bindings = []
    for a in ev["artifacts"]:
        try:
            compact = a["sd_jwt_compact"]
            if not isinstance(compact, str) or compact != compact.strip() or not compact.isascii():
                raise Ap2EvidenceError("sd_jwt_compact must be the exact ASCII compact serialization (no surrounding whitespace)")
            key = a["key"]
            if not isinstance(key, dict) or not isinstance(key.get("jwk"), dict):
                raise Ap2EvidenceError("artifact key.jwk must be an object")
            if key.get("provenance_class") is not None and not isinstance(key["provenance_class"], str):   # r2: a list was a TypeError in sorted()
                raise Ap2EvidenceError("artifact key.provenance_class must be a string")
            parsed = parse_sd_jwt(compact)
            if not isinstance(parsed["payload"], dict) or not isinstance(parsed["header"], dict):
                raise Ap2EvidenceError("JWT header and payload must be objects")
            sig_ok = verify_es256(parsed["signing_input"], parsed["signature"], key["jwk"])
            resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
            claims_ok = _canon(resolved) == _canon(a.get("resolved_claims"))
            kb = verify_kb_jwt(parsed, resolved)
            art_results.append({"name": a.get("name"), "signature_ok": sig_ok,
                                "claims_match": claims_ok, "kb_jwt": kb,
                                "provenance_class": key.get("provenance_class")})
            all_ok = (all_ok and sig_ok and claims_ok
                      and kb.get("verified") is not False)
            for_bindings.append({"name": a.get("name"), "compact": parsed["compact"],
                                 "resolved_claims": resolved})
        except Exception as e:  # noqa: BLE001 — any malformation of an artifact is that artifact's error, never a traceback
            art_results.append({"name": a.get("name") if isinstance(a, dict) else None, "error": f"{type(e).__name__}: {str(e)[:120]}"})
            all_ok = False

    try:   # r4: the binding SET (SPEC §4) — entries compared by sorted canonical form; the scan order of JS Object.keys puts
        # array-index keys ("0", "7") first, so an ordered comparison split the verdict on a pack the reference itself built
        bindings_ok = (sorted(_canon(b) for b in find_bindings(for_bindings)) == sorted(_canon(b) for b in ev.get("bindings", []))) if all_ok else False
    except Exception:  # noqa: BLE001
        bindings_ok = False

    ts = ev.get("rfc3161_timestamp") or {}
    rfc = {"claimed": bool(ts.get("anchored", False)), "verified": None}
    if ts.get("anchored") and isinstance(ts.get("tsr_b64"), str):
        rfc = {"claimed": True, **_verify_rfc3161(ts["tsr_b64"], recomputed_digest, tsa_cert=tsa_cert)}
    elif ts.get("anchored"):
        rfc = {"claimed": True, "verified": False, "note": "anchored claimed but tsr_b64 absent or not a string"}

    classes = sorted({r.get("provenance_class") for r in art_results
                      if r.get("provenance_class")})

    # OMEGA producer signature(s) over the digest: crypto-agile, hybrid (classical + ML-DSA-65).
    # A claimed-but-invalid signature is tamper -> fail-closed. pq_protected only on a valid PQ sig.
    prod = ev.get("producer_signatures")
    if prod is not None:   # 1.1.0 r1: an EMPTY block is present with zero passing signatures -> not ok (SPEC §5), like the JS verifier
        pv = _sigsuite.verify_producer_block(
            prod, recomputed_digest.encode("ascii"),
            trusted=trusted_producer_keys)
        producer = {"present": True, "scheme": pv["scheme"], "ok": pv["ok"],
                    "pq_protected": pv["pq_protected"], "trusted": pv["trusted"],
                    "signatures": pv["results"]}
        if not pv["ok"]:
            all_ok = False
        # a pinned trust set that the producer key does NOT match = not authentic
        if trusted_producer_keys is not None and pv["trusted"] is not True:
            all_ok = False
    else:
        producer = {"present": False, "pq_protected": False, "trusted": None,
                    "note": "no producer signature; pack integrity rests on digest + time anchor only. "
                            "Without a pinned producer key a signature would prove consistency, not authenticity."}
    # relying-party policy: enforce PQ / producer so a stripped-signature downgrade is rejected
    policy_ok = True
    if require_producer and not (producer["present"] and producer.get("ok")):
        policy_ok = False
    if require_pq and not (producer.get("pq_protected") and producer.get("trusted") is True):
        policy_ok = False
    # require_anchor: the existed-by claim must be PROVEN, not merely claimed. A missing
    # anchor, an unverifiable one (no openssl -> verified None), or a failing token all
    # reject — fail-closed, "claimed" never upgrades to "proven".
    if require_anchor and rfc.get("verified") is not True:
        policy_ok = False
    if require_anchor and tsa_cert is not None and rfc.get("tsa_verified") is not True:
        policy_ok = False

    return {"digest_ok": digest_ok, "artifacts": art_results,
            "producer_signatures": producer, "pq_protected": producer.get("pq_protected", False),
            "bindings_ok": bindings_ok, "rfc3161": rfc,
            "provenance_classes": classes,
            # tutto auto-asserito = la firma prova solo coerenza interna, mai identita'
            "self_asserted_only": bool(classes) and set(classes) <= {"jwk_header"},
            # un evidence senza artefatti non prova NULLA: mai 'valid' (falso-verde per l'auditor)
            "policy_ok": policy_ok,
            "valid": bool(art_results and digest_ok and all_ok and bindings_ok
                          and rfc.get("verified") is not False and policy_ok),
            "honest_scope": ev.get("honest_scope")}


# ────────────────────────────────────────────────────────── CLI

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="ap2-evidence-pack", allow_abbrev=False, add_help=False,
                                description="Self-contained, offline-verifiable dispute "
                                            "evidence for agentic-payment SD-JWT mandates")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build", allow_abbrev=False, add_help=False)
    b.add_argument("out")
    b.add_argument("artifacts", nargs="+", metavar="name=path",
                   help="e.g. intent=intent.sdjwt cart=cart.sdjwt")
    b.add_argument("--key", action="append", default=[], metavar="name=jwk.json",
                   help="supplied verification JWK for an artifact")
    b.add_argument("--jwks-url", action="append", default=[], metavar="name=https://...",
                   help="fetch the key from a JWKS at build time (TLS witness)")
    b.add_argument("--tsa", help="RFC 3161 TSA URL (optional third-party time anchor)")
    b.add_argument("--subject", default="agentic-payment mandate evidence")
    v = sub.add_parser("verify", allow_abbrev=False, add_help=False)
    v.add_argument("evidence")
    v.add_argument("--trusted-producer-key", action="append", default=None, metavar="ALG=B64",
                   help="pin a producer public key as <sig_alg>=<base64> (e.g. ed25519=…, ml-dsa-65=…); may repeat. With any pin, an unpinned producer is not authentic")
    v.add_argument("--require-producer", action="store_true", help="policy: a valid producer signature is required")
    v.add_argument("--require-pq", action="store_true", help="policy: a valid, PINNED post-quantum producer signature is required")
    v.add_argument("--require-anchor", action="store_true", help="policy: the RFC 3161 anchor must be present and BOUND to this pack (status granted, messageImprint = digest); with --tsa-cert also TSA-verified")
    v.add_argument("--tsa-cert", help="PEM certificate (or chain) of the TSA: verify the token's signature and chain with openssl ts -verify (without it, the TSA is NOT verified — declared)")
    raw = list(sys.argv[1:] if argv is None else argv)
    # 1.1.0: one CLI grammar with the sibling verifiers — "" or a flag as a value, "--", -h/--help, a value on a boolean flag,
    # an abbreviated flag = usage (exit 2, no verdict); the file path itself must not be "" or flag-like
    if "--" in raw or any(x in ("-h", "--help") for x in raw) or any(x.split("=", 1)[0] in ("--require-producer", "--require-pq", "--require-anchor") and "=" in x for x in raw):
        p.error("unexpected argument")
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok in ("--trusted-producer-key", "--key", "--jwks-url", "--tsa", "--subject", "--tsa-cert"):
            val = raw[i + 1] if i + 1 < len(raw) else None
            if val is None or val == "" or val.startswith("-"):
                p.error(f"{tok} needs a value (got {val!r})")
            i += 2; continue
        if tok.split("=", 1)[0] in ("--trusted-producer-key", "--key", "--jwks-url", "--tsa", "--subject", "--tsa-cert") and "=" in tok:
            val = tok.split("=", 1)[1]
            if val == "" or val.startswith("-"):
                p.error(f"{tok.split('=', 1)[0]} needs a value (got {val!r})")
        i += 1
    a = p.parse_args(raw)
    if a.cmd == "build":
        arts = []
        for spec in a.artifacts:
            name, _, path = spec.partition("=")
            if not path:
                p.error(f"artifact {spec!r}: expected name=path")
            with open(path, encoding="utf-8") as f:
                arts.append({"name": name, "sd_jwt": f.read()})
        keys = {}
        for spec in a.key:
            name, _, path = spec.partition("=")
            with open(path, encoding="utf-8") as f:
                keys[name] = json.load(f)
        jwks = dict(s.partition("=")[::2] for s in a.jwks_url)
        try:
            print(json.dumps(build_evidence(arts, a.out, keys=keys, jwks_urls=jwks,
                                            tsa_url=a.tsa, subject=a.subject), indent=1))
            return 0
        except Ap2EvidenceError as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            return 1
    if a.cmd == "verify":
        if a.evidence == "" or a.evidence.startswith("-"):
            p.error(f"evidence path needs a value (got {a.evidence!r})")
        trusted = None
        if a.trusted_producer_key:
            trusted = {}
            for spec in a.trusted_producer_key:
                alg, sep, key = spec.partition("=")
                if not sep or not alg or not key:
                    p.error(f"--trusted-producer-key expects ALG=B64 (got {spec!r})")
                trusted.setdefault(alg, []).append(key)
        r = verify_evidence(a.evidence, trusted_producer_keys=trusted, require_pq=a.require_pq,
                            require_producer=a.require_producer, require_anchor=a.require_anchor, tsa_cert=a.tsa_cert)
        print(json.dumps(r, indent=1))
        return 0 if r["valid"] else 1
    p.print_help(sys.stderr)   # r3: usage goes to stderr, no verdict on stdout — as every other usage path and the JS verifier
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
