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
presumption (a QTSP service does), and validates x5c chains only when the relying party supplies a trust anchor
(`--trust-anchor`, SPEC §6.7): nothing about a chain is sealed in the file itself.
ES256 only, by design; other algs are rejected loudly, never half-verified.

Usage:
  python3 ap2_evidence.py build out.json checkout=checkout.sdjwt payment=payment.sdjwt \
          [--key name=jwk.json] [--jwks-url name=https://...] [--tsa URL]
  python3 ap2_evidence.py verify out.json
"""
from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
import re
import stat
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from contextvars import ContextVar
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
for _pqc in ("pqcrypto", "ap2_pqcrypto"):        # the clone has pqcrypto/; the wheel installs it as ap2_pqcrypto/ (1.3.0)
    if os.path.isfile(os.path.join(_HERE, _pqc, "sigsuite.py")):   # the file, not the directory: PyPI's pqcrypto/ may sit beside the wheel
        sys.path.insert(0, os.path.join(_HERE, _pqc))
        break
import sigsuite as _sigsuite  # noqa: E402  (crypto-agile hybrid classical + ML-DSA-65 producer signatures)
try:   # SPEC §12, 1.8.0: the NIST Beacon pulse check. A copy of this file without it (cryptovalid-opencore vendors
    import ap2_nist_beacon as _nb  # noqa: E402  ap2_evidence.py alone) reads every pack but one with `not_before`
except ImportError:   # which it refuses (format_unsupported), never verifies
    _nb = None

EVIDENCE_FORMAT = "ap2-evidence-pack/1.0"

HONEST_SCOPE = (
    "Proves: these exact SD-JWT artifacts, with the snapshotted key material (see each "
    "key's provenance_class), verified at build time; the RFC 3161 token (if present) binds this digest to a "
    "TimeStampResp, and attests the TSA's clock only once the relying party has verified the TSA's signature "
    "(--tsa-cert): a self-issued token satisfies the binding alone. Does NOT prove the issuer authorised "
    "the key beyond what the provenance class states, does NOT confer eIDAS qualified-"
    "archive legal presumption, and does NOT by itself validate x5c chains to a trust anchor "
    "— that is an act of the relying party at verification time, with `--trust-anchor`, reported in "
    "`chain_verified` and in each artifact's `x5c_leaf` (SPEC §6.7): the x5c bytes are sealed inside the signed header, the "
    "validation RESULT never is — and "
    "never proves the truth of the recorded transaction itself. When a producer signature is present, it protects the SEALED CONTENT (the file minus the digest, the anchor block and the signatures themselves - so a removed or downgraded time anchor is caught only under a require-anchor policy), and authenticity ONLY for a relying party that has PINNED the producer public key out of band (an embedded key alone proves consistency, not authenticity), across the retention window (hybrid: a classical signature + FIPS-204 ML-DSA-65, surviving the quantum transition per NIST IR 8547); it does NOT retro-protect the underlying ES256 mandate signature - for the existed-before-a-quantum-adversary claim you still need a trusted time anchor (RFC 3161 / RFC 4998 renewal). 'valid' means each "
    "artifact verifies and the SEALED CONTENT is intact — NOT that the file as a whole is unaltered (the anchor block lies "
    "outside the digest), NOT that the mandates form a bound "
    "chain (read `bindings`) nor that self-asserted keys prove issuer identity (read "
    "`provenance_classes`/`self_asserted_only`). KB-JWT holder binding is verified "
    "when the issuer payload carries cnf.jwk; without cnf.jwk it is recorded as "
    "present-but-unverifiable, never painted green. KB-JWT aud/nonce/iat are RECORDED "
    "for the auditor, not validated — their expected values are transaction context "
    "this tool cannot know offline.")

HONEST_SCOPE_SHA256 = hashlib.sha256(HONEST_SCOPE.encode("utf-8")).hexdigest()
# 1.9.0 (SPEC §1): the scope 1.0.0-1.0.2 sealed (same text in the three tags); a pack carrying it is named, not "a rewritten scope"
HONEST_SCOPE_SHA256_1_0 = "431877e44b759e99d306f79dd52739f08bd94bc05d70a6a03ee82f74fc0f15db"
_PACK_1_0_REFUSAL = ("honest_scope is the scope of ap2-evidence-pack 1.0.0-1.0.2 (sha256 431877e4...): a pack built by 1.0.x, "
                     "sealed under rules 1.1.0 changed (SPEC §1, CHANGELOG 1.1.0); this verifier reads packs built by 1.1.0 "
                     "and later, and does not verify it")   # r8: pinned in SPEC §1, so both verifiers refuse a rewritten scope


class Ap2EvidenceError(ValueError):
    """Fail-closed parse/verify error (message is auditor-readable, never a traceback)."""


class Ap2WriteError(Ap2EvidenceError, OSError):
    """1.5.2 — the output file (the pack `build` writes, the pack `stamp` rewrites) could not be written. Also an OSError,
    which is what `build_evidence` raised there before. The CLI exits 74 (EX_IOERR) on it, whatever the outcome was.

    1.6.0 (SPEC §6.10): raised by `verify_evidence` when a check asked for could not be RUN here (openssl's temporary
    files, openssl that cannot be started or does not answer); it then carries the COMPLETE receipt in `receipt`, where
    the subject of that check is `not_evaluated` with reason `instrument_failure` and the other subjects are evaluated.
    The CLI writes that receipt and exits 74. `receipt` is None when nothing was computed (a file that was not written)."""

    def __init__(self, *args, receipt=None):
        super().__init__(*args)
        self.receipt = receipt


class Ap2UnknownMember(Ap2EvidenceError):
    """1.6.0 — SPEC §9.1: a key outside the closed list of an object of this format. A refusal of class `unknown_member`
    (§6.9): it can come from a later revision of the format, so it is kept apart from a malformed input."""


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


_NUMBER_LITERAL = re.compile(r"(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?")


def _integral_literal(text: str) -> Optional[int]:
    """1.7.2 (SPEC §3.1, the SD-JWT layer): the integer a JSON number literal written with a fraction or an exponent
    denotes, when its value is an integer within +/-(2^53-1); None otherwise. Decided on the DECIMAL DIGITS of the literal,
    exactly — never through binary64 (float("10.000000000000000001") is 10.0; here it is not an integer). The JS verifier
    runs the same digit algorithm (`integralLiteral`), so both verifiers read, or refuse, the same literals."""
    m = _NUMBER_LITERAL.fullmatch(text)
    if not m:
        return None
    neg, ip, fp, ex = m.group(1) == "-", m.group(2), m.group(3) or "", m.group(4) or "0"
    digits = (ip + fp).lstrip("0")
    if not digits:
        return 0                                    # 0.0, -0.0, 0e99999: zero, whatever the exponent
    ex_digits = ex.lstrip("+-").lstrip("0")
    if len(ex_digits) > 9:                           # an exponent of ten digits or more: far outside the range, either way
        return None
    shift = int(ex) - len(fp)                        # value = int(digits) * 10**shift
    if shift < 0:
        if len(digits) <= -shift or digits[shift:].strip("0"):
            return None                              # a non-zero digit below the units: not an integer
        digits = digits[:shift]
        shift = 0
    if len(digits) + shift > 16:                     # 2^53-1 has 16 digits
        return None
    v = int(digits) * 10 ** shift
    if v > _SAFE_INT:
        return None
    return -v if neg else v


# 1.7.2 (SPEC §3.1): None = the default, a literal with a fraction or an exponent inside a token is that artifact's error;
# a list = the relying party asked for `accept_integral_floats`: an integral one is read as its integer and its text is
# appended here, so the receipt names every literal read that way (per artifact). A ContextVar: one value per call/thread.
_INTEGRAL_READ: ContextVar = ContextVar("ap2_integral_read", default=None)


def _token_number(text: str):
    shown = text if len(text) <= 30 else text[:30] + "…"   # the literal is attacker-sized; the receipt keeps 120 chars of an error
    read = _INTEGRAL_READ.get()
    v = _integral_literal(text)
    if v is None:   # 1.9.0: said first — up to 1.8.x `0.1` without the option "needs accept_integral_floats", which does not read it
        raise Ap2EvidenceError(f"float {shown!r} in the SD-JWT: not an integer within +/-(2^53-1) (SPEC §3.1)")
    if read is None:
        raise Ap2EvidenceError(f"float {shown!r} in the SD-JWT needs accept_integral_floats")   # literal first: the receipt keeps 120 chars
    read.append(shown)
    return v


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


def loads_strict(text: str, token: bool = False):
    """Strict JSON for the evidence file: no duplicate keys, no floats, integers within +/-(2^53-1), no NaN/Infinity,
    nesting <= 512 by linear pre-scan, no lone UTF-16 surrogate escape. Raises Ap2EvidenceError.
    `token=True` (1.7.2, SPEC §3.1): the JSON of an SD-JWT segment, where a literal with a fraction or an exponent whose
    value is an integer within the range is read as that integer (`10.0` -> 10); any other such literal is refused."""
    if _nesting_depth(text) > MAX_JSON_DEPTH:
        raise Ap2EvidenceError(f"json_too_deep: nesting exceeds {MAX_JSON_DEPTH}")
    if _has_lone_surrogate(text):
        raise Ap2EvidenceError("lone_surrogate: unpaired UTF-16 surrogate escape")
    try:
        return json.loads(text, object_pairs_hook=_no_dup_pairs, parse_float=_token_number if token else _no_float,
                          parse_int=_bounded_int, parse_constant=_no_constant)
    except RecursionError as e:
        raise Ap2EvidenceError("json_too_deep") from e
    except ValueError as e:
        if isinstance(e, Ap2EvidenceError): raise
        raise Ap2EvidenceError(f"not JSON: {str(e)[:80]}") from e


_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)


def read_evidence_file(path: str):
    """Read + decode + parse the evidence file under the profile. UTF-8 strict (a raw byte is a refusal, never U+FFFD),
    a size bound before reading, an unreadable path is a refusal — all Ap2EvidenceError, never a traceback.
    The file is opened WITHOUT blocking and read only if the OPEN descriptor is a regular file, at most
    MAX_EVIDENCE_BYTES bytes: measured 25/09/2026, a FIFO in its place blocked both verifiers and a symlink to /dev/zero
    passed the size check (a device reports size 0) and was read until memory ran out, in both."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):   # refused BEFORE it is opened (opening a device can act on it)
            raise Ap2EvidenceError("unreadable evidence file: not a regular file")
        fd = os.open(path, _OPEN_FLAGS)
        try:                                          # fstat on the open descriptor: closes the race with a swap in between
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise Ap2EvidenceError("unreadable evidence file: not a regular file")
            if st.st_size > MAX_EVIDENCE_BYTES:
                raise Ap2EvidenceError(f"evidence file exceeds {MAX_EVIDENCE_BYTES} bytes")
            with os.fdopen(os.dup(fd), "rb") as f:
                raw = f.read(MAX_EVIDENCE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_EVIDENCE_BYTES:   # a file that grows while it is read is refused, never buffered past the bound
            raise Ap2EvidenceError(f"evidence file exceeds {MAX_EVIDENCE_BYTES} bytes")
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
    return loads_strict(text, token=True)


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
    A trailing '~' means no key-binding JWT. Returns raw parts, decoded header/payload.
    1.8.1 (SPEC §6 step 2, RFC 9901 §4): the grammar is closed. No '~' at all (`sd_jwt_no_separator`), an empty component
    before the last (`sd_jwt_empty_component`), or a last component that is neither empty nor a KB-JWT (three
    dot-separated segments; `sd_jwt_final_component_not_kb_jwt`, e.g. a missing trailing '~') is refused with that name.
    Up to 1.8.0 they were read as a JWT with no disclosures, dropped in silence, and taken as the KB-JWT."""
    compact = compact.strip()
    if "~" not in compact:   # 1.9.0: the message says how a plain JWS (an AP2 receipt) enters
        raise Ap2EvidenceError("sd_jwt_no_separator: an SD-JWT has at least one '~' after the issuer JWT "
                               "(RFC 9901 §4: <Issuer-signed JWT>~<D.1>~...~<D.N>~[<KB-JWT>]); a plain JWS such as an AP2 "
                               "receipt enters as <jwt>~, an SD-JWT with no disclosures (SPEC §2.1)")
    parts = compact.split("~")
    jwt, middle, kb = parts[0], parts[1:-1], parts[-1] or None
    if any(d == "" for d in middle):   # 1.9.0: an AP2 chain (`~~` before an issuer JWT) is split by build, never here
        raise Ap2EvidenceError("sd_jwt_empty_component: an empty component between two '~' "
                               "(RFC 9901 §4: DISCLOSURE = 1*base64url; only the last component may be empty; an AP2 chain "
                               "joins its hops with '~~' before an issuer JWT, and `build` splits it into hops, SPEC §2.1)")
    if kb is not None and kb.count(".") != 2:   # 1.9.0: the message names the usual cause
        raise Ap2EvidenceError("sd_jwt_final_component_not_kb_jwt: the last '~'-separated component is neither empty nor "
                               "a KB-JWT of three dot-separated segments, so it would be read as the KB-JWT: is the trailing "
                               "'~' missing? (RFC 9901 §4: an SD-JWT without a KB-JWT ends with '~')")
    seg = jwt.split(".")
    if len(seg) != 3:   # 1.8.0 (SPEC §13): the dots found are named
        raise Ap2EvidenceError(f"issuer JWT must have 3 dot-separated segments (found {len(seg) - 1} dot(s))")
    try:
        header = _loads_segment(_b64url_decode(seg[0]), "JWT header")
        payload = _loads_segment(_b64url_decode(seg[1]), "JWT payload")
    except (ValueError, Ap2EvidenceError) as e:
        raise Ap2EvidenceError(f"JWT header/payload not valid JSON/base64url: {e}") from e
    return {"compact": compact, "jwt": jwt, "header": header, "payload": payload,
            "signature": _b64url_decode(seg[2]),
            "signing_input": f"{seg[0]}.{seg[1]}".encode("ascii"),
            "disclosures": list(middle), "kb_jwt": kb}


# ---- SPEC §13: the JOSE header profile (1.8.0) ----------------------------------------------------------------------

JOSE_PROFILES = {   # profile: (typ, source, symmetric algorithms refused)
    "openid4vci-proof": ("openid4vci-proof+jwt", "OpenID4VCI 1.0 Final (2025-09-16) Appendix F.1", True),
    "key-attestation": ("key-attestation+jwt", "OpenID4VCI 1.0 Final (2025-09-16) Appendix D.1", True),
    "sd-jwt-vc": ("dc+sd-jwt", "draft-ietf-oauth-sd-jwt-vc-27 §2.2.1", False),
    "kb-jwt": ("kb+jwt", "RFC 9901 §4.3", False),
}
_SYMMETRIC = ("HS256", "HS384", "HS512")


def decode_jose_header(segment: str) -> Dict:
    """SPEC §13: the first segment of a JWS compact serialization, strict base64url, UTF-8, a JSON object with no member
    twice; Ap2EvidenceError otherwise."""
    header = _loads_segment(_b64url_decode(segment), "JOSE header")
    if not isinstance(header, dict):
        raise Ap2EvidenceError("JOSE header is not a JSON object")
    return header


_ASCII_LOWER = {c: c + 32 for c in range(0x41, 0x5B)}


_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")   # RFC 9110 §5.6.2


def _media_type(typ):
    """SPEC §13 (1.8.1): a `typ` read as a media type, for comparison, or None when it is not one.
    RFC 7515 §4.1.9: "Per RFC 2045, all media type values, subtype values, and parameter names are case insensitive.
    However, parameter values are case sensitive unless otherwise specified"; 'application/' implied when the value has no
    '/'. The grammar is RFC 9110 §8.3.1 and §5.6.6 with one rule of this format: every ';' is followed by a parameter (RFC 9110
    writes *( OWS ";" OWS [ parameter ] ), an empty parameter allowed; here it is no media type, as under 1.8.0),
    ASCII only: the type, subtype and parameter names with A-Z folded (str.lower makes U+212A KELVIN SIGN a 'k'), each
    value as written, a quoted-string read without its quotes and quoted-pairs (RFC 9110 §5.6.4, §5.6.6: "The quoted and
    unquoted values are equivalent"); parameters in any order, a name twice is no media type. Up to 1.8.0 the whole value
    was folded, so `x+jwt;p=A` equalled `x+jwt;p=a`, and `kb+jwt; p=a` or `kb+jwt;p="a"` did not equal `kb+jwt;p=a`."""
    if not isinstance(typ, str):
        return None
    n = len(typ)

    def token(i):
        j = i
        while j < n and typ[j] in _TCHAR:
            j += 1
        return (typ[i:j], j) if j > i else (None, i)

    t, i = token(0)
    if t is None:
        return None
    if i < n and typ[i] == "/":
        sub, i = token(i + 1)
        if sub is None:
            return None
        full = t + "/" + sub
    elif "/" in typ:   # a '/' elsewhere: the value contains one, so nothing is prepended, and it is no type/subtype
        return None
    else:
        full = "application/" + t
    params = {}
    while i < n:
        while i < n and typ[i] in " \t":
            i += 1
        if i >= n or typ[i] != ";":
            return None
        i += 1
        while i < n and typ[i] in " \t":
            i += 1
        if i >= n or typ[i] == ";":   # SPEC §13, this format's rule: a ';' with no parameter after it is no media
            return None                # type (RFC 9110 §5.6.6 allows it; 1.8.0 refused it too, so nothing widens)
        name, i = token(i)
        if name is None or i >= n or typ[i] != "=":
            return None
        i += 1
        if i < n and typ[i] == '"':
            i, val = i + 1, []
            while True:
                if i >= n:
                    return None
                c = typ[i]
                if c == '"':
                    i += 1
                    break
                if c == "\\":
                    if i + 1 >= n or not (typ[i + 1] in "\t " or 0x21 <= ord(typ[i + 1]) <= 0x7E):
                        return None
                    val.append(typ[i + 1])
                    i += 2
                elif c in "\t " or c == "!" or 0x23 <= ord(c) <= 0x5B or 0x5D <= ord(c) <= 0x7E:
                    val.append(c)
                    i += 1
                else:
                    return None
            value = "".join(val)
        else:
            value, i = token(i)
            if value is None:
                return None
        key = name.translate(_ASCII_LOWER)
        if key in params:
            return None
        params[key] = value
    return full.translate(_ASCII_LOWER), tuple(sorted(params.items()))


def check_jose_header(header, expected_typ: str, allowed_algs) -> Dict:
    """SPEC §13: {"ok", "why", "typ", "alg"}; never raises on `header`, ValueError on the caller's arguments"""
    if not isinstance(expected_typ, str) or _media_type(expected_typ) is None:   # 1.8.1: a media type (SPEC §13)
        raise ValueError("expected_typ: a media type (RFC 9110 §8.3.1; 'application/' implied without '/')")
    if not isinstance(allowed_algs, (list, tuple)) or not allowed_algs \
            or not all(isinstance(a, str) and a for a in allowed_algs) or "none" in allowed_algs:
        raise ValueError('allowed_algs: a non-empty list of algorithm names, without "none" (RFC 8725 §3.2)')
    out = {"ok": False, "why": None, "typ": None, "alg": None}
    if not isinstance(header, dict):
        out["why"] = "header_not_object"
        return out
    out["typ"], out["alg"] = header.get("typ"), header.get("alg")
    if "crit" in header:
        out["why"] = "crit_not_understood"
    elif "alg" not in header:
        out["why"] = "alg_missing"
    elif not isinstance(header["alg"], str):
        out["why"] = "alg_not_string"
    elif header["alg"] not in allowed_algs:
        out["why"] = "alg_not_allowed"
    elif "typ" not in header:
        out["why"] = "typ_missing"
    elif not isinstance(header["typ"], str):
        out["why"] = "typ_not_string"
    elif _media_type(header["typ"]) is None or _media_type(header["typ"]) != _media_type(expected_typ):
        out["why"] = "typ_mismatch"
    else:
        out["ok"] = True
    return out


def check_jose_profile(header, profile: str, allowed_algs) -> Dict:
    """SPEC §13: check_jose_header with a built-in profile's typ; `profile_unknown` for a name not in JOSE_PROFILES"""
    if profile not in JOSE_PROFILES:
        return {"ok": False, "why": "profile_unknown", "typ": None, "alg": None}
    typ, source, no_symmetric = JOSE_PROFILES[profile]
    if no_symmetric and isinstance(allowed_algs, (list, tuple)) and any(a in _SYMMETRIC for a in allowed_algs):
        raise ValueError(f"{profile}: {source} forbids a symmetric algorithm (MAC)")
    out = check_jose_header(header, typ, allowed_algs)
    out["profile"] = profile
    return out


def _disclosure_digest(disclosure_b64: str) -> str:
    # SD-JWT: digest = b64url(sha-256(ASCII of the base64url-encoded disclosure))
    return _sha256_b64url(disclosure_b64.encode("ascii"))


def resolve_disclosures(payload: Dict, disclosures: List[str], census: Optional[Dict] = None) -> Dict:
    """Replace _sd digests / '...' array placeholders with the disclosed claims.
    Fail-closed: duplicate digests, malformed disclosures, or disclosures that match
    nothing are ERRORS (per SD-JWT processing rules), never silently ignored.
    1.7.0 (SPEC §6 step 2): a digest value encountered more than once — in an `_sd` array or as an array placeholder, in
    the payload or inside a disclosed value, matched or not — is an error at the second encounter, before anything under
    it is resolved (RFC 9901 §7.1 step 4; up to 1.6.0 a repeated placeholder expanded the mandate twice, `valid: true`);
    a disclosed claim named `_sd` or `...` is an error (§7.1 step 3.c.ii.2; up to 1.6.0 inserted as an ordinary claim).
    `census`, when a dict, receives `encountered` (every digest value met, in order) and `matched` (those with a
    disclosure): SPEC §11.3 step 5 reads its hidden digests from here, so the two sections share one census.
    1.7.1 (SPEC §6 step 2): the resolved claims nest no deeper than MAX_JSON_DEPTH (the §3.1 bound), else
    `disclosures_too_deep`; the walk is iterative (an explicit stack of generators), so neither the bound nor the error
    depends on the interpreter's recursion limit (up to 1.7.0 a chain of 1500 nested disclosures raised RecursionError,
    measured on Python 3.9, 3.11 and 3.13)."""
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
    encountered: List[str] = []   # 1.7.0: every digest value met, matched or decoy (RFC 9901 §7.1 step 4 says "encountered")
    seen = set()

    def meet(dig):
        if dig in seen:
            raise Ap2EvidenceError(f"digest {dig[:12]!r}… encountered more than once in the issuer payload "
                                   "(RFC 9901 §7.1 step 4, rejected fail-closed)")
        seen.add(dig)
        encountered.append(dig)

    def walk(node, depth):   # a generator: `yield (child, depth)` hands a child to run(), which sends back its resolved value
        if isinstance(node, (dict, list)) and depth > MAX_JSON_DEPTH:
            raise Ap2EvidenceError(f"disclosures_too_deep: the resolved claims nest deeper than {MAX_JSON_DEPTH} "
                                   "(SPEC §6 step 2, rejected fail-closed)")
        if isinstance(node, dict):
            # 1.8.1 (SPEC §6 step 2): the reserved names as plain keys. RFC 9901 §4.1 item 7, "..." only to convey a
            # digest (an array placeholder, handled in the list branch, never reaches here); §4.1.1, _sd_alg only at the
            # top level of the payload (depth 1). Up to 1.8.0 a plain "..." was an ordinary claim, a nested _sd_alg dropped.
            if "..." in node:
                raise Ap2EvidenceError('sd_dots_outside_placeholder: a key "..." outside an array placeholder {"...": '
                                       '<digest>} (RFC 9901 §4.1 item 7, rejected fail-closed)')
            if "_sd_alg" in node and depth > 1:
                raise Ap2EvidenceError("sd_alg_not_top_level: a key _sd_alg below the top level of the issuer payload "
                                       "(RFC 9901 §4.1.1, rejected fail-closed)")
            out = {}
            for k, v in node.items():
                if k in ("_sd", "_sd_alg"):
                    continue
                out[k] = yield (v, depth + 1)
            sd = node.get("_sd", [])
            if not isinstance(sd, list) or any(not isinstance(x, str) for x in sd):
                raise Ap2EvidenceError("_sd must be a list of digest strings")
            for dig in sd:
                meet(dig)
                if dig in by_digest:
                    d, arr = by_digest[dig]
                    if len(arr) != 3:
                        raise Ap2EvidenceError("object disclosure must be [salt,name,value]")
                    if not isinstance(arr[1], str):
                        raise Ap2EvidenceError("disclosed claim name must be a string")
                    if arr[1] in ("_sd", "..."):
                        raise Ap2EvidenceError(f"disclosed claim name {arr[1]!r} is reserved (RFC 9901 §7.1 step 3.c.ii.2, rejected fail-closed)")
                    if arr[1] in out:
                        raise Ap2EvidenceError(f"disclosed claim {arr[1]!r} collides")
                    out[arr[1]] = yield (arr[2], depth + 1)
                    used.add(dig)
            return out
        if isinstance(node, list):
            out_l = []
            for item in node:
                if isinstance(item, dict) and set(item.keys()) == {"..."}:
                    dig = item["..."]
                    if not isinstance(dig, str):
                        raise Ap2EvidenceError("array disclosure placeholder must be a digest string")
                    meet(dig)
                    if dig in by_digest:
                        d, arr = by_digest[dig]
                        if len(arr) != 2:
                            raise Ap2EvidenceError("array disclosure must be [salt,value]")
                        out_l.append((yield (arr[1], depth + 1)))
                        used.add(dig)
                    # undisclosed array element: omitted (that is selective disclosure)
                else:
                    out_l.append((yield (item, depth + 1)))
            return out_l
        return node

    def run(root):
        stack, value = [walk(root, 1)], None
        while stack:
            try:
                child = stack[-1].send(value)
            except StopIteration as stop:   # that node is resolved: its value goes to its parent
                stack.pop()
                value = stop.value
                continue
            stack.append(walk(*child))
            value = None
        return value

    resolved = run(payload)
    unused = set(by_digest) - used
    if unused:
        raise Ap2EvidenceError(f"{len(unused)} disclosure(s) match no digest in the "
                               "payload (rejected fail-closed)")
    if census is not None:
        census["encountered"] = encountered
        census["matched"] = used
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
    try:   # 1.7.3: measured on 1.7.2, a JWK whose (x, y) is not a point of P-256 — a --key file, a header jwk, a JWKS key or
        # cnf.jwk — was a ValueError traceback out of `build` (exit 1, no reason); verify already reported it as the artifact's error
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as e:
        raise Ap2EvidenceError("JWK x/y is not a point of P-256") from e


def _load_x5c_leaf(x5c: List[str]):
    """The leaf CERTIFICATE (not just its key): r7 also reads subject/issuer, to tell a self-signed leaf (still self-asserted)
    from one someone else issued."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    try:   # r7: a leaf wrapped at 76 columns, not a certificate, or not a string used to be a bare ValueError -> traceback out of `build`
        leaf = x509.load_der_x509_certificate(_sigsuite._unb64(x5c[0]))   # r6: strict RFC 4648 — b64decode() dropped a space/newline, the JS verifier refused it
    except Ap2EvidenceError:
        raise
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"x5c leaf is not a strict-base64 DER certificate: {type(e).__name__}") from e
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise Ap2EvidenceError("x5c leaf key is not EC P-256 (ES256 only, declared)")
    return leaf


def _pubkey_from_x5c_leaf(x5c: List[str]):
    return _load_x5c_leaf(x5c).public_key()


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


PROVENANCE_CLASSES = frozenset({"supplied", "x5c_header", "jwk_header", "jwks_fetched", "chain_cnf"})   # chain_cnf: 1.9.0, SPEC §2.1

# ── closed schema (SPEC §9, 1.4.0). Measured 2026-10-10 on 1.3.0: a key nobody defined, inside rfc3161_timestamp, the
# producer block or a signature entry, was accepted with valid: true and no trace in the receipt. Every object this format
# defines is now an exhaustive key list (§9.1: unknown = refusal / artifact error / FAIL entry, with the key named); every
# object a standard defines follows that standard's rule for the unknown (§9.2: ignored AND reported).
_JOSE_HEADER_REGISTERED = frozenset({"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"})   # RFC 7515 §4.1, RFC 7519 §5
_JWK_REGISTERED = frozenset({"kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "d"})   # RFC 7517 §4, RFC 7518 §6.2
_CNF_REGISTERED = frozenset({"jwk", "jwe", "jku", "kid"})                                                                     # RFC 7800 §3.1
_KB_CLAIMS_REGISTERED = frozenset({"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce", "sd_hash"})                      # RFC 7519 §4.1, RFC 9901 §4.3


def _is_str(v): return isinstance(v, str)
def _is_bool(v): return isinstance(v, bool)
def _is_obj(v): return isinstance(v, dict)
def _is_list(v): return isinstance(v, list)
def _is_str_or_none(v): return v is None or isinstance(v, str)
def _is_bool_or_none(v): return v is None or isinstance(v, bool)
def _is_true(v): return v is True
def _is_list_of_str(v): return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _jkey(k) -> str:
    return json.dumps(k, ensure_ascii=False)   # the same spelling as JSON.stringify in the JS verifier


def _check_closed(obj, what: str, allowed: Dict[str, tuple], err=None):
    """SPEC §9.1: `allowed` maps every key of the object to (predicate, description, required). An object that is not a
    dict, a key outside `allowed`, a wrong type or a missing required key raises `err` (Ap2EvidenceError by default) with
    the object and the key named — the same three messages the JS verifier produces."""
    err = err or Ap2EvidenceError
    if not isinstance(obj, dict):
        raise err(f"{what} must be an object (SPEC §9.1)")
    unknown = sorted(k for k in obj if k not in allowed)   # 1.4.1: the first unknown key by code point, not by file order
    if unknown:                                            # (JS Object.keys puts integer-like keys first: the two named different keys)
        raise (Ap2UnknownMember if err is Ap2EvidenceError else err)(f"{what}: unknown key {_jkey(unknown[0])} (SPEC §9.1)")
    for k, (pred, desc, required) in allowed.items():
        if k in obj:
            if not pred(obj[k]):
                raise err(f"{what}: {k} must be {desc} (SPEC §9.1)")
        elif required:
            raise err(f"{what}: missing {k} (SPEC §9.1)")


def _check_unknown(obj, what: str, allowed) -> None:
    """1.6.0 — SPEC §9.1/§6.9: only the unknown-key rule of `_check_closed`, for the objects whose other violations stay an
    artifact error or a FAIL entry (`artifacts[i]` and its `key`, `kb_jwt`, `verified_at_build`; `signatures[i]`). An
    object that is not a dict is left to those rules."""
    if isinstance(obj, dict):
        unknown = sorted(k for k in obj if k not in allowed)
        if unknown:
            raise Ap2UnknownMember(f"{what}: unknown key {_jkey(unknown[0])} (SPEC §9.1)")


_TOP_KEYS = {"evidence_format": (_is_str, "a string", True), "subject": (_is_str, "a string", True), "created_utc": (_is_str, "a string", True),
             "artifacts": (_is_list, "a list", True), "bindings": (_is_list, "a list", False), "honest_scope": (_is_str, "a string", True),
             "evidence_digest_sha256": (_is_str, "a string", True), "rfc3161_timestamp": (_is_obj, "an object", False), "producer_signatures": (_is_obj, "an object", False),
             "anchors": (lambda v: isinstance(v, list) and len(v) > 0, "a non-empty list", False),   # 1.5.0 — SPEC §3.3
             "not_before": (_is_obj, "an object", False)}   # 1.8.0 — SPEC §12
_ANCHOR_MECHANISMS = ("rfc3161",)   # SPEC §3.3: the mechanisms this revision defines; any other is a refusal naming it
_ANCHOR_RFC3161_KEYS = {"mechanism": (lambda v: v == "rfc3161", '"rfc3161"', True), "tsr_b64": (_is_str, "a string", True),
                        "tsa_url": (_is_str, "a string", False), "note": (_is_str, "a string", False)}
_DIGEST_EXCLUDED = ("evidence_digest_sha256", "rfc3161_timestamp", "producer_signatures", "anchors")   # SPEC §3 (1.5.0: + anchors)
_RFC3161_KEYS = {"anchored": (_is_bool, "a boolean", True), "tsr_b64": (_is_str, "a string", False),   # tsr_b64 ABSENT under anchored: §6.4 says rfc3161_verified false, not a refusal
                 "tsa_url": (_is_str, "a string", False), "tsa": (_is_str, "a string", False), "note": (_is_str, "a string", False)}
_PRODUCER_KEYS = {"scheme": (lambda v: v in ("hybrid", "classical-only"), '"hybrid" or "classical-only"', True),
                  "over": (lambda v: v == "evidence_digest_sha256", '"evidence_digest_sha256"', True), "signatures": (_is_list, "a list", True)}
_BINDING_KEYS = {"in": (_is_str, "a string", True), "claim": (_is_str, "a string", True), "commits_to": (_is_str, "a string", True),
                 "encoding": (lambda v: v in ("hex", "b64url"), '"hex" or "b64url"', True),
                 "over": (lambda v: v == "issuer_jwt", '"issuer_jwt"', False)}   # 1.9.0 (SPEC §4)
_ARTIFACT_KEYS = {"name": (_is_str, "a string", True), "sd_jwt_compact": (_is_str, "a string", True), "header": (_is_obj, "an object", True),
                  "key": (_is_obj, "an object", True), "resolved_claims": (lambda v: True, "", True), "kb_jwt": (_is_obj, "an object", True),
                  "verified_at_build": (_is_obj, "an object", True)}
_KEY_KEYS = {"jwk": (_is_obj, "an object", True), "provenance_class": (_is_str, "a string", True), "note": (_is_str, "a string", False),
             "x5c_chain_sha256": (_is_list_of_str, "a list of strings", False), "jwks_url": (_is_str, "a string", False),
             "jwks_sha256": (_is_str, "a string", False), "fetched_utc": (_is_str, "a string", False),
             "chain_from": (_is_str, "a string", False)}   # 1.9.0 (SPEC §2.1): with chain_cnf, and only with it
_KB_COPY_KEYS = {"present": (_is_bool, "a boolean", True), "verified": (_is_bool_or_none, "a boolean or null", False), "signature_ok": (_is_bool, "a boolean", False),
                 "sd_hash_ok": (_is_bool, "a boolean", False), "note": (_is_str_or_none, "a string or null", False), "claims_recorded_not_validated": (_is_obj, "an object", False)}
_VAB_KEYS = {"signature_ok": (_is_true, "true", True), "disclosures_ok": (_is_true, "true", True)}
_KB_RECOMPUTED = ("verified", "signature_ok", "sd_hash_ok", "claims_recorded_not_validated")   # each, when present in the copy, MUST equal the recomputation (SPEC §9.1)


def _jose_header_ignored(header: Dict, what: str) -> List[str]:
    """RFC 7515 §4: header parameters not understood MUST be ignored — unless named in `crit` (§4.1.11), where an extension
    the recipient does not understand makes the JWS INVALID. This format understands no extension, so a well-formed `crit`
    is always a rejection; a malformed one (not a non-empty list of distinct strings, naming a registered parameter or one
    absent from the header — all "MUST NOT" for producers) is one too. Returns the ignored names, sorted, for the receipt."""
    if "crit" in header:
        crit = header["crit"]
        if (not isinstance(crit, list) or not crit or any(not isinstance(c, str) for c in crit) or len(set(crit)) != len(crit)
                or any(c in _JOSE_HEADER_REGISTERED or c not in header for c in crit)):
            raise Ap2EvidenceError(f"{what}: malformed crit (RFC 7515 §4.1.11)")
        raise Ap2EvidenceError(f"{what}: crit names extension(s) this verifier does not understand (RFC 7515 §4.1.11: the JWS is invalid)")
    return sorted(k for k in header if k not in _JOSE_HEADER_REGISTERED)


def _unknown_members(obj, registered) -> List[str]:
    return sorted(k for k in obj if k not in registered) if isinstance(obj, dict) else []


def _check_provenance(pc, parsed: Dict, key: Dict, trust_anchor: Optional[str] = None, at_time: Optional[str] = None):
    """1.1.0 r5: the provenance class is the field the honest_scope sends the relying party to, and it was the one field
    entirely under the pack author's control — relabelling `jwk_header` as `x5c_header` flipped `self_asserted_only` to
    False with no x5c anywhere. The two header-derived classes are now RECONCILED against the header the verifier just
    parsed; `supplied` and `jwks_fetched` remain capture-time assertions that cannot be checked offline (SPEC §2).

    Returns (self_asserted, leaf_identity): r8: offline, "issued by someone else" is NOT establishable — r7 read it off
    `subject != issuer`, two DN strings the forger writes himself (measured: a leaf self-signed with its own key, declaring
    `CN=DigiCert Global Root CA` as issuer, cleared the flag in both verifiers while the pack stayed `valid`). The only thing
    that can clear it is a CHAIN validated to a trust anchor the RELYING PARTY supplies (`--trust-anchor`, same idiom as
    `--tsa-cert`): without one, every class — `jwk_header`, `x5c_header`, `supplied`, `jwks_fetched` — is self-asserted."""
    if pc not in ("jwk_header", "x5c_header"):
        return True, None
    header = parsed.get("header") if isinstance(parsed.get("header"), dict) else {}
    jwk = key.get("jwk") or {}
    if pc == "jwk_header":
        hj = header.get("jwk")
        if not isinstance(hj, dict) or any(hj.get(f) != jwk.get(f) for f in ("kty", "crv", "x", "y")):
            raise Ap2EvidenceError("provenance_class jwk_header but the signed header carries no matching jwk")
        return True, None
    x5c = header.get("x5c")
    if not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], str):
        raise Ap2EvidenceError("provenance_class x5c_header but the signed header carries no x5c")
    try:
        cert = _load_x5c_leaf(x5c)
        leaf = _jwk_from_pubkey(cert.public_key())
    except Exception as e:  # noqa: BLE001
        raise Ap2EvidenceError(f"provenance_class x5c_header but the x5c leaf is unusable: {type(e).__name__}") from e
    if any(leaf.get(f) != jwk.get(f) for f in ("kty", "crv", "x", "y")):
        raise Ap2EvidenceError("provenance_class x5c_header but the x5c leaf key differs from the snapshotted jwk")
    # r9: the receipt names WHO the certificate was issued to. A cleared flag means "a CA under your anchor certified this
    # key", never "the key belongs to the mandate's issuer" — an auditor cannot tell CN=the-bank from CN=attacker without this.
    ident = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
             "serial": format(cert.serial_number, "x"),
             "not_valid_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "not_valid_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "sha256": hashlib.sha256(cert.public_bytes(_serialization().Encoding.DER)).hexdigest()}
    ident["chain_verified"] = None     # r11: always present, as in the JS receipt — None = not measured
    if trust_anchor is None:
        return True, ident   # no anchor: the certificate proves only that the key is in a blob the signer wrote
    diag: Dict = {}
    try:
        chain_ok = _verify_x5c_chain(x5c, trust_anchor, at_time=at_time, diag=diag)
        if diag.get("broken"):
            ident["_broken"] = diag["broken"]
    except Ap2WriteError as e:   # 1.6.0 (SPEC §6.10): not run here = not measured (None); the receipt goes on
        chain_ok = None
        ident["_not_run"] = str(e)
    ident["chain_verified"] = chain_ok
    return (chain_ok is not True), ident   # only a chain that really validated clears it (None = openssl absent = unmeasurable)


def _serialization():
    from cryptography.hazmat.primitives import serialization
    return serialization


def _openssl_tmpdir() -> str:
    """A private directory for the files openssl reads. One this process cannot create or write is Ap2WriteError (the
    check could not be run here: exit 74 in the CLI), never a traceback or a check reported as failed (1.5.2: measured
    13/10/2026 under `ulimit -f 0`, `verify --tsa-cert` on a valid pack raised a traceback, exit 1, and with
    `--trust-anchor` the artifact was reported as an error, so the pack was "not valid")."""
    import tempfile
    try:
        base = tempfile.gettempdir()   # it probes every candidate by writing a file there
    except OSError as e:   # its message lists the candidate paths: a reason that would change with the environment
        raise Ap2WriteError("cannot write a temporary file for openssl: no usable temporary directory") from e
    try:
        return tempfile.mkdtemp(prefix="ap2-openssl-", dir=base)
    except OSError as e:
        raise _tmp_error(e) from e


def _tmp_error(e: OSError) -> "Ap2WriteError":
    why = os.strerror(e.errno) if isinstance(e.errno, int) else str(e)
    return Ap2WriteError(f"cannot write a temporary file for openssl: {type(e).__name__}: {why}")


def _run_openssl(cmd: List[str], timeout: int, **kw):
    """subprocess.run of openssl for a check the caller asked for. openssl that cannot be started HERE (fork refused under
    `ulimit -u` or low memory: EAGAIN/ENOMEM; no descriptor left for its pipes: EMFILE; the binary gone since `which`) is
    Ap2WriteError, the same "this check cannot be run here" as a temporary file that cannot be written: before (1.5.1 to
    cb36d56) it was reported as a failed check — measured 13/10/2026 under RLIMIT_NPROC 1, `verify --tsa-cert
    --require-anchor` on a valid pack: `tsa_verified: false`, `valid: false`, exit 1. openssl that gives no answer within
    `timeout` seconds is the same case: the check did not finish here, and a machine too slow for it is not a fact about
    the input (measured 13/10/2026 with an openssl that answers after 20 s: a valid pack was `tsa_verified: false`,
    `valid: false`, exit 1 under `--require-anchor`)."""
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired as e:
        raise Ap2WriteError(f"cannot run openssl here: no answer within {timeout} s") from e
    except OSError as e:
        why = os.strerror(e.errno) if isinstance(e.errno, int) else str(e)
        raise Ap2WriteError(f"cannot run openssl here: {type(e).__name__}: {why}") from e
    if r.returncode < 0:   # 1.6.0 (SPEC §6.10, krausz §3.1 "a crashed dependency"): openssl killed by a signal gave no
        # answer — measured 18/10/2026 with an openssl killed by SIGSEGV: `tsa_invalid` / `chain_unresolved`, a finding about
        # the input, and exit 1 on a valid pack under --require-anchor
        raise Ap2WriteError(f"cannot run openssl here: terminated by signal {-r.returncode}")
    return r


def _tmp_write(path: str, data: bytes) -> None:
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as e:
        raise _tmp_error(e) from e


def _verify_x5c_chain(x5c: List[str], trust_anchor: str, at_time: Optional[str] = None, timeout: int = 15,
                      diag: Optional[Dict] = None) -> Optional[bool]:
    """Validate the x5c chain to a PEM trust anchor with `openssl verify` (the reference only, like `openssl ts -verify` for
    the TSA — the JS verifier reports `chain_verified: null` and never clears `self_asserted_only`: declared divergence).

    `at_time` (r9) is the TSTInfo `genTime` of a TSA-VERIFIED RFC 3161 token, when there is one: the chain is then validated
    AT that time (`openssl verify -attime`), because a signing certificate lives 1-3 years and this format exists to verify
    years later — measured: a leaf valid 2020-2021 whose chain is fine under the anchor was `chain_verified: false` at
    today's clock, so the ONLY mechanism that clears `self_asserted_only` never fired in the scenario the format is for.
    Without a proven time the current clock is used, as `openssl verify` does by default.

    Returns True/False, or None when openssl is absent (r9: unmeasurable is not the same as failed — `self_asserted_only`
    stays fail-closed either way); raises Ap2WriteError (1.5.2) when the check cannot be run here (see _run_openssl)."""
    import shutil
    exe = shutil.which("openssl")
    if not exe:
        return None          # r9: not measurable here, which is not the same as "the chain failed"
    d = _openssl_tmpdir()
    try:
        def pem(b: bytes) -> bytes:
            body = base64.b64encode(b).decode()
            return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE-----\n").encode()
        try:
            chain = [_sigsuite._unb64(c) for c in x5c]
        except Exception:  # noqa: BLE001
            if diag is not None:
                diag["broken"] = "an x5c entry is not strict base64"
            return False
        leaf_path = os.path.join(d, "leaf.pem")
        _tmp_write(leaf_path, pem(chain[0]))
        # 1.8.1 (SPEC §6 step 7): the anchor the relying party supplies and nothing else. Without -no-CApath -no-CAstore
        # openssl adds its default store (the system CAs, SSL_CERT_FILE, SSL_CERT_DIR): measured on 2026-11-18 on 1.8.0,
        # a leaf of a CA in that store was verified / ca_certified under an unrelated --trust-anchor. As the TSA
        # key-identifier step (key_id_token_problem).
        cmd = [exe, "verify", "-CAfile", trust_anchor, "-no-CApath", "-no-CAstore"]
        if at_time:
            import calendar
            import time as _t
            try:
                cmd += ["-attime", str(calendar.timegm(_t.strptime(at_time.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")))]
            except ValueError:
                pass
        if len(chain) > 1:
            unt = os.path.join(d, "untrusted.pem")
            _tmp_write(unt, b"".join(pem(c) for c in chain[1:]))
            cmd += ["-untrusted", unt]
        r = _run_openssl(cmd + [leaf_path], timeout, text=True)
        if r.returncode != 0 and "nknown option" in (r.stderr or "") + (r.stdout or ""):   # before OpenSSL 3.0
            raise Ap2WriteError("this openssl does not know an option of `verify` (OpenSSL 3.0 or later is needed): "
                                + ((r.stderr or r.stdout or "").strip()[-120:]))
        ok = r.returncode == 0 and ": OK" in (r.stdout or "")
        if not ok and diag is not None and "certificate signature failure" in ((r.stdout or "") + (r.stderr or "")):
            diag["broken"] = "certificate signature failure"   # 1.6.0 (SPEC §6.9): a signature inside the chain does not verify
        return ok
    except Ap2WriteError:
        raise
    except Exception:  # noqa: BLE001
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


_HEADER_KEY_SOURCES = ("jku", "jwk", "x5u", "x5c")   # RFC 7515 §4.1.2, §4.1.3, §4.1.5, §4.1.6: each names the signing key
_SOURCE_OF_CLASS = {"jwk_header": "jwk", "x5c_header": "x5c"}


def _key_material_not_used(header: Dict, pc) -> List[str]:
    """1.7.3 (SPEC §2 (d)): the key sources of the protected header that are present and are not where the snapshotted key
    came from, sorted. Up to 1.7.2 they were passed over in silence."""
    used = _SOURCE_OF_CLASS.get(pc)
    return sorted(k for k in _HEADER_KEY_SOURCES if k in header and k != used)


def _same_key(a, b) -> bool:
    return isinstance(a, dict) and isinstance(b, dict) and all(a.get(f) == b.get(f) for f in ("kty", "crv", "x", "y"))


def _reconcile_unused_header_keys(header: Dict, jwk: Dict, pc) -> None:
    """1.7.3 (SPEC §2 (d)): a header `jwk` or `x5c` that is not the source of the snapshotted key must still name that key
    (RFC 7515 §4.1.3/§4.1.6 define both as the signing key). A different key, or a value that is not a key, is refused —
    this format's choice: neither RFC 7515 nor draft-ietf-oauth-sd-jwt-vc-27 makes it an error (-27 §2.5: inputs of other
    mechanisms MUST NOT be treated as identifying the Issuer unless policy binds them)."""
    used = _SOURCE_OF_CLASS.get(pc)
    if "jwk" in header and used != "jwk" and not _same_key(header["jwk"], jwk):
        raise Ap2EvidenceError("the header jwk names another key than the one the artifact verifies under (SPEC §2 (d), RFC 7515 §4.1.3)")
    if "x5c" in header and used != "x5c":
        x5c = header["x5c"]
        if not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], str):
            raise Ap2EvidenceError("the header x5c is not a non-empty list of certificates (SPEC §2 (d), RFC 7515 §4.1.6)")
        try:
            leaf = _jwk_from_pubkey(_load_x5c_leaf(x5c).public_key())
        except Exception as e:  # noqa: BLE001
            raise Ap2EvidenceError(f"the header x5c leaf is unusable: {type(e).__name__} (SPEC §2 (d), RFC 7515 §4.1.6)") from e
        if not _same_key(leaf, jwk):
            raise Ap2EvidenceError("the header x5c leaf names another key than the one the artifact verifies under (SPEC §2 (d), RFC 7515 §4.1.6)")


def _usable_jwk(k: Dict) -> bool:
    """1.7.3 (SPEC §2 (c)): a JWK of the set that can verify ES256; the others are not considered (RFC 7517 §5)."""
    ops = k.get("key_ops")
    return (k.get("kty") == "EC" and k.get("crv") == "P-256" and isinstance(k.get("x"), str) and isinstance(k.get("y"), str)
            and k.get("use", "sig") == "sig" and k.get("alg", "ES256") == "ES256"
            and (ops is None and "key_ops" not in k or isinstance(ops, list) and "verify" in ops))


def _not_used_note(header: Dict, pc) -> str:
    names = _key_material_not_used(header, pc)
    return (f"; not used for the key: {', '.join(names)} in the header (SPEC §2 (d): a jwk or x5c there names this same key, "
            "a jku or x5u is never fetched)") if names else ""


def _snapshot_key(parsed: Dict, supplied_jwk: Optional[Dict] = None,
                  jwks_url: Optional[str] = None, timeout: int = 20) -> Dict:
    """Choose the verification key and record WHERE it came from (provenance class).
    1.7.3 (SPEC §2): the key the CALLER names — a supplied key or a JWKS URL — is the policy and is used whatever the header
    carries (draft-ietf-oauth-sd-jwt-vc-27 §2.5: the key comes from a mechanism "permitted for the given Issuer according to
    policy"); both for one artifact is refused by the callers (build_evidence, the CLI). Without one: x5c header > jwk header. Fail-closed if none.
    Up to 1.7.2 the order was supplied > x5c > jwk > JWKS: a --jwks-url was never fetched for a token carrying jwk or x5c,
    and the self-declared key won in silence (measured 2026-11-03). The header key sources not used are compared by
    `_reconcile_unused_header_keys` after the signature check, and named in the note."""
    header = parsed["header"]
    if header.get("alg") != "ES256":
        raise Ap2EvidenceError(f"alg {header.get('alg')!r} unsupported: ES256 only "
                               "(other algs are rejected, never half-verified)")
    if supplied_jwk is not None:
        if not isinstance(supplied_jwk, dict) or not supplied_jwk:
            raise Ap2EvidenceError("a supplied key must be a non-empty JSON object, a JWK (SPEC §2 (b))")
        return {"jwk": supplied_jwk, "provenance_class": "supplied",
                "note": "key material supplied by the caller (caller vouches); "
                        "the caller's choice is the policy, whatever the header carries" + _not_used_note(header, "supplied")}
    if jwks_url is not None:
        if not isinstance(jwks_url, str) or not jwks_url.startswith("https://"):
            raise Ap2EvidenceError("JWKS URL must be a string starting https:// (TLS is the whole witness)")
        if "kid" in header and not isinstance(header["kid"], str):
            raise Ap2EvidenceError("the header kid is not a string (RFC 7515 §4.1.4): the JWKS key cannot be chosen")
        try:   # r7: an unreachable endpoint or a non-JSON body used to be a URLError/JSONDecodeError traceback
            with urllib.request.urlopen(jwks_url, timeout=timeout) as r:  # nosec B310 - https enforced above
                raw = r.read(1024 * 1024 + 1)      # cap: un JWKS gigante = DoS, non una chiave
                final_url = r.geturl()
        except Exception as e:  # noqa: BLE001
            raise Ap2EvidenceError(f"JWKS fetch failed: {type(e).__name__}") from e
        if not isinstance(final_url, str) or not final_url.startswith("https://"):   # 1.7.3 (SPEC §2 (c)): urllib follows a
            # redirect to http; measured 2026-11-03 on 1.7.2 and on the 1.7.3 draft, a 302 https -> http was followed, the set read over plain http
            # and snapshotted as jwks_fetched under the https URL, exit 0
            raise Ap2EvidenceError("JWKS fetch was redirected to a URL that is not https:// (TLS is the whole witness): refused")
        if len(raw) > 1024 * 1024:
            raise Ap2EvidenceError("JWKS response exceeds 1MB cap (refused fail-closed)")
        try:
            jwks = json.loads(raw.decode())
        except Exception as e:  # noqa: BLE001
            raise Ap2EvidenceError(f"JWKS body is not JSON: {type(e).__name__}") from e
        # 1.7.1 (NEMESIS2): a body that parses but is not {"keys": [object, ...]} (RFC 7517 §5) is a refusal; measured on 1.7.0
        # and 1.7.1 with the fetch replaced in-process, a list, a string, null, "keys": 5 or "keys": [5] was a traceback
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or any(not isinstance(k, dict) for k in jwks["keys"]):
            raise Ap2EvidenceError('JWKS body is not a JSON object with "keys", a list of JWK objects (RFC 7517 §5)')
        usable = [k for k in jwks["keys"] if _usable_jwk(k)]   # 1.7.3 (SPEC §2 (c)): the rule is written, not "the first entry"
        unusable = len(jwks["keys"]) - len(usable)
        if "kid" in header:
            kid = header["kid"]
            match = [k for k in usable if k.get("kid") == kid]
            if not match:
                raise Ap2EvidenceError(f"no usable ES256 key in the JWKS carries kid={kid!r} "
                                       f"({len(jwks['keys'])} keys, {unusable} not usable) (SPEC §2 (c))")
            if len(match) > 1:
                raise Ap2EvidenceError(f"{len(match)} usable keys in the JWKS carry kid={kid!r}: ambiguous, refused (SPEC §2 (c))")
        else:
            match = usable
            if not match:
                raise Ap2EvidenceError(f"the JWKS holds no usable ES256 key ({len(jwks['keys'])} keys, {unusable} not usable) "
                                       "(SPEC §2 (c))")
            if len(match) > 1:
                raise Ap2EvidenceError(f"the token carries no kid and the JWKS holds {len(match)} usable keys: ambiguous, refused "
                                       "— name the key with --key (SPEC §2 (c))")
        return {"jwk": {k: match[0][k] for k in ("kty", "crv", "x", "y", "kid")
                        if k in match[0]},
                "provenance_class": "jwks_fetched",
                "jwks_url": jwks_url, "jwks_sha256": hashlib.sha256(raw).hexdigest(),
                "fetched_utc": _utcnow(),
                "note": "fetched over TLS at build time — a capture witness, "
                        "not proof of issuer control of the key"
                        + (f"; {unusable} JWK(s) of the set not usable for ES256, not considered (RFC 7517 §5)" if unusable else "")
                        + _not_used_note(header, "jwks_fetched")}
    if "x5c" in header:   # 1.7.3: present = carried, whatever its value (an empty or null x5c was passed over up to 1.7.2)
        if not isinstance(header["x5c"], list) or not header["x5c"] or len(header["x5c"]) > 10:
            raise Ap2EvidenceError("x5c chain absent or too long (>10 certs): refused "
                                   "(a huge chain is a DoS vector, not a key)")
        pub = _pubkey_from_x5c_leaf(header["x5c"])
        try:
            chain_fp = [hashlib.sha256(_sigsuite._unb64(c)).hexdigest() for c in header["x5c"]]   # r6: strict, like the leaf
        except Exception as e:  # noqa: BLE001 — r7: a receipt, not a traceback
            raise Ap2EvidenceError(f"x5c chain entry is not strict base64: {type(e).__name__}") from e
        return {"jwk": _jwk_from_pubkey(pub), "provenance_class": "x5c_header",
                "x5c_chain_sha256": chain_fp,
                "note": "leaf cert key verified the signature; chain recorded, PKI path "
                        "NOT validated to a trust anchor here (declared)" + _not_used_note(header, "x5c_header")}
    if "jwk" in header:
        if not isinstance(header["jwk"], dict):
            raise Ap2EvidenceError("the header jwk is not a JSON object (RFC 7515 §4.1.3)")
        return {"jwk": {k: header["jwk"][k] for k in ("kty", "crv", "x", "y")
                        if k in header["jwk"]},
                "provenance_class": "jwk_header",
                "note": "key embedded in the protected header (self-asserted)" + _not_used_note(header, "jwk_header")}
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
    # 1.4.0 (SPEC §9.2): RFC 9901 §4.3 — typ REQUIRED and MUST be kb+jwt (§7.3 step 5.d); iat/aud/nonce/sd_hash REQUIRED with
    # their types. Presence and type, never the values (the sealed scope: aud/nonce/iat are recorded, not validated). Checked
    # whether or not the holder key is known, like the §3.1 segment profile.
    # 1.8.0 (SPEC §7.3, §13): compared as RFC 7515 §4.1.9 says, so "KB+JWT" and "application/kb+jwt" are kb+jwt
    if not isinstance(header.get("typ"), str) or _media_type(header["typ"]) != _media_type("kb+jwt"):   # None != the tuple
        raise Ap2EvidenceError("kb-jwt typ must be \"kb+jwt\" (RFC 9901 §4.3)")
    ignored = {"kb_jwt_header": _jose_header_ignored(header, "kb-jwt header")}
    for claim, pred, desc in (("iat", lambda v: isinstance(v, int) and not isinstance(v, bool), "an integer"), ("aud", _is_str, "a string"),
                              ("nonce", _is_str, "a string"), ("sd_hash", _is_str, "a string")):
        if claim not in payload:
            raise Ap2EvidenceError(f"kb-jwt payload: missing {claim} (RFC 9901 §4.3)")
        if not pred(payload[claim]):
            raise Ap2EvidenceError(f"kb-jwt payload: {claim} must be {desc} (RFC 9901 §4.3)")
    ignored["kb_jwt_claims"] = _unknown_members(payload, _KB_CLAIMS_REGISTERED)
    # 1.1.0 r2: `cnf` absent or an object, `cnf.jwk` absent or an object (an empty object is a holder key that fails to
    # parse, not "unknown"): present-with-null used to be an AttributeError here and "absent" in JS
    rc = resolved_claims if isinstance(resolved_claims, dict) else {}
    if "cnf" in rc and not isinstance(rc["cnf"], dict):
        raise Ap2EvidenceError("cnf must be an object")
    cnf = rc.get("cnf", {})
    ignored["cnf"] = _unknown_members(cnf, _CNF_REGISTERED)   # RFC 7800 §3.1: not understood -> ignored, here reported
    _b64url_decode(seg[2])   # the §3.1 profile applies to all three segments even when the holder key is unknown: without
    # this, a KB-JWT whose signature segment is non-canonical base64url passed with valid: true, because the branch below
    # returns before the signature is ever decoded (found by probing the six uncovered KB-JWT branches)
    recorded = {k: payload.get(k) for k in ("aud", "nonce", "iat") if k in payload}   # final check: the sealed scope says
    # these are RECORDED whenever a KB-JWT is present — this branch returned before recording them, in both verifiers
    presentation = parsed["compact"].rsplit("~", 1)[0] + "~"
    sd_hash_ok = payload.get("sd_hash") == _sha256_b64url(presentation.encode("ascii"))   # RFC 9901 §4.3.1: no key needed
    if "jwk" not in cnf:   # 1.8.1 (SPEC §9.2): sd_hash checked here too; `verified` stays null, the signature is not checked
        if not sd_hash_ok:   # SPEC §9.2 (this format's rule; RFC 9901 §7.3 step 5.g asks it only when Key Binding is required)
            raise Ap2EvidenceError("sd_hash_mismatch: the KB-JWT sd_hash is not the hash of this presentation "
                                   "(RFC 9901 §4.3.1; checked without cnf.jwk, SPEC §9.2)")
        return {"present": True, "verified": None, "sd_hash_ok": sd_hash_ok, "claims_recorded_not_validated": recorded,
                "note": "no cnf.jwk in issuer payload — holder key unknown (declared)", "_ignored": ignored}
    jwk = cnf["jwk"]
    if not isinstance(jwk, dict):
        raise Ap2EvidenceError("cnf.jwk must be an object")
    ignored["cnf_jwk"] = _unknown_members(jwk, _JWK_REGISTERED)   # RFC 7517 §4
    sig_ok = verify_es256(f"{seg[0]}.{seg[1]}".encode("ascii"),
                          _b64url_decode(seg[2]), jwk)
    return {"present": True, "verified": bool(sig_ok and sd_hash_ok),
            "signature_ok": sig_ok, "sd_hash_ok": sd_hash_ok, "note": None,
            "claims_recorded_not_validated": recorded, "_ignored": ignored}


# ────────────────────────────────────────────────────────── bindings

def find_bindings(artifacts: List[Dict]) -> List[Dict]:
    """Cross-artifact hash commitments, recomputed from the PRIMARY quantity: sha-256 over
    each artifact's exact compact serialization (hex and b64url forms), matched against
    every string claim of the other artifacts. Deterministic; found-or-absent, never guessed.
    1.9.0 (SPEC §4): also over each artifact's issuer-signed JWT alone (AP2's receipt `reference`, the chain hop's
    `issuer_jwt_hash`), recorded with `"over": "issuer_jwt"`."""
    by_value = {}   # r5: inverse index (digest string -> name, encoding) — the per-leaf scan used to be O(artifacts), quadratic
    for a in artifacts:
        raw = a["compact"].encode("ascii")
        by_value.setdefault(hashlib.sha256(raw).hexdigest(), []).append((a["name"], "hex", None))
        by_value.setdefault(_sha256_b64url(raw), []).append((a["name"], "b64url", None))
        ij = a["compact"].split("~", 1)[0].encode("ascii")
        by_value.setdefault(hashlib.sha256(ij).hexdigest(), []).append((a["name"], "hex", "issuer_jwt"))
        by_value.setdefault(_sha256_b64url(ij), []).append((a["name"], "b64url", "issuer_jwt"))
    found = []

    def scan(node, path, holder):
        if isinstance(node, dict):
            for k, v in node.items():
                scan(v, f"{path}.{k}" if path else k, holder)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                scan(v, f"{path}[{i}]", holder)
        elif isinstance(node, str):
            for other, enc, over in by_value.get(node, ()):
                if other == holder:
                    continue
                found.append({"in": holder, "claim": path, "commits_to": other, "encoding": enc,
                              **({"over": over} if over else {})})

    for a in artifacts:
        scan(a["resolved_claims"], "", a["name"])
    return found


def bindings_recorded_match(found: List[Dict], recorded) -> Optional[List[Dict]]:
    """SPEC §4 (1.9.0): whether the recorded binding set is the recomputed one. Returns None when it is not, else the
    recomputed bindings the pack does not record — [] when the two sets are equal, and, for a pack that records no binding
    over the issuer JWT (every pack built before 1.9.0), the recomputed bindings with `over`: ALL of them left out, never
    some. Measured on 2026-11-18 on the first 1.9.0 draft, which asked equality alone: a pack built by 1.8.0 from a chain
    split by hand and a receipt of the AP2 SDK, `valid: true` there, came out `binding_mismatch`."""
    rec = sorted(_canon(b) for b in recorded)
    if sorted(_canon(b) for b in found) == rec:
        return []
    if sorted(_canon(b) for b in found if "over" not in b) == rec:
        return sorted((b for b in found if "over" in b), key=_canon)   # one order in both verifiers (their scan orders differ)
    return None


# ────────────────────────────────────────────────────────── AP2 delegation chains (SPEC §2.1, 1.9.0)
# draft-gco-oauth-delegate-sd-jwt-00 §6 as the AP2 SDK implements it (google-agentic-commerce/AP2 e1ea56d,
# code/sdk/python/ap2/sdk/sdjwt/chain.py and kb_sd_jwt.py): hops joined by "~~", the root an SD-JWT, every later hop a
# KB-SD-JWT signed with the previous hop's cnf.jwk and bound to it by exactly one of sd_hash / issuer_jwt_hash.
AP2_HOP_TYPS_TERMINAL = ("kb+sd-jwt", "kb-sd-jwt")
AP2_HOP_TYPS_INTERMEDIATE = ("kb+sd-jwt+kb", "kb-sd-jwt+kb")


def split_ap2_chain(token: str) -> Optional[List[str]]:
    """SPEC §2.1: the hops of an AP2 chain `<hop0>~~<hop1>...`, each an SD-JWT of its own (the '~' the SDK drops before
    joining is put back on every hop but the last), or None when `token` is not one: a chain needs at least two parts and
    every part after the first starting with an issuer JWT (three dot-separated segments before its first '~'); so
    `<jwt>~~` (an empty component, RFC 9901 §4) is never read as a chain. Raises on a part that is empty or starts
    with '~' once the token is a chain (`ap2_chain_malformed`)."""
    token = token.strip()
    parts = token.split("~~")
    if len(parts) < 2 or any(p.split("~", 1)[0].count(".") != 2 or p.startswith("~") for p in parts[1:]):
        return None
    if not parts[0] or parts[0].startswith("~") or parts[0].endswith("~") or any(p.endswith("~~") for p in parts):
        raise Ap2EvidenceError("ap2_chain_malformed: an AP2 chain is hops joined by '~~', each hop an SD-JWT without its "
                               "last '~' (AP2 SDK mandate.py; SPEC §2.1)")
    if "~" not in parts[-1]:
        raise Ap2EvidenceError("ap2_chain_malformed: what follows the last '~~' is a JWT with no '~': the last hop of an AP2 "
                               "chain keeps its '~' (<open>~~<closed>~); read as one SD-JWT it is an empty component before "
                               "a KB-JWT (RFC 9901 §4: DISCLOSURE = 1*base64url) — refused either way (SPEC §2.1)")
    if any("~" in p and p.rsplit("~", 1)[1].count(".") == 2 for p in parts[:-1]):
        raise Ap2EvidenceError("ap2_chain_malformed: a hop before the last ends with a KB-JWT; in an AP2 chain the next hop "
                               "is the key binding, and only the last hop may carry one (AP2 kb_sd_jwt.py; SPEC §2.1)")
    return [p + "~" for p in parts[:-1]] + [parts[-1]]


def chain_cnf_jwk(resolved: Dict) -> Dict:
    """SPEC §2.1: the key the next hop is verified with — `cnf.jwk` of the hop's resolved claims, looked up where the AP2
    SDK looks (ParsedToken._find_cnf): in each object element of `delegate_payload`, then at the top level. Every `cnf`
    found must be an object whose `jwk` is an object; two that name different keys are ambiguous (refused, this format's
    rule; the SDK takes the first); none is `chain_cnf_missing` (the SDK: 'Previous token missing cnf.jwk')."""
    found = []
    dp = resolved.get("delegate_payload") if isinstance(resolved, dict) else None
    for holder in ([x for x in dp if isinstance(x, dict)] if isinstance(dp, list) else []) + [resolved]:
        if isinstance(holder, dict) and "cnf" in holder:
            cnf = holder["cnf"]
            if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
                raise Ap2EvidenceError("chain_cnf_malformed: a cnf of the previous hop is not an object with a jwk object (SPEC §2.1)")
            found.append(cnf["jwk"])
    if not found:
        raise Ap2EvidenceError("chain_cnf_missing: the previous hop carries no cnf.jwk to verify this hop with (SPEC §2.1)")
    if any(not _same_key(f, found[0]) for f in found[1:]):
        raise Ap2EvidenceError("chain_cnf_ambiguous: the previous hop carries two cnf.jwk naming different keys (SPEC §2.1)")
    return {f: found[0].get(f) for f in ("kty", "crv", "x", "y") if f in found[0]}


def check_chain_hop(parsed: Dict, resolved: Dict, prev_compact: str) -> Dict:
    """SPEC §2.1, the checks of the AP2 SDK's kb_sd_jwt.verify that need no transaction context: `typ` one of the four
    KB-SD-JWT types (compared as SPEC §13 says), exactly one of `sd_hash` / `issuer_jwt_hash` at the top level of the
    hop's claims and equal to BASE64URL(SHA-256) of the previous hop's SD-JWT (without a KB-JWT) / its issuer JWT, a
    terminal type with no `cnf` in `delegate_payload` and an intermediate one with one, a terminal hop carrying `iat`.
    Each failure is that artifact's error. Not checked (transaction context and time, as for a KB-JWT): `aud`, `nonce`,
    the values of `iat` and `exp`."""
    typ = parsed["header"].get("typ")
    mt = _media_type(typ) if isinstance(typ, str) else None
    term = mt is not None and mt in {_media_type(t) for t in AP2_HOP_TYPS_TERMINAL}
    inter = mt is not None and mt in {_media_type(t) for t in AP2_HOP_TYPS_INTERMEDIATE}
    if not (term or inter):
        raise Ap2EvidenceError(f"chain_hop_typ: a hop after the first must have typ kb+sd-jwt or kb+sd-jwt+kb (got {_jkey(typ)}; "
                               "AP2 kb_sd_jwt.py, SPEC §2.1)")
    has = [c for c in ("sd_hash", "issuer_jwt_hash") if c in resolved]
    if len(has) != 1:
        raise Ap2EvidenceError(f"chain_binding_mismatch: a hop must carry exactly one of sd_hash and issuer_jwt_hash "
                               f"(found {len(has)}; AP2 common.verify_binding, SPEC §2.1)")
    prev_sd_jwt = prev_compact.rsplit("~", 1)[0] + "~"
    want = (_sha256_b64url(prev_sd_jwt.encode("ascii")) if has[0] == "sd_hash" else issuer_jwt_hash(prev_compact))
    if resolved[has[0]] != want:
        raise Ap2EvidenceError(f"chain_binding_mismatch: {has[0]} is not the hash of the previous hop (SPEC §2.1)")
    dp = resolved.get("delegate_payload")
    has_cnf = isinstance(dp, list) and any(isinstance(x, dict) and isinstance(x.get("cnf"), dict) for x in dp)
    if term and has_cnf:
        raise Ap2EvidenceError("chain_terminal_with_cnf: a terminal hop (kb+sd-jwt) must not carry cnf (AP2 kb_sd_jwt.py, SPEC §2.1)")
    if inter and not has_cnf:
        raise Ap2EvidenceError("chain_intermediate_without_cnf: an intermediate hop (kb+sd-jwt+kb) must carry cnf "
                               "(AP2 kb_sd_jwt.py, SPEC §2.1)")
    if term and "iat" not in resolved:   # the SDK's verify_expected_claims, run on terminal hops: presence needs no context
        raise Ap2EvidenceError("chain_terminal_without_iat: a terminal hop (kb+sd-jwt) must carry iat (AP2 common.py "
                               "verify_expected_claims, SPEC §2.1)")
    return {"binding": has[0], "terminal": term}


# ────────────────────────────────────────────────────────── RFC 3161 time anchor

def _rfc3161_stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """OPTIONAL RFC 3161 timestamp via openssl (graceful when absent). Its absence
    never invalidates the evidence — signatures and digests stand on their own."""
    import shutil
    import subprocess
    from urllib.parse import urlparse
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL scheme not allowed (http/https only)"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    try:   # 1.5.2: the query comes from openssl's stdout, not a temporary file (with none writable, tempfile.mkdtemp() raised
        # outside this try: a traceback, exit 1; measured 13/10/2026 under `ulimit -f 0`)
        r = _run_openssl([exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert"], timeout)
        if r.returncode != 0 or not r.stdout:
            return {"anchored": False, "note": "openssl ts-query failed"}
        req = r.stdout
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(http, timeout=timeout) as rh:
            resp = rh.read()
        # anchored only on a token whose imprint is THIS digest (2026-10-03: any HTTP body — an error page, a rejection, a token
        # for another digest — was recorded as anchored: True)
        try:     # the DER walk reads an imprint even from a non-granted reply carrying a token: both checks are needed
            facts = parse_timestamp_resp(resp)
        except Ap2EvidenceError:
            facts = {}
        if not (facts.get("granted") and facts.get("imprint") == digest_hex.lower()):
            return {"anchored": False, "tsa_url": tsa_url, "note": "TSA reply is not a granted token for this digest"}
        return {"anchored": True, "tsa_url": tsa_url, "tsr_b64": base64.b64encode(resp).decode()}   # 1.4.0: `tsa_url`, the vectors' spelling (`tsa` stays accepted, SPEC §9.1)
    except Ap2WriteError:   # 1.5.3: openssl not started here (fork refused, no descriptor) or silent past `timeout`:
        raise               # stamp exits 74 with the pack unchanged; build records it as a note (_rfc3161_stamp_noted)
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}


def _rfc3161_stamp_noted(digest_hex: str, tsa_url: str) -> Dict:
    """build: an anchor that could not be asked for here is the pack's unanchored note, as before 1.5.3."""
    try:
        return _rfc3161_stamp(digest_hex, tsa_url)
    except Ap2WriteError as e:
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}


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


def parse_timestamp_resp(tsr: bytes, _partial: Optional[Dict] = None) -> Dict:
    """Minimal DER walk of an RFC 3161 TimeStampResp: PKIStatus and the TSTInfo messageImprint hash (hex). No signature
    or certificate processing — the same two facts the JS verifier reads (SPEC §3.2). `_partial` collects what was read
    before any failure, so the caller can report a measured `granted` instead of asserting one (r10)."""
    _partial = {} if _partial is None else _partial
    tag, st, en = _der_tlv(tsr, 0)
    if tag != 0x30:
        raise Ap2EvidenceError("not a TimeStampResp")
    # r10: PKIStatus is read first and carried on the exception, so a truncated token does not make the receipt claim
    # `granted: false` — a fact it never established (the JS verifier reported the status it had actually read)
    kids = _der_children(tsr, st, en)
    if not kids:
        raise Ap2EvidenceError("empty TimeStampResp")
    stag, sst, sen = kids[0]
    sk = _der_children(tsr, sst, sen)
    if not sk or sk[0][0] != 0x02:
        raise Ap2EvidenceError("no PKIStatus")
    status_bytes = tsr[sk[0][1]:sk[0][2]]
    granted = len(status_bytes) == 1 and status_bytes[0] in (0, 1)
    _partial["granted"] = granted
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
        if re.fullmatch(r"[0-9]{14}(\.[0-9]+)?Z", gt):   # r9: ASCII digits, as the JS verifier
            gen_time = gt
    return {"granted": granted, "imprint": tsr[mic[1][1]:mic[1][2]].hex(), "gen_time": gen_time,
            "tst_info": bytes(tsr[wrap[1]:wrap[2]])}   # 1.5.0 (SPEC §3.3): the TSTInfo the TSA signed = the identity of the anchor



# ---- RFC 3161: a signer named by subjectKeyIdentifier (as cryptovalid-opencore SPEC §11 step 7) ----------------------
# `openssl ts -verify` reads the token as PKCS #7, whose SignerInfo knows only issuerAndSerialNumber, and refuses a token
# whose signer is named by subjectKeyIdentifier (RFC 5652 §5.3) with an ASN.1 error. For that form the same checks are
# made one by one. Standard library and the openssl binary only.

_SKI_ESS_V1, _SKI_ESS_V2, _SKI_SAN = "1.2.840.113549.1.9.16.2.12", "1.2.840.113549.1.9.16.2.47", "2.5.29.17"
_SKI_HASHES = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
               "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512", "2.16.840.1.101.3.4.2.8": "sha3_256",
               "2.16.840.1.101.3.4.2.9": "sha3_384", "2.16.840.1.101.3.4.2.10": "sha3_512"}


def _ski_items(buf, where):
    """every DER element of `buf` as (tag, value); definite lengths in the shortest form, filling `buf` exactly"""
    out, i, n = [], 0, len(buf)
    while i < n:
        tag = buf[i]
        if tag & 0x1F == 0x1F or i + 1 >= n:
            raise ValueError(where + ": not DER")
        first, j = buf[i + 1], i + 2
        if first < 0x80:
            ln = first
        else:
            k = first & 0x7F
            if first == 0x80 or k > 4 or j + k > n or buf[j] == 0:
                raise ValueError(where + ": not DER")
            ln = int.from_bytes(buf[j:j + k], "big")
            if ln < 0x80:
                raise ValueError(where + ": not DER")
            j += k
        if j + ln > n:
            raise ValueError(where + ": not DER")
        out.append((tag, bytes(buf[j:j + ln])))
        i = j + ln
    return out


def _ski_one(buf, where, tag):
    items = _ski_items(buf, where)
    if len(items) != 1 or items[0][0] != tag:
        raise ValueError(where + ": not one element of tag 0x%02x" % tag)
    return items[0][1]


def _ski_oid(v):
    arcs, cur = [], 0
    for b in v:
        cur = (cur << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(cur)
            cur = 0
    if not arcs:
        raise ValueError("OBJECT IDENTIFIER: empty")
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first] + arcs[1:])


def _ski_tlv(tag, v):
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def _ski_token(der):
    """the TimeStampToken (ContentInfo) of a TimeStampResp, or `der` itself when it is already a ContentInfo"""
    top = _ski_items(_ski_one(der, "reply", 0x30), "reply")
    if top and top[0][0] == 0x30 and len(top) == 2 and top[1][0] == 0x30 and top[1][1][:1] == b"\x06":
        return _ski_tlv(0x30, top[1][1])           # {PKIStatusInfo, ContentInfo}
    return bytes(der)


def _ski_parts(token):
    """(SignerInfo elements, TSTInfo elements, the token's certificates as DER)"""
    ci = _ski_items(_ski_one(token, "ContentInfo", 0x30), "ContentInfo")
    sd = _ski_items(_ski_one(ci[1][1], "SignedData", 0x30), "SignedData")
    si = _ski_items(_ski_items(sd[-1][1], "signerInfos")[0][1], "SignerInfo")
    eci = _ski_items(sd[2][1], "encapContentInfo")
    tst = _ski_items(_ski_one(_ski_one(eci[1][1], "eContent", 0x04), "TSTInfo", 0x30), "TSTInfo")
    certs = [_ski_tlv(t, v) for tag, val in sd[3:] if tag == 0xA0 for t, v in _ski_items(val, "certificates") if t == 0x30]
    return si, tst, certs


def tsa_signer_certificate_absent(der, pinned_pem=None):
    """SPEC §3.2 (1.8.1): True only when every certificate the check looks in was read and none is the one the
    SignerInfo's `sid` names (RFC 5652 §5.3): issuerAndSerialNumber, the issuer compared as X509_NAME_cmp and the serial
    as an integer; subjectKeyIdentifier, against the certificate's subjectKeyIdentifier extension (as OpenSSL looks it up).
    It looks in the token's certificates, and for a subjectKeyIdentifier signer also in `pinned_pem` (the --tsa-cert file,
    which `openssl cms -verify -certfile` searches; `openssl ts -verify -CAfile` does not search the CA file for the
    signer). Anything not read answers False: the absence is never presumed (the check then runs as before)."""
    import base64
    import re
    try:
        token = _ski_token(der)
        ci = _ski_items(_ski_one(token, "ContentInfo", 0x30), "ContentInfo")
        sd = _ski_items(_ski_one(ci[1][1], "SignedData", 0x30), "SignedData")
        sis = _ski_items(sd[-1][1], "signerInfos")
        if len(sis) != 1 or sis[0][0] != 0x30:
            return False
        sid = _ski_items(sis[0][1], "SignerInfo")[1]
        certs = []
        for tag, val in sd[3:-1]:
            if tag == 0xA0:
                for t, v in _ski_items(val, "certificates"):
                    if t != 0x30:
                        return False
                    certs.append(_ski_tlv(t, v))
        if sid[0] == 0x80 and pinned_pem:
            blocks = re.findall(rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----", pinned_pem)
            if pinned_pem.count(b"-----BEGIN") != len(blocks):
                return False
            certs += [base64.b64decode(b"".join(b.split())) for b in blocks]
        if sid[0] == 0x30:
            ias = _ski_items(sid[1], "issuerAndSerialNumber")
            if len(ias) != 2 or ias[0][0] != 0x30 or ias[1][0] != 0x02:
                return False
            issuer, serial = _ski_tlv(0x30, ias[0][1]), int.from_bytes(ias[1][1], "big", signed=True)
        elif sid[0] != 0x80:
            return False
        for c in certs:
            tbs = _ski_items(_ski_items(_ski_one(c, "certificate", 0x30), "certificate")[0][1], "tbsCertificate")
            k = 1 if tbs[0][0] == 0xA0 else 0
            if tbs[k][0] != 0x02 or tbs[k + 2][0] != 0x30:
                return False
            if sid[0] == 0x30:
                if int.from_bytes(tbs[k][1], "big", signed=True) == serial and _ski_names_equal(_ski_tlv(0x30, tbs[k + 2][1]), issuer):
                    return False
                continue
            for t, v in tbs[k + 6:]:
                if t != 0xA3:
                    continue
                for et, ev in _ski_items(_ski_one(v, "extensions", 0x30), "extensions"):
                    e = _ski_items(ev, "Extension") if et == 0x30 else []
                    if not e or e[0][0] != 0x06:
                        return False
                    if _ski_oid(e[0][1]) == "2.5.29.14" and e[-1][0] == 0x04 and _ski_one(e[-1][1], "SubjectKeyIdentifier", 0x04) == sid[1]:
                        return False
        return True
    except (ValueError, IndexError):
        return False


def signer_named_by_key_id(der):
    """True when the token's SignerInfo names its signer by [0] subjectKeyIdentifier (False when unreadable)"""
    try:
        return _ski_parts(_ski_token(der))[0][1][0] == 0x80
    except (ValueError, IndexError):
        return False


# OpenSSL's canonical form of a Name (x509_name_canon, asn1_string_canon), the comparison X509_NAME_cmp makes and
# `openssl ts -verify` uses for the tsa field and the ESS issuerSerial
_SKI_STRINGS = {0x0C: "utf-8", 0x13: "latin-1", 0x14: "latin-1", 0x16: "latin-1", 0x1A: "latin-1",
                0x1E: "utf-16-be", 0x1C: "utf-32-be"}
_SKI_SPACE = b" \t\n\v\f\r"


def _ski_canon_value(tag, value):
    enc = _SKI_STRINGS.get(tag)
    if enc is None:
        return ("raw", tag, value)
    b = value.decode(enc).encode("utf-8").strip(_SKI_SPACE)
    out, i = bytearray(), 0
    while i < len(b):
        c = b[i]
        if c >= 0x80:
            out.append(c)
            i += 1
        elif c in _SKI_SPACE:
            out.append(0x20)
            while i < len(b) and b[i] in _SKI_SPACE:
                i += 1
        else:
            out.append(c + 32 if 0x41 <= c <= 0x5A else c)
            i += 1
    return ("str", bytes(out))


def _ski_name_canon(name_tlv):
    rdns = []
    for t, rdn in _ski_items(_ski_one(name_tlv, "Name", 0x30), "Name"):
        if t != 0x31:
            raise ValueError("Name: an RDN is not a SET")
        attrs = []
        for t2, atv in _ski_items(rdn, "RDN"):
            a = _ski_items(atv, "AttributeTypeAndValue")
            if t2 != 0x30 or len(a) != 2 or a[0][0] != 0x06:
                raise ValueError("Name: AttributeTypeAndValue")
            attrs.append((a[0][1], _ski_canon_value(a[1][0], a[1][1])))
        rdns.append(tuple(sorted(attrs, key=repr)))
    return tuple(rdns)


def _ski_names_equal(a_tlv, b_tlv):
    try:
        return _ski_name_canon(a_tlv) == _ski_name_canon(b_tlv)
    except ValueError:
        return False


def _ski_general_names_equal(a, b):
    """GENERAL_NAME_cmp: the same type; a directoryName compared as a Name, any other type by its bytes"""
    if a[0] != b[0]:
        return False
    return _ski_names_equal(a[1], b[1]) if a[0] == 0xA4 else a[1] == b[1]


def _ski_pem(der):
    import base64
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


def _ski_issuer_serial(cert_der):
    """(serialNumber value bytes, issuer Name TLV) of a DER certificate (1.9.0, for a later ESSCertID's issuerSerial)."""
    tbs = _ski_items(_ski_items(_ski_one(cert_der, "certificate", 0x30), "certificate")[0][1], "tbsCertificate")
    k = 1 if tbs[0][0] == 0xA0 else 0
    return tbs[k][1], _ski_tlv(0x30, tbs[k + 2][1])


class KeyIdCheckNotRun(Exception):
    """the key-id step could not be run here (an openssl whose `verify` does not know an option it needs)"""


def _ski_policies_shape(el):
    """ESS `policies` (RFC 2634 §5.4.1): SEQUENCE OF PolicyInformation, each a SEQUENCE that starts with an OID"""
    if el[0] != 0x30:
        return False
    for t, v in _ski_items(el[1], "policies"):
        pi = _ski_items(v, "PolicyInformation") if t == 0x30 else []
        if not pi or pi[0][0] != 0x06:
            return False
    return True


def key_id_token_problem(der, digest_hex, ca_file, at, tmp, exe="openssl"):
    """the checks of `openssl ts -verify -digest D -CAfile CA -attime T`, made one by one for a token whose signer is
    named by subjectKeyIdentifier: None when they hold, else why not. `tmp` is an empty private directory."""
    import hashlib
    import os
    import subprocess
    try:
        token = _ski_token(der)
        ci = _ski_items(_ski_one(token, "ContentInfo", 0x30), "ContentInfo")
        sis = _ski_items(_ski_items(_ski_one(ci[1][1], "SignedData", 0x30), "SignedData")[-1][1], "signerInfos")
        if len(sis) != 1 or sis[0][0] != 0x30:   # RFC 3161 §2.4.2: no signature other than the TSA's
            return "%d SignerInfos (exactly one is evaluated here)" % len(sis)
        si, tst, certs = _ski_parts(token)
        mi = _ski_items(tst[2][1], "messageImprint")
        if mi[1][1].hex() != digest_hex.lower():
            return "the TSTInfo imprint is not the digest"
    except (ValueError, IndexError) as e:
        return "token not read: %s" % e
    tp, sp = os.path.join(tmp, "ski_token.der"), os.path.join(tmp, "ski_signer.pem")
    with open(tp, "wb") as fh:
        fh.write(token)
    r = subprocess.run([exe, "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", tp, "-certfile", ca_file,
                        "-signer", sp, "-out", os.devnull], capture_output=True, timeout=30)
    if r.returncode != 0 or not os.path.exists(sp):
        return "openssl cms -verify: " + ((r.stderr or b"").decode(errors="replace").strip().splitlines() or ["refused"])[-1][:160]
    with open(sp, "rb") as fh:
        pem = fh.read()
    import base64
    b64 = pem.split(b"-----BEGIN CERTIFICATE-----")[1].split(b"-----END CERTIFICATE-----")[0]
    signer = base64.b64decode(b"".join(b64.split()))
    try:
        tbs = _ski_items(_ski_items(_ski_one(signer, "certificate", 0x30), "certificate")[0][1], "tbsCertificate")
        k = 1 if tbs[0][0] == 0xA0 else 0
        serial, issuer, subject = tbs[k][1], _ski_tlv(0x30, tbs[k + 2][1]), _ski_tlv(0x30, tbs[k + 4][1])
        san = []
        for tag, v in tbs[k + 6:]:
            if tag == 0xA3:
                for _t, ev in _ski_items(_ski_one(v, "extensions", 0x30), "extensions"):
                    e = _ski_items(ev, "Extension")
                    if _ski_oid(e[0][1]) == _SKI_SAN:
                        san = [_ski_tlv(gt, gv) for gt, gv in _ski_items(_ski_one(e[-1][1], "subjectAltName", 0x30), "GeneralNames")]
        attrs, allowed = {}, None   # allowed: 1.9.0, the token certificates a later ESSCertID names (None: no limit)
        for t, av in _ski_items(si[3][1], "signedAttrs"):   # Attribute ::= SEQUENCE { attrType OID, attrValues SET }
            a = _ski_items(av, "Attribute") if t == 0x30 else []
            if len(a) != 2 or a[0][0] != 0x06 or a[1][0] != 0x31:
                return "a signed attribute is not {attrType, attrValues SET}"
            attrs.setdefault(_ski_oid(a[0][1]), []).append(a[1][1])
        found = [o for o in (_SKI_ESS_V1, _SKI_ESS_V2) if o in attrs]
        if not found:
            return "no signingCertificate or signingCertificateV2 attribute (ESS)"
        for o in found:
            vals = attrs[o]
            if len(vals) != 1 or len(_ski_items(vals[0], "attrValues")) != 1:
                return "ESS attribute %s: not exactly one value" % o
            sc = _ski_items(_ski_one(vals[0], "SigningCertificate", 0x30), "SigningCertificate")
            if not 1 <= len(sc) <= 2 or sc[0][0] != 0x30 or (len(sc) == 2 and not _ski_policies_shape(sc[1])):
                return "ESS attribute %s: not {certs, policies?}" % o
            ids = _ski_items(sc[0][1], "certs")
            if not ids:   # 1.9.0 (SPEC §3.2): RFC 2634 §5.4 / RFC 5035: the first ESSCertID is the signer's, the ones after
                return "ESS attribute %s: no ESSCertID" % o   # it limit the certificates of the path (up to 1.8.x: exactly one)
            parsed_ids = []
            for n_, (t_, v_) in enumerate(ids):
                if t_ != 0x30:
                    return "ESS attribute %s: the ESSCertID is not a SEQUENCE" % o
                cid = _ski_items(v_, "ESSCertID")
                alg = "sha1"
                if o == _SKI_ESS_V2:
                    alg = "sha256"
                    if cid and cid[0][0] == 0x30:
                        ai = _ski_items(cid[0][1], "hashAlgorithm")
                        alg = _SKI_HASHES.get(_ski_oid(ai[0][1]))
                        if alg is None or not (len(ai) == 1 or (len(ai) == 2 and ai[1] == (0x05, b""))):
                            return "ESSCertIDv2: hash algorithm not known"
                        cid = cid[1:]
                if not cid or cid[0][0] != 0x04 or len(cid) > 2 or (len(cid) == 2 and cid[1][0] != 0x30):
                    return "ESSCertID: not {certHash, issuerSerial?}"
                if len(cid[0][1]) != hashlib.new(alg).digest_size:
                    return "ESSCertID: certHash is not a %s digest" % alg
                if any(pa == alg and ph == cid[0][1] for pa, ph, _c in parsed_ids):
                    return "ESS attribute %s: a certificate listed twice" % o
                parsed_ids.append((alg, cid[0][1], cid))
            alg, _h, cid = parsed_ids[0]
            if cid[0][1] != hashlib.new(alg, signer).digest():
                return "ESS certHash is not the hash of the signer certificate"
            if len(parsed_ids) > 1:   # the path may use only the token certificates a later ESSCertID names (RFC 5035 §5.4.1)
                named = []
                for alg2, h2, cid2 in parsed_ids[1:]:
                    hit = [c for c in certs if hashlib.new(alg2, c).digest() == h2]
                    if len(cid2) == 2:   # an issuerSerial is checked against the token certificate it hashes, when there is one
                        for c in hit:
                            ser_c, iss_c = _ski_issuer_serial(c)
                            iss2 = _ski_items(cid2[1][1], "IssuerSerial")
                            nm2 = _ski_items(_ski_one(_ski_tlv(0x30, iss2[0][1]), "GeneralNames", 0x30), "GeneralNames") \
                                if iss2 and iss2[0][0] == 0x30 else None
                            if not (len(iss2) == 2 and iss2[1][0] == 0x02 and nm2 is not None and len(nm2) == 1
                                    and nm2[0][0] == 0xA4 and _ski_names_equal(nm2[0][1], iss_c)
                                    and int.from_bytes(iss2[1][1], "big", signed=True) == int.from_bytes(ser_c, "big", signed=True)):
                                return "ESS issuerSerial of a later ESSCertID does not name the certificate it hashes"
                    named += hit
                allowed = named if allowed is None else [c for c in allowed if c in named]
            if len(cid) == 2:
                iss = _ski_items(cid[1][1], "IssuerSerial")
                names = _ski_items(_ski_one(_ski_tlv(0x30, iss[0][1]), "GeneralNames", 0x30), "GeneralNames") \
                    if iss and iss[0][0] == 0x30 else None
                if not (len(iss) == 2 and iss[1][0] == 0x02 and names is not None and len(names) == 1
                        and names[0][0] == 0xA4 and _ski_names_equal(names[0][1], issuer)
                        and int.from_bytes(iss[1][1], "big", signed=True) == int.from_bytes(serial, "big", signed=True)):
                    return "ESS issuerSerial does not name the signer certificate's issuer and serial number"
        tsa = [v for tag, v in tst[5:] if tag == 0xA0]
        if tsa:   # ts_check_signer_name: the subject (a directoryName), then each name of the subjectAltName
            gn = _ski_items(tsa[0], "tsa")
            if len(gn) != 1 or not (_ski_general_names_equal(gn[0], (0xA4, subject))
                                    or any(_ski_general_names_equal(gn[0], _ski_items(n, "GeneralName")[0]) for n in san)):
                return "the TSTInfo tsa field names neither the signer's subject nor one of its subjectAltName"
    except (ValueError, IndexError) as e:
        return "signer certificate or attributes not read: %s" % e
    if allowed is not None:   # 1.9.0 (SPEC §3.2, RFC 5035 §5.4.1): only these may build the path below the pins
        certs = [c for c in certs if c in allowed]
    up = os.path.join(tmp, "ski_untrusted.pem")
    with open(up, "wb") as fh:
        fh.write(b"".join(_ski_pem(c) for c in certs))
    cmd = [exe, "verify", "-purpose", "timestampsign", "-attime", str(int(at)), "-CAfile", ca_file, "-no-CApath",
           "-no-CAstore"] + (["-untrusted", up] if certs else []) + [sp]
    r = subprocess.run(cmd, capture_output=True, timeout=30)
    if r.returncode != 0 and b"nknown option" in (r.stderr or b"") + (r.stdout or b""):   # before OpenSSL 3.0
        raise KeyIdCheckNotRun("this openssl does not know an option of `verify` (OpenSSL 3.0 or later is needed): "
                               + (r.stderr or r.stdout or b"").decode(errors="replace").strip()[-120:])
    if r.returncode != 0:
        return "openssl verify: " + ((r.stderr or r.stdout or b"").decode(errors="replace").strip().splitlines() or ["refused"])[-1][:160]
    return None


def _verify_rfc3161(tsr_b64: str, expected_digest_hex: str, timeout: int = 15, tsa_cert: Optional[str] = None) -> Dict:
    """RFC 3161 token check (SPEC §3.2). `verified` = the token parses, its status is granted and the TSTInfo
    messageImprint equals the recomputed pack digest — BINDING, not TSA authenticity: the TSA signature and certificate
    chain are validated only when the relying party supplies the TSA certificate (`tsa_cert`, PEM), through
    `openssl ts -verify -CAfile`; then `tsa_verified` is True/False (None when not requested or openssl is absent).
    1.1.0 r1: a self-forged TimeStampResp with status 0 and the right imprint used to pass the JS verifier and to
    fail this one only because `openssl ts -reply -text` refused the minimal DER — neither was a check of the TSA."""
    import shutil
    try:
        tsr = _sigsuite._unb64(tsr_b64)                       # strict base64 (a space inside the token used to be skipped)
    except (ValueError, TypeError):
        return {"verified": False, "granted": None, "imprint_ok": None, "gen_time": None, "tsa_verified": None, "note": "tsr_b64 is not canonical base64"}   # r11: None = never read, not "it did not match"
    partial: Dict = {}
    try:
        info = parse_timestamp_resp(tsr, partial)
    except Exception as e:  # noqa: BLE001 — any malformed DER is "not parseable" (r2: an empty EXPLICIT [0] was an IndexError traceback)
        return {"verified": False, "granted": partial.get("granted"), "imprint_ok": partial.get("imprint_ok"), "gen_time": None, "tsa_verified": None,
                "note": f"token not parseable: {type(e).__name__}: {str(e)[:80]}"}   # r11: imprint_ok too — None when never read   # r10: the status READ, or None — never an unmeasured False
    # r11: None when the token carried no messageImprint at all — "never read" is not "did not match"
    imprint_ok = None if info.get("imprint") is None else (info["imprint"] == expected_digest_hex.lower())
    partial["imprint_ok"] = imprint_ok
    out = {"verified": bool(info["granted"] and imprint_ok is True), "granted": info["granted"], "imprint_ok": imprint_ok, "gen_time": info.get("gen_time"), "tsa_verified": None}
    if tsa_cert is None:
        return out
    exe = shutil.which("openssl")
    if not exe:
        out["tsa_note"] = "openssl absent — TSA signature/chain NOT verified"; return out
    try:
        d = _openssl_tmpdir()
    except Ap2WriteError as e:   # 1.6.0 (SPEC §6.10): the check could not be run here — recorded, the receipt goes on
        out["tsa_note"] = f"check not run here: {e}"; out["_not_run"] = str(e); return out
    try:
        path = os.path.join(d, "t.tsr")
        _tmp_write(path, tsr)
        try:
            with open(tsa_cert, "rb") as fh:
                pinned = fh.read()
        except OSError:
            pinned = None   # read by openssl below, which reports it, as before: nothing is presumed absent then
        if pinned is not None and tsa_signer_certificate_absent(tsr, pinned):   # 1.8.1 (SPEC §3.2): the signature cannot be evaluated here
            out["tsa_verified"] = None
            out["tsa_reason"] = "signer_certificate_absent"
            out["tsa_note"] = ("signature not evaluated: the signer certificate the SignerInfo names is not in the token"
                               + (" nor in the --tsa-cert file" if signer_named_by_key_id(tsr) else "")
                               + " (ETSI EN 319 102-1 V1.4.1 §5.2.3.3: INDETERMINATE / NO_SIGNING_CERTIFICATE_FOUND)")
            return out
        if signer_named_by_key_id(tsr):   # 1.8.0 (SPEC §3.2): openssl ts cannot read this SignerInfo; same checks one by one
            import calendar, time as _t
            at = calendar.timegm(_t.strptime(info["gen_time"].split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")) \
                if info.get("gen_time") else int(_t.time())
            try:
                why = key_id_token_problem(tsr, expected_digest_hex, tsa_cert, at, d, exe)
            except KeyIdCheckNotRun as e:   # SPEC §3.2, §6.10: not run here = not measured (None), never a failed TSA
                out["tsa_verified"] = None; out["tsa_note"] = f"check not run here: {e}"[:200]; out["_not_run"] = str(e)
                return out
            out["tsa_verified"] = why is None
            if why:
                out["tsa_note"] = why[-160:]
            return out
        cmd = [exe, "ts", "-verify", "-digest", expected_digest_hex, "-sha256", "-in", path, "-CAfile", tsa_cert]
        if info.get("gen_time"):   # r4: validate the chain at the token's own genTime (`-attime`), so a TSA certificate that expired
            # AFTER issuing does not turn `tsa_verified` False years later; revocation is not checked (declared)
            import calendar, time as _t
            cmd += ["-attime", str(calendar.timegm(_t.strptime(info["gen_time"].split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")))]
        r = _run_openssl(cmd, timeout, text=True)
        out["tsa_verified"] = r.returncode == 0 and "Verification: OK" in (r.stdout or "")
        if not out["tsa_verified"]:   # `verified` keeps its §3.2 meaning (binding); the TSA outcome is its own field, in both verifiers
            out["tsa_note"] = (r.stderr or r.stdout).strip()[-160:]
    except Ap2WriteError as e:   # 1.6.0 (SPEC §6.10): not run here = not measured (None), never a failed TSA
        out["tsa_verified"] = None; out["tsa_note"] = f"check not run here: {e}"; out["_not_run"] = str(e)
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


def _write_pack_file(path: str, obj) -> None:
    """Write a pack to `path` whole or not at all (1.5.2). The JSON goes to a new file with an unpredictable name, created
    O_EXCL in the same directory with the mode a plain open() would give it (or the mode of the pack it replaces), is
    flushed, fsync'd and closed inside the try, and only then renamed onto `path`; on any failure the temporary file is
    removed and whatever was at `path` before is left as it was. Before, `build` and `sign_evidence` opened `path` with
    "w": a write that failed part way (a full disk, `ulimit -f`) truncated an earlier pack at that path (measured on
    1.5.1: 5 891 bytes became 2 048, and the pack no longer verified). A symlink is followed (the file it names is
    replaced, the link stays); an existing file this process may not write is refused as before (PermissionError); a
    path that is not a regular file (a FIFO, /dev/stdout, /dev/null) is written directly, as before, since it cannot be
    renamed onto. Raises OSError."""
    import secrets
    try:
        st = os.stat(path)
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISREG(st.st_mode):
        if stat.S_ISDIR(st.st_mode):
            raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)
        return
    real = os.path.realpath(path)
    if st is not None:   # the kernel's own check, without truncating: a read-only pack is not replaced behind its back
        os.close(os.open(real, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)))
    d = os.path.dirname(real) or "."
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    while True:
        tmp = os.path.join(d, ".ap2-pack-%s.tmp" % secrets.token_hex(8))
        try:
            fd = os.open(tmp, flags, 0o666)   # 0o666 less the umask, as open(path, "w") gives a new file
            break
        except FileExistsError:
            continue
    try:
        if st is not None:
            os.fchmod(fd, stat.S_IMODE(st.st_mode))   # the pack keeps its permissions
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(obj, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, real)
        tmp = None
    finally:
        if fd is not None:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _refuse_oversize(evidence, outcome: str = "not built") -> None:
    """SPEC §3.1: a verifier refuses an evidence file over 64 MiB, so `build`, `stamp` and `sign_evidence` do not write one.
    The size is that of the text the writers write (the same `json.dump` options, UTF-8). Measured on 1.7.1 before this
    check: a token with one 50 MB disclosure built a 116 670 431-byte pack, exit 0, that both verifiers refused; and
    `stamp` / `sign_evidence` on a pack 200 bytes under the bound wrote 67 109 963 / 67 116 150 bytes, refused alike."""
    try:
        n = len(json.dumps(evidence, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))
    except UnicodeEncodeError as e:   # a str holding surrogate code points (library input only): the writer would raise the same
        raise Ap2EvidenceError(f"the pack cannot be written as UTF-8 (a surrogate code point) — {outcome}") from e
    if n > MAX_EVIDENCE_BYTES:
        raise Ap2EvidenceError(f"the pack would be refused by verify (SPEC §3.1): evidence file exceeds "
                               f"{MAX_EVIDENCE_BYTES} bytes ({n}) — {outcome}")


def build_evidence(artifacts: List[Dict], out_path: str,
                   keys: Optional[Dict[str, Dict]] = None,
                   jwks_urls: Optional[Dict[str, str]] = None,
                   tsa_url: Optional[str] = None,
                   subject: str = "agentic-payment mandate evidence",
                   extra_tsa_urls: Optional[List[str]] = None,
                   accept_integral_floats: bool = False, not_before: Optional[Dict] = None) -> Dict:
    """See `_build_evidence`. 1.7.2 (SPEC §3.1): without `accept_integral_floats` a token whose JSON writes a number with a
    fraction or an exponent (`10.0`, as the AP2 SDK writes every budget) is refused; with it an integral one is read as its
    integer, the pack records the integer (`resolved_claims`), and the result says so and lists the literals. A pack built
    that way verifies only under `accept_integral_floats` (declared in SPEC §3.1)."""
    if type(accept_integral_floats) is not bool:
        raise ValueError(f"accept_integral_floats must be a boolean (got {accept_integral_floats!r})")
    tok = _INTEGRAL_READ.set([] if accept_integral_floats else None)
    try:
        r = _build_evidence(artifacts, out_path, keys=keys, jwks_urls=jwks_urls, tsa_url=tsa_url, subject=subject,
                            extra_tsa_urls=extra_tsa_urls, not_before=not_before)
        read = _INTEGRAL_READ.get()
    finally:
        _INTEGRAL_READ.reset(tok)
    if accept_integral_floats:
        r["accept_integral_floats"] = True
        r["integral_literals_read"] = read
    return r


def _build_evidence(artifacts: List[Dict], out_path: str,
                    keys: Optional[Dict[str, Dict]] = None,
                    jwks_urls: Optional[Dict[str, str]] = None,
                    tsa_url: Optional[str] = None,
                    subject: str = "agentic-payment mandate evidence",
                    extra_tsa_urls: Optional[List[str]] = None, not_before: Optional[Dict] = None) -> Dict:
    """artifacts: [{name, sd_jwt}]. not_before (1.8.0, SPEC §12): the block, sealed with the artifacts; refused
    (no file) when §12.2 refuses it or when its NB1/NB2 check does not verify at build. Verifies every artifact NOW, snapshots the key material
    used, records bindings, and writes ONE self-contained evidence file. Any artifact that
    fails to verify aborts the build (an evidence file must never contain a red light
    dressed as evidence — fail-closed at the source)."""
    keys, jwks_urls = {} if keys is None else keys, {} if jwks_urls is None else jwks_urls   # 1.7.3: None only; [] or 0 is no object
    if not isinstance(keys, dict) or not isinstance(jwks_urls, dict):
        raise Ap2EvidenceError("keys and jwks_urls must be objects from artifact name to key / URL (SPEC §2 (b))")
    names = [a["name"] for a in artifacts]
    if any(not isinstance(n, str) or not n for n in names):   # r5: build wrote a pack with name "" that both verifiers then refused
        raise Ap2EvidenceError("artifact name must be a non-empty string (SPEC §2)")
    if len(set(names)) != len(names):
        raise Ap2EvidenceError("duplicate artifact names (bindings would silently "
                               "overwrite each other — refused fail-closed)")
    for what, given in (("keys", keys), ("jwks_urls", jwks_urls)):   # 1.7.2 (SPEC §2): a supplied key names an artifact of
        stray = [k for k in given if k not in names]               # this build; up to 1.7.1 a stray name was ignored in silence
        if stray:
            raise Ap2EvidenceError(f"{what}: no artifact named {stray[0]!r} in this build (SPEC §2)")
    for name, v in keys.items():   # 1.7.3 (SPEC §2 (b)): a value is checked by its presence, not its truth — measured on
        if not isinstance(v, dict) or not v:   # the 1.7.3 draft, keys {"m": None} built the pack with the header key (jwk_header)
            raise Ap2EvidenceError(f"keys[{name!r}]: a supplied key must be a non-empty JSON object, a JWK (SPEC §2 (b))")
    for name, v in jwks_urls.items():
        if not isinstance(v, str) or not v.startswith("https://"):
            raise Ap2EvidenceError(f"jwks_urls[{name!r}]: JWKS URL must be a string starting https:// (SPEC §2 (b))")
    both = sorted(set(keys) & set(jwks_urls))   # 1.7.3 (SPEC §2 (b)): two sources named for one artifact is ambiguous
    if both:
        raise Ap2EvidenceError(f"artifact {both[0]!r}: both a supplied key and a JWKS URL — ambiguous, refused (SPEC §2 (b))")
    not_used = {}
    entries, for_bindings = [], []
    # 1.9.0 (SPEC §2.1): an AP2 chain `<hop0>~~<hop1>...` given for name N becomes the artifacts N.0, N.1, ...; the key
    # named for N is the key of N.0, every later hop is verified with the previous hop's cnf.jwk (class chain_cnf)
    expanded = []
    for a in artifacts:
        hops = split_ap2_chain(a["sd_jwt"]) if isinstance(a.get("sd_jwt"), str) else None
        if hops is None:
            expanded.append({"name": a["name"], "sd_jwt": a["sd_jwt"], "key_for": a["name"], "chain_from": None})
            continue
        for i, h in enumerate(hops):
            expanded.append({"name": f"{a['name']}.{i}", "sd_jwt": h, "key_for": a["name"] if i == 0 else None,
                             "chain_from": f"{a['name']}.{i - 1}" if i else None})
    hop_names = [e["name"] for e in expanded]
    if len(set(hop_names)) != len(hop_names):
        raise Ap2EvidenceError("duplicate artifact names once the AP2 chains are split into hops (N.0, N.1, ...; SPEC §2.1) "
                               "— refused fail-closed")
    done = {}
    for a in expanded:
        parsed = parse_sd_jwt(a["sd_jwt"])
        if not isinstance(parsed["header"], dict) or not isinstance(parsed["payload"], dict):
            raise Ap2EvidenceError(f"artifact {a['name']!r}: JWT header and payload must be objects")
        _jose_header_ignored(parsed["header"], "JWT header")   # RFC 7515 §4.1.11 at build: refused at the source, like a bad signature
        if a["chain_from"] is None:
            key = _snapshot_key(parsed, supplied_jwk=keys.get(a["key_for"]),
                                jwks_url=jwks_urls.get(a["key_for"]))
        else:
            prev = done[a["chain_from"]]
            if parsed["header"].get("alg") != "ES256":   # as _snapshot_key does for every other artifact
                raise Ap2EvidenceError(f"artifact {a['name']!r}: alg {parsed['header'].get('alg')!r} unsupported: ES256 only "
                                       "(other algs are rejected, never half-verified)")
            try:
                key = {"jwk": chain_cnf_jwk(prev["resolved_claims"]), "provenance_class": "chain_cnf",
                       "chain_from": a["chain_from"],
                       "note": "the cnf.jwk of the previous hop of this AP2 chain, an artifact of this pack (SPEC §2.1)"}
            except Ap2EvidenceError as e:
                raise Ap2EvidenceError(f"artifact {a['name']!r}: {e} (build refused)") from e
        v = _verify_one(parsed, key)
        if not v["signature_ok"]:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: ES256 signature INVALID "
                                   "(build refused — no evidence file for a red light)")
        try:   # 1.7.3 (SPEC §2 (d)): after the signature, so a wrong supplied key still reads "signature INVALID"
            _reconcile_unused_header_keys(parsed["header"], key["jwk"], key["provenance_class"])
        except Ap2EvidenceError as e:
            raise Ap2EvidenceError(f"artifact {a['name']!r}: {e} (build refused)") from e
        if _key_material_not_used(parsed["header"], key["provenance_class"]):
            not_used[a["name"]] = _key_material_not_used(parsed["header"], key["provenance_class"])
        if a["chain_from"] is not None:   # 1.9.0 (SPEC §2.1): the AP2 hop rules, after the signature under the previous cnf.jwk
            try:
                check_chain_hop(parsed, v["resolved_claims"], done[a["chain_from"]]["compact"])
            except Ap2EvidenceError as e:
                raise Ap2EvidenceError(f"artifact {a['name']!r}: {e} (build refused)") from e
        done[a["name"]] = {"compact": parsed["compact"], "resolved_claims": v["resolved_claims"]}
        kb = verify_kb_jwt(parsed, v["resolved_claims"]); kb.pop("_ignored", None)   # the receipt's report, not part of the sealed copy
        if kb.get("verified") is None:   # 1.8.1 (SPEC §9.2): sd_hash_ok of the holder-key-unknown branch is the receipt's,
            kb.pop("sd_hash_ok", None)   # not sealed: a 1.8.0 verifier, which does not recompute it there, refuses a copy with it
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
    if not_before is not None:   # 1.8.0 — SPEC §12: inside the digest; a producer does not write a block §12 refuses
        parse_not_before(not_before)
        chk = check_not_before(not_before, evidence, [{"signature_ok": True, "claims_match": True}] * len(entries), None)
        bad = {k: v for k, v in chk["checks"].items() if k in ("NB1", "NB2") and v != "verified"}
        if bad or chk["checks"]["NB3"].startswith("failed"):
            raise Ap2EvidenceError(f"not_before does not verify at build: {dict(chk['checks'])} (SPEC §12)")
        evidence["not_before"] = not_before
    try:   # 1.7.1 (SPEC §3.1): a pack the verifier's profile refuses is not written — measured on 1.7.0, `build` wrote packs
        # `verify` refused as json_too_deep (a chain of nested disclosures, a deep member of a --key JWK) or for a float
        canonical = _canon(evidence)   # a supplied key is not bounded before this line: one nested ~990 deep was a RecursionError
        loads_strict(canonical.decode("ascii"))   # the fields added below (the digest, the TSA blocks) are at most 3 deep
    except RecursionError as e:
        raise Ap2EvidenceError(f"the pack would be refused by verify (SPEC §3.1): json_too_deep: nesting exceeds "
                               f"{MAX_JSON_DEPTH} — not built") from e
    except (ValueError, TypeError) as e:   # Ap2EvidenceError is a ValueError; json.dumps raises ValueError/TypeError on library
        # input that is not JSON (a cycle, an integer past the interpreter's digit limit, a set): measured, an uncaught exception
        raise Ap2EvidenceError(f"the pack would be refused by verify (SPEC §3.1): {e} — not built") from e
    _refuse_oversize(evidence)   # §3.1 also bounds the file at 64 MiB: checked before any TSA is asked, and again below
    evidence["evidence_digest_sha256"] = hashlib.sha256(canonical).hexdigest()
    if os.path.isdir(out_path):   # refused before any TSA is asked (the same reason the write itself gives)
        raise Ap2WriteError(f"cannot write the pack {out_path!r}: IsADirectoryError: {os.strerror(errno.EISDIR)}")
    evidence["rfc3161_timestamp"] = (
        _rfc3161_stamp_noted(evidence["evidence_digest_sha256"], tsa_url)
        if tsa_url else {"anchored": False, "note": "no TSA provided"})
    # 1.5.0 — SPEC §3.3: every further TSA goes to `anchors` (the first stays in rfc3161_timestamp, so a pack built with one
    # TSA is still read by 1.4.x verifiers); an anchor that could not be obtained is NOT written (an entry is a token or
    # nothing) and is reported in the build result
    added, failed = [], []
    for u in extra_tsa_urls or []:
        st = _rfc3161_stamp_noted(evidence["evidence_digest_sha256"], u)
        if st.get("anchored"):
            added.append({"mechanism": "rfc3161", "tsr_b64": st["tsr_b64"], "tsa_url": u})
        else:
            failed.append({"tsa_url": u, "note": st.get("note")})
    if added:
        evidence["anchors"] = added
    _refuse_oversize(evidence)   # with the digest and the TSA blocks: the bytes the writer below produces
    try:   # 1.5.2: a pack that cannot be written is EX_IOERR in the CLI, not a traceback (exit 1, the "not valid" code)
        _write_pack_file(out_path, evidence)
    except OSError as e:
        raise Ap2WriteError(f"cannot write the pack {out_path!r}: {type(e).__name__}: {e.strerror or e}") from e
    chains = {}
    for e in expanded:
        if e["chain_from"] is not None or (e["key_for"] is not None and e["name"] != e["key_for"]):
            chains.setdefault(e["name"].rsplit(".", 1)[0], []).append(e["name"])
    return {"out": out_path, "artifacts": len(entries), **({"ap2_chains": chains} if chains else {}),   # 1.9.0 (SPEC §2.1)
            "bindings": len(evidence["bindings"]),
            "evidence_digest_sha256": evidence["evidence_digest_sha256"],
            "rfc3161_anchored": evidence["rfc3161_timestamp"].get("anchored", False),
            "anchors_added": len(added), **({"anchors_failed": failed} if failed else {}),
            **({"key_material_not_used": not_used} if not_used else {})}   # 1.7.3 (SPEC §2 (d))


def add_anchor(path: str, tsa_url: str) -> Dict:
    """1.5.0 — SPEC §3.3: append one RFC 3161 anchor to an EXISTING pack (a second TSA, or a later token from any TSA).
    The token commits to the pack's digest, not to the anchors already there, so it proves existence from its own time
    only: it is not an RFC 4998 renewal. The token is requested for the digest RECOMPUTED from the sealed content, and
    the pack is refused unchanged when that differs from the declared digest (stamping a pack that does not verify would attest
    nothing). The digest and the producer signatures do not change: `anchors` lies outside them. Written atomically."""
    import tempfile
    path = os.path.realpath(path)   # a symlink is followed: the pack it names is stamped, the link stays a link
    try:
        dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    except OSError as e:
        raise Ap2EvidenceError(f"cannot open the pack's directory: {type(e).__name__}") from e
    try:
        try:   # the read-modify-write under an exclusive lock on the directory: measured on b3edfc8, six concurrent stamps of one
            import fcntl   # pack all reported success and the file kept ONE anchor (the others lost), two raised FileNotFoundError
            fcntl.flock(dfd, fcntl.LOCK_EX)
        except ImportError:   # no fcntl (Windows): no lock — concurrent stamps of one pack are not supported there (declared)
            pass
        ev = read_evidence_file(path)
        if ev.get("evidence_format") != EVIDENCE_FORMAT:
            raise Ap2EvidenceError(f"evidence_format must be {EVIDENCE_FORMAT!r}")
        digest = hashlib.sha256(_canon({k: v for k, v in ev.items() if k not in _DIGEST_EXCLUDED})).hexdigest()
        if digest != ev.get("evidence_digest_sha256"):
            raise Ap2EvidenceError("the declared evidence_digest_sha256 does not match the sealed content: not stamped")
        if "anchors" in ev and not (isinstance(ev["anchors"], list) and ev["anchors"]):
            raise Ap2EvidenceError("anchors must be a non-empty list (SPEC §3.3): not stamped")
        try:   # 1.5.3: measured on 1.5.2 under RLIMIT_NPROC 1: "no anchor obtained: BlockingIOError", a refusal, exit 1
            st = _rfc3161_stamp(digest, tsa_url)
        except Ap2WriteError as e:
            raise Ap2WriteError(f"{e}: not stamped") from e
        if not st.get("anchored"):
            raise Ap2EvidenceError(f"no anchor obtained: {st.get('note')}")
        ev.setdefault("anchors", []).append({"mechanism": "rfc3161", "tsr_b64": st["tsr_b64"], "tsa_url": tsa_url})
        _refuse_oversize(ev, "not stamped")   # 1.7.1 (SPEC §3.1): the anchor must not take the pack over 64 MiB; the pack is unchanged
        mode = os.stat(path).st_mode & 0o7777
        tmp = None
        try:   # a fresh, unpredictable name created O_EXCL (a fixed name could be a planted symlink: measured, it overwrote its target)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".ap2-stamp-", suffix=".tmp")
            os.fchmod(fd, mode)   # the pack keeps its permissions (0600 became 0644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(ev, f, ensure_ascii=False, indent=1, sort_keys=True)
                f.flush(); os.fsync(f.fileno())
            os.replace(tmp, path); tmp = None
        except OSError as e:
            raise Ap2WriteError(f"cannot write the stamped pack: {type(e).__name__}: not stamped") from e
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return {"out": path, "evidence_digest_sha256": digest, "anchors": len(ev["anchors"])}
    finally:
        os.close(dfd)


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
    _refuse_oversize(ev, "not signed")   # 1.7.1 (SPEC §3.1): the producer block must not take the pack over 64 MiB
    _write_pack_file(path, ev)   # 1.5.2: whole or not at all; the pack read above stays as it was on a failed write
    algs = [x["sig_alg"] for x in ev["producer_signatures"]["signatures"]]
    return {"out": path, "scheme": ev["producer_signatures"]["scheme"], "sig_algs": algs,
            "pq_protected": any(a in _sigsuite.POST_QUANTUM for a in algs),
            "producer_public_keys": identity.public_keys()}


def _chain_verdict(trust_anchor, art_results):
    if trust_anchor is None:
        return None
    attempted = [r["x5c_leaf"] for r in art_results if r.get("x5c_leaf") is not None]
    if not attempted or any(x.get("chain_verified") is None for x in attempted):
        return None          # nothing was attempted, or openssl could not measure one of them
    return all(x.get("chain_verified") is True for x in attempted)


def _anchor_identity(tsr_b64: str) -> bytes:
    """SPEC §3.3: the identity of an anchor is the TSTInfo the TSA signed (eContent of the token), not the bytes around it.
    Called only on a token whose binding verified, i.e. that parsed; the decoded bytes are the fallback for a stubbed check."""
    raw = _sigsuite._unb64(tsr_b64)
    try:
        return b"tst:" + parse_timestamp_resp(raw)["tst_info"]
    except Ap2EvidenceError:
        return b"raw:" + raw


def _gt_key(gt: str):
    """Order key of a GeneralizedTime `YYYYMMDDHHMMSS[.f]Z` (the only shape parse_timestamp_resp reports): whole seconds, then
    the fraction as a number — a string comparison put "…00.5Z" before "…00Z" ('.' < 'Z')."""
    whole, _, frac = gt.rstrip("Z").partition(".")
    return (whole, float("0." + frac) if frac else 0.0)


STATES_VOCABULARY = "ap2-evidence-pack/states-1"   # 1.6.0 — SPEC §6.9: immutable; a change of meaning is a new identifier
REFUSAL_CLASSES = ("format_unsupported", "unknown_member", "malformed")
SUBJECTS = ("sealed_content", "holder_binding", "time_anchor", "producer_signature", "issuer_identity")
POLICY_UNMET = ("require_producer", "require_pq", "require_anchor", "min_anchors", "require_binding", "trusted_producer_keys",
                "trust_set_complete")   # require_binding: 1.9.0


def _refusal_receipt(msg: str, cls: str) -> Dict:
    """A refusal (SPEC §6.9): the pack was not admitted, so it receives no `states` and no `policy`; the twelve 1.5.x fields
    keep their values, `false` by construction (not measured: read `admission`, SPEC §10)."""
    assert cls in REFUSAL_CLASSES, cls
    return {"digest_ok": False, "artifacts": [], "producer_signatures": {"present": False, "ok": None, "pq_protected": False, "trusted": None},
            "pq_protected": False, "bindings_ok": False, "rfc3161": {"claimed": False, "verified": None}, "anchors": [], "anchors_verified": 0, "provenance_classes": [],
            "self_asserted_only": True, "chain_verified": None, "policy_ok": False, "valid": False, "honest_scope": None, "refused": msg,
            "admission": "refused", "refusal_class": cls, "states_vocabulary": STATES_VOCABULARY, "states": None, "policy": None,
            "mldsa_backend": bool(_sigsuite.MLDSA_AVAILABLE)}


def _subject(elements: List[Tuple]) -> Dict:
    """SPEC §6.9: one state per subject from its elements (state, reason, detail). Precedence: contradicted >
    not_evaluated/instrument_failure > other not_evaluated > verified; `verified` only when every element is. `reasons`:
    one per element that is not verified, in element order (for a `verified` subject, the qualifiers its elements carry)."""
    def rank(e):
        return 3 if e[0] == "contradicted" else 2 if e[1] == "instrument_failure" else 1 if e[0] == "not_evaluated" else 0
    top = max(elements, key=rank)
    state = top[0]
    if state == "verified":
        reasons = [e[1] for e in elements if e[1]]
    else:
        reasons = [e[1] for e in elements if e[0] != "verified"]
    out = {"state": state, "reasons": reasons}
    details = [e[2] for e in elements if len(e) > 2 and e[2]]
    if details:
        out["detail"] = "; ".join(details)
    return out


def _anchor_element(r: Dict, tsa_requested: bool) -> Tuple:
    """SPEC §6.9, `time_anchor`: one RFC 3161 token (the `rfc3161_timestamp` block or one `anchors` entry)."""
    if r.get("verified") is not True:
        return ("contradicted", "binding_mismatch" if r.get("imprint_ok") is False else "token_invalid")
    if not tsa_requested:
        return ("not_evaluated", "tsa_not_checked")
    if r.get("tsa_verified") is True:
        return ("verified", None)
    if r.get("tsa_verified") is False:
        return ("not_evaluated", "tsa_invalid")
    if r.get("tsa_reason") == "signer_certificate_absent":   # 1.8.1 (SPEC §3.2, §6.9): not evaluated, not an instrument fault
        return ("not_evaluated", "signer_certificate_absent")
    return ("not_evaluated", "instrument_failure", r.get("tsa_note") or "TSA signature not checked by this verifier")


def derive_states(*, digest_ok, art_results, binding_set_match, ts_block, rfc_block, anchor_results, tsa_requested,
                  producer, pinned, trust_anchor_given) -> Dict:
    """SPEC §6.9 — the five subjects of an admitted pack, from the facts the verifier measured (the same derivation as
    the JS verifier's deriveStates)."""
    sealed = [("verified", None) if digest_ok else ("contradicted", "digest_mismatch")]
    if not art_results:
        sealed.append(("contradicted", "artifact_invalid", "the pack carries no artifact"))
    for r in art_results:
        bad = "error" in r or r.get("signature_ok") is not True or r.get("claims_match") is not True
        sealed.append(("contradicted", "artifact_invalid") if bad else ("verified", None))
    if binding_set_match is not None:   # recomputed whenever every artifact's signature and claims verified (SPEC §6.9)
        sealed.append(("verified", None) if binding_set_match else ("contradicted", "binding_mismatch"))
    verified_arts = [r for r in art_results if "error" not in r]
    not_seen = None if len(verified_arts) == len(art_results) else "artifacts that are errors are stated in sealed_content only"
    holder = []
    for r in verified_arts:
        if r.get("chain_hop"):   # 1.9.0 (SPEC §2.1, §6.9): an AP2 hop is the holder binding of the hop before it
            holder.append(("verified", None))
        kb = r.get("kb_jwt") or {}
        if not kb.get("present"):
            continue
        if kb.get("verified") is True:
            holder.append(("verified", None))
        elif kb.get("verified") is False:
            holder.append(("contradicted", "kb_signature_invalid" if kb.get("signature_ok") is not True else "sd_hash_mismatch"))
        else:
            holder.append(("not_evaluated", "holder_key_unknown"))
    if not holder:
        holder = [("not_evaluated", "not_present", not_seen)]
    time_ = []
    if ts_block.get("anchored"):
        time_.append(_anchor_element(rfc_block, tsa_requested) if isinstance(ts_block.get("tsr_b64"), str) else ("contradicted", "token_missing"))
    for r in anchor_results:
        time_.append(_anchor_element(r, tsa_requested))
    if not time_:
        time_ = [("not_evaluated", "not_present")]
    prod = []
    if not producer.get("present"):
        prod = [("not_evaluated", "not_present")]
    else:
        for e in producer.get("signatures") or []:
            if e.get("status") == "FAIL":
                prod.append(("contradicted", "signature_invalid"))
            elif e.get("status") == "SKIP":
                prod.append(("not_evaluated", "backend_missing"))
            elif not pinned:
                prod.append(("not_evaluated", "self_asserted"))
            elif e.get("key_trusted") is True:
                prod.append(("verified", None))
            else:
                prod.append(("not_evaluated", "key_unresolved"))
        if not producer.get("signatures"):
            prod.append(("contradicted", "signature_invalid", "the producer block carries no signature entry"))
        elif producer.get("scheme_ok") is not True:
            prod.append(("contradicted", "signature_invalid", f"scheme {_jkey(producer.get('scheme'))} does not match its entries (SPEC §5)"))
    issuer = []
    for r in verified_arts:
        if r.get("provenance_class") != "x5c_header":
            issuer.append(("not_evaluated", "self_asserted"))
        elif not trust_anchor_given:
            issuer.append(("not_evaluated", "no_trust_anchor"))
        else:
            leaf = r.get("x5c_leaf") or {}
            cv = leaf.get("chain_verified")
            if cv is True:
                issuer.append(("verified", "ca_certified"))
            elif cv is False:
                issuer.append(("contradicted", "chain_broken", leaf.get("_broken")) if leaf.get("_broken") else ("not_evaluated", "chain_unresolved"))
            else:
                issuer.append(("not_evaluated", "instrument_failure", f"check not run here: {leaf['_not_run']}" if leaf.get("_not_run")
                              else "openssl absent — x5c chain NOT verified"))
    if not issuer:
        issuer = [("not_evaluated", "not_present", not_seen or "the pack carries no artifact")]
    return {"sealed_content": _subject(sealed), "holder_binding": _subject(holder), "time_anchor": _subject(time_),
            "producer_signature": _subject(prod), "issuer_identity": _subject(issuer)}


# ────────────────────────────────────────────────────────── not-before block (SPEC §12, 1.8.0)
# OURS: a NIST Beacon value inside the sealed content, in one object with the payment it dates — salted commitments to the
# payer's and payee's IBANs (and names, details), the amount, the currency, a payment id and a record salt (Regulation (EU)
# 2023/1113 Art. 5(1) minimum; disclosure on request, Art. 5(2); no personal data in clear). Member names and commitment
# encoding: the cryptovalid-payment/1 rules decided for the three projects (SPEC §12.2, §12.6). The AP2 mandates are not
# changed: the block names the mandate artifact and the path where its issuer signed the amount.
NOT_BEFORE_PROFILE = "ap2-evidence-pack.not-before/1"
COMMITMENT_LABEL = b"cryptovalid-payment/1/"
IBAN_MEMBERS = ("payer_iban_commitment", "payee_iban_commitment")
TEXT_MEMBERS = ("payer_name_commitment", "payer_details_commitment", "payee_name_commitment")
COMMITMENT_MEMBERS = IBAN_MEMBERS + TEXT_MEMBERS
# ISO 4217 minor units of the currencies whose amount NB2 can compare with an AP2 integer (closed; another currency:
# not_evaluated). The ISO 4217 minor units of these five (SPEC §12.3; test_ap2_currency_table.py compares them with list one).
MINOR_UNITS = {"EUR": 2, "USD": 2, "GBP": 2, "CHF": 2, "JPY": 0}
_AMOUNT = re.compile(r"(0|[1-9][0-9]{0,17})(?:\.([0-9]{1,4}))?")
_HEX64L = re.compile(r"[0-9a-f]{64}")
_HEX32L = re.compile(r"[0-9a-f]{32}")
_RECORD_SALT = re.compile(r"(?:[0-9a-f]{2}){16,64}")
_HEX128 = re.compile(r"[0-9A-Fa-f]{128}")
_PAYMENT_ID = re.compile(r"[A-Za-z0-9/?:().,'+ -]{1,35}")
_NB_KEYS = {"profile": (lambda v: v == NOT_BEFORE_PROFILE, repr(NOT_BEFORE_PROFILE), True),
            "payment": (_is_obj, "an object", True), "mandate": (_is_obj, "an object", True),
            "pulses": (_is_obj, "an object", True)}
_NB_PAYMENT_KEYS = {"payment_id": (_is_str, "a string", True), "amount": (_is_str, "a string", True),
                    "currency": (_is_str, "a string", True),
                    "payer_iban_commitment": (_is_str, "a string", True), "payee_iban_commitment": (_is_str, "a string", True),
                    "record_salt": (_is_str, "a string", True), "beacon": (_is_obj, "an object", True),
                    "payer_name_commitment": (_is_str, "a string", False), "payer_details_commitment": (_is_str, "a string", False),
                    "payee_name_commitment": (_is_str, "a string", False)}
_DISCLOSURE_KEYS = {"member": (lambda v: v in COMMITMENT_MEMBERS, "one of the five commitment members", True),
                    "salt": (lambda v: _is_str(v) and _HEX32L.fullmatch(v) is not None, "32 lowercase hexadecimal characters", True),
                    "value": (lambda v: _is_str(v) and 0 < len(v) <= 1024 and _is_text(v) and _portable(v),
                              "a non-empty string of at most 1024 characters assigned in Unicode 13.0.0", True)}


# SPEC §12.2 "Unicode version" (as cryptovalid-opencore §18): the code points assigned in Unicode 13.0.0 (the database of
# CPython 3.9), ranges of hex code points. NFC of a string of these is the same in every later version; of a code point
# assigned later it is not (measured 16/11/2026: CPython 3.9, 3.13 and Node 22 disagree on U+1E08F U+0316, U+105D2 U+0307).
_U13 = ("0-377,37A-37F,384-38A,38C,38E-3A1,3A3-52F,531-556,559-58A,58D-58F,591-5C7,5D0-5EA,5EF-5F4,600-61C,61E-70D,70F-74"
        "A,74D-7B1,7C0-7FA,7FD-82D,830-83E,840-85B,85E,860-86A,8A0-8B4,8B6-8C7,8D3-983,985-98C,98F-990,993-9A8,9AA-9B0,9B"
        "2,9B6-9B9,9BC-9C4,9C7-9C8,9CB-9CE,9D7,9DC-9DD,9DF-9E3,9E6-9FE,A01-A03,A05-A0A,A0F-A10,A13-A28,A2A-A30,A32-A33,A3"
        "5-A36,A38-A39,A3C,A3E-A42,A47-A48,A4B-A4D,A51,A59-A5C,A5E,A66-A76,A81-A83,A85-A8D,A8F-A91,A93-AA8,AAA-AB0,AB2-AB"
        "3,AB5-AB9,ABC-AC5,AC7-AC9,ACB-ACD,AD0,AE0-AE3,AE6-AF1,AF9-AFF,B01-B03,B05-B0C,B0F-B10,B13-B28,B2A-B30,B32-B33,B3"
        "5-B39,B3C-B44,B47-B48,B4B-B4D,B55-B57,B5C-B5D,B5F-B63,B66-B77,B82-B83,B85-B8A,B8E-B90,B92-B95,B99-B9A,B9C,B9E-B9"
        "F,BA3-BA4,BA8-BAA,BAE-BB9,BBE-BC2,BC6-BC8,BCA-BCD,BD0,BD7,BE6-BFA,C00-C0C,C0E-C10,C12-C28,C2A-C39,C3D-C44,C46-C4"
        "8,C4A-C4D,C55-C56,C58-C5A,C60-C63,C66-C6F,C77-C8C,C8E-C90,C92-CA8,CAA-CB3,CB5-CB9,CBC-CC4,CC6-CC8,CCA-CCD,CD5-CD"
        "6,CDE,CE0-CE3,CE6-CEF,CF1-CF2,D00-D0C,D0E-D10,D12-D44,D46-D48,D4A-D4F,D54-D63,D66-D7F,D81-D83,D85-D96,D9A-DB1,DB"
        "3-DBB,DBD,DC0-DC6,DCA,DCF-DD4,DD6,DD8-DDF,DE6-DEF,DF2-DF4,E01-E3A,E3F-E5B,E81-E82,E84,E86-E8A,E8C-EA3,EA5,EA7-EB"
        "D,EC0-EC4,EC6,EC8-ECD,ED0-ED9,EDC-EDF,F00-F47,F49-F6C,F71-F97,F99-FBC,FBE-FCC,FCE-FDA,1000-10C5,10C7,10CD,10D0-1"
        "248,124A-124D,1250-1256,1258,125A-125D,1260-1288,128A-128D,1290-12B0,12B2-12B5,12B8-12BE,12C0,12C2-12C5,12C8-12D"
        "6,12D8-1310,1312-1315,1318-135A,135D-137C,1380-1399,13A0-13F5,13F8-13FD,1400-169C,16A0-16F8,1700-170C,170E-1714,"
        "1720-1736,1740-1753,1760-176C,176E-1770,1772-1773,1780-17DD,17E0-17E9,17F0-17F9,1800-180E,1810-1819,1820-1878,18"
        "80-18AA,18B0-18F5,1900-191E,1920-192B,1930-193B,1940,1944-196D,1970-1974,1980-19AB,19B0-19C9,19D0-19DA,19DE-1A1B"
        ",1A1E-1A5E,1A60-1A7C,1A7F-1A89,1A90-1A99,1AA0-1AAD,1AB0-1AC0,1B00-1B4B,1B50-1B7C,1B80-1BF3,1BFC-1C37,1C3B-1C49,1"
        "C4D-1C88,1C90-1CBA,1CBD-1CC7,1CD0-1CFA,1D00-1DF9,1DFB-1F15,1F18-1F1D,1F20-1F45,1F48-1F4D,1F50-1F57,1F59,1F5B,1F5"
        "D,1F5F-1F7D,1F80-1FB4,1FB6-1FC4,1FC6-1FD3,1FD6-1FDB,1FDD-1FEF,1FF2-1FF4,1FF6-1FFE,2000-2064,2066-2071,2074-208E,"
        "2090-209C,20A0-20BF,20D0-20F0,2100-218B,2190-2426,2440-244A,2460-2B73,2B76-2B95,2B97-2C2E,2C30-2C5E,2C60-2CF3,2C"
        "F9-2D25,2D27,2D2D,2D30-2D67,2D6F-2D70,2D7F-2D96,2DA0-2DA6,2DA8-2DAE,2DB0-2DB6,2DB8-2DBE,2DC0-2DC6,2DC8-2DCE,2DD0"
        "-2DD6,2DD8-2DDE,2DE0-2E52,2E80-2E99,2E9B-2EF3,2F00-2FD5,2FF0-2FFB,3000-303F,3041-3096,3099-30FF,3105-312F,3131-3"
        "18E,3190-31E3,31F0-321E,3220-9FFC,A000-A48C,A490-A4C6,A4D0-A62B,A640-A6F7,A700-A7BF,A7C2-A7CA,A7F5-A82C,A830-A83"
        "9,A840-A877,A880-A8C5,A8CE-A8D9,A8E0-A953,A95F-A97C,A980-A9CD,A9CF-A9D9,A9DE-A9FE,AA00-AA36,AA40-AA4D,AA50-AA59,"
        "AA5C-AAC2,AADB-AAF6,AB01-AB06,AB09-AB0E,AB11-AB16,AB20-AB26,AB28-AB2E,AB30-AB6B,AB70-ABED,ABF0-ABF9,AC00-D7A3,D7"
        "B0-D7C6,D7CB-D7FB,E000-FA6D,FA70-FAD9,FB00-FB06,FB13-FB17,FB1D-FB36,FB38-FB3C,FB3E,FB40-FB41,FB43-FB44,FB46-FBC1"
        ",FBD3-FD3F,FD50-FD8F,FD92-FDC7,FDF0-FDFD,FE00-FE19,FE20-FE52,FE54-FE66,FE68-FE6B,FE70-FE74,FE76-FEFC,FEFF,FF01-F"
        "FBE,FFC2-FFC7,FFCA-FFCF,FFD2-FFD7,FFDA-FFDC,FFE0-FFE6,FFE8-FFEE,FFF9-FFFD,10000-1000B,1000D-10026,10028-1003A,10"
        "03C-1003D,1003F-1004D,10050-1005D,10080-100FA,10100-10102,10107-10133,10137-1018E,10190-1019C,101A0,101D0-101FD,"
        "10280-1029C,102A0-102D0,102E0-102FB,10300-10323,1032D-1034A,10350-1037A,10380-1039D,1039F-103C3,103C8-103D5,1040"
        "0-1049D,104A0-104A9,104B0-104D3,104D8-104FB,10500-10527,10530-10563,1056F,10600-10736,10740-10755,10760-10767,10"
        "800-10805,10808,1080A-10835,10837-10838,1083C,1083F-10855,10857-1089E,108A7-108AF,108E0-108F2,108F4-108F5,108FB-"
        "1091B,1091F-10939,1093F,10980-109B7,109BC-109CF,109D2-10A03,10A05-10A06,10A0C-10A13,10A15-10A17,10A19-10A35,10A3"
        "8-10A3A,10A3F-10A48,10A50-10A58,10A60-10A9F,10AC0-10AE6,10AEB-10AF6,10B00-10B35,10B39-10B55,10B58-10B72,10B78-10"
        "B91,10B99-10B9C,10BA9-10BAF,10C00-10C48,10C80-10CB2,10CC0-10CF2,10CFA-10D27,10D30-10D39,10E60-10E7E,10E80-10EA9,"
        "10EAB-10EAD,10EB0-10EB1,10F00-10F27,10F30-10F59,10FB0-10FCB,10FE0-10FF6,11000-1104D,11052-1106F,1107F-110C1,110C"
        "D,110D0-110E8,110F0-110F9,11100-11134,11136-11147,11150-11176,11180-111DF,111E1-111F4,11200-11211,11213-1123E,11"
        "280-11286,11288,1128A-1128D,1128F-1129D,1129F-112A9,112B0-112EA,112F0-112F9,11300-11303,11305-1130C,1130F-11310,"
        "11313-11328,1132A-11330,11332-11333,11335-11339,1133B-11344,11347-11348,1134B-1134D,11350,11357,1135D-11363,1136"
        "6-1136C,11370-11374,11400-1145B,1145D-11461,11480-114C7,114D0-114D9,11580-115B5,115B8-115DD,11600-11644,11650-11"
        "659,11660-1166C,11680-116B8,116C0-116C9,11700-1171A,1171D-1172B,11730-1173F,11800-1183B,118A0-118F2,118FF-11906,"
        "11909,1190C-11913,11915-11916,11918-11935,11937-11938,1193B-11946,11950-11959,119A0-119A7,119AA-119D7,119DA-119E"
        "4,11A00-11A47,11A50-11AA2,11AC0-11AF8,11C00-11C08,11C0A-11C36,11C38-11C45,11C50-11C6C,11C70-11C8F,11C92-11CA7,11"
        "CA9-11CB6,11D00-11D06,11D08-11D09,11D0B-11D36,11D3A,11D3C-11D3D,11D3F-11D47,11D50-11D59,11D60-11D65,11D67-11D68,"
        "11D6A-11D8E,11D90-11D91,11D93-11D98,11DA0-11DA9,11EE0-11EF8,11FB0,11FC0-11FF1,11FFF-12399,12400-1246E,12470-1247"
        "4,12480-12543,13000-1342E,13430-13438,14400-14646,16800-16A38,16A40-16A5E,16A60-16A69,16A6E-16A6F,16AD0-16AED,16"
        "AF0-16AF5,16B00-16B45,16B50-16B59,16B5B-16B61,16B63-16B77,16B7D-16B8F,16E40-16E9A,16F00-16F4A,16F4F-16F87,16F8F-"
        "16F9F,16FE0-16FE4,16FF0-16FF1,17000-187F7,18800-18CD5,18D00-18D08,1B000-1B11E,1B150-1B152,1B164-1B167,1B170-1B2F"
        "B,1BC00-1BC6A,1BC70-1BC7C,1BC80-1BC88,1BC90-1BC99,1BC9C-1BCA3,1D000-1D0F5,1D100-1D126,1D129-1D1E8,1D200-1D245,1D"
        "2E0-1D2F3,1D300-1D356,1D360-1D378,1D400-1D454,1D456-1D49C,1D49E-1D49F,1D4A2,1D4A5-1D4A6,1D4A9-1D4AC,1D4AE-1D4B9,"
        "1D4BB,1D4BD-1D4C3,1D4C5-1D505,1D507-1D50A,1D50D-1D514,1D516-1D51C,1D51E-1D539,1D53B-1D53E,1D540-1D544,1D546,1D54"
        "A-1D550,1D552-1D6A5,1D6A8-1D7CB,1D7CE-1DA8B,1DA9B-1DA9F,1DAA1-1DAAF,1E000-1E006,1E008-1E018,1E01B-1E021,1E023-1E"
        "024,1E026-1E02A,1E100-1E12C,1E130-1E13D,1E140-1E149,1E14E-1E14F,1E2C0-1E2F9,1E2FF,1E800-1E8C4,1E8C7-1E8D6,1E900-"
        "1E94B,1E950-1E959,1E95E-1E95F,1EC71-1ECB4,1ED01-1ED3D,1EE00-1EE03,1EE05-1EE1F,1EE21-1EE22,1EE24,1EE27,1EE29-1EE3"
        "2,1EE34-1EE37,1EE39,1EE3B,1EE42,1EE47,1EE49,1EE4B,1EE4D-1EE4F,1EE51-1EE52,1EE54,1EE57,1EE59,1EE5B,1EE5D,1EE5F,1E"
        "E61-1EE62,1EE64,1EE67-1EE6A,1EE6C-1EE72,1EE74-1EE77,1EE79-1EE7C,1EE7E,1EE80-1EE89,1EE8B-1EE9B,1EEA1-1EEA3,1EEA5-"
        "1EEA9,1EEAB-1EEBB,1EEF0-1EEF1,1F000-1F02B,1F030-1F093,1F0A0-1F0AE,1F0B1-1F0BF,1F0C1-1F0CF,1F0D1-1F0F5,1F100-1F1A"
        "D,1F1E6-1F202,1F210-1F23B,1F240-1F248,1F250-1F251,1F260-1F265,1F300-1F6D7,1F6E0-1F6EC,1F6F0-1F6FC,1F700-1F773,1F"
        "780-1F7D8,1F7E0-1F7EB,1F800-1F80B,1F810-1F847,1F850-1F859,1F860-1F887,1F890-1F8AD,1F8B0-1F8B1,1F900-1F978,1F97A-"
        "1F9CB,1F9CD-1FA53,1FA60-1FA6D,1FA70-1FA74,1FA78-1FA7A,1FA80-1FA86,1FA90-1FAA8,1FAB0-1FAB6,1FAC0-1FAC2,1FAD0-1FAD"
        "6,1FB00-1FB92,1FB94-1FBCA,1FBF0-1FBF9,20000-2A6DD,2A700-2B734,2B740-2B81D,2B820-2CEA1,2CEB0-2EBE0,2F800-2FA1D,30"
        "000-3134A,E0001,E0020-E007F,E0100-E01EF,F0000-FFFFD,100000-10FFFD")
_U13_LO, _U13_HI = zip(*((int(a, 16), int(b or a, 16)) for a, _, b in (x.partition("-") for x in _U13.split(","))))


def _portable(v: str) -> bool:
    """Every code point of v assigned in Unicode 13.0.0, no surrogate."""
    import bisect
    for ch in v:
        cp = ord(ch)
        i = bisect.bisect_right(_U13_LO, cp) - 1
        if i < 0 or cp > _U13_HI[i] or 0xD800 <= cp <= 0xDFFF:
            return False
    return True


def _is_text(v: str) -> bool:
    """A string that UTF-8 can encode (no lone surrogate, which json.loads lets through as "\\ud800")."""
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
_NB_BEACON_KEYS = {"source": (lambda v: v == "nist-beacon-2.0", '"nist-beacon-2.0"', True),
                   "chain_index": (lambda v: type(v) is int and v >= 0, "an integer >= 0", True),
                   "pulse_index": (lambda v: type(v) is int and v >= 1, "an integer >= 1", True),
                   "output_value": (lambda v: _is_str(v) and _HEX128.fullmatch(v) is not None, "128 hexadecimal characters", True)}
_NB_MANDATE_KEYS = {"artifact": (lambda v: _is_str(v) and v != "", "a non-empty string", True),
                    "amount_claim": (lambda v: _is_str(v) and v != "", "a non-empty string", True)}
_NB_PULSES_KEYS = {"pulse": (_is_obj, "an object", True), "previous_pulse": (_is_obj, "an object", True),
                   "certificate": (_is_str, "a string", True)}
_IBAN = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(0|[1-9][0-9]*)\]")
_MISSING = object()


def iban_problem(s) -> Optional[str]:
    """None for an IBAN in the electronic form of ISO 13616-1 (as cryptovalid-opencore SPEC §18): two capital letters,
    check digits 02-98, 11 to 30 capital letters or digits; ISO 7064 MOD 97-10 = 1. Else the reason. The registry's
    per-country length and BBAN structure are not checked (§12.6)."""
    if not isinstance(s, str) or not re.fullmatch(r"[A-Z0-9]*", s):
        return "iban_charset"
    if not 15 <= len(s) <= 34:
        return "iban_length"
    if not _IBAN.fullmatch(s):
        return "iban_charset"
    if not 2 <= int(s[2:4]) <= 98:
        return "iban_check_digits"
    n = int("".join(str(int(c, 36)) for c in s[4:] + s[:4]))
    return None if n % 97 == 1 else "iban_checksum"


def normalise_commitment_value(member: str, value: str) -> str:
    """SPEC §12.2: an IBAN member's value upper case with every space removed, then the IBAN rule (ValueError with the
    reason); a name or details member's value in Unicode NFC."""
    import unicodedata
    if member not in COMMITMENT_MEMBERS:
        raise ValueError(f"{member!r} is not a commitment member")
    if not isinstance(value, str) or not 0 < len(value) <= 1024 or not _is_text(value):
        raise ValueError("a value is a non-empty string of at most 1024 characters")
    if member in IBAN_MEMBERS:
        if not value.isascii():                       # refused before upper case: "ß".upper() is "SS"
            raise ValueError("iban_charset")
        v = value.replace(" ", "").upper()
        why = iban_problem(v)
        if why:
            raise ValueError(why)
        return v
    if not _portable(value):   # SPEC §12.2: NFC is the same in every runtime only for code points of Unicode 13.0.0
        raise ValueError("value_not_portable: a code point not assigned in Unicode 13.0.0")
    return unicodedata.normalize("NFC", value)


def payment_commitment(member: str, salt: bytes, value: str) -> str:
    """SPEC §12.2: lowercase hex SHA-256("cryptovalid-payment/1/" || member || 0x00 || salt (16 bytes) || UTF-8(value)),
    the value normalised first (normalise_commitment_value)."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError("the salt is exactly 16 bytes")
    v = normalise_commitment_value(member, value)
    return hashlib.sha256(COMMITMENT_LABEL + member.encode("ascii") + b"\x00" + bytes(salt) + v.encode("utf-8")).hexdigest()


def make_payment(*, payment_id: str, amount: str, currency: str, payer_iban: str, payee_iban: str, beacon: Dict,
                 salts: Dict[str, bytes], record_salt: bytes, payer_name: Optional[str] = None,
                 payer_details: Optional[str] = None, payee_name: Optional[str] = None) -> Dict:
    """SPEC §12.2: the `payment` object from clear values — only commitments are returned; the caller keeps the clear
    values and `salts` (member -> 16 bytes) outside the pack."""
    if not isinstance(record_salt, (bytes, bytearray)) or not 16 <= len(record_salt) <= 64:
        raise ValueError("record_salt is 16 to 64 bytes")
    pay = {"payment_id": payment_id, "amount": amount, "currency": currency, "record_salt": bytes(record_salt).hex(),
           "beacon": beacon}
    for member, value in (("payer_iban_commitment", payer_iban), ("payee_iban_commitment", payee_iban),
                          ("payer_name_commitment", payer_name), ("payer_details_commitment", payer_details),
                          ("payee_name_commitment", payee_name)):
        if value is not None:
            pay[member] = payment_commitment(member, salts[member], value)
    return pay


def check_disclosure(path: str, disclosure) -> Dict:
    """SPEC §12.2: a disclosure {member, salt, value} (Art. 5(2)) against the commitment the pack sealed. Read-only.
    Returns {"member", "outcome": "matches" | "disclosure_mismatch" | "member_absent" | "disclosure_iban_invalid",
    "reason"?} (the names of cryptovalid-opencore SPEC §18).
    Raises Ap2EvidenceError for a disclosure outside its grammar or a pack without a valid block."""
    _check_closed(disclosure, "disclosure", _DISCLOSURE_KEYS)
    ev = read_evidence_file(path)
    nb = ev.get("not_before")
    if not isinstance(nb, dict):
        raise Ap2EvidenceError("the pack carries no not_before block (SPEC §12)")
    parse_not_before(nb)
    m = disclosure["member"]
    out = {"member": m, "note": "the pack must also verify (verify) for the commitment to be the sealed one"}
    if m in IBAN_MEMBERS:
        v = disclosure["value"]
        why = "iban_charset" if not v.isascii() else iban_problem(v.replace(" ", "").upper())
        if why:
            return dict(out, outcome="disclosure_iban_invalid", reason=why)
    if m not in nb["payment"]:
        return dict(out, outcome="member_absent")
    got = payment_commitment(m, bytes.fromhex(disclosure["salt"]), disclosure["value"])
    return dict(out, outcome="matches" if got == nb["payment"][m] else "disclosure_mismatch")


def _resolve_path(node, path: str):
    """The value at a §4 path (`a.b[0].c`), or _MISSING."""
    pos, first = 0, True
    while pos < len(path):
        if path[pos] == ".":
            if first:
                return _MISSING
            pos += 1
            m = _PATH_TOKEN.match(path, pos)
            if not m or m.group(1) is None:
                return _MISSING
        else:
            m = _PATH_TOKEN.match(path, pos)
            if not m or (m.group(1) is not None and not first):
                return _MISSING
        if m.group(1) is not None:
            if not isinstance(node, dict) or m.group(1) not in node:
                return _MISSING
            node = node[m.group(1)]
        else:
            i = int(m.group(2))
            if not isinstance(node, list) or i >= len(node):
                return _MISSING
            node = node[i]
        pos, first = m.end(), False
    return _MISSING if first else node


def parse_not_before(nb) -> Dict:
    """SPEC §12.2: the closed block. Raises Ap2UnknownMember / Ap2EvidenceError naming the member and the reason."""
    if _nb is None:
        raise Ap2EvidenceError("not_before: the ap2_nist_beacon module is not installed (SPEC §12)")
    _check_closed(nb, "not_before", _NB_KEYS)
    _check_closed(nb["payment"], "not_before.payment", _NB_PAYMENT_KEYS)
    _check_closed(nb["payment"]["beacon"], "not_before.payment.beacon", _NB_BEACON_KEYS)
    _check_closed(nb["mandate"], "not_before.mandate", _NB_MANDATE_KEYS)
    _check_closed(nb["pulses"], "not_before.pulses", _NB_PULSES_KEYS)
    pay = nb["payment"]
    m = _AMOUNT.fullmatch(pay["amount"])
    if m is None:
        raise Ap2EvidenceError("not_before.payment.amount: not a decimal string (SPEC §12.2)")
    if int(m.group(1)) == 0 and int(m.group(2) or "0") == 0:
        raise Ap2EvidenceError("not_before.payment.amount: not greater than zero (SPEC §12.2)")
    if not re.fullmatch(r"[A-Z]{3}", pay["currency"]):
        raise Ap2EvidenceError("not_before.payment.currency: not three capital letters A-Z (SPEC §12.2)")
    if not _RECORD_SALT.fullmatch(pay["record_salt"]):
        raise Ap2EvidenceError("not_before.payment.record_salt: not 32 to 128 lowercase hexadecimal characters, an even number (SPEC §12.2)")
    p = pay["payment_id"]
    if not _PAYMENT_ID.fullmatch(p) or p != p.strip(" "):
        raise Ap2EvidenceError("not_before.payment.payment_id: not 1 to 35 characters of the allowed set (SPEC §12.2)")
    for k in (m for m in COMMITMENT_MEMBERS if m in pay):
        if not _HEX64L.fullmatch(pay[k]):
            raise Ap2EvidenceError(f"not_before.payment.{k}: not 64 lowercase hexadecimal characters (SPEC §12.2)")
    for k in ("pulse", "previous_pulse"):
        try:
            _nb.check_grammar(nb["pulses"][k])
        except _nb.PulseError as e:
            if str(e).startswith("pulse_unknown_member"):
                raise Ap2UnknownMember(f"not_before.pulses.{k}: unknown key ({e}) (SPEC §12.2)")
            raise Ap2EvidenceError(f"not_before.pulses.{k}: {e} (SPEC §12.2)")
    try:
        _nb.read_certificate(nb["pulses"]["certificate"])
    except _nb.PulseError as e:
        raise Ap2EvidenceError(f"not_before.pulses.certificate: {e} (SPEC §12.2)")
    return nb


def _amount_equals_minor(amount: str, currency: str, minor) -> Optional[bool]:
    """amount (decimal string) in currency equals `minor` integer minor units; None when the currency's minor unit is
    not in MINOR_UNITS."""
    e = MINOR_UNITS.get(currency)
    if e is None:
        return None
    whole, _, frac = amount.partition(".")
    if len(frac.rstrip("0")) > e:
        return False
    return type(minor) is int and int(whole) * 10 ** e + int((frac + "0" * e)[:e] or "0") == minor


def check_not_before(nb: Dict, ev: Dict, art_results: List[Dict], proven_time: Optional[str], pinned=None) -> Dict:
    """SPEC §12.3: NB1-NB3, the window, the mandate's payee. `proven_time`: the earliest TSA-verified genTime or None."""
    pinned = _nb.PINNED if pinned is None else pinned
    pul = nb["pulses"]
    r = _nb.verify_pair(pul["pulse"], pul["previous_pulse"], pul["certificate"], pinned)
    T = r["time"]
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    pay = nb["payment"]
    out = {"profile": NOT_BEFORE_PROFILE, "source": "nist-beacon-2.0", "chain": r["chain"], "pulse": r["pulse"],
           "time": T.strftime(fmt), "certificate_id": r["certificate_id"], "checks": {},
           "covers": sorted(k for k in pay if k != "beacon") + ["mandate:" + nb["mandate"]["artifact"]],
           "window": {"not_before": None, "not_before_operator_promise": None, "not_after": None},
           "mandate_payee": None}
    c = out["checks"]
    b = pay["beacon"]
    if not r["ok"]:
        c["NB1"] = "failed:" + r["reason"]
    elif (b["chain_index"], b["pulse_index"]) != (r["chain"], r["pulse"]) or bytes.fromhex(b["output_value"]) != r["output"]:
        c["NB1"] = "failed:beacon_value_mismatch"
    else:
        c["NB1"] = "verified"
    md = nb["mandate"]
    idx = [i for i, a in enumerate(ev["artifacts"]) if a.get("name") == md["artifact"]]
    if not idx:
        c["NB2"] = "failed:mandate_not_in_pack"
    else:
        ar = art_results[idx[0]]
        if not (ar.get("signature_ok") is True and ar.get("claims_match") is True):
            c["NB2"] = "not_evaluated:mandate_not_verified"
        else:
            claims = ev["artifacts"][idx[0]]["resolved_claims"]
            v = _resolve_path(claims, md["amount_claim"])
            if v is _MISSING:
                c["NB2"] = "failed:amount_claim_not_found"
            elif not (isinstance(v, dict) and set(v) == {"amount", "currency"}) or v["currency"] != pay["currency"]:
                c["NB2"] = "failed:amount_not_the_mandate_amount"
            else:
                eq = _amount_equals_minor(pay["amount"], pay["currency"], v["amount"])
                c["NB2"] = ("not_evaluated:currency_minor_unit_unknown" if eq is None
                            else "verified" if eq else "failed:amount_not_the_mandate_amount")
            dp = claims.get("delegate_payload") if isinstance(claims, dict) else None
            for holder in (claims, dp[0] if isinstance(dp, list) and dp else None):
                if isinstance(holder, dict) and isinstance(holder.get("payee"), dict):
                    out["mandate_payee"] = holder["payee"]
                    break
    if c["NB1"] != "verified":
        c["NB3"] = "not_evaluated:beacon_not_verified"
    else:
        try:   # §1 checks the pattern only: 2026-02-30T00:00:00Z passes it and is no time to compare
            created = datetime.strptime(ev["created_utc"], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            created = None
        if created is None:
            c["NB3"] = "failed:created_utc_not_a_time"
        elif created < T:
            c["NB3"] = "failed:created_before_beacon"
        elif proven_time is None:
            c["NB3"] = "not_evaluated:no_verified_time_anchor"
        else:
            whole, _, frac = proven_time.rstrip("Z").partition(".")
            try:   # 1.8.1 (SPEC §12.3): second 60 or 61 passes time.strptime (-attime) and is no datetime
                gt = datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            except ValueError:
                gt = None
            # exact: T is in whole milliseconds, so genTime < T iff its whole milliseconds are (a float rounds .9999995 up)
            if gt is None:
                c["NB3"] = "not_evaluated:verified_time_not_a_time"
            elif gt + timedelta(milliseconds=int((frac + "000")[:3])) < T:
                c["NB3"] = "failed:window_inverted"
            else:
                c["NB3"] = "verified"
                out["window"]["not_after"] = proven_time
    if c["NB1"] == "verified" and c["NB2"] == "verified":
        out["window"]["not_before"] = T.strftime(fmt)
        out["window"]["not_before_operator_promise"] = (T - timedelta(seconds=r["period_s"])).strftime(fmt)
    vals = list(c.values())
    out["state"] = ("failed" if any(x.startswith("failed") for x in vals)
                    else "verified" if all(x == "verified" for x in vals) else "not_evaluated")
    return out


def verify_evidence(path: str, trusted_producer_keys=None, require_pq: bool = False,
                    require_producer: bool = False, require_anchor: bool = False, tsa_cert: Optional[str] = None,
                    trust_anchor: Optional[str] = None, min_anchors: Optional[int] = None,
                    trust_set_complete: bool = False, accept_integral_floats: bool = False,
                    require_bindings=None) -> Dict:
    """See `_verify_evidence`. 1.9.0 (SPEC §6.9): `require_bindings`, a list of (in, commits_to) artifact-name pairs, each
    of which the recomputed binding set must hold (`policy.unmet` `require_binding` otherwise, `policy_ok` false). 1.7.2 (SPEC §3.1): `accept_integral_floats` (default False) reads a number literal of a token
    written with a fraction or an exponent whose value is an integer within +/-(2^53-1) (`10.0`) as that integer; without
    it such a literal is that artifact's error. When it is set the receipt says so (`accept_integral_floats: true`) and
    each artifact entry lists the literals read that way (`integral_literals_read`); without it neither member is present,
    and the receipt is the 1.7.1 receipt but for the message of an artifact whose token has such a literal."""
    if type(accept_integral_floats) is not bool:   # SPEC §7 discipline: an option of the wrong type never changes a verdict in silence
        raise ValueError(f"accept_integral_floats must be a boolean (got {accept_integral_floats!r})")
    if require_bindings is not None and not (isinstance(require_bindings, (list, tuple)) and all(
            isinstance(pr, (list, tuple)) and len(pr) == 2 and all(isinstance(x, str) and x for x in pr) for pr in require_bindings)):
        raise ValueError(f"require_bindings must be a list of (in, commits_to) pairs of non-empty names (got {require_bindings!r})")
    tok = _INTEGRAL_READ.set([] if accept_integral_floats else None)
    try:
        r = _verify_evidence(path, trusted_producer_keys=trusted_producer_keys, require_pq=require_pq,
                             require_producer=require_producer, require_anchor=require_anchor, tsa_cert=tsa_cert,
                             trust_anchor=trust_anchor, min_anchors=min_anchors, trust_set_complete=trust_set_complete,
                             require_bindings=require_bindings)
    except Ap2WriteError as e:
        if accept_integral_floats and isinstance(getattr(e, "receipt", None), dict):
            e.receipt["accept_integral_floats"] = True
        raise
    finally:
        _INTEGRAL_READ.reset(tok)
    if accept_integral_floats:
        r["accept_integral_floats"] = True
    return r


def _verify_evidence(path: str, trusted_producer_keys=None, require_pq: bool = False,
                     require_producer: bool = False, require_anchor: bool = False, tsa_cert: Optional[str] = None,
                     trust_anchor: Optional[str] = None, min_anchors: Optional[int] = None,
                     trust_set_complete: bool = False, require_bindings=None) -> Dict:
    """OFFLINE re-verification from the evidence file alone: digest, every signature with
    the SNAPSHOTTED key, every disclosure, every binding, and the RFC 3161 token's binding
    (status + imprint; the TSA itself only with `tsa_cert`, via openssl). Fail-closed. Raises Ap2WriteError (1.5.2) when
    a check asked for (`tsa_cert`, `trust_anchor`) cannot be run here — openssl's temporary files cannot be written,
    openssl cannot be started, or it gives no answer in time: no verdict, rather than a check reported as failed. openssl
    absent is not this case: the field is None (not measured) and a policy that needs it is not met.

    1.6.0 (SPEC §6.9, §6.10): the receipt carries `admission`, `refusal_class`, `states_vocabulary`, `states` (five subjects)
    and `policy` ({met, unmet}); `trust_set_complete` declares the pinned set complete (an unpinned key is then also a
    policy failure, `unmet: ["trust_set_complete"]`). A check that could not be RUN here no longer leaves the caller without
    a receipt: the receipt is completed (that subject `not_evaluated/instrument_failure`) and Ap2WriteError carries it."""
    if min_anchors is not None and (type(min_anchors) is not int or min_anchors < 1):   # SPEC §3.3: an integer >= 1 —
        raise ValueError(f"min_anchors must be an integer >= 1 (got {min_anchors!r})")      # 0, NaN or "2" never weakens the policy in silence
    try:
        ev = read_evidence_file(path)
    except Ap2EvidenceError as e:   # 1.1.0: a hostile or unreadable file is a refusal receipt, never a traceback
        return _refusal_receipt(str(e), "malformed")

    def refusal(msg, cls="malformed"):   # 1.6.0 — SPEC §6.9: every refusal names its class
        return _refusal_receipt(msg, cls)
    # 1.1.0 (review r1): the SHAPE of the top-level fields is checked before anything touches them — `artifacts` a list of
    # objects, `bindings` a list, `rfc3161_timestamp` an object or absent, `producer_signatures` an object or absent. A wrong
    # type used to be a TypeError/AttributeError traceback (the JS verifier answered); `producer_signatures: {}` was "absent".
    if ev.get("evidence_format") != EVIDENCE_FORMAT:   # r5: version confusion — a "…/2.0" pack was verified under the 1.0 rules
        return refusal(f"evidence_format must be {EVIDENCE_FORMAT!r}", "format_unsupported")
    for f in ("subject", "created_utc", "honest_scope"):   # SPEC §1 MUSTs: present and a string, or the receipt is silently poorer
        if not isinstance(ev.get(f), str):
            return refusal(f"{f} must be a string (SPEC §1)")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", ev["created_utc"]):   # r6: §1 says ISO-8601 UTC, only the type was checked.
        # r9: [0-9], not \d — in Python \d matches every Unicode Nd digit, in JavaScript only [0-9], so "٢٠٢٦-٠٩-٢٢T٠٠:٠٠:٠٠Z"
        # (Arabic-Indic) verified here and was refused by the JS verifier: opposite verdicts on a pack in profile.
        return refusal("created_utc must be ISO-8601 UTC, YYYY-MM-DDTHH:MM:SSZ (SPEC §1)")
    if hashlib.sha256(ev["honest_scope"].encode("utf-8")).hexdigest() != HONEST_SCOPE_SHA256:
        # r8: the receipt used to REPRINT whatever scope the file carried — an author could write "anchored by a QTSP under
        # eIDAS art. 45j" and see it beside `valid: true`. The scope is the format's, not the pack's (SPEC §1).
        if hashlib.sha256(ev["honest_scope"].encode("utf-8")).hexdigest() == HONEST_SCOPE_SHA256_1_0:   # 1.9.0 (SPEC §1)
            return refusal(_PACK_1_0_REFUSAL, "format_unsupported")
        return refusal("honest_scope does not match the canonical scope of this evidence_format (SPEC §1)", "format_unsupported")
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
    # 1.4.0 — SPEC §9.1: the top-level object, the anchor block, the producer block and every binding entry are CLOSED
    if "not_before" in ev and _nb is None:   # 1.8.0 — SPEC §12: a copy without the beacon module never verifies one
        return refusal("not_before: this copy of the verifier has no ap2_nist_beacon module (SPEC §12)", "format_unsupported")
    try:
        _check_closed(ev, "top level", _TOP_KEYS)
        if "rfc3161_timestamp" in ev:
            _check_closed(ev["rfc3161_timestamp"], "rfc3161_timestamp", _RFC3161_KEYS)
        if "producer_signatures" in ev:
            _check_closed(ev["producer_signatures"], "producer_signatures", _PRODUCER_KEYS)
        for i, b in enumerate(ev.get("bindings", [])):
            _check_closed(b, f"bindings[{i}]", _BINDING_KEYS)
        for i, an in enumerate(ev.get("anchors", [])):   # 1.5.0 — SPEC §3.3/§9.1: closed entries, the mechanism first
            if not isinstance(an, dict):
                raise Ap2EvidenceError(f"anchors[{i}] must be an object (SPEC §9.1)")
            if "mechanism" not in an:
                raise Ap2EvidenceError(f"anchors[{i}]: missing mechanism (SPEC §9.1)")
            if not isinstance(an["mechanism"], str):
                raise Ap2EvidenceError(f"anchors[{i}]: mechanism must be a string (SPEC §9.1)")
            if an["mechanism"] not in _ANCHOR_MECHANISMS:   # 1.6.0: a mechanism a later revision may define -> format_unsupported
                return refusal(f"anchors[{i}]: mechanism {_jkey(an['mechanism'])} is not defined by this revision (SPEC §3.3)", "format_unsupported")
            _check_closed(an, f"anchors[{i}]", _ANCHOR_RFC3161_KEYS)
        # 1.6.0 — SPEC §9.1/§6.9 (not additive): an unknown key in an artifact entry (and its key, kb_jwt and verified_at_build
        # objects) or in a producer-signature entry is a refusal of class unknown_member, as in every other object of §9.1:
        # 1.5.x made it an artifact error or a FAIL entry, which a reader of the twelve fields took for an altered pack.
        # Only the unknown-key rule moves; a wrong type or a missing key stays an artifact error / FAIL entry.
        for i, a in enumerate(ev["artifacts"]):
            _check_unknown(a, f"artifacts[{i}]", _ARTIFACT_KEYS)
            for sub, keys in (("key", _KEY_KEYS), ("kb_jwt", _KB_COPY_KEYS), ("verified_at_build", _VAB_KEYS)):
                _check_unknown(a.get(sub), f"artifacts[{i}].{sub}", keys)
        sigs = ev.get("producer_signatures", {}).get("signatures")
        for i, e in enumerate(sigs if isinstance(sigs, list) else []):
            _check_unknown(e, f"producer_signatures.signatures[{i}]", _sigsuite.ENTRY_KEYS)
        if "not_before" in ev:   # 1.8.0 — SPEC §12.2: closed at every level, IBANs checked, before any check runs
            parse_not_before(ev["not_before"])
    except Ap2UnknownMember as e:
        return refusal(str(e), "unknown_member")
    except Ap2EvidenceError as e:
        return refusal(str(e))
    e2 = {k: v for k, v in ev.items() if k not in _DIGEST_EXCLUDED}
    recomputed_digest = hashlib.sha256(_canon(e2)).hexdigest()
    digest_ok = recomputed_digest == ev.get("evidence_digest_sha256")

    # r9: the time anchor is checked FIRST, so a TSA-verified genTime can date the x5c chain validation below
    ts = ev.get("rfc3161_timestamp") or {}
    rfc = {"claimed": bool(ts.get("anchored", False)), "verified": None}
    if ts.get("anchored") and isinstance(ts.get("tsr_b64"), str):
        rfc = {"claimed": True, **_verify_rfc3161(ts["tsr_b64"], recomputed_digest, tsa_cert=tsa_cert)}
    elif ts.get("anchored"):
        rfc = {"claimed": True, "verified": False, "note": "anchored claimed but tsr_b64 absent"}
    # 1.5.0 — SPEC §3.3: every `anchors` entry checked like the block above; COUNTING = binding verified (+ TSA-verified when
    # --tsa-cert was given); DISTINCT = a different signed TSTInfo (a copied token is one anchor, however it is wrapped);
    # any failing claim fails the pack
    anchor_results = [{"mechanism": an["mechanism"], "claimed": True, **_verify_rfc3161(an["tsr_b64"], recomputed_digest, tsa_cert=tsa_cert)}
                      for an in ev.get("anchors", [])]
    counted, earliest = set(), None
    for r_, tok in ([(rfc, ts.get("tsr_b64"))] if rfc.get("claimed") else []) + [(r_, an["tsr_b64"]) for r_, an in zip(anchor_results, ev.get("anchors", []))]:
        if r_.get("verified") is True and (tsa_cert is None or r_.get("tsa_verified") is True):
            # the TSTInfo the TSA signed, not the wrapper: the same token re-wrapped (bytes after the TimeStampResp, a status
            # string, a longer length) verified as a second anchor under --tsa-cert --min-anchors 2 (measured on b3edfc8)
            counted.add(_anchor_identity(tok))
            if r_.get("tsa_verified") is True and r_.get("gen_time") and (earliest is None or _gt_key(r_["gen_time"]) < _gt_key(earliest)):
                earliest = r_["gen_time"]
    anchors_verified = len(counted)
    rfc_block = rfc   # 1.6.0: the block's own result, before the §3.3 aggregate (an element of `time_anchor`)
    if anchor_results:   # the aggregate of §3.3; without `anchors` the block is exactly what 1.4.x reported
        rfc = dict(rfc, claimed=True, verified=(False if (rfc.get("verified") is False or any(x.get("verified") is not True for x in anchor_results)) else True))
    proven_time = earliest

    art_results, all_ok = [], True
    for_bindings = []
    chain_seen = {}   # 1.9.0 (SPEC §2.1): the artifacts verified so far, by name, for chain_from
    for a in ev["artifacts"]:
        _read = _INTEGRAL_READ.get()   # 1.7.2 (SPEC §3.1): the literals this artifact had read as integers, when asked
        _read0 = None if _read is None else len(_read)
        try:
            _check_closed(a, "artifact", _ARTIFACT_KEYS)   # 1.4.0 — SPEC §9.1: the entry, its key, its KB record and its attestation are CLOSED
            _check_closed(a["key"], "artifact key", _KEY_KEYS)
            _check_closed(a["kb_jwt"], "artifact kb_jwt", _KB_COPY_KEYS)
            _check_closed(a["verified_at_build"], "artifact verified_at_build", _VAB_KEYS)
            compact = a["sd_jwt_compact"]
            if not isinstance(compact, str) or compact != compact.strip() or not compact.isascii():
                raise Ap2EvidenceError("sd_jwt_compact must be the exact ASCII compact serialization (no surrounding whitespace)")
            key = a["key"]
            if not isinstance(key, dict) or not isinstance(key.get("jwk"), dict):
                raise Ap2EvidenceError("artifact key.jwk must be an object")
            pc = key.get("provenance_class")
            if not isinstance(pc, str) or pc not in PROVENANCE_CLASSES:   # r7: absent/null used to mean "no class", which CLEARED self_asserted_only   # r2: a list was a TypeError in sorted(); r5: an out-of-enum value passed as a strong class
                raise Ap2EvidenceError(f"artifact key.provenance_class must be one of {sorted(PROVENANCE_CLASSES)}")
            if (pc == "chain_cnf") != ("chain_from" in key):   # 1.9.0 (SPEC §2.1): chain_from with chain_cnf, and only with it
                raise Ap2EvidenceError("artifact key.chain_from goes with provenance_class chain_cnf, and only with it (SPEC §2.1)")
            prev_hop = None
            if pc == "chain_cnf":   # the key is reconciled against the previous hop the pack carries, verified before this one
                prev_hop = chain_seen.get(key["chain_from"])
                if prev_hop is None:
                    raise Ap2EvidenceError(f"artifact key.chain_from {_jkey(key['chain_from'])} names no artifact before this one "
                                           "that verified (SPEC §2.1)")
                if not _same_key(chain_cnf_jwk(prev_hop["resolved"]), key["jwk"]):
                    raise Ap2EvidenceError("provenance_class chain_cnf but the key is not the cnf.jwk of the artifact named by "
                                           "chain_from (SPEC §2.1)")
            parsed = parse_sd_jwt(compact)
            if not isinstance(parsed["payload"], dict) or not isinstance(parsed["header"], dict):
                raise Ap2EvidenceError("JWT header and payload must be objects")
            if _canon(a["header"]) != _canon(parsed["header"]):   # 1.4.0 — SPEC §2: the informative copy must say what the signed header says
                raise Ap2EvidenceError("artifact header copy differs from the decoded protected header (SPEC §2)")
            if bool(parsed["kb_jwt"]) != a["kb_jwt"]["present"]:
                raise Ap2EvidenceError("artifact kb_jwt.present contradicts the compact serialization (SPEC §9.1)")
            # SPEC §9.2 — the standards' rule for the unknown: ignored, and REPORTED (crit: RFC 7515 §4.1.11, a rejection)
            ignored = {"header": _jose_header_ignored(parsed["header"], "JWT header"),
                       "header_jwk": _unknown_members(parsed["header"].get("jwk"), _JWK_REGISTERED),
                       "key_jwk": _unknown_members(key["jwk"], _JWK_REGISTERED)}
            self_asserted, leaf_ident = _check_provenance(pc, parsed, key, trust_anchor, at_time=proven_time)   # r5: reconciled, not believed; r7/r8: it decides self_asserted_only; r9: at a proven time, and it names the leaf
            _reconcile_unused_header_keys(parsed["header"], key["jwk"], pc)   # 1.7.3 (SPEC §2 (d), §6 step 2)
            ignored["key_material"] = _key_material_not_used(parsed["header"], pc)   # SPEC §9.2: named, never dropped in silence
            sig_ok = verify_es256(parsed["signing_input"], parsed["signature"], key["jwk"])
            resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
            claims_ok = _canon(resolved) == _canon(a.get("resolved_claims"))
            chain_hop = None
            if prev_hop is not None and sig_ok and claims_ok:   # 1.9.0 (SPEC §2.1): the AP2 hop rules, each an artifact error
                chain_hop = dict(check_chain_hop(parsed, resolved, prev_hop["compact"]), **{"from": key["chain_from"]})
            kb = verify_kb_jwt(parsed, resolved)
            for k in _KB_RECOMPUTED:   # SPEC §9.1 (NEMESIS 2026-10-11): a recorded KB value that says something else is that artifact's error
                if k in a["kb_jwt"] and (k not in kb or _canon(a["kb_jwt"][k]) != _canon(kb[k])):
                    raise Ap2EvidenceError(f"artifact kb_jwt.{k} contradicts the KB-JWT (SPEC §9.1)")
            ignored.update(kb.pop("_ignored", {}))
            art_results.append({"name": a.get("name"), "signature_ok": sig_ok,
                                "claims_match": claims_ok, "kb_jwt": kb,
                                "provenance_class": key.get("provenance_class"),
                                "self_asserted": self_asserted,
                                "ignored": {k: v for k, v in sorted(ignored.items()) if v},   # SPEC §9.2: only the non-empty slots
                                **({"x5c_leaf": leaf_ident} if leaf_ident else {}),
                                **({"chain_hop": chain_hop} if chain_hop else {})})
            all_ok = (all_ok and sig_ok and claims_ok
                      and kb.get("verified") is not False)
            for_bindings.append({"name": a.get("name"), "compact": parsed["compact"],
                                 "resolved_claims": resolved})
            if sig_ok and claims_ok and isinstance(a.get("name"), str):
                chain_seen[a["name"]] = {"compact": parsed["compact"], "resolved": resolved}
        except Ap2WriteError:   # this process could not run a check (no writable temporary file): not the artifact's error
            raise
        except Exception as e:  # noqa: BLE001 — any malformation of an artifact is that artifact's error, never a traceback
            art_results.append({"name": a.get("name") if isinstance(a, dict) else None, "error": f"{type(e).__name__}: {str(e)[:120]}"})
            all_ok = False
        if _read is not None:
            art_results[-1]["integral_literals_read"] = _read[_read0:]

    # 1.6.0 — SPEC §6.9: the binding set as an element of sealed_content is recomputed whenever every artifact's issuer
    # signature and claims verified — also when a KB-JWT failed, where `bindings_ok` is false by the §6 step 3 rule without a
    # recomputation (the state must not say `verified` over a check that did not run; found by verifiers/states_controls.py)
    binding_set_match = None
    if art_results and len(for_bindings) == len(art_results) and all(r.get("signature_ok") is True and r.get("claims_match") is True for r in art_results):
        try:
            binding_set_match = bindings_recorded_match(find_bindings(for_bindings), ev.get("bindings", [])) is not None
        except Exception:  # noqa: BLE001
            binding_set_match = False
    bindings_not_recorded = []   # 1.9.0 (SPEC §4): the bindings over the issuer JWT a pack built before 1.9.0 does not record
    try:   # r4: the binding SET (SPEC §4) — entries compared by sorted canonical form; the scan order of JS Object.keys puts
        # array-index keys ("0", "7") first, so an ordered comparison split the verdict on a pack the reference itself built
        bindings_ok = False
        if all_ok:
            _nr = bindings_recorded_match(find_bindings(for_bindings), ev.get("bindings", []))
            bindings_ok = _nr is not None
            bindings_not_recorded = _nr or []
    except Exception:  # noqa: BLE001
        bindings_ok = False

    classes = sorted({r.get("provenance_class") for r in art_results
                      if r.get("provenance_class")})

    # OMEGA producer signature(s) over the digest: crypto-agile, hybrid (classical + ML-DSA-65).
    # A claimed-but-invalid signature is tamper -> fail-closed. pq_protected only on a valid PQ sig.
    prod = ev.get("producer_signatures")
    if prod is not None:   # 1.1.0 r1: an EMPTY block is present with zero passing signatures -> not ok (SPEC §5), like the JS verifier
        pv = _sigsuite.verify_producer_block(
            prod, recomputed_digest.encode("ascii"),
            trusted=trusted_producer_keys)
        producer = {"present": True, "scheme": pv["scheme"], "scheme_ok": pv["scheme_ok"], "ok": pv["ok"],
                    "pq_protected": pv["pq_protected"], "trusted": pv["trusted"],
                    "signatures": pv["results"]}
        if not pv["ok"]:
            all_ok = False
        # a pinned trust set that the producer key does NOT match = not authentic
        if trusted_producer_keys is not None and pv["trusted"] is not True:
            all_ok = False
    else:
        producer = {"present": False, "ok": None, "pq_protected": False, "trusted": None,   # 1.6.0: `ok` always present
                    "note": "no producer signature; pack integrity rests on digest + time anchor only. "
                            "Without a pinned producer key a signature would prove consistency, not authenticity."}
    # relying-party policy: enforce PQ / producer so a stripped-signature downgrade is rejected
    # require_anchor: the existed-by claim must be PROVEN, not merely claimed. A missing anchor, an unverifiable one (no
    # openssl -> verified None), or a failing token all reject — fail-closed, "claimed" never upgrades to "proven".
    # 1.6.0 — SPEC §6.9: each requirement that is not met is NAMED in `policy.unmet`; `policy_ok` keeps its 1.5.x meaning
    # (the four policy inputs of 1.5.x), `policy.met` is false when anything in `unmet` (also the pinned set and
    # `trust_set_complete`).
    unmet, binding_policy_missing = [], None
    if require_producer and not (producer["present"] and producer.get("ok")):
        unmet.append("require_producer")
    if require_pq and not (producer.get("pq_protected") and producer.get("trusted") is True):
        unmet.append("require_pq")
    if require_anchor and anchors_verified < 1:
        unmet.append("require_anchor")
    if min_anchors is not None and anchors_verified < min_anchors:   # SPEC §3.3: require_anchor alone is min_anchors = 1
        unmet.append("min_anchors")
    if require_bindings:   # 1.9.0 (SPEC §6.9): each (in, commits_to) pair must be in the RECOMPUTED set, which counts only
        held = set()       # when bindings_ok (every artifact verified and the recorded set equal to the recomputation)
        if bindings_ok:
            held = {(b["in"], b["commits_to"]) for b in find_bindings(for_bindings)}
        missing = [list(pr) for pr in require_bindings if tuple(pr) not in held]
        if missing:
            unmet.append("require_binding")
            binding_policy_missing = missing
    policy_ok = not unmet
    if trusted_producer_keys is not None and producer["present"] and producer.get("trusted") is not True:
        unmet.append("trusted_producer_keys")
    tsa_requested = tsa_cert is not None
    states = derive_states(digest_ok=digest_ok, art_results=art_results, binding_set_match=binding_set_match, ts_block=ts,
                           rfc_block=rfc_block, anchor_results=anchor_results, tsa_requested=tsa_requested, producer=producer,
                           pinned=trusted_producer_keys is not None, trust_anchor_given=trust_anchor is not None)
    if trust_set_complete and "key_unresolved" in states["producer_signature"]["reasons"]:   # SPEC §6.9 (krausz §5.4.2)
        unmet.append("trust_set_complete")
    not_run = [x.pop("_not_run") for x in [rfc_block] + anchor_results if "_not_run" in x]
    for r_ in art_results:
        leaf = r_.get("x5c_leaf")
        if leaf:
            leaf.pop("_broken", None)
            if "_not_run" in leaf:
                not_run.append(leaf.pop("_not_run"))
    if rfc is not rfc_block:
        rfc.pop("_not_run", None)

    nb_rep = None
    if "not_before" in ev:   # 1.8.0 — SPEC §12.3: NB1-NB3 after the time anchors (proven_time) and the artifacts
        nb_rep = check_not_before(ev["not_before"], ev, art_results, proven_time)
    receipt = {"digest_ok": digest_ok, "artifacts": art_results,
            "producer_signatures": producer, "pq_protected": producer.get("pq_protected", False),
            "bindings_ok": bindings_ok, **({"bindings_not_recorded": bindings_not_recorded} if bindings_not_recorded else {}),   # 1.9.0 (SPEC §4)
            "rfc3161": rfc,
            "anchors": anchor_results, "anchors_verified": anchors_verified,   # 1.5.0 — SPEC §3.3
            "provenance_classes": classes,
            # r7 FAIL-CLOSED, r10 with ANY: the flag warns that a key in this pack is self-asserted, so ONE reconciled
            # artifact must not clear it for the others — measured: a pack whose mandate was `jwk_header` and whose second
            # artifact chained to the anchor reported `self_asserted_only: false`, i.e. "no self-asserted key here", while
            # the mandate-signing key had never been reconciled at all. A label ("supplied", "jwks_fetched") never clears it.
            "self_asserted_only": (not art_results) or any(r.get("self_asserted", True) for r in art_results),   # final check: zero artifacts is not "no self-asserted key", it is nothing measured
            # r8: what the verifier DID about chains — None when no anchor was supplied (so the flag above is fail-closed true)
            # r9: True only if every chain really validated; None when openssl could not measure it. r11: only artifacts that
            # ATTEMPTED a chain count — before, one `jwk_header` artifact anywhere collapsed the field to None even when every
            # x5c chain present had validated, which is the r10 `all()` defect one field over (invisible to the oracle, since
            # the JS verifier always answers null).
            "chain_verified": _chain_verdict(trust_anchor, art_results),
            # un evidence senza artefatti non prova NULLA: mai 'valid' (falso-verde per l'auditor)
            "policy_ok": policy_ok,
            "valid": bool(art_results and digest_ok and all_ok and bindings_ok
                          and rfc.get("verified") is not False and policy_ok
                          and (nb_rep is None or nb_rep["state"] != "failed")),   # 1.8.0 — SPEC §12.3
            "honest_scope": ev.get("honest_scope"),
            "admission": "admitted", "refusal_class": None,   # 1.6.0 — SPEC §6.9
            "states_vocabulary": STATES_VOCABULARY, "states": states,
            "policy": {"met": not unmet, "unmet": [u for u in POLICY_UNMET if u in unmet],
                       **({"require_binding_missing": binding_policy_missing} if binding_policy_missing else {})},
            # informative, both verifiers (SPEC §6): whether THIS verifier can check ML-DSA-65 at all — without it a
            # producer signature is SKIP, never a pass, and the reader of the receipt should not have to guess why
            "mldsa_backend": bool(_sigsuite.MLDSA_AVAILABLE)}
    if nb_rep is not None:   # 1.8.0 — SPEC §12.3: only when the pack carries the block
        receipt["not_before"] = nb_rep
    if not_run:   # 1.6.0 — SPEC §6.10: a check asked for could not be run here — the COMPLETE receipt travels with the error
        raise Ap2WriteError(not_run[0], receipt=receipt)
    return receipt


# ────────────────────────────────────────────────────────── restriction record (SPEC §11, 1.7.0)
# A profile of this repository, not of AP2: a record that names an open mandate of the same pack by the hash of its
# issuer JWT — in a constraint of its own type, so that an AP2 verifier that does not know the profile fails it (AP2:
# "Any unknown Constraints MUST be treated as failing evaluation") instead of reading a second mandate — and must be no
# broader than it. Closed by construction: a name or a type outside the lists of SPEC §11.4 is
# `not_evaluated` (or, for an added constraint of an unknown type, the AP2 rule "Any unknown Constraints MUST be treated as
# failing evaluation" — accepted and REPORTED), a hidden digest is never assumed absent, and nothing is `verified` that is
# broader than the original or not bound to it.

RESTRICTS_CONSTRAINT = "io.github.robertolocatelli81.restricts"   # SPEC §11.1: a constraint type, in the Mandate Content
RESTRICTS_KEYS = ("issuer_jwt_hash", "type")
RESTRICTION_PROFILE = "io.github.robertolocatelli81.restriction/1"
_FREQ_ORDER = ("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY")   # SPEC §11.4: least to most separated
_OPEN_CONTENT_KEYS = {   # SPEC §11.4: the properties of open_payment_mandate.json / open_checkout_mandate.json at AP2 e1ea56d
    "mandate.payment.open.1": ("vct", "constraints", "cnf", "payee", "payment_amount", "payment_instrument", "pisp",
                               "execution_date", "risk_data", "iat", "exp"),
    "mandate.checkout.open.1": ("vct", "constraints", "cnf", "iat", "exp"),
}


def _is_int(v):
    return type(v) is int   # a JSON integer; never a boolean (bool is an int subclass in Python)


def _is_list_of_obj(v):
    return isinstance(v, list) and all(isinstance(x, dict) for x in v)


_ALLOWED_LIST = ({"allowed": _is_list_of_obj}, {})
_CONSTRAINT_SCHEMAS = {   # type -> (required {key: predicate}, optional {key: predicate}); SPEC §11.4 table
    "payment.amount_range": ({"currency": _is_str, "max": _is_int}, {"min": _is_int}),
    "payment.budget": ({"currency": _is_str, "max": _is_int}, {}),
    "payment.agent_recurrence": ({"frequency": lambda v: isinstance(v, str) and v in _FREQ_ORDER}, {"max_occurrences": _is_int}),
    "payment.allowed_payees": _ALLOWED_LIST,
    "payment.allowed_payment_instruments": _ALLOWED_LIST,
    "payment.allowed_pisps": _ALLOWED_LIST,
    "checkout.allowed_merchants": _ALLOWED_LIST,
    "payment.execution_date": ({}, {"not_before": _is_str, "not_after": _is_str}),
    "payment.reference": ({"conditional_transaction_id": _is_str}, {}),
    "checkout.line_items": ({"items": lambda v: isinstance(v, list) and len(v) > 0 and all(isinstance(x, dict) for x in v)}, {}),
}
_LINE_ITEM_KEYS = ("acceptable_items", "id", "quantity")


def _is_sha256_b64url(v: str) -> bool:
    """SPEC §11.3 step 2: strict base64url (§3.1) of exactly 32 bytes."""
    try:
        return len(_b64url_decode(v)) == 32
    except Ap2EvidenceError:
        return False


def issuer_jwt_hash(compact: str) -> str:
    """SPEC §11.1: BASE64URL(SHA-256(ASCII of the Issuer-signed JWT)) — the `issuer_jwt_hash` of the Delegate SD-JWT draft
    and of the AP2 SDK's compute_issuer_jwt_hash; the disclosures and the KB-JWT are not part of it."""
    return _sha256_b64url(compact.split("~", 1)[0].encode("ascii"))


def _digest_census(parsed: Dict) -> int:
    """SPEC §11.3 step 5: the digests of the issuer payload with no disclosure — the `_sd` entries and the {"...": d}
    placeholders, in the payload and inside every disclosed value — counted by the §6 step 2 resolver itself (one census
    for the two sections). Raises Ap2EvidenceError on what §6 step 2 refuses, a digest encountered more than once among it
    (1.7.0; up to the 2026-10-28 draft this function kept a census of its own, because the 1.6.0 resolver did not)."""
    c: Dict = {}
    resolve_disclosures(parsed["payload"], parsed["disclosures"], census=c)
    return len(set(c["encountered"]) - c["matched"])


def _mandate_form(resolved: Dict) -> Tuple[Optional[str], Optional[Dict]]:
    """SPEC §11.1 (the AP2 SDK's from_sd_jwt): `delegate_payload` holding exactly one object, else the payload itself.
    (None, None) when `delegate_payload` is there but not a list of one object."""
    if "delegate_payload" not in resolved:
        return "payload", resolved
    dp = resolved["delegate_payload"]
    if isinstance(dp, list) and len(dp) == 1 and isinstance(dp[0], dict):
        return "delegate_payload", dp[0]
    return None, None


def _is_ref(c) -> bool:
    """SPEC §11.1: a constraint of this profile's type (well-formed or not: §11.3 step 2 judges its form)."""
    return isinstance(c, dict) and c.get("type") == RESTRICTS_CONSTRAINT


def _record_refs(resolved) -> Tuple[bool, List[Tuple[str, Dict]]]:
    """SPEC §11.2: (the name at the top level of the payload, [(path, constraint) of this profile's type]). The Mandate
    Content of §11.1, or — when `delegate_payload` is a list that is not exactly one object — each of its object elements."""
    if not isinstance(resolved, dict):
        return False, []
    form, content = _mandate_form(resolved)
    if form == "delegate_payload":
        contents = [("delegate_payload[0].", content)]
    elif form == "payload":
        contents = [("", content)]
    else:
        dp = resolved.get("delegate_payload")
        contents = [(f"delegate_payload[{i}].", x) for i, x in enumerate(dp) if isinstance(x, dict)] if isinstance(dp, list) else []
    refs = []
    for base, c in contents:
        cons = c.get("constraints")
        if isinstance(cons, list):
            refs += [(f"{base}constraints[{j}]", x) for j, x in enumerate(cons) if _is_ref(x)]
    return RESTRICTS_CONSTRAINT in resolved, refs


def _dp_disclosed(parsed: Dict) -> bool:
    """SPEC §11.1: `delegate_payload` is a property disclosure of the payload — a digest of the payload's own `_sd`, in any
    position, whose disclosure is named so (nothing nested: a disclosure of that name inside the Mandate Content is a name
    of the content). The holder could then leave the whole Mandate Content out — measured with the SDK at e1ea56d: with
    terms signed at the top level beside it, the token minus that disclosure verifies in the typed path as an ordinary
    mandate with the top-level terms. For R this is `restricts_disclosable` (§11.3 step 2); for O, which then has two
    readings, `original_disclosable` (§11.3 step 6)."""
    payload = parsed.get("payload") if isinstance(parsed, dict) else None
    sd = payload.get("_sd") if isinstance(payload, dict) else None
    if not isinstance(sd, list):
        return False
    dmap = {_disclosure_digest(d): _loads_segment(_b64url_decode(d), "disclosure") for d in parsed["disclosures"]}
    return any(isinstance(dg, str) and isinstance(dmap.get(dg), list) and len(dmap[dg]) == 3 and dmap[dg][1] == "delegate_payload"
               for dg in sd)


def _ref_is_plain(parsed: Dict, ref: Dict) -> bool:
    """SPEC §11.1/§11.3 step 2: the reference is an element, as signed, of the `constraints` list of the Mandate Content —
    not an array-element disclosure (the holder could leave it out) and with no disclosure inside it. The raw Mandate
    Content is found the way the resolver finds it: `delegate_payload`, a PLAIN key of the payload (as a property
    disclosure the holder could leave the whole content out — measured with the SDK at e1ea56d: with a mandate signed at
    the top level beside it, what is left verifies as an ordinary typed mandate), holding `delegate_payload[0]` (an object
    or an array-element disclosure), else the payload; `constraints` a plain key or a property disclosure (a mandate
    without `constraints` is no typed mandate: the field is required). Anything else is not plain."""
    try:
        dmap = {_disclosure_digest(d): _loads_segment(_b64url_decode(d), "disclosure") for d in parsed["disclosures"]}

        def prop(obj, name):
            if name in obj:
                return obj[name]
            for dg in obj.get("_sd", []) if isinstance(obj.get("_sd"), list) else []:
                dd = dmap.get(dg)
                if isinstance(dd, list) and len(dd) == 3 and dd[1] == name:
                    return dd[2]
            return None

        def unwrap(el):   # an element of delegate_payload: the object, or the value of its array-element disclosure
            if isinstance(el, dict) and set(el) == {"..."}:
                dd = dmap.get(el["..."])
                return dd[1] if isinstance(dd, list) and len(dd) == 2 else None
            return el

        payload = parsed["payload"]
        if _dp_disclosed(parsed):
            return False   # `delegate_payload` itself a property disclosure: the holder could leave the whole content out
        dp = payload.get("delegate_payload")
        contents = [payload] if dp is None else [unwrap(el) for el in dp] if isinstance(dp, list) else []
        want = _canon(ref)
        for content in contents:
            cons = prop(content, "constraints") if isinstance(content, dict) else None
            if isinstance(cons, list) and any(isinstance(x, dict) and _canon(x) == want for x in cons):
                return True
        return False
    except Exception:  # noqa: BLE001 — a structure the resolver accepted but this reading cannot follow: not shown plain
        return False


def _constraint_shape(c) -> Tuple[str, Optional[str]]:
    """SPEC §11.4: ("ok" | "unknown_type" | "malformed" | "unknown_name", what). A wrong type or a missing required key is
    checked BEFORE an unknown key, so a record with both is contradicted, not merely not_evaluated."""
    if not isinstance(c, dict) or not isinstance(c.get("type"), str):
        return "malformed", "type"
    schema = _CONSTRAINT_SCHEMAS.get(c["type"])
    if schema is None:
        return "unknown_type", c["type"]
    req, opt = schema
    for k, pred in req.items():
        if k not in c or not pred(c[k]):
            return "malformed", k
    for k, pred in opt.items():
        if k in c and not pred(c[k]):
            return "malformed", k
    if c["type"] == "checkout.line_items":
        for i, it in enumerate(c["items"]):
            if not (_is_str(it.get("id")) and _is_list_of_obj(it.get("acceptable_items")) and _is_int(it.get("quantity"))
                    and it["quantity"] > 0):
                return "malformed", f"items[{i}]"
    unknown = sorted(k for k in c if k != "type" and k not in req and k not in opt)
    if unknown:
        return "unknown_name", unknown[0]
    if c["type"] == "checkout.line_items":
        for i, it in enumerate(c["items"]):
            extra = sorted(k for k in it if k not in _LINE_ITEM_KEYS)
            if extra:
                return "unknown_name", f"items[{i}].{extra[0]}"
    return "ok", None


def _date_form(s: str) -> Optional[str]:
    """SPEC §11.4 execution_date: the two comparable forms, ASCII digits, a real calendar date (and time); else None."""
    for form, rx, fmt in (("date", r"[0-9]{4}-[0-9]{2}-[0-9]{2}", "%Y-%m-%d"),
                          ("datetime", r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", "%Y-%m-%dT%H:%M:%SZ")):
        if re.fullmatch(rx, s):
            try:
                datetime.strptime(s, fmt)
            except ValueError:
                return None
            return form
    return None


def _subset(narrow: List, wide: List) -> bool:
    """Every element of `narrow` canonically equal (§3) to an element of `wide`."""
    w = {_canon(x) for x in wide}
    return all(_canon(x) in w for x in narrow)


def _within(t: str, o: Dict, r: Dict) -> Optional[bool]:
    """SPEC §11.4 table: is the well-formed constraint `r` (in R) within the well-formed constraint `o` (in O), both of
    type `t`? None = not comparable here (execution_date forms)."""
    if t == "payment.amount_range":
        if r["currency"] != o["currency"] or r["max"] > o["max"]:
            return False
        return not ("min" in o and ("min" not in r or r["min"] < o["min"]))
    if t == "payment.budget":
        return r["currency"] == o["currency"] and r["max"] <= o["max"]
    if t == "payment.agent_recurrence":
        if _FREQ_ORDER.index(r["frequency"]) < _FREQ_ORDER.index(o["frequency"]):
            return False
        return not ("max_occurrences" in o and ("max_occurrences" not in r or r["max_occurrences"] > o["max_occurrences"]))
    if t in ("payment.allowed_payees", "payment.allowed_payment_instruments", "payment.allowed_pisps", "checkout.allowed_merchants"):
        return _subset(r["allowed"], o["allowed"])
    if t == "payment.reference":
        return r["conditional_transaction_id"] == o["conditional_transaction_id"]
    if t == "payment.execution_date":
        out: Optional[bool] = True
        for bound, later_is_narrower in (("not_before", True), ("not_after", False)):
            if bound not in o:
                continue
            if bound not in r:
                return False
            fo, fr = _date_form(o[bound]), _date_form(r[bound])
            if fo is None or fo != fr:
                out = None
                continue
            if (r[bound] < o[bound]) if later_is_narrower else (r[bound] > o[bound]):
                return False
        return out
    if t == "checkout.line_items":
        if len(r["items"]) != len(o["items"]):
            return False
        for ri, oi in zip(r["items"], o["items"]):
            if ri["id"] != oi["id"] or ri["quantity"] != oi["quantity"]:
                return False
            if not ri["acceptable_items"] and oi["acceptable_items"]:   # an empty list is a wildcard in the AP2 SDK
                return False
            if not _subset(ri["acceptable_items"], oi["acceptable_items"]):
                return False
        return True
    raise AssertionError(t)   # unreachable: _within is called only on a type of _CONSTRAINT_SCHEMAS


def evaluate_restriction(original: Dict, restriction: Dict) -> Dict:
    """SPEC §11.3 steps 4–6 and §11.4. `original` / `restriction`: {"parsed": parse_sd_jwt(...), "resolved": the resolved
    claims, "jwk": the snapshotted key.jwk} of two artifacts that verified in a valid pack. Returns
    {"state", "reasons": [{"state", "reason", "at"}], "reported": [{"reason", "at"}]}."""
    reasons: List[Dict] = []
    reported: List[Dict] = []

    def no(state, reason, at):
        reasons.append({"state": state, "reason": reason, "at": at})

    def done():
        states = {x["state"] for x in reasons}
        state = "contradicted" if "contradicted" in states else "not_evaluated" if states else "verified"
        return {"state": state, "reasons": reasons, "reported": reported}

    ko, kr = original["jwk"], restriction["jwk"]   # step 4: the same issuer key
    if not (isinstance(ko, dict) and isinstance(kr, dict)) or any(ko.get(k) != kr.get(k) for k in ("kty", "crv", "x", "y")):
        no("contradicted", "issuer_key_differs", "restriction")
    for side, art in (("original", original), ("restriction", restriction)):   # step 5: nothing hidden
        try:
            hidden = _digest_census(art["parsed"])
        except Ap2EvidenceError:   # what §6 step 2 refuses (a repeated digest among it): reachable only by a direct call
            no("not_evaluated" if side == "original" else "contradicted", "original_malformed" if side == "original" else "malformed", side)
            continue
        if hidden:
            no("not_evaluated", "undisclosed_digests", side)
    if any(x["reason"] in ("undisclosed_digests", "malformed", "original_malformed") for x in reasons):
        return done()
    if _dp_disclosed(original["parsed"]):   # step 6, first: O with `delegate_payload` a property disclosure has two readings (§11.1)
        no("not_evaluated", "original_disclosable", "original")
        return done()
    fo, co = _mandate_form(original["resolved"])   # step 6: the same, readable form
    fr, cr = _mandate_form(restriction["resolved"])
    if fo is None:
        no("not_evaluated", "form_unsupported", "original")
    if fr is None:
        no("not_evaluated", "form_unsupported", "restriction")
    if fo is None or fr is None:
        return done()
    if fo != fr:
        no("not_evaluated", "form_differs", "restriction")
        return done()

    def time_rule(o, r, k, at, later_is_narrower):
        if k in o and not _is_int(o[k]):
            no("not_evaluated", "original_malformed", "original." + at)
        elif k in r and not _is_int(r[k]):
            no("contradicted", "malformed", "restriction." + at)
        elif k in o and (k not in r or (r[k] < o[k] if later_is_narrower else r[k] > o[k])):
            no("contradicted", "time_widened", "restriction." + at)

    def equal_rule(o, r, k, at, reason):
        if (k in o) != (k in r) or (k in o and _canon(o[k]) != _canon(r[k])):
            no("contradicted", reason, "restriction." + at)

    def unknown_rule(o, r, k, at):
        if not (k in o and k in r and _canon(o[k]) == _canon(r[k])):
            no("not_evaluated", "unknown_name", ("original." if k in o else "restriction.") + at)

    top_rules = {"exp": lambda o, r, k, at: time_rule(o, r, k, at, False),
                 "nbf": lambda o, r, k, at: time_rule(o, r, k, at, True),
                 "cnf": lambda o, r, k, at: equal_rule(o, r, k, at, "cnf_differs")}
    for k in ("iss", "sub", "aud", "vct"):
        top_rules[k] = lambda o, r, k, at: equal_rule(o, r, k, at, "claim_changed")

    def typed_only(o, r, k, at, pred):   # iat, jti: not compared (a new token has its own), but typed (RFC 7519 §4.1.6/§4.1.7)
        if k in o and not pred(o[k]):
            no("not_evaluated", "original_malformed", "original." + at)
        if k in r and not pred(r[k]):
            no("contradicted", "malformed", "restriction." + at)

    top_rules["iat"] = lambda o, r, k, at: typed_only(o, r, k, at, _is_int)
    top_rules["jti"] = lambda o, r, k, at: typed_only(o, r, k, at, _is_str)

    def compare_keys(o, r, rules, prefix):
        for k in sorted(set(o) | set(r)):
            (rules.get(k) or unknown_rule)(o, r, k, prefix + k)

    if fo == "delegate_payload":   # the top level beside delegate_payload; the content is compared below
        rules = dict(top_rules, delegate_payload=lambda o, r, k, at: None)
        compare_keys(original["resolved"], restriction["resolved"], rules, "")
        base = "delegate_payload[0]."
    else:
        base = ""

    vo, vr = co.get("vct"), cr.get("vct")
    if not isinstance(vo, str) or vo not in _OPEN_CONTENT_KEYS:   # SPEC §11.4: another vct is matched only when equal
        if _canon(co) != _canon(cr):
            no("not_evaluated", "vct_not_supported", "original." + base + "vct")
        return done()
    if vr != vo:
        no("contradicted", "claim_changed", "restriction." + base + "vct")
        return done()
    preset = lambda o, r, k, at: (no("contradicted", "preset_changed", "restriction." + at)   # noqa: E731
                                  if k in o and (k not in r or _canon(o[k]) != _canon(r[k])) else None)
    content_rules = {"vct": lambda o, r, k, at: None, "constraints": lambda o, r, k, at: None,
                     "cnf": top_rules["cnf"], "exp": top_rules["exp"], "iat": top_rules["iat"]}
    for k in _OPEN_CONTENT_KEYS[vo]:
        content_rules.setdefault(k, preset)
    if fo == "payload":   # the payload IS the content: the registered top-level names keep their rules
        for k, f in top_rules.items():
            content_rules.setdefault(k, f)
    compare_keys(co, cr, content_rules, base)

    oc, rc = co.get("constraints", []), cr.get("constraints", [])
    if not isinstance(oc, list):
        no("not_evaluated", "original_malformed", "original." + base + "constraints")
        return done()
    if not isinstance(rc, list):
        no("contradicted", "malformed", "restriction." + base + "constraints")
        return done()
    rcanon = {_canon(x) for x in rc}
    ocanon = {_canon(x) for x in oc}
    shapes = [_constraint_shape(x) for x in rc]
    for i, c in enumerate(oc):   # every requirement of O is met by one of R
        at = f"{base}constraints[{i}]"
        if _is_ref(c):   # SPEC §11.4: O's own reference to a third mandate is the chain rule's (§11.3 step 7)
            continue
        if _canon(c) in rcanon:
            continue
        shape, what = _constraint_shape(c)
        if shape == "unknown_type":
            no("not_evaluated", "unknown_name", "original." + at)
            continue
        if shape != "ok":
            no("not_evaluated", "original_malformed", f"original.{at}" + (f".{what}" if what else ""))
            continue
        same = [(x, s) for x, s in zip(rc, shapes) if isinstance(x, dict) and x.get("type") == c["type"]]
        if not same:
            no("contradicted", "constraint_removed", "original." + at)
            continue
        verdicts = [_within(c["type"], c, x) for x, (s, _) in same if s == "ok"]
        if True in verdicts:
            continue
        if any(s == "unknown_name" for _, (s, _) in same):
            continue   # that constraint of R is not_evaluated below: it may be the one within c
        if None in verdicts:
            no("not_evaluated", "date_form", "original." + at)
        else:
            no("contradicted", "constraint_widened", "original." + at)
    o_types = {c.get("type") for c in oc if isinstance(c, dict)}
    for j, (x, (shape, what)) in enumerate(zip(rc, shapes)):   # every constraint R adds
        at = f"restriction.{base}constraints[{j}]"
        if _is_ref(x) or _canon(x) in ocanon:   # R's reference is the binding (§11.3), not a term
            continue
        if shape == "unknown_type":
            reported.append({"reason": "unknown_constraint_added", "at": at})
        elif shape == "malformed":
            no("contradicted", "malformed", at + (f".{what}" if what else ""))
        elif shape == "unknown_name":
            no("not_evaluated", "unknown_name", f"{at}.{what}")
        elif x["type"] == "payment.agent_recurrence" and "payment.agent_recurrence" not in o_types:
            no("not_evaluated", "recurrence_added", at)
    return done()


def _existed_by(receipt: Dict) -> Optional[str]:
    """SPEC §11.2: the earliest gen_time among the anchors whose binding AND TSA signature verified (None without one)."""
    cands = [x for x in [receipt.get("rfc3161") or {}] + list(receipt.get("anchors") or [])
             if x.get("verified") is True and x.get("tsa_verified") is True and isinstance(x.get("gen_time"), str)]
    return min((x["gen_time"] for x in cands), key=_gt_key, default=None)


def verify_restrictions(path: str, tsa_cert: Optional[str] = None, accept_integral_floats: bool = False) -> Dict:
    """See `_verify_restrictions`. 1.7.2 (SPEC §3.1): `accept_integral_floats` is passed to the pack's verification and
    applies to the tokens the evaluation reads (§11); the receipt says so when it is set."""
    if type(accept_integral_floats) is not bool:
        raise ValueError(f"accept_integral_floats must be a boolean (got {accept_integral_floats!r})")
    tok = _INTEGRAL_READ.set([] if accept_integral_floats else None)
    try:
        r = _verify_restrictions(path, tsa_cert=tsa_cert)
    except Ap2WriteError as e:
        if accept_integral_floats and isinstance(getattr(e, "receipt", None), dict):
            e.receipt["accept_integral_floats"] = True
        raise
    finally:
        _INTEGRAL_READ.reset(tok)
    if accept_integral_floats:
        r["accept_integral_floats"] = True
    return r


def _verify_restrictions(path: str, tsa_cert: Optional[str] = None) -> Dict:
    """SPEC §11.2: verify the pack (§6, default policy, `tsa_cert` passed through), then evaluate every restriction record
    in it. The pack is read ONCE: the verification and the evaluation run on the same snapshot (a private copy of the
    parsed file), so a file swapped between two reads cannot give one verdict about two contents. Raises Ap2WriteError when
    the copy cannot be written (no receipt), or — like verify_evidence — when a check asked for could not be run here: its
    `receipt` is then the complete restriction receipt."""
    import shutil
    import tempfile
    not_run, ev = None, None
    try:
        ev = read_evidence_file(path)
    except Ap2EvidenceError as e:   # the refusal verify_evidence gives for the same file (SPEC §3.1), without a second read
        receipt = _refusal_receipt(str(e), "malformed")
    else:
        try:
            tmp = tempfile.mkdtemp(prefix="ap2-restriction-")
        except OSError as e:
            raise Ap2WriteError(f"cannot write the private copy of the pack: {type(e).__name__}: "
                                f"{os.strerror(e.errno) if isinstance(e.errno, int) else e}") from e
        try:
            copy = os.path.join(tmp, "pack.json")
            try:
                with open(copy, "w", encoding="utf-8") as fh:
                    # ensure_ascii=False + compact separators: never longer than the file read (an escaped emoji would be),
                    # so a pack under the size bound stays under it; the parse is strict, so the copy means what the file meant
                    fh.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":")))
            except OSError as e:
                raise Ap2WriteError(f"cannot write the private copy of the pack: {type(e).__name__}: "
                                    f"{os.strerror(e.errno) if isinstance(e.errno, int) else e}") from e
            try:
                receipt = verify_evidence(copy, tsa_cert=tsa_cert, accept_integral_floats=_INTEGRAL_READ.get() is not None)
            except Ap2WriteError as e:
                if e.receipt is None:
                    raise
                receipt, not_run = e.receipt, e
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    out = {"restriction_profile": RESTRICTION_PROFILE, "constraint_type": RESTRICTS_CONSTRAINT,
           "admission": receipt.get("admission"), "refusal_class": receipt.get("refusal_class"), "valid": receipt.get("valid"),
           "time_anchor": (receipt.get("states") or {}).get("time_anchor"), "existed_by": _existed_by(receipt),
           "restrictions": [], "met": False}
    if receipt.get("admission") == "admitted":
        arts = []
        for a in ev["artifacts"]:   # admitted: a list of objects with unique non-empty string names (§6 step 1)
            try:
                parsed = parse_sd_jwt(a["sd_jwt_compact"])
                resolved = resolve_disclosures(parsed["payload"], parsed["disclosures"])
                arts.append({"name": a["name"], "parsed": parsed, "resolved": resolved, "jwk": a["key"]["jwk"],
                             "hash": issuer_jwt_hash(parsed["compact"])})
            except Exception:  # noqa: BLE001 — an artifact that does not parse is an error of the pack, which is then not valid
                arts.append({"name": a.get("name"), "resolved": None})
        for r in arts:
            misplaced, refs = _record_refs(r["resolved"])
            if not misplaced and not refs:
                continue
            val = refs[0][1].get("issuer_jwt_hash") if len(refs) == 1 else None
            entry = {"in": r["name"], "restricts": val if isinstance(val, str) else None, "original": None,
                     "same_issuer_jwt": [], "state": "not_evaluated", "reasons": [], "reported": []}
            out["restrictions"].append(entry)
            if receipt.get("valid") is not True:   # step 1
                entry["reasons"] = [{"state": "not_evaluated", "reason": "pack_not_valid", "at": "restriction"}]
                continue
            bad = None   # step 2, in the order of SPEC §11.3
            if misplaced:
                bad = ("restricts_misplaced", "restriction." + RESTRICTS_CONSTRAINT)
            elif len(refs) != 1:
                bad = ("restricts_malformed", "restriction." + refs[1][0])
            elif (tuple(sorted(refs[0][1])) != RESTRICTS_KEYS or not isinstance(val, str) or not _is_sha256_b64url(val)):
                bad = ("restricts_malformed", "restriction." + refs[0][0])
            elif not _ref_is_plain(r["parsed"], refs[0][1]):
                bad = ("restricts_disclosable", "restriction." + refs[0][0])
            if bad:
                entry.update(state="contradicted", reasons=[{"state": "contradicted", "reason": bad[0], "at": bad[1]}])
                continue
            matches = [o for o in arts if o is not r and o.get("hash") == val]   # step 3
            if not matches:
                entry["reasons"] = [{"state": "not_evaluated", "reason": "original_not_in_pack", "at": "restriction"}]
                continue
            matches.sort(key=lambda o: _digest_census(o["parsed"]))   # stable: the fewest hidden digests, then pack order
            o = matches[0]
            entry["original"] = o["name"]
            entry["same_issuer_jwt"] = sorted(m["name"] for m in matches[1:])
            entry.update(evaluate_restriction(o, r))
        by_name = {e["in"]: e for e in out["restrictions"]}   # step 7: a chain is as strong as its weakest link
        changed = True
        while changed:
            changed = False
            for e in out["restrictions"]:
                up = by_name.get(e["original"])
                if e["state"] == "verified" and up is not None and up["state"] != "verified":
                    e["reasons"].append({"state": "not_evaluated", "reason": "original_not_verified", "at": "original"})
                    e["state"] = "not_evaluated"
                    changed = True
        out["met"] = bool(out["restrictions"]) and all(e["state"] == "verified" for e in out["restrictions"])
    if not_run is not None:
        raise Ap2WriteError(str(not_run), receipt=out)
    return out


# ────────────────────────────────────────────────────────── CLI

EX_IOERR = 74   # 1.5.2 — sysexits.h: the outcome was computed but its receipt (or the output file) was not written whole


def _to_devnull(stream) -> None:
    """The bytes still buffered in a stream whose write failed must not fail again at interpreter exit: that exit is 120
    with an "Exception ignored" message, not ours. fd -> /dev/null, so the final flush succeeds and discards them."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, stream.fileno())
        os.close(null)
    except (OSError, ValueError, AttributeError):
        pass


def _text_layer_bytes(stream, buf, text: str) -> bytes:
    """The bytes Python's own text layer over `buf` writes for `text` as the first thing written: its encoding and error
    handler, "\\n" as os.linesep where the platform translates it (not Linux; not measured here), and a byte order mark
    only where that layer puts one: utf-16 / utf-32 only on a stream seekable at offset 0 (a file), utf-8-sig on a pipe
    too, none on a seekable stream past offset 0 (measured on Python 3.9, 3.11 and 3.13, 13/10/2026)."""
    import codecs
    if os.linesep != "\n":
        text = text.replace("\n", os.linesep)
    encoding = stream.encoding or "utf-8"
    enc = codecs.getincrementalencoder(encoding)(stream.errors or "strict")
    try:
        seekable = buf.seekable()
        at_start = seekable and buf.tell() == 0
    except (OSError, ValueError):
        seekable = at_start = False
    if (seekable and not at_start) or (not seekable and codecs.lookup(encoding).name in ("utf-16", "utf-32")):
        enc.setstate(0)   # no byte order mark
    return enc.encode(text, final=True)


def _wait_writable(buf) -> None:
    """The stream is non-blocking and full: wait until it can take more, as a blocking write would (the reader is slow,
    not gone; one that goes away makes the next write EPIPE). `select` sleeps in the kernel and Python retries it after a
    signal (PEP 475). The descriptor is asked for only here: a byte stream with no descriptor (an io.BytesIO under a
    TextIOWrapper, as pytest's capsys) never blocks. POSIX only: on Windows `select` waits on sockets only, so a full
    non-blocking pipe there is reported as 74 (not measured)."""
    import select
    try:
        select.select([], [buf.fileno()], [])
    except (OSError, ValueError) as e:   # no descriptor, or one select cannot wait on
        raise OSError(f"non-blocking and cannot be waited for: {e}")


def _write_all(stream, text: str) -> None:
    """Write the whole text to `stream` (stdout or stderr) and flush it; raise when it did not all get there. The bytes go
    to `stream.buffer` in a loop that checks the count: with -u or PYTHONUNBUFFERED that is a raw FileIO whose write() can
    take part of the data (`ulimit -f`, a disk nearly full) and return the count without raising, or return None (a full
    non-blocking pipe), and the text layer above dropped the rest in silence (measured 13/10/2026 on 1.5.2 before this
    change: exit 0 with 24 bytes of the receipt on a file under `ulimit -f 1`). A non-blocking stream that is full is
    waited for, never given up on (before: 74 with 65 536 bytes in the pipe, or 0 with them under -u). A text stream
    with no bytes below it (io.StringIO) gets the text itself."""
    buf = getattr(stream, "buffer", None)
    while True:   # whatever the text layer still holds goes first: text a caller in process wrote and left unflushed, on a
        try:      # full non-blocking stream, is waited for like the receipt (before: exit 74 with nothing written)
            stream.flush()
            break
        except BlockingIOError:
            if buf is None:
                raise
            _wait_writable(buf)
    if buf is None:
        stream.write(text)
        stream.flush()
        return
    data = memoryview(_text_layer_bytes(stream, buf, text))
    while data:
        try:
            n = buf.write(data)
            waited = False
        except BlockingIOError as e:   # buffered stream on a full non-blocking pipe: part of it taken
            n, waited = e.characters_written, True
        if n is None:   # raw stream on a full non-blocking pipe: nothing taken
            n, waited = 0, True
        if n < 0 or n > len(data) or (n == 0 and not waited):
            raise OSError(f"short write: {len(data)} bytes not written")
        data = data[n:]
        if data and waited:
            _wait_writable(buf)
    while True:   # flushed HERE, before the exit code is chosen, not by the interpreter at exit
        try:
            buf.flush()
            return
        except BlockingIOError:
            _wait_writable(buf)


def _emit(text: str) -> Optional[str]:
    """Write the receipt to stdout whole and flushed, before the exit code is chosen. Returns None when every byte was
    handed to the OS, else the reason. Before 1.5.2 the receipt went through print(): on /dev/full or a closed pipe a
    receipt that fit the stream buffer failed at the interpreter's final flush (exit 120, "Exception ignored"), a larger
    one failed inside print() (a traceback, exit 1, also for a valid pack: 84 620 bytes measured), and with stdout closed
    (`>&-`, sys.stdout is None) print() did nothing and the exit was the verdict's 0/1 (measured 2026-10-12 on 1.5.1)."""
    out = sys.stdout
    if out is None:
        return "stdout is closed"
    try:
        _write_all(out, text + "\n")
        return None
    except (OSError, ValueError) as e:   # ENOSPC, EPIPE, EBADF, EFBIG; ValueError: write to a closed file object
        _to_devnull(out)
        return f"{type(e).__name__}: {e}"


def _say(text: str) -> bool:
    """Write `text` to stderr without ever raising, through the same writer as the receipt (a full non-blocking stderr is
    waited for); True when it was written. A stderr that fails is pointed at the null device, so the interpreter's last
    flush cannot fail again and turn the exit code into 120."""
    err = sys.stderr
    if err is None:
        return False
    try:
        _write_all(err, text)
        return True
    except (OSError, ValueError):
        _to_devnull(err)
        return False


def _not_written(reason: str) -> int:
    """One line on stderr, if stderr can take it; the exit is EX_IOERR either way."""
    _say(f"receipt not written: {reason}\n")
    return EX_IOERR


def _refused(msg: str) -> int:
    """A refusal of `build` / `stamp`: one `{"error": ...}` line on stderr, exit 1; never on stdout. When that line cannot
    be written (stderr on /dev/full, or closed) the exit is EX_IOERR, as for a lost receipt (1.5.2 review: before, stderr
    full gave the interpreter's 120 and stderr closed sent the refusal to stdout)."""
    if _say(json.dumps({"error": msg}) + "\n"):
        return 1   # a closed stderr (_ClosedStderr) turns this into EX_IOERR in main()
    return EX_IOERR


class _ClosedStderr:
    """sys.stderr while fd 2 is closed (sys.stderr is None): what would have gone there is counted, never sent to stdout
    (argparse prints its usage to stdout when sys.stderr is None)."""
    lost = False

    def write(self, s):
        if s:
            self.lost = True
        return len(s)

    def flush(self):
        pass


class _Parser(argparse.ArgumentParser):
    """argparse up to 3.12 lets the OSError of a usage message written to a full stderr escape (a traceback, then 120);
    3.13 swallows it. Here the failed write is recorded and the exit becomes EX_IOERR in every version."""
    stderr_lost = False

    def _print_message(self, message, file=None):
        if not message:
            return
        file = sys.stderr if file is None else file
        if file is sys.stderr:
            if not _say(message):
                _Parser.stderr_lost = True
            return
        try:
            file.write(message)
        except (OSError, ValueError):
            _Parser.stderr_lost = True
            _to_devnull(file)


def _stderr_settled(rc: int) -> int:
    """The exit code once stderr is flushed: EX_IOERR when a message meant for stderr (usage, refusal, the "receipt not
    written" line) did not get there, so a full or closed stderr never gives the interpreter's 120 or a traceback."""
    err = sys.stderr
    if getattr(err, "lost", False) or _Parser.stderr_lost:
        return EX_IOERR
    try:
        if err is not None:
            err.flush()
        return rc
    except (OSError, ValueError):
        _to_devnull(err)
        return EX_IOERR


def main(argv: Optional[List[str]] = None) -> int:
    if sys.stderr is None:
        sys.stderr = _ClosedStderr()
    _Parser.stderr_lost = False
    try:
        rc = _main(argv)
    except SystemExit as e:   # argparse usage errors (2)
        if not isinstance(e.code, int):
            raise
        raise SystemExit(_stderr_settled(e.code)) from None
    return _stderr_settled(rc)


def _main(argv: Optional[List[str]] = None) -> int:
    p = _Parser(prog="ap2-evidence", allow_abbrev=False, add_help=False,   # 1.9.0: the installed command's name
                                description="Self-contained, offline-verifiable dispute "
                                            "evidence for agentic-payment SD-JWT mandates")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build", allow_abbrev=False, add_help=False)
    b.add_argument("out")
    b.add_argument("artifacts", nargs="+", metavar="name=path",
                   help="e.g. checkout=checkout.sdjwt payment=payment.sdjwt")
    b.add_argument("--key", action="append", default=[], metavar="name=jwk.json",
                   help="supplied verification JWK for an artifact")
    b.add_argument("--jwks-url", action="append", default=[], metavar="name=https://...",
                   help="fetch the key from a JWKS at build time (TLS witness)")
    b.add_argument("--tsa", action="append", default=[], help="RFC 3161 TSA URL (optional third-party time anchor); may repeat: the first goes to rfc3161_timestamp, the others to anchors (SPEC §3.3)")
    b.add_argument("--subject", default="agentic-payment mandate evidence")
    b.add_argument("--accept-integral-floats", action="store_true", help="1.7.2 (SPEC §3.1): read a number of a token written with a fraction or an exponent whose value is an integer within +/-(2^53-1) (10.0, as the AP2 SDK writes a budget) as that integer, and say so in the result; without it such a token is refused")
    st = sub.add_parser("stamp", allow_abbrev=False, add_help=False)   # 1.5.0 — SPEC §3.3: add an anchor to an existing pack
    st.add_argument("evidence")
    st.add_argument("--tsa", required=True, action="append", help="RFC 3161 TSA URL: append its token to `anchors` (exactly one per run)")
    v = sub.add_parser("verify", allow_abbrev=False, add_help=False)
    v.add_argument("evidence")
    v.add_argument("--trusted-producer-key", action="append", default=None, metavar="ALG=B64",
                   help="pin a producer public key as <sig_alg>=<base64> (e.g. ed25519=…, ml-dsa-65=…); may repeat. With any pin, an unpinned producer is not authentic")
    v.add_argument("--require-producer", action="store_true", help="policy: a valid producer signature is required")
    v.add_argument("--require-pq", action="store_true", help="policy: a valid, PINNED post-quantum producer signature is required")
    v.add_argument("--trust-set-complete", action="store_true", help="policy (1.6.0): the pinned producer keys are the COMPLETE trust set — a producer key outside it is then also a policy failure (policy.unmet trust_set_complete); never turns a key_unresolved into signature_invalid")
    v.add_argument("--require-anchor", action="store_true", help="policy: the RFC 3161 anchor must be present and BOUND to this pack (status granted, messageImprint = digest); with --tsa-cert also TSA-verified")
    v.add_argument("--trust-anchor", help="PEM trust anchor: validate the artifact x5c chain with openssl verify. Without it every key is self-asserted (offline, a certificate proves only that the signer wrote it) — the JS verifier cannot validate chains and reports chain_verified null (declared)")
    v.add_argument("--min-anchors", help="policy: at least N distinct anchors must verify (SPEC §3.3; --require-anchor alone is 1)")
    v.add_argument("--require-binding", action="append", default=None, metavar="IN->TO",
                   help="policy (1.9.0, SPEC §6.9): artifact IN must commit to artifact TO by a recomputed binding (§4); may repeat. "
                        "Unmet: policy.unmet require_binding, not valid. Default: none (the format cannot know which artifact a relying party expects bound)")
    v.add_argument("--tsa-cert", help="PEM certificate (or chain) of the TSA: verify the token's signature and chain with openssl ts -verify (without it, the TSA is NOT verified — declared)")
    v.add_argument("--accept-integral-floats", action="store_true", help="1.7.2 (SPEC §3.1): read a number of a token written with a fraction or an exponent whose value is an integer within +/-(2^53-1) (10.0, as the AP2 SDK writes a budget) as that integer, and say so in the result; without it such a token is refused")
    rs = sub.add_parser("restriction", allow_abbrev=False, add_help=False)   # SPEC §11 (1.7.0)
    rs.add_argument("evidence")
    rs.add_argument("--tsa-cert", help="PEM certificate (or chain) of the TSA, as for verify: without it `existed_by` is null")
    rs.add_argument("--accept-integral-floats", action="store_true", help="1.7.2 (SPEC §3.1): read a number of a token written with a fraction or an exponent whose value is an integer within +/-(2^53-1) (10.0, as the AP2 SDK writes a budget) as that integer, and say so in the result; without it such a token is refused")
    raw = list(sys.argv[1:] if argv is None else argv)
    # 1.9.0: `ap2-evidence -h` / `--help` ALONE prints the commands and their options (stdout, exit 0); no argument at all
    # is a usage error that names them (exit 2). Up to 1.8.0 both answered "unexpected argument" and no help existed
    # (measured on the PyPI wheel 1.8.0, 2026-11-18). After a command, -h/--help stays a usage error: the grammar of
    # `verify` is shared with the JavaScript verifier (verifiers/differential_oracle.py, cases cli-help and cli-h).
    if raw in (["-h"], ["--help"]):
        out = [p.format_help().rstrip(), "", "commands (each refuses -h; the options below are all there is):"]
        for name, sp in (("build", b), ("stamp", st), ("verify", v), ("restriction", rs)):
            sp.prog = "ap2-evidence " + name
            out += ["", sp.format_help().rstrip()]
        why = _emit("\n".join(out))   # 1.9.0: through the receipt's writer — print() on /dev/full or a closed stdout exited 0 with no help written
        if why is not None:
            _say(f"help not written: {why}\n")
            return EX_IOERR
        return 0
    if not raw:
        p.error("a command is needed: build, stamp, verify or restriction (ap2-evidence --help lists them)")
    # 1.1.0: one CLI grammar with the sibling verifiers — "" or a flag as a value, "--", -h/--help, a value on a boolean flag,
    # an abbreviated flag = usage (exit 2, no verdict); the file path itself must not be "" or flag-like
    if "--" in raw or any(x in ("-h", "--help") for x in raw) or any(x.split("=", 1)[0] in ("--require-producer", "--require-pq", "--require-anchor", "--trust-set-complete", "--accept-integral-floats") and "=" in x for x in raw):
        p.error("unexpected argument")
    i = 0
    while i < len(raw):
        tok = raw[i]
        if tok in ("--trusted-producer-key", "--key", "--jwks-url", "--tsa", "--subject", "--tsa-cert", "--trust-anchor", "--min-anchors"):
            val = raw[i + 1] if i + 1 < len(raw) else None
            if val is None or val == "" or val.startswith("-"):
                p.error(f"{tok} needs a value (got {val!r})")
            i += 2; continue
        if tok.split("=", 1)[0] in ("--trusted-producer-key", "--key", "--jwks-url", "--tsa", "--subject", "--tsa-cert", "--trust-anchor", "--min-anchors") and "=" in tok:
            val = tok.split("=", 1)[1]
            if val == "" or val.startswith("-"):
                p.error(f"{tok.split('=', 1)[0]} needs a value (got {val!r})")
        i += 1
    a = p.parse_args(raw)
    if a.cmd == "build":
        # r5: every name=path pair is validated as a pair, and a file that cannot be read is a usage error (exit 2),
        # never the FileNotFoundError traceback `--key foo` / a missing artifact file used to produce
        def _pair(flag, spec):
            name, sep, path = spec.partition("=")
            if not sep or not name or not path:
                p.error(f"{flag} expects name=path (got {spec!r})")
            return name, path

        def _read(flag, path, as_json=False):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f) if as_json else f.read()
            except OSError as e:
                p.error(f"{flag}: cannot read {path!r} ({type(e).__name__})")
            except ValueError as e:
                p.error(f"{flag}: {path!r} is not valid JSON ({e})")
            except RecursionError:   # 1.7.1: measured on 1.7.0, a --key file 100000 arrays deep was a traceback (exit 1)
                p.error(f"{flag}: {path!r} nests too deep to be parsed")

        arts = []
        for spec in a.artifacts:
            name, path = _pair("artifact", spec)
            arts.append({"name": name, "sd_jwt": _read("artifact", path)})
        art_names = [x["name"] for x in arts]
        def _named(flag, specs):
            """1.7.2 (SPEC §2): every name=... of this flag is an artifact of THIS build, and given once — before any file
            under it is read or any URL fetched. Measured on 1.7.1: `--key nope=k.json` and a repeated `--key a=...` were
            ignored in silence (the header key, or the last file, used; exit 0)."""
            out = []
            for spec in specs:
                name, val = _pair(flag, spec)
                if name not in art_names:
                    p.error(f"{flag}: no artifact named {name!r} in this build (artifacts: {', '.join(art_names)})")
                if any(n == name for n, _ in out):
                    p.error(f"{flag}: {name!r} given more than once")
                out.append((name, val))
            return out
        key_pairs, jwks_pairs = _named("--key", a.key), _named("--jwks-url", a.jwks_url)
        both = sorted({n for n, _ in key_pairs} & {n for n, _ in jwks_pairs})   # 1.7.3 (SPEC §2 (b)): before any file is read
        if both:
            p.error(f"--key and --jwks-url both name {both[0]!r}: ambiguous (one key source per artifact)")
        keys = {}
        for name, path in key_pairs:
            keys[name] = _read("--key", path, as_json=True)
            if not isinstance(keys[name], dict) or not keys[name]:   # a list was an AttributeError traceback; null and {}
                p.error(f"--key: {path!r} is not a non-empty JSON object (a JWK)")   # fell back to the header key in silence
        jwks = dict(jwks_pairs)
        try:
            res = build_evidence(arts, a.out, keys=keys, jwks_urls=jwks,
                                 tsa_url=(a.tsa[0] if a.tsa else None), subject=a.subject,
                                 extra_tsa_urls=a.tsa[1:], accept_integral_floats=a.accept_integral_floats)
        except Ap2WriteError as e:
            return _not_written(str(e))
        except Ap2EvidenceError as e:
            return _refused(str(e))
        why = _emit(json.dumps(res, indent=1))
        return 0 if why is None else _not_written(why)
    if a.cmd == "stamp":
        if a.evidence == "" or a.evidence.startswith("-"):
            p.error(f"evidence path needs a value (got {a.evidence!r})")
        if len(a.tsa) != 1:   # measured on b3edfc8: `--tsa A --tsa B` stamped B only, exit 0, A dropped in silence
            p.error(f"stamp takes exactly one --tsa (got {len(a.tsa)}): run it once per TSA")
        try:
            res = add_anchor(a.evidence, a.tsa[0])
        except Ap2WriteError as e:
            return _not_written(str(e))
        except Ap2EvidenceError as e:
            return _refused(str(e))
        why = _emit(json.dumps(res, indent=1))
        return 0 if why is None else _not_written(why)
    if a.cmd == "verify":
        if a.evidence == "" or a.evidence.startswith("-"):
            p.error(f"evidence path needs a value (got {a.evidence!r})")
        min_anchors = None
        if a.min_anchors is not None:
            if not re.fullmatch(r"[1-9][0-9]{0,5}", a.min_anchors):   # ASCII digits, >= 1 (the JS verifier: the same grammar)
                p.error(f"--min-anchors expects an integer >= 1 (got {a.min_anchors!r})")
            min_anchors = int(a.min_anchors)
        req_b = None
        if a.require_binding:   # 1.9.0: IN->TO, both non-empty, no second "->"
            req_b = []
            for spec in a.require_binding:
                frm, sep, to = spec.partition("->")
                if not sep or not frm or not to or "->" in to:
                    p.error(f"--require-binding expects IN->TO (got {spec!r})")
                req_b.append((frm, to))
        trusted = None
        if a.trusted_producer_key:
            trusted = {}
            for spec in a.trusted_producer_key:
                alg, sep, key = spec.partition("=")
                if not sep or not alg or not key:
                    p.error(f"--trusted-producer-key expects ALG=B64 (got {spec!r})")
                trusted.setdefault(alg, []).append(key)
        for flag, path in (("--tsa-cert", a.tsa_cert), ("--trust-anchor", a.trust_anchor)):   # 1.6.0 review: a relying-party
            if path is not None:   # file that cannot be read was handed to openssl and reported as `tsa_invalid` / `chain_unresolved`
                try:               # (a statement about the pack); now a usage error, as for `build` (r5)
                    ok = stat.S_ISREG(os.stat(path).st_mode) and os.access(path, os.R_OK)
                except (OSError, ValueError):
                    ok = False
                if not ok:
                    p.error(f"{flag}: cannot read {path!r} (not a readable regular file)")
        try:
            r = verify_evidence(a.evidence, trusted_producer_keys=trusted, require_pq=a.require_pq,
                                require_producer=a.require_producer, require_anchor=a.require_anchor, tsa_cert=a.tsa_cert,
                                trust_anchor=a.trust_anchor, min_anchors=min_anchors, trust_set_complete=a.trust_set_complete,
                                accept_integral_floats=a.accept_integral_floats, require_bindings=req_b)
        except Ap2WriteError as e:   # a check could not be run here: never "not valid"
            if e.receipt is None:
                return _not_written(str(e))
            # 1.6.0 — SPEC §6.10: the COMPLETE receipt (that subject not_evaluated/instrument_failure, the others evaluated)
            # and exit 74; a receipt that cannot be written is 74 too, with "receipt not written" on stderr (SPEC §10)
            why = _emit(json.dumps(e.receipt, indent=1))
            if why is not None:
                return _not_written(why)
            _say(f"check not run here: {e}\n")
            return EX_IOERR
        why = _emit(json.dumps(r, indent=1))
        if why is not None:   # 1.5.2: never the verdict's 0/1 when the receipt did not reach stdout whole
            return _not_written(why)
        return 0 if r["valid"] else 1
    if a.cmd == "restriction":   # SPEC §11.2: exit 0 iff every restriction record of a valid pack is verified
        if a.evidence == "" or a.evidence.startswith("-"):
            p.error(f"evidence path needs a value (got {a.evidence!r})")
        if a.tsa_cert is not None:
            try:
                ok = stat.S_ISREG(os.stat(a.tsa_cert).st_mode) and os.access(a.tsa_cert, os.R_OK)
            except (OSError, ValueError):
                ok = False
            if not ok:
                p.error(f"--tsa-cert: cannot read {a.tsa_cert!r} (not a readable regular file)")
        try:
            r = verify_restrictions(a.evidence, tsa_cert=a.tsa_cert, accept_integral_floats=a.accept_integral_floats)
        except Ap2WriteError as e:
            if e.receipt is None:
                return _not_written(str(e))
            why = _emit(json.dumps(e.receipt, indent=1))
            if why is not None:
                return _not_written(why)
            _say(f"check not run here: {e}\n")
            return EX_IOERR
        why = _emit(json.dumps(r, indent=1))
        if why is not None:
            return _not_written(why)
        return 0 if r["met"] else 1
    p.print_help(sys.stderr)   # r3: usage goes to stderr, no verdict on stdout — as every other usage path and the JS verifier
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
