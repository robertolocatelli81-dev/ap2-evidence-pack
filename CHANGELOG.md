# Changelog

## 1.1.0 — 2026-09-22 — acceptance profile, one CLI grammar, an independent verifier and a differential oracle

Propagation of the verifier-hygiene classes found in the cra-evidence / omega-evidence / cryptovalid reviews (21/09/2026),
measured on the 1.0.2 verifier first (every case below was red there).

- **Acceptance profile of the evidence file** (SPEC §3.1): non-UTF-8, BOM, >64 MiB, non-object, duplicate keys, floats,
  integers beyond ±(2^53−1), `NaN`/`Infinity`, nesting >512, lone surrogate escapes are refused with a receipt
  (`valid: false`, `refused: <reason>`) — never a traceback. 1.0.2 crashed on non-UTF-8 (`UnicodeDecodeError`),
  100000-deep (`RecursionError`), a missing path or a directory, and accepted a float, 2^53+1 or a lone surrogate with a
  recomputed digest.
- **Strict base64url / base64**: SD-JWT segments and producer-block values must be canonical (alphabet, length, padding,
  trailing bits). 1.0.2 stripped whitespace and added padding silently, and a space inside a producer signature still
  verified (`sigsuite._unb64` was `b64decode`).
- **One CLI grammar** with the sibling verifiers: `--help`/`-h` (exit 0 before), `--`, an empty or flag-like value at any
  occurrence, an abbreviated flag, a value on a boolean flag, a second positional = usage (exit 2, no verdict); `--flag=value`
  accepted. The relying-party policy is now on the CLI: `--trusted-producer-key ALG=B64` (repeatable), `--require-producer`,
  `--require-pq`, `--require-anchor` (they existed in the API only).
- **Independent verifier** `verifiers/js/ap2-verify.mjs` (Node, `node:crypto` only): ES256, SD-JWT disclosures, KB-JWT,
  bindings, producer Ed25519 / ECDSA P-256 / ML-DSA-65 (OpenSSL ≥ 3.5, else SKIP = incomplete), RFC 3161 status +
  messageImprint (SPEC §3.2), the same profile and CLI grammar.
- **Differential oracle** `verifiers/differential_oracle.py`: 8 vectors (+1 under `--tsa-cert`) + 39 hostile files + 15 CLI cases
  + 1 positive control = 64, 0 disagreements, 1 declared (TSA proof is openssl-only); 43 red against 1.0.2; a crash counts as
  a disagreement. Review round 1 (Opus/Sonnet/Haiku) added the wrong-JSON-shape class (tracebacks in the reference), the
  empty producer block, lenient `tsr_b64` and JWK coordinates, the binder-side base64url mutations and the forged TimeStampResp. Two new vectors with a **real RFC 3161 token** from a probe TSA (certificate shipped):
  `anchor_valid` (ACCEPT) and `anchor_wrong_digest` (a real token for another digest: REJECT) — before, the only anchor
  vector was garbage bytes, so a verifier that never parsed the token passed it.
- RFC 3161: `verified` = status granted + messageImprint equals the digest (BINDING), in both verifiers by a DER walk — a
  self-forged TimeStampResp with the right imprint satisfies it, so it never meant TSA authenticity (1.0.x said
  "cryptographically verify": it ran `openssl ts -reply -text`, which verifies nothing). New `--tsa-cert <PEM>`: the
  reference verifies the token's signature and chain with `openssl ts -verify -CAfile` (`tsa_verified`), required by
  `--require-anchor --tsa-cert`; the JS verifier cannot and does not pass that policy (declared).

- **Review round 2** (Opus/Sonnet/Haiku, 22/09/2026): the §3.1 profile now applies INSIDE the SD-JWT (issuer header/payload,
  disclosures, KB-JWT) — the reference read the signed payload with `json.loads` (a duplicate key read last-wins, a BOM
  skipped) while the JS parser refused, so one verifier certified `{"amount":"1","amount":"999"}` as `"999"` and the other
  refused it; present-with-`null` is not absent (`dict.get` vs `??`): `_sd`, `_sd_alg`, `{"...": d}`, disclosure names,
  `cnf`, `cnf.jwk` have imposed shapes; JWK `x`/`y` must be 32 bytes (RFC 7518 §6.2.1 — 31/33 bytes verified in the
  reference, refused in JS); `provenance_class` a string (a list was a `TypeError` in `sorted`); `anchored` a boolean
  (`[]` was "not anchored" in the reference and "anchored, unverified" in JS); `sig_alg` a string (`"constructor"` under a
  pinned key crashed the JS verifier on its prototype-bearing table, now `Object.create(null)`; a list was a `TypeError`
  in the reference); an empty EXPLICIT `[0]` in the TimeStampResp was an `IndexError` traceback. Oracle: 90 cases,
  0 disagreements, 1 declared; `proto-key` case rehashed so that it
  can fail; a declared divergence that stops appearing is reported. README: the Node requirement is OpenSSL ≥ 3.5 for
  ML-DSA-65 (not "Node ≥ 20"); the JS conformance test SKIPS on a build without ML-DSA instead of failing.
- **Review round 3** (Opus/Sonnet/Haiku, 22/09/2026): `artifacts[].name` must be a non-empty unique string (refusal) — the
  JS binding table was a prototype-bearing object: an absent name was a `TypeError` crash, an int name was stringified
  (`bindings_ok` false against the reference's `true`), `"__proto__"` set the prototype and vanished (valid in the
  reference, not in JS); the JS DER length used `<<` (int32): a 4-byte length `84 80 00 00 00` went negative, passed the
  overrun check and a TimeStampResp the reference refuses verified in JS; the bare invocation of the reference printed its
  help on stdout with exit 2 (now stderr, like every usage path and the JS verifier); the oracle's usage rule is exit 2 AND
  nothing on stdout. Oracle: 97 cases, 0 disagreements, 1 declared; positive controls 5 red on the round-2 state, 26 on the
  round-1 state, 71 on 1.0.2.
- **Review round 4** (Opus/Sonnet/Haiku, 22/09/2026): `bindings` is compared as a SET in both verifiers (SPEC §4 now defines
  the entry schema, the claim-path grammar and both encodings) — JavaScript's `Object.keys` enumerates array-index keys
  (`"0"`, `"2"`) before the others, so a cart committing under `intent_hash` and `"0"` was scanned in a different order and
  the ORDERED comparison gave `valid: true` in the reference and `false` in the JS verifier on a pack `build` had produced.
  The ablation is now one layer at a time (ablating strict base64url alone had left the unit suite green — that layer was
  not measured; three base64url cases added). The probe TSA certificate is re-issued for 20 years and the two anchor tokens
  with it (it expired in 2 days, so `tsa_verified` would have gone false in 48 hours); the reference validates the chain at
  the token's own `genTime` (`openssl ts -verify -attime`), both verifiers report `rfc3161.gen_time`; the stale
  `requires: ["openssl"]` is off the anchor vectors (the binding check needs no openssl). Oracle: 102 cases,
  0 disagreements, 1 declared; positive control 2 red on the round-3 state.
- **Review round 5** (Opus/Sonnet/Haiku, 22/09/2026): `provenance_class` is RECONCILED with the signed header instead of
  believed — relabelling `jwk_header` as `x5c_header` made `self_asserted_only` false with no `x5c` anywhere (the one
  field the honest scope sends the auditor to), and out-of-enum values passed as strong classes; the enum is closed in
  both verifiers. `evidence_format` and the §1 MUSTs (`subject`, `created_utc`, `honest_scope`) are checked: a
  `ap2-evidence-pack/2.0` pack used to be verified under the 1.0 rules (version confusion) and a pack with no
  `honest_scope` produced a receipt with `honest_scope: null`. The binding scan uses an inverse index instead of a
  per-leaf loop over the artifacts — the cost was quadratic (measured: 0.70 s at 2 000 artifacts, 5.04 s at 4 000;
  after: 0.009 s and 0.015 s, 0.071 s at 16 000); the set of bindings is unchanged. `build` refuses an empty artifact
  name (it used to write a pack, exit 0, that both verifiers then refused) and its CLI validates `name=path` pairs and
  reports unreadable files as usage (exit 2) instead of a `FileNotFoundError` traceback. The oracle now compares the
  eleven normative fields of SPEC §6 plus `provenance_classes` (it compared seven; `provenance_classes` really did diverge, sorted by code point
  in the reference and by UTF-16 code unit in JS — the JS side now uses the same comparator) and runs 113 cases,
  0 disagreements, 1 declared; the file-level ablation is applied at its use site (patching `loads_strict` also ablated
  the JWT level, since `_loads_segment` delegates to it); two tests that claimed "in both verifiers" now skip instead of
  passing when node is absent, and the bare-invocation loop really runs the JS CLI. Three vector descriptions realigned
  with the code (they still said "neither verifier validates the TSA chain", "cryptographic token verification" and
  "the one ACCEPT of the set").
- **Review round 6** (Opus/Sonnet/Haiku, 22/09/2026): the JS "JWT header and payload must be objects" check had ended up
  INSIDE an unterminated line comment in round 5 — a signed payload that is a JSON array verified there and failed in the
  reference; it is code again, and the oracle case that was supposed to cover it (`payload-list-rehashed`) turned out to
  swap the segment without re-signing, so both verifiers failed on the signature and the shape rule was never reached:
  the payload/header shape cases are now built as freshly SIGNED packs. The `x5c` leaf is decoded with the strict base64
  decoder in the reference (`base64.b64decode` dropped a space or newline, the JS verifier refused the same bytes) and the
  `x5c_header` branch, which had no coverage at all, gets four oracle cases with a real self-signed leaf. A stray
  `unittest.main()` in the middle of `test_ap2_evidence.py` meant 13 of its 27 tests never ran in CI (holder binding,
  producer content binding, x5c chain limits): removed, and CI now fails if a module collects fewer tests as a script than
  as a module. `created_utc` is imposed as ISO-8601 UTC in both verifiers (SPEC §1 said MUST, only the type was checked).
  Oracle: 121 cases, 0 disagreements, 1 declared; positive control 3 red on the round-5 state.

Verdicts unchanged on in-profile evidence produced by 1.0.x `build`.
