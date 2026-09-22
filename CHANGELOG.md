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
  0 disagreements, 1 declared; 21 red against the round-1 state, 65 against 1.0.2; `proto-key` case rehashed so that it
  can fail; a declared divergence that stops appearing is reported. README: the Node requirement is OpenSSL ≥ 3.5 for
  ML-DSA-65 (not "Node ≥ 20"); the JS conformance test SKIPS on a build without ML-DSA instead of failing.

Verdicts unchanged on in-profile evidence produced by 1.0.x `build`.
