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
- **Differential oracle** `verifiers/differential_oracle.py`: 8 vectors + 20 hostile files + 14 CLI cases, 0 disagreements;
  21 red against 1.0.2. Two new vectors with a **real RFC 3161 token** from a probe TSA (certificate shipped):
  `anchor_valid` (ACCEPT) and `anchor_wrong_digest` (a real token for another digest: REJECT) — before, the only anchor
  vector was garbage bytes, so a verifier that never parsed the token passed it.
- RFC 3161: `verified` = status granted + messageImprint equals the digest, in both verifiers; the TSA signature/chain is
  validated by neither (SPEC §3.2, declared).

Verdicts unchanged on in-profile evidence produced by 1.0.x `build`.
