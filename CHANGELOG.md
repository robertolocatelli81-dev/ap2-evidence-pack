# Changelog

## 1.1.0 — 2026-09-22 — acceptance profile, one CLI grammar, an independent verifier and a differential oracle

Propagation of the verifier-hygiene classes found in the cra-evidence / omega-evidence / cryptovalid reviews (21/09/2026),
the hygiene classes of the first four bullets were measured on the 1.0.2 verifier first: that day's oracle was red on 97
of its 124 cases there. Later rounds found defects 1.0.2 could not exhibit at all, having neither a second verifier nor
the policy flags.

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
- **Review round 7** (Opus/Sonnet/Haiku, 22/09/2026): `self_asserted_only` is FAIL-CLOSED (SPEC §6.7). Round 5 reconciled
  two of the six spellings of `provenance_class`; the other four still cleared the flag with no evidence at all —
  measured: `"supplied"` and `"jwks_fetched"` cleared it on the strength of the label, and `null` or a DELETED field
  cleared it by making the class set empty. Since `producer_signatures` sits outside the digest, an unsigned pack is
  freely editable, so the one field the honest scope sends the auditor to was the pack author's to choose. Now the class
  is REQUIRED and in the enum (absent/null/other = refusal of that artifact), and the flag is true unless every key was
  reconciled to a certificate leaf that someone else issued — a self-signed `x5c` leaf is still self-asserted. `build`
  no longer tracebacks on an `x5c` leaf wrapped at 76 columns, a non-certificate, a non-string entry or an unreachable
  JWKS (bare `ValueError`/`URLError` escaped `except Ap2EvidenceError`): they are `{"error": …}` receipts, exit 1. The
  oracle compares `rfc3161.gen_time` too and gets a CA-issued `x5c` leaf as the positive control of the honesty flag
  (122 cases, 0 disagreements, 1 declared); an unparseable token returns the same receipt shape in both verifiers; the
  ablation checks the patched module still imports, so a botched patch cannot masquerade as a red ablation.
- **Review round 8** (Opus/Sonnet/Haiku, 22/09/2026): round 7 had moved the author's freedom one field along — it cleared
  `self_asserted_only` when the leaf's issuer DN differed from its subject DN, and **measured**: a certificate SELF-SIGNED
  with its own key, declaring `CN=DigiCert Global Root CA` as issuer, cleared the flag in both verifiers on a `valid` pack.
  Offline, "issued by someone else" is not establishable, so nothing clears the flag any more except an `x5c` chain that
  validates to a trust anchor the relying party supplies: new `--trust-anchor <PEM>` (`openssl verify` in the reference,
  `chain_verified` true/false; the JS verifier cannot validate chains and reports `null` — the second declared divergence,
  like `--tsa-cert`). A refusal receipt now carries `self_asserted_only: true` as well (it printed the green value, `false`,
  on a file the verifier had refused to read). `honest_scope` is pinned by SHA-256 to the canonical scope of the declared
  `evidence_format` in both verifiers: the receipt used to REPRINT whatever scope the file carried, so an author could write
  "anchored by a QTSP under eIDAS art. 45j" and see it beside `valid: true`. Oracle: 124 cases, 0 disagreements,
  2 declared.
- **Review round 9** (Opus/Sonnet/Haiku, 22/09/2026): `created_utc` was validated with `\d`, which in Python matches every
  Unicode Nd digit and in JavaScript only `[0-9]` — measured: `"٢٠٢٦-٠٩-٢٢T٠٠:٠٠:٠٠Z"` verified in the reference and was
  refused by the JS verifier, opposite verdicts on a pack in profile (non-ASCII text is in profile by §3.1). `--trust-anchor`,
  added in r8, was outside the reference's CLI grammar: `--trust-anchor ""` gave a verdict on stdout there and usage exit 2
  in JS. The x5c chain was validated at the CURRENT clock, so a leaf valid 2020-2021 — the ordinary case for a format whose
  claim is "verifies offline years later" — could never clear `self_asserted_only`; it is now validated at the `genTime` of a
  TSA-verified token when the pack carries one, like the TSA chain since r4. `chain_verified` is tri-state (`null` when
  openssl is absent: unmeasurable is not failed) and present in refusal receipts, which lacked it while the JS ones had it.
  Both verifiers now report `artifacts[].x5c_leaf` (subject and issuer DN, serial, validity, SHA-256): a cleared flag means
  a CA under the relying party's anchor certified that key, never that the key belongs to the mandate's issuer — without the
  DN an auditor cannot tell `CN=the-bank` from `CN=attacker`. Oracle: 129 cases, 0 disagreements, 2 declared; positive
  control 4 red on the round-8 state, plus a unit test for the expired leaf measured red there.
- **Review round 10** (Opus/Sonnet/Haiku, 22/09/2026): `self_asserted_only` was computed with `all()` over the per-artifact
  flags, so ONE reconciled artifact cleared it for the whole pack — measured: a pack whose mandate carried a self-asserted
  `jwk_header` key and whose second artifact chained to the relying party's anchor reported `self_asserted_only: false`,
  i.e. "no self-asserted key here", while the mandate-signing key had never been reconciled at all (and the JS verifier
  said `true`: an undeclared divergence the oracle could not see). It is `any()` in both now. The reference asserted
  `granted: false` on a truncated token whose PKIStatus it had already read as granted; both verifiers now carry the status
  that was actually read into the failure path, or `null`. The JS receipt did not carry the leaf validity that SPEC §6.7
  requires, and rendered DNs in OpenSSL multi-line form while the reference used RFC 4514 — the same certificate produced
  two different receipts in the field §6.7 asks for precisely to tell `CN=the-bank` from `CN=attacker`; RFC 4514 in both.
  The oracle now compares `rfc3161.granted`, `rfc3161.imprint_ok`, `chain_verified` and the `x5c_leaf` identity: 130 cases,
  0 disagreements, 3 declared, and **10 red** against the round-9 state. README: 19 CLI cases, not 16.
- **Self-audit before release** (22/09/2026, on the error classes committed during these rounds): the README's "hostile
  files" count had gone stale a third time (97 against 99 measured), so the oracle now PRINTS its own decomposition
  (`9 vector runs + 99 hostile files + 3 positive controls + 19 CLI cases = 130`) and the public numbers are copied from a
  measurement instead of counted by hand. A trailing `//` comment swallowed the rest of its line twice in one day — a shape
  check, then `policy_ok` — so `test_both_receipts_carry_the_same_field_names` now compares the KEY SETS of the two
  receipts (top level, per artifact, `rfc3161`, and on a refusal), measured red against the previous commit; it caught
  `mldsa_backend`, emitted by the JS verifier alone and documented nowhere, which is now in both receipts and in SPEC §6.
  Last of the "asserted but not measured" class: `granted` is `null`, not `false`, when `tsr_b64` never decoded and no
  PKIStatus was ever read. Checked and clean: no hostile oracle case shares the intact vector's verdict tuple.
- **Review round 11** (Opus/Sonnet/Haiku, 22/09/2026), the last before the release: the sealed `honest_scope` said the
  format "does NOT validate x5c chains to a trust anchor", which round 8 had made false — so a `verify --trust-anchor`
  printed `chain_verified: true` in the same JSON object as a scope denying that chains are ever validated. The scope is
  pinned by SHA-256, so correcting it invalidates every existing pack: it was done now, before the tag, and the whole
  vector set was regenerated with fresh keys and two re-issued RFC 3161 tokens (the declared genTime in the oracle moved
  with them — the run reported the mismatch instead of passing silently, which is what that guard is for).
  `chain_verified` no longer collapses to `null` because a pack also contains a non-x5c artifact: only artifacts that
  attempted a chain count, so a mandate/cart pack mixing `jwk_header` and `x5c_header` now reports what was measured —
  the round-10 `all()` defect one field over, and invisible to the oracle because the JS verifier always answers `null`.
  `imprint_ok` is `null` wherever no messageImprint was read (it asserted `false`, the same accusation round 10 made of
  `granted`, applied to half the object), and the two early `return`s of the JS token walk carry the same fields as every
  other branch. The reference emits `x5c_leaf.chain_verified` always, as the JS receipt did: the same certificate was
  producing a six-field receipt on one side and a seven-field one on the other. Oracle: 130 cases, 0 disagreements,
  4 declared.

- **Final check before the tag** (Fable 5.1, 22/09/2026): three public sentences were false of the measurements and one
  rule the verifiers enforce was missing from the SPEC. `self_asserted_only` printed its GREEN value on a pack with zero
  artifacts (`any()` over an empty list) — the honesty flag is fail-closed there too now, in both verifiers, held by
  `test_honesty_flag_and_scope_are_fail_closed` measured red against the previous commit. Both verifiers refused a
  rewritten `honest_scope` citing "SPEC §1", but the SPEC carried neither the canonical text nor its hash: §1 now pins it
  by SHA-256 and §8 reproduces it verbatim, so an independent implementation can enforce the rule from the text alone.
  The sealed scope itself said "nothing about a chain is sealed in this file" (the x5c bytes are sealed; the validation
  RESULT is not) and that an RFC 3161 token attests the TSA's clock without adding that this holds only once the relying
  party verifies the TSA signature — both corrected, which changed the pinned hash a second time and regenerated the
  vectors again. Stale numbers fixed: the ablation is 1 error + 1 failure on the first layer, the declared divergences are
  three `--trust-anchor` packs plus the `--tsa-cert` one, and the hostile-file list named three cases that do not exist.

- **After the second final pass** (22/09/2026): the sealed scope promises the KB-JWT `aud`/`nonce`/`iat` are RECORDED
  whenever a KB-JWT is present. Measured: neither verifier recorded them on the branch where the KB-JWT carries no
  `cnf.jwk` — the reference returned early with a `note`, the JS verifier without one, so the two receipts differed in
  shape there as well. Both record them on every branch now, with identical fields, and the receipt-shape test covers a
  pack that carries a KB-JWT (red against the previous commit). Found by checking the branch the tests did not reach.
  That prompted a coverage measurement of the whole reference under the tests AND the oracle — 79% of its lines — which
  named `verify_kb_jwt` as the least exercised path. Probing its six uncovered branches found another defect, shared by
  both verifiers: a KB-JWT whose signature segment is non-canonical base64url verified with `valid: true`, because the
  branch for an unknown holder key returns before the signature is ever decoded, so the §3.1 profile never reached it.
  Both verifiers now apply the profile to all three KB-JWT segments; measured on the previous commit, that pack was
  `valid: true` in both. The same measurement was then redone counting the subprocesses the oracle spawns (85%, not 79%:
  the first figure missed every case the oracle runs out of process — a measuring instrument reading the wrong quantity,
  which is the class this release kept finding). The next largest uncovered region, the seven `resolve_disclosures`
  branches, was probed the same way and found CONCORDANT and correct in both verifiers — no defect there. Both sets are
  oracle cases now: 144 cases, 0 disagreements, 4 declared.

**Breaking: 1.1.0 refuses every pack built by 1.0.x.** The scope statement is sealed and pinned by SHA-256 (SPEC §1/§8),
and it was corrected during the review rounds, so a 1.0.x pack is refused with `honest_scope does not match the canonical
scope of this evidence_format` — measured on a pack built with the `v1.0.2` tree and verified with this one, in both
verifiers. Re-build with 1.1.0: a pack built by this tree is ACCEPT in both verifiers and the
conformance runner exits 0 on all eight vectors.
