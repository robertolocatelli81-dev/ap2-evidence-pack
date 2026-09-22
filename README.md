# ap2-evidence-pack

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539659.svg)](https://doi.org/10.5281/zenodo.22539659)

**Self-contained, offline-verifiable dispute evidence for agentic-payment SD-JWT mandates
(AP2-style Intent / Cart / Payment mandate chains).**

The [AP2 spec](https://ap2-protocol.org/ap2/specification/) tells implementers *what* to
keep for dispute resolution — the SD-JWTs with their disclosures, in compact serialization —
and deliberately leaves retrieval/retention mechanics out of scope. But financial
dispute/retention windows run to 5–7 years, and an ES256 mandate is re-verifiable at
dispute time only if the issuer's key material is still resolvable. Years later, JWKS
endpoints are gone and keys have rotated.

This tool turns a set of SD-JWT mandates into **one evidence file** that verifies
**offline, years later**:

- parses SD-JWT compact serialization and resolves selective disclosures **fail-closed**
  (unmatched, duplicate, or malformed disclosures are rejected, never ignored);
- verifies each **ES256** signature at build time and **snapshots the key material used**,
  tagged with an explicit provenance class — `supplied` (caller vouches; always wins over
  self-asserted header material), `x5c_header`, `jwk_header`, `jwks_fetched` (TLS witness
  at capture) — declared rather than flattened;
- verifies **KB-JWT holder binding** against the issuer payload's `cnf.jwk` (three honest
  states: verified / invalid → build refused / present-but-unverifiable, never painted green);
- recomputes **cross-mandate hash bindings** from the exact compact serializations
  (hex and base64url SHA-256);
- seals everything under a canonical SHA-256 digest with an **optional RFC 3161
  timestamp**, so "this key material existed and verified at time T" is attested by a
  third-party clock — re-checked offline for binding (status + imprint) by both verifiers,
  and for TSA authenticity by the reference when the TSA certificate is supplied (`--tsa-cert`).

## Usage

```bash
pip install cryptography    # the only dependency

python3 examples/make_samples.py     # generates sample intent.sdjwt + cart.sdjwt
python3 ap2_evidence.py build evidence.json intent=intent.sdjwt cart=cart.sdjwt \
        [--key name=jwk.json] [--jwks-url name=https://...] [--tsa http://tsa.example]

python3 ap2_evidence.py verify evidence.json     # offline, fail-closed; exit 0/1
python3 ap2_evidence.py verify evidence.json --trusted-producer-key ed25519=<b64> --trusted-producer-key ml-dsa-65=<b64> --require-pq --require-anchor   # relying-party policy (1.1.0)
node verifiers/js/ap2-verify.mjs evidence.json   # the independent verifier, same flags
```

Or as a library: `build_evidence(...)` / `verify_evidence(...)`.

## Honest scope

This file proves *what verified against which key material at capture time* — nothing
more. It does **not** prove issuer key authorization beyond what each provenance class
states, does **not** confer qualified-archive legal presumption (in the EU that is a
QTSP service under eIDAS art. 45j), and validates x5c chains only when you supply a trust anchor
(`--trust-anchor`, SPEC §6.7) — nothing about a chain is sealed in the file itself. ES256 only, by design; other algorithms are rejected loudly, never half-verified.
`valid: true` means every artifact verifies and the file is intact — read `bindings` for
chain linkage and `provenance_classes` / `self_asserted_only` for capture strength.
`self_asserted_only` is fail-closed (SPEC §6.7): offline **nothing** clears it — not a label
(`supplied`, `jwks_fetched`), not a certificate that names a famous CA as its issuer. Only an
`x5c` chain that validates to a trust anchor YOU supply does (`--trust-anchor <PEM>`, reported in
`chain_verified`, validated at the `genTime` of a TSA-verified token when the pack has one, so an
expired signing certificate still counts years later); the Node verifier cannot validate chains and
reports `chain_verified: null`. A cleared flag says a CA under your anchor certified that key — not
that the key belongs to the mandate's issuer; read `artifacts[].x5c_leaf` for the subject and issuer
DN of the certificate that was validated.

## Producer signatures (post-quantum hybrid)

`sign_evidence(...)` adds a **hybrid producer signature** over the pack digest — a
classical signature (ed25519 or ecdsa-p256) plus **FIPS 204 ML-DSA-65** — so the pack's
integrity/authenticity survives the quantum transition (NIST IR 8547). Verification is
fail-closed; authenticity requires the relying party to **pin** the producer public keys
out of band (an embedded key proves consistency, never authenticity). Policy flags on
`verify_evidence`: `require_producer`, `require_pq`, `require_anchor`. The ML-DSA-65
path is checked against a NIST ACVP sigVer subset (`pqcrypto/vectors/`) — the same nine
cases the elara-mesh verifier runs, so both stacks answer to one set of NIST-published ACVP vectors — a local check
against public test data, not a NIST validation.

## Conformance (normative)

The format is defined by `SPEC_AP2_EVIDENCE.md` plus the test vectors in
`spec/vectors/ap2/` — two ACCEPTs (`valid_signed`, the positive control, and `anchor_valid`,
a real RFC 3161 token from a probe TSA whose certificate ships beside it) and six REJECTs
(stripped-signature downgrade, valid-but-unpinned producer key, digest mismatch, time
anchor required-but-missing, time anchor claimed-but-invalid, a real token issued for
another digest). An independent verifier
claims conformance by reproducing each vector's `normative` block under its declared
policy, from the spec text alone:

```bash
python3 spec/vectors/ap2/run_ap2_conformance.py   # exit 0 = conformant
```

| Implementation | Runtime / deps | Status |
|---|---|---|
| `ap2_evidence.py` | Python 3 + `cryptography` | reference — conformant 8/8; ACVP ML-DSA-65 sigVer 9/9 |
| `verifiers/js/ap2-verify.mjs` | Node with OpenSSL ≥ 3.5 for ML-DSA-65 (measured: Node 22.23.2 / OpenSSL 3.5.7 locally, Node 24 in CI), `node:crypto` only; on an older build ML-DSA-65 is SKIP = incomplete, never a pass, and the ML-DSA vectors are not measured (the JS conformance test skips, it does not pass); no TSA signature check — `tsa_verified` null | independent — conformant 8/8 on every normative field through `run_ap2_conformance.run(verify_fn=…)` (`test_ap2_conformance.py`) |

**Differential oracle** (`verifiers/differential_oracle.py`, 22/09/2026): the two verifiers must
give the same `(valid, digest_ok, bindings_ok, producer_ok, pq_protected, rfc3161_verified,
policy_ok, producer_present, producer_trusted, rfc3161_claimed/granted/imprint_ok/gen_time, chain_verified,
self_asserted_only, provenance_classes, and the `x5c_leaf` identity of every artifact)`
— the eleven normative fields of SPEC §6 plus `rfc3161.granted`, `rfc3161.imprint_ok`, `rfc3161.gen_time`,
`chain_verified`, `provenance_classes` and the `x5c_leaf` identity — on the 8 vectors under their declared policy (plus `anchor_valid` under
`--require-anchor --tsa-cert`, and the CA-issued `x5c` leaf under `--trust-anchor`), 99 hostile files that carry the digest a lenient verifier would
recompute or a wrong JSON shape (`__proto__` key with the digest recomputed over it, non-UTF-8, float `1.0`, 2^53+1, 100000-deep,
`NaN`, lone surrogate, duplicate key, BOM, non-object, `artifacts`/`key`/`jwk`/`rfc3161_timestamp`/
`producer_signatures` of the wrong type, an empty producer block, base64url with a space /
padding / `+` on the binding artifact, a padded JWK coordinate, a deep JWT header, a non-object
payload, a trailing NBSP on the compact serialization, a space inside `tsr_b64`, claims and
bindings mismatch, producer base64 with a space, unknown producer algorithm, PQ signature
stripped under `--require-pq`, a self-forged TimeStampResp with the right imprint, a
TimeStampResp with an empty SignedData / eContent, `sig_alg` `"constructor"` / `"__proto__"` /
a list / an object under a pinned key, `provenance_class` a list or an int, `anchored` a list /
an object / `0` / `"false"`, and — inside a freshly ES256-signed payload, digest recomputed —
a duplicate key, a BOM, `_sd` `null` / `{}` / `[1]`, `_sd_alg: null`, `{"...": [1]}`, a
disclosure whose name is a list, `cnf` `null` / a string, `cnf.jwk` `{}`, JWK `x` of 31 and of 33
bytes; an artifact `name` absent / an int / `"__proto__"` / empty / duplicate; a DER element with a
4-byte length whose top bit is set inside the TSTInfo; and — built by the reference itself — packs whose
bindings sit under array-index claim keys, whose recorded binding list is reversed, or which carry a
duplicated binding entry; `provenance_class` `x5c_header` with no `x5c` in the signed header, out of
enum, a list or absent; `evidence_format` `…/2.0` or absent; `subject`/`created_utc`/`honest_scope`
absent or the wrong type, `created_utc` not ISO-8601; a SIGNED payload that is an array or a string,
a signed 100000-deep header; a real self-signed `x5c` leaf — canonical, with a space, with a newline,
one whose key differs from the snapshotted JWK, and one issued by a CA rather than self-signed;
`provenance_class` `supplied`, out of enum, a list or absent; `honest_scope` absent; a pack whose mandate is
self-asserted while a second artifact chains to the anchor) and 19 command-line grammar cases
(18 usage exit 2,
nothing on stdout, in both — the bare invocation without a subcommand included — and one
`--flag=value` form that must produce a verdict, not usage), plus three positive
controls (non-ASCII text in profile; a fresh-key pack that must be `valid` in both; the CA-issued `x5c`
leaf under `--trust-anchor`, the only case in the suite where `self_asserted_only` is false — and its
negative control, the self-signed leaf against the same anchor, where it stays true):
**130 cases, 0 disagreements, of which 4 are declared divergences** (the run prints its own
decomposition — `9 vector runs + 99 hostile files + 3 positive controls + 19 CLI cases = 130` — so these
numbers are copied from a measurement rather than counted by hand, which is how three of them went stale
during the review rounds) — the real token under `--tsa-cert`, where the
reference proves the TSA with openssl and the JS verifier reports `tsa_verified: null` and does
not pass the policy; and the three packs under `--trust-anchor` — the CA-issued leaf, the self-signed leaf and the mixed
mandate-plus-chained pack — whose chains the reference validates with `openssl verify` (clearing `self_asserted_only` for
the CA-issued one) while the JS verifier cannot and reports `chain_verified: null`. A crash counts as a disagreement, and a declared divergence that stops
appearing is reported. Positive controls (`AP2_ORACLE_PY_ROOT` / `AP2_ORACLE_JS` point the oracle
at another checkout), measured 22/09/2026 with the 124-case oracle: against the 1.0.2 reference it is red on 97
(the CLI had no policy flags; float / 2^53+1 / lone surrogate / a space inside a producer
signature or inside `tsr_b64` accepted; `producer_signatures: {}` and `producer_signatures: []`
treated as absent, `valid: true`; tracebacks on non-UTF-8, 100000-deep, BOM, a missing path and
on wrong-typed `artifacts`/`key`/`jwk`/`rfc3161_timestamp`; `--help` exit 0, `--` a verdict);
against the states after rounds 10 and 11 it is red on **0**, and that is not a clean bill: pointing the oracle at an older
checkout makes BOTH verifiers old, so they agree with each other and the run only reports that the declared divergences no
longer appear. The defects the last two rounds fixed were shared by the two verifiers, which is exactly what a differential
oracle cannot see — they are held by unit tests measured red against those commits instead. Against round 9 the oracle was
red on 10 with that round's 130-case set, against the state after round 7 on 3 — the two `--trust-anchor` cases, which that reference
does not know (it exits 2 on the flag), plus the declared divergence that stops appearing there and is reported as
a disagreement — against the state after round 6 on 0 — the round-7
findings were defects the two verifiers SHARED, held instead by two unit tests measured red against the round-6 code
(`test_provenance_class_is_reconciled_and_format_is_pinned`, `test_build_side_x5c_and_jwks_errors_are_receipts`) —
against the state after round 5 on 3 (a signed array payload verified in the JS
verifier, whose shape check had spent a round inside an unterminated line comment; an `x5c` leaf spelled
with a space or a newline was accepted by the reference's lenient `base64.b64decode` and refused by the
JS verifier), against the state after round 4 on 0: the round-5 findings are defects the two
verifiers SHARED (a differential oracle measures agreement, not correctness), and they are held instead
by two unit tests that go red against the round-4 reference —
`test_provenance_class_is_reconciled_and_format_is_pinned` and `test_build_refuses_what_verify_refuses`
(measured 22/09/2026). Against the state after round 3 the oracle is red on 2 (the binding-set cases above),
against the state after round 2 on 5 (the round-3 cases: an absent artifact `name`
crashed the JS binding table, an int name was stringified by it and `"__proto__"` vanished from it; a
4-byte DER length went negative in the JS `<<` and a token the reference refuses verified there; the bare
invocation printed the reference's help on stdout) and against the state after round 1 on 26 (the round-2 cases: the reference read
the signed payload with `json.loads` — duplicate key last-wins, BOM skipped — while the JS parser
refused; present-with-`null` was "absent" in JS and a `TypeError` in the reference; 31/33-byte JWK
coordinates verified in the reference; `anchored: []` was not anchored in the reference and
anchored-unverified in JS; `sig_alg: "constructor"` under a pin crashed the JS verifier;
an empty EXPLICIT `[0]` in the token was an `IndexError` in the reference). Round 4 added the binding
cases: `bindings` is a SET (SPEC §4) in both, because JavaScript enumerates array-index object keys
first — an ordered comparison split the verdict on a pack the reference itself had built.
Ablation (`verifiers/lax_python_ablation.sh`, measured 22/09/2026): each strict layer of the reference
removed **alone** from a copy — file-level strict JSON, JWT-level strict JSON, strict base64url, the JWK
coordinate length — must turn `test_ap2_conformance.py` red by itself, and each does (1 error + 1
failure for the file-level layer, then 1 failure each). Measured on 22/09 before that split: ablating base64url alone left the
suite green, so that layer was not measured by the unit suite; three unit cases were added for it.

Independent implementations (any language): open a PR to be listed here.

## Tests

```bash
python3 test_ap2_evidence.py      # negative controls first — the bench can fail
python3 test_ap2_conformance.py   # conformance vectors + ACVP ML-DSA-65 + signature suite + acceptance profile + CLI grammar + JS agreement
python3 verifiers/differential_oracle.py   # Python vs Node on every vector, hostile file and CLI case (needs node)
verifiers/lax_python_ablation.sh           # the strict layers removed from a copy of the reference -> the suite must be red
```


## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/ap2-evidence-pack/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with payment networks, PSPs and wallets that need offline dispute evidence for AP2 mandates. Write with the use case; the answer says what is measured and what is not.
- **Licence**: Apache-2.0: use it freely, also in closed products. If you build on it, a note in Discussions helps the roadmap (and tells the author the work is used).
- **Citation**: DOI [10.5281/zenodo.22539659](https://doi.org/10.5281/zenodo.22539659) (Zenodo, concept DOI: always the latest version).
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.

## License

Apache-2.0 — © 2026 Roberto Locatelli. Built to be contributed to / aligned with the
AP2 ecosystem; feedback and adaptation requests welcome.

## Disclaimer

This is an independent, third-party tool. It is **not affiliated with, endorsed by, or
sponsored by Google** or the AP2 / Agent Payments Protocol project; "AP2" is used solely
to describe the protocol this tool interoperates with. The software is provided **"AS IS"**,
without warranties or conditions of any kind, and with no acceptance of liability, as per
the Apache-2.0 license (§7–8). Nothing in this repository is legal advice, and no
representation is made that any output constitutes admissible or sufficient evidence in
any legal or regulatory proceeding.

## Install (pip)

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ ap2-evidence-pack
```

Release artifacts are attached to GitHub Releases; the index links carry `#sha256=` fragments verified by pip. All documented `python3 <file>.py` commands keep working unchanged from a clone.
