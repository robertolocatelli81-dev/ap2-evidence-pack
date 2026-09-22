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
QTSP service under eIDAS art. 45j), and does **not** validate x5c chains to a trust
anchor. ES256 only, by design; other algorithms are rejected loudly, never half-verified.
`valid: true` means every artifact verifies and the file is intact — read `bindings` for
chain linkage and `provenance_classes` / `self_asserted_only` for capture strength.

## Producer signatures (post-quantum hybrid)

`sign_evidence(...)` adds a **hybrid producer signature** over the pack digest — a
classical signature (ed25519 or ecdsa-p256) plus **FIPS 204 ML-DSA-65** — so the pack's
integrity/authenticity survives the quantum transition (NIST IR 8547). Verification is
fail-closed; authenticity requires the relying party to **pin** the producer public keys
out of band (an embedded key proves consistency, never authenticity). Policy flags on
`verify_evidence`: `require_producer`, `require_pq`, `require_anchor`. The ML-DSA-65
path is checked against a NIST ACVP sigVer subset (`pqcrypto/vectors/`) — the same nine
cases the elara-mesh verifier runs, so both stacks answer to one NIST oracle.

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
| `verifiers/js/ap2-verify.mjs` | Node ≥ 20, `node:crypto` only (ML-DSA-65 through the build's OpenSSL ≥ 3.5, else SKIP = incomplete, never a pass; no TSA signature check — `tsa_verified` null) | independent — conformant 8/8 on every normative field through `run_ap2_conformance.run(verify_fn=…)` (`test_ap2_conformance.py`) |

**Differential oracle** (`verifiers/differential_oracle.py`, 22/09/2026): the two verifiers must
give the same `(valid, digest_ok, bindings_ok, producer_ok, pq_protected, rfc3161_verified,
policy_ok)` on the 8 vectors under their declared policy (plus `anchor_valid` under
`--require-anchor --tsa-cert`), 39 hostile files that carry the digest a lenient verifier would
recompute or a wrong JSON shape (`__proto__` key, non-UTF-8, float `1.0`, 2^53+1, 100000-deep,
`NaN`, lone surrogate, duplicate key, BOM, non-object, `artifacts`/`key`/`jwk`/`rfc3161_timestamp`/
`producer_signatures` of the wrong type, an empty producer block, base64url with a space /
padding / `+` on the binding artifact, a padded JWK coordinate, a deep JWT header, a non-object
payload, a trailing NBSP on the compact serialization, a space inside `tsr_b64`, claims and
bindings mismatch, producer base64 with a space, unknown producer algorithm, PQ signature
stripped under `--require-pq`, a self-forged TimeStampResp with the right imprint) and 15
command-line grammar cases (usage exit 2, no verdict, in both), plus one positive control
(non-ASCII text, in profile): **0 disagreements on 64 cases, 1 declared** — the real token under
`--tsa-cert`, where the reference proves the TSA with openssl and the JS verifier reports
`tsa_verified: null` and does not pass the policy. A crash counts as a disagreement. The same
oracle against the 1.0.2 reference is red on 43 (measured 22/09/2026: the CLI had no policy
flags; float / 2^53+1 / lone surrogate / a space inside a producer signature or inside `tsr_b64`
accepted; `producer_signatures: {}` treated as absent; tracebacks on non-UTF-8, 100000-deep,
BOM, a missing path and on every wrong-typed field; `--help` exit 0, `--` a verdict). Ablation:
with the strict parser and base64 removed from the reference, `test_ap2_conformance.py` is red.

Independent implementations (any language): open a PR to be listed here.

## Tests

```bash
python3 test_ap2_evidence.py      # negative controls first — the bench can fail
python3 test_ap2_conformance.py   # conformance vectors + ACVP ML-DSA-65 + signature suite + acceptance profile + CLI grammar + JS agreement
python3 verifiers/differential_oracle.py   # Python vs Node on every vector, hostile file and CLI case (needs node)
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
