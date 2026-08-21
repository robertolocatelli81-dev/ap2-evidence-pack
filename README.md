# ap2-evidence-pack

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
  third-party clock — and verifies that token cryptographically on re-check.

## Usage

```bash
pip install cryptography    # the only dependency

python3 ap2_evidence.py build evidence.json intent=intent.sdjwt cart=cart.sdjwt \
        [--key name=jwk.json] [--jwks-url name=https://...] [--tsa http://tsa.example]

python3 ap2_evidence.py verify evidence.json     # offline, fail-closed; exit 0/1
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

## Tests

```bash
python3 test_ap2_evidence.py    # 21 tests; negative controls first — the bench can fail
```

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
