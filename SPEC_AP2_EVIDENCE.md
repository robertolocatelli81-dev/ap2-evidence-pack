<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Roberto Locatelli -->

# ap2-evidence-pack — normative format v1.0 (2026-09-05), specification revision 1.9.0 (2026-11-20)

> Unreleased revision 1.10.0 (after 1.9.0, 2026-11-20): §6 step 2, the issuer signature is verified only under the
> `alg` the signed header names (`issuer_alg_not_es256`); §3.2, an openssl that does not answer on the key-identifier
> path, or a temporary file of that path that cannot be written, is a check not run (`null`), not a `false`; §6 step 7
> and §6.9, a validated x5c chain clears `self_asserted_only` only when its leaf is issued for signing (keyUsage and
> extendedKeyUsage, RFC 5280 §4.2.1.3 and §4.2.1.12), `x5c_leaf.key_purpose` in both verifiers, reason
> `key_purpose_not_signing` (added to the reasons of `ap2-evidence-pack/states-1`, as 1.8.1 added
> `signer_certificate_absent`); §2 (d), the x5c leaf is DER by one set of rules in both verifiers, and what a receipt
> says of it is read by that walk, not by a library (`x5c leaf is not DER: <rule>`), and §6 step 7 applies X.690
> §11.2.2 to keyUsage; §6 step 6,
> §5 and §6.9, a pinned producer set implies `require_producer`: a pack without a producer block is not `valid` under it, `policy.unmet` `trusted_producer_keys` (vector `stripped_signature`:
> `trusted_producer_keys` added to its `policy.unmet`, `valid` unchanged); §7, one vector added for §6 step 2,
> `issuer_alg_not_es256`, and one for §6 step 7, `issuer_x5c_key_purpose_not_signing` (fifty-nine).

> Revision 1.9.0 (2026-11-20; it contains 1.8.1, which was not released on its own): §2.1 (new), AP2 delegation chains
> `<hop0>~~<hop1>...` are read in their native form — split into hops by `build`, every hop after the first verified with
> the previous hop's `cnf.jwk` (provenance class `chain_cnf`, key member `chain_from`) under the hop rules of the AP2 SDK,
> and counted in `holder_binding` (§6.9). §4, a binding is also searched over an artifact's issuer JWT (`"over":
> "issuer_jwt"`, AP2's receipt `reference`; a pack built before 1.9.0, which records none, stays valid and the receipt
> lists them in `bindings_not_recorded`). §6.9, the policy `require_binding`. §3.2, more than one ESSCertID. §1, a
> pack built by 1.0.x is refused by name. §3.1, a non-integer number stays outside this format, stated against RFC 7519
> §2, and is named as such with or without `accept_integral_floats`. §9.1, the three new members. §10, the mapping
> follows draft-xg-payment-dispute-profile-02. A 1.8.x verifier refuses a pack that carries `chain_cnf`, `chain_from` or
> `over` (unknown class or member); a pack without them is read as by 1.8.1. §6 step 2 (written as 1.8.1, after the
> note below): the reserved names as plain keys — `...` outside an array placeholder, `_sd_alg` below the top level of
> the payload — are that artifact's error (RFC 9901 §4.1 item 7, §4.1.1); §11 says what that changed there. §5, §8
> and §12 are unchanged.
>
> Revision 1.8.1 (2026-11-18): §6 step 2, the grammar of `sd_jwt_compact` is closed (RFC 9901 §4, Proposed Standard,
> November 2025, no errata listed on 2026-11-18): no `~` at all (`sd_jwt_no_separator`), an empty component before the
> last (`sd_jwt_empty_component`), or a last component that is neither empty nor a KB-JWT of three dot-separated segments
> (`sd_jwt_final_component_not_kb_jwt`, a missing trailing `~`) is that artifact's error, named. Up to 1.8.0 the first was
> read as a JWT with no disclosures (`valid: true`), the second dropped in silence (`valid: true`), and the third taken as
> the KB-JWT, so the last disclosure vanished from `resolve_disclosures` and the artifact failed only later, as "kb-jwt
> must have 3 dot-separated segments" (measured on 2026-11-18 on the PyPI wheel 1.7.3 and on the tag v1.8.0, both
> verifiers). §6 step 2 and §9.2: without `cnf.jwk` the KB-JWT's `sd_hash` is checked too (this format's rule: RFC 9901
> §4.3.1 needs no key, and §7.3 step 5.g asks the check only when Key Binding is required): a wrong one is that artifact's error, `sd_hash_mismatch` (up to 1.8.0 `valid: true`, the same receipt as
> a right one); a right one keeps `verified: null`, `sd_hash_ok: true`, `not_evaluated / holder_key_unknown`. §3.2: a
> token whose signer certificate is not found is `tsa_verified: null`, `tsa_reason: "signer_certificate_absent"`,
> `time_anchor` `not_evaluated / signer_certificate_absent` (up to 1.8.0 `false`, `tsa_invalid`). Four vectors added (§7).
> §13: `typ` compared as a media type with the parameter values case-sensitive (RFC 7515 §4.1.9) and the grammar of
> RFC 9110; up to 1.8.0 the whole value was folded, so `x+jwt;p=A` equalled `x+jwt;p=a` (measured on 2026-11-18 on
> v1.8.0), against the 1.8.0 text of this section, which said parameters were "compared as written".
> §1, §3.1, §3.3, §4, §5, §8 and §10–§12 are unchanged.
>
> Revision 1.8.0 (2026-11-18): §12, the `not_before` block — a NIST Beacon pulse inside the sealed
> content, in one object with salted commitments to the payer's and payee's IBANs (and names and details), the amount,
> the currency, a payment id and a record salt — no personal data in clear; a lower time bound to go with the RFC 3161
> upper one. A 1.7.3 verifier refuses a pack with it (unknown top-level key). Also in 1.8.0: §3.2 (a TSA token that names
> its signer by key identifier is checked; a token with two SignerInfos is not `tsa_verified`; an openssl before 3.0 gives
> `null`, a check not run, §6.10), §6, §7, §9.2 and §13 (the KB-JWT `typ` compared as RFC 7515 §4.1.9 says; the JOSE header
> profile). A pack without the block is read as by 1.7.3 except where these change the outcome: a KB-JWT whose `typ` is
> `KB+JWT` or `application/kb+jwt` was that artifact's error under 1.7.3 and verifies now, and the tokens of §3.2 above.
>
> Revision 1.7.3 (2026-11-03): §2, the key the caller names for an artifact is the verification key, whatever the
> protected header carries; the JWKS key is chosen by a written rule (`kid`, one usable key, otherwise a refusal); every
> key source of the header that was not used is compared when it carries a key (a different key is a refusal) and named
> (§6 step 2, §9.2 `ignored.key_material`); three vectors added (§7). Up to 1.7.2 a `--jwks-url` was never fetched for a
> token that carried `jwk` or `x5c`, measured 2026-11-03. Revision 1.7.2 (2026-11-03) changed §2 and §3.1 (their 1.7.2
> paragraphs) and §7 (the `accept_integral_floats` policy key) without a note here. §1, §3–§5, §8, §10 and §11 are unchanged.
>
> Revision 1.7.1 (2026-10-29): §6 step 2 refuses an artifact whose resolved claims nest deeper than 512, the bound of
> §3.1 (`disclosures_too_deep`; up to 1.7.0 nothing bounded them, measured 2026-10-29; one vector added, §7); §3.1: a
> producer does not write a pack the profile refuses. §1, §2, §4, §5 and §8–§11 are unchanged.
>
> Revision 1.7.0 (2026-10-29): §6 step 2 refuses an artifact whose issuer payload encounters a digest value more than once
> and one whose disclosure carries a claim named `_sd` or `...` (RFC 9901 §7.1 steps 4 and 3.c.ii.2 — up to 1.6.0 both
> verifiers accepted them, measured 2026-10-28; three vectors added, §7); §11, the restriction record profile. §1–§5 and
> §8–§10 are unchanged.

Status: **proposed format** (no standards body; normative for this repository), defined by the conformance vectors in
`spec/vectors/ap2/` (each `<name>.json` pack + `<name>.expected.json`
policy/verdict). Revision 1.6.0 adds to every receipt one closed field per question a relying party asks (§6.9):
`admission` (was the pack evaluated at all, and if not, `refusal_class`), `states` (one state per subject — sealed content,
holder binding, time anchor, producer signature, issuer identity — with its reasons) and `policy` (which requirement of the
relying party is not met); it gives exit 74 a complete receipt when a check could not be run here (§6.10), makes an unknown
key inside an artifact entry or a producer-signature entry a refusal like every other object of §9.1 (NOT additive: the
twelve fields of two vectors change, §9.1), and adds §10, an informative reading of the receipt for a relying party. The
twelve fields of §6 keep their meaning. Revision 1.5.4 writes down two rules both verifiers already followed and the text did not state — the
order of the checks of an `anchors` entry (§3.3) and `bindings_ok` when an artifact fails (§6 step 3) —; changes what
§5 reports on a producer block that is not `ok` (`producer_trusted`, `pq_protected`, and so `policy_ok` under
`require_pq`: field values of packs that were already not `valid`, whose `valid` does not change); and lets an expected
file declare the cryptographic backend its verdict needs (`requires_backend`, §7). Revision 1.5.0 adds §3.3: `anchors`, a closed list of additional time anchors outside the
digest, so one pack can carry more than one commitment to the same digest (a pack with `anchors` needs a 1.5.0 verifier:
1.4.x refuses the unknown top-level key, as §9 requires). Revision 1.4.0 adds §9, the CLOSED SCHEMA: every object this format defines
has an exhaustive key list, and a key outside it is a refusal with a reason — never silently
accepted; objects defined by a standard (JOSE header, JWT claims, JWK, `cnf`) follow that
standard's rule for the unknown (ignore) and the ignored names are REPORTED in the receipt.
The `evidence_format` string is unchanged: 1.4.0 narrows what is accepted, it does not change
the sealed content or the digest of a conformant pack (every 1.1–1.3 vector still verifies; the 1.0.x vectors stopped
verifying in 1.1.0, when `honest_scope` was pinned). An independent verifier claims conformance by reproducing every
vector's `normative` block from this text alone — see §7. Reference
implementation: `ap2_evidence.py` (informative, not normative).

Scope (what a valid pack proves): these exact SD-JWT artifacts, with the
snapshotted key material, verified when the pack was built; the pack was not
altered afterwards; and — only when an RFC 3161 token is bound to the pack AND the
relying party has verified the TSA's signature with the TSA's certificate (§3.2) — all
of it existed by that TSA's time. It does NOT prove the issuer authorised a key beyond
the declared provenance class, and never proves the truth of the recorded
transaction.

## 1. Container

One UTF-8 JSON object. A strict parser MUST reject duplicate object keys
(top-level or nested). Top-level fields (the list is EXHAUSTIVE — §9: any other top-level key is a refusal):

| Field | Req | Meaning |
|---|---|---|
| `evidence_format` | MUST | `"ap2-evidence-pack/1.0"` |
| `subject` | MUST | free-text description |
| `created_utc` | MUST | ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `artifacts` | MUST | array of artifact entries (§2), ≥ 1 — an empty pack is never `valid` |
| `bindings` | MUST | array of discovered hash bindings (§4) |
| `honest_scope` | MUST | the canonical scope statement of this format version, verbatim (below), part of the sealed content |

**The scope statement is fixed by the format version, not chosen by the pack.** For
`ap2-evidence-pack/1.0` it is the exact string whose SHA-256 over its UTF-8 bytes is
`a4b12a682847c23c4a136dd399c6aa0dfa69540a5c7200039d506e86ac31dfbf`
(the canonical text is `HONEST_SCOPE` in `ap2_evidence.py` and is reproduced in §8). A verifier
MUST refuse a pack whose `honest_scope` hashes to anything else, whatever else the pack contains —
after the §3.1 profile parse and the `evidence_format` check, which come first: the
receipt reprints the scope beside its verdict, so a pack that could rewrite it could make the
receipt state anything. 1.1.0: the sealed text was corrected three times before release, on five sentences — it claimed the
format never validates x5c chains (false since `--trust-anchor`); it said an RFC 3161 token attests
the TSA's clock without adding that this holds only once the relying party verifies the TSA
signature; it said nothing about a chain is sealed (the x5c bytes are, the validation result is not);
and it described the producer signature and `valid` as covering "the file", when both cover the
SEALED CONTENT — §3 excludes the digest, the anchor block and the signatures, so a removed time
anchor is caught only under `require_anchor`.
1.9.0: a pack whose `honest_scope` is the scope 1.0.0–1.0.2 sealed (the same text in the three tags, SHA-256
`431877e44b759e99d306f79dd52739f08bd94bc05d70a6a03ee82f74fc0f15db`) is refused as before (`format_unsupported`: 1.1.0
changed the rules it was sealed under — the binding encodings, the digest exclusions, the scope), and the refusal says so
in words ("the scope of ap2-evidence-pack 1.0.0-1.0.2 … a pack built by 1.0.x"), in both verifiers; up to 1.8.x it read
"honest_scope does not match the canonical scope", which a reader takes for a rewritten scope. Measured on 2026-11-18: the
1.8.0 verifiers refuse the six 1.0 vectors an independent reader copied. Reading 1.0.x packs is not offered: their rules
are those 1.1.0 corrected (r1–r11 in the CHANGELOG), and a verifier that applied them would give their false greens back.
| `evidence_digest_sha256` | MUST | hex SHA-256 over the canonical content (§3) |
| `rfc3161_timestamp` | MUST at build (a verifier treats an absent block as `anchored: false`) | `{"anchored": false, "tsa_url"?: string, "note"?: string}` or `{"anchored": true, "tsr_b64": <b64 DER TimeStampResp>, "tsa_url"?: string, "note"?: string}` — closed (§9.1; 1.10.0: `tsr_b64` under `anchored: false` is a refusal, 1.0–1.9 accepted it and checked nothing); `tsa` is accepted as the 1.0–1.3 spelling of `tsa_url` |
| `producer_signatures` | MAY | hybrid producer-signature block (§5), closed (§9.1) |
| `anchors` | MAY (1.5.0) | non-empty list of additional time anchors (§3.3), closed (§9.1) |

## 2. Artifact entry

| Field | Meaning |
|---|---|
| `name` | non-empty string, unique within the pack (a non-string, empty or duplicate name is a refusal at verify; duplicate names MUST reject at build) |
| `sd_jwt_compact` | the EXACT compact serialization `issuer-JWT~disclosure*~[kb-jwt]` |
| `header` | the decoded protected header: an informative copy that MUST be canonically equal (§3) to the header the verifier decodes from `sd_jwt_compact` — a copy that says something else is that artifact's error (1.4.0) |
| `key` | `{"jwk": <P-256 JWK>, "provenance_class": <class>, ...}` — the snapshotted verification key |
| `resolved_claims` | payload with every `_sd` digest resolved to its disclosed claim |
| `kb_jwt` | KB-JWT verification record (§6, `kb_verified`): closed object (§9.1) whose `present` MUST equal whether `sd_jwt_compact` carries a KB-JWT |
| `verified_at_build` | build-time attestation: exactly `{"signature_ok": true, "disclosures_ok": true}` (§9.1 — a pack never carries a red light dressed as evidence) |

An artifact entry is a closed object (§9.1): a key outside this table is that artifact's error.

`provenance_class` is one of `x5c_header`, `jwk_header`, `supplied`, `jwks_fetched`, and since 1.9.0 `chain_cnf` (§2.1)
— the format records how the key was captured instead of pretending all captures
are equal. `jwk_header` is self-asserted. Any other value (or a non-string) is a
refusal of that artifact. A verifier MUST RECONCILE the two header-derived classes
with the header it just parsed: `jwk_header` requires the signed header to carry a
`jwk` equal to the snapshotted one on `kty`/`crv`/`x`/`y`; `x5c_header` requires a
signed `x5c` whose leaf public key equals it; `x5c` entries are strict base64 (RFC 4648,
no whitespace) like every other base64 value in the format. `supplied` and `jwks_fetched` are
capture-time assertions that cannot be checked offline — a verifier records them,
and a relying party MUST NOT read them as proof of anything beyond the declaration.
`provenance_class` is REQUIRED on every artifact: absent, `null`, a non-string or an
out-of-enum value is a refusal of that artifact (1.1.0 r7 — before, a missing class
silently CLEARED `self_asserted_only`).
1.1.0 r5: before this rule `provenance_class` was believed, so relabelling
`jwk_header` as `x5c_header` flipped `self_asserted_only` to false with no `x5c`
anywhere in the pack — the one field the honest scope sends the auditor to.

1.7.2 — a supplied key names an artifact. `--key name=jwk.json` and `--jwks-url name=URL` (the `supplied` and
`jwks_fetched` classes) are given FOR a named artifact of the build: the reference `build` refuses, as a usage error
(exit 2, no file, before any key file is read or any URL fetched), a name that is not an artifact of this build or a
name given twice to the same flag, and `build_evidence` refuses (`Ap2EvidenceError`, no file) a `keys` or `jwks_urls`
name that is not an artifact. Up to 1.7.1 such a name was ignored in silence — measured 2026-11-02 on 1.7.1: `--key
nope=k.json` built the pack with the header keys (`jwk_header`) and exit 0; `--key payment=K1 --key payment=K2` used K2
alone, exit 0 — so a mistyped name left the caller's trust decision out of the pack with no sign of it.

1.7.3 — the key the caller names is the policy (NORMATIVE for a producer; the reference `build`). draft-ietf-oauth-sd-jwt-vc-27
(16 November 2026, the current revision on the IETF datatracker, read on 2026-11-17; the sentences quoted here are the
same as in -23 of 31 October 2026, cited until 1.8.0) §2.5: "A recipient MUST determine and validate the public verification key for the Issuer-signed JWT
using a supported key discovery and validation mechanism that is permitted for the given Issuer according to policy",
and "If a recipient cannot validate that the public verification key corresponds to the Issuer of the Issuer-signed JWT
using a permitted key discovery and validation mechanism, the SD-JWT VC MUST be rejected". -27 adds: "The recipient's
policy determines which mechanism applies to an Issuer; the SD-JWT VC does not." Here the caller's flag IS that
policy. Up to 1.7.2 the order was supplied key > header `x5c` > header `jwk` > JWKS: measured 2026-11-03 on 1.7.2, a
`--jwks-url` given for a token that carries `jwk` or `x5c` was never fetched, the header key was snapshotted
(`jwk_header` / `x5c_header`) and the build ended with exit 0 — the key the signer declared won over the source the caller
chose, with no sign of it. From 1.7.3:

(a) A key named by the caller for an artifact — `--key name=…` / `keys` (`supplied`) or `--jwks-url name=…` / `jwks_urls`
(`jwks_fetched`) — is that artifact's verification key, whatever the protected header carries. Header key material is
used only when the caller names none: `x5c` (the leaf's key; sd-jwt-vc-27 §2.5 "Inline X.509 Certificates"), otherwise
`jwk` (self-asserted); neither: refusal, as before. A header parameter is "carried" when its name is present, whatever its
value: up to 1.7.2 an `x5c` or `jwk` whose value was empty or `null` was passed over in silence; from 1.7.3 it is used as
any other and, being unusable, refused.

(b) Both a supplied key and a JWKS URL for one artifact: refusal, ambiguous — the reference `build` as a usage error (exit
2, no file, before any key file is read or any URL fetched), `build_evidence` as `Ap2EvidenceError` (no file). A `keys`
value that is not a non-empty JSON object, or a `jwks_urls` value that is not a string starting `https://`, is a refusal
— `null` included: a name given is a key source named, whatever its value (measured 2026-11-03 on 1.7.2: `keys` `{}`, `[]`
or `null`, `jwks_urls` `""`, `5` or `null`, each built the pack with the header key, `jwk_header`).

(c) The key of a JWKS. The set is fetched over https and must be `{"keys": [object, ...]}` (RFC 7517 §5), as before; a
redirect to a URL that is not `https://` is a refusal (measured 2026-11-03 on 1.7.2: a 302 from the https URL to plain http
was followed, the set read over http and snapshotted as `jwks_fetched` under the https URL, exit 0); a redirect to another
https URL is followed, and the pack records the URL the caller gave. Its
USABLE keys are the JWKs with `kty` `"EC"`, `crv` `"P-256"`, `x` and `y` strings, no `use` other than `"sig"`, no `alg`
other than `"ES256"`, and, when `key_ops` is present, a list containing `"verify"`; the others are not considered (RFC 7517
§5: "Implementations SHOULD ignore JWKs within a JWK Set that use "kty" (key type) values that are not understood by
them, that are missing required members, or for which values are out of the supported ranges"; for `use`, `alg` and
`key_ops`, RFC 7515 Appendix D step 2, given there "for illustration purposes only": "keys with inappropriate values of
those parameters would be excluded") and their number is
written in the key's `note`. When the protected header carries `kid` it must be a string (RFC 7515 §4.1.4; any other type
is a refusal) and EXACTLY ONE usable key must carry that `kid`, compared as a case-sensitive string (RFC 7517 §4.5): none
is a refusal, two or more a refusal, ambiguous (RFC 7517 §4.5 only says distinct keys "SHOULD use distinct "kid"
values"). Without `kid` the set must hold exactly one usable key: none is a refusal, two or more a refusal, ambiguous —
the caller can name the key with `--key`. Up to 1.7.2, without `kid` the first entry of the set was taken, of whatever
type.

(d) Key sources of the header that were not used. RFC 7515 §6 lists seven header parameters that "can be used to identify
the key used" (`jku`, `jwk`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`); four of them carry the key or point to it: `jku` (§4.1.2), `jwk` (§4.1.3, "the public key that corresponds to the key used to digitally sign the JWS"), `x5u`
(§4.1.5) and `x5c` (§4.1.6, the certificate "corresponding to the key used to digitally sign the JWS"). Every one of them
present in the protected header and not the source of the snapshotted key is NAMED: in the build result
(`key_material_not_used`, an object from artifact name to the sorted names, present when one is not empty), in the
key's `note`, and at verification in `artifacts[i].ignored.key_material` (§9.2). `jku` and `x5u` are never fetched (as
before). `jwk` and `x5c` carry a key, and that key MUST equal the snapshotted key on `kty`, `crv`, `x`, `y` (for `x5c`:
the public key of the leaf, `x5c[0]`, strict base64 DER, EC P-256; the rest of the chain is not read for this
comparison): a different key, or a value that is not such a key, is a refusal at build (after the signature check, so a
wrong supplied key still reads `signature INVALID`) and that artifact's error at verification (§6 step 2), whatever the
provenance class — also the `jwk` beside the `x5c` an `x5c_header` key came from. This is this format's choice: neither
RFC 7515 nor sd-jwt-vc-27 says what a recipient does with a header that names another key than the one the signature
verifies under (sd-jwt-vc-27 §2.5: "A recipient MUST NOT treat inputs of other mechanisms as identifying the Issuer
unless its policy binds them to that identity"; it does not make them an error); a header that contradicts the signature is refused, not ignored. Not compared (declared): `x5t` and
`x5t#S256`, the header `kid` against the `kid` of a supplied key, and, at verification, the header `kid` against the `kid`
of a `jwks_fetched` key (a capture-time fact).

1.10.0, what DER means for the leaf `x5c[0]`, wherever it is read (an `x5c_header` key, an `x5c` beside another key
source, the key purpose of §6 step 7). Both verifiers walk the whole certificate with the same rules, and a leaf that
breaks one is not a certificate here: that artifact's error, `x5c leaf is not DER: <rule>`, in both. Since 1.10.0 no
library reads the leaf to decide whether it is a certificate or what a receipt says of it (`x5c_leaf`: subject, issuer,
serial, validity): that is read from the walk by the rules below, and the library is asked only whether the public key,
read from the walk too, is a point of P-256. With a trust anchor (§6 step 7) the reference still gives the chain, leaf
included, to `openssl verify`, which reads it for `chain_verified` and, when it reports a certificate signature
failure, the reason `chain_broken` (§6.9) only. The rules are those of ITU-T X.690 (02/2021,
in force with its Erratum 1 of 09/2021, read on itu.int on
2026-11-21) and of RFC 5280 §4.1 for the shape of a certificate:
- every element: a one-octet tag (no tag number above 30, X.690 §8.1.2.4), the definite length in the fewest octets
  (§10.1), inside its parent, nothing after the certificate; the tags are a closed list — universal BOOLEAN, INTEGER, BIT
  STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, UTF8String, NumericString, PrintableString, TeletexString, IA5String,
  UTCTime, GeneralizedTime, UniversalString, BMPString in the primitive form (§10.2: "For bitstring, octetstring and
  restricted character string types, the constructed form of encoding shall not be used"), SEQUENCE and SET in the
  constructed form, and the context tags `[0]` to `[3]` constructed and `[1]`, `[2]` primitive of RFC 5280 §4.1 (`rule`:
  `length`, `tag`);
- nesting: no element inside more than sixteen constructed elements — `depth`. X.690 sets no bound: this one is a choice
  of this format. The deepest element RFC 5280 §4.1 puts outside an extension value is inside seven (the hash of the
  mask generation function in RSASSA-PSS parameters); measured 2026-11-21, five at most in the 148 certificates of the
  system store and in the 32 of the TLS chains of ten public sites read for this measure. Measured the same day without the bound: a signature
  AlgorithmIdentifier whose parameter is 1500 empty SEQUENCEs one inside the other — DER by every other rule, `valid:
  true` in both verifiers on 1.9.0 — was `valid: true` for the JS verifier and an artifact error for the reference,
  whose walk ended in a RecursionError;
- BOOLEAN: one octet, `00` or `FF` (§8.2.1, §11.1) — `boolean`; INTEGER: one or more octets, the first nine bits not all
  ones nor all zero (§8.3.2) — `integer`; NULL: no contents — `null`; OBJECT IDENTIFIER: every subidentifier in the
  fewest octets, the last octet of each with bit 8 clear (§8.19.2) — `oid`; BIT STRING: the unused-bits octet 0 to 7, 0
  when there is no other octet, and the unused bits zero (§11.2.1) — `bit_string`;
- the character strings: UTF8String valid UTF-8 (no overlong form, no surrogate), PrintableString in `A-Z a-z 0-9`,
  space and `'()+,-./:=?`, NumericString in `0-9` and space, IA5String in 7 bits, TeletexString in 7 bits (1.10.0: this
  format does not read the T.61 repertoire; cryptography 50.0.2 refused an octet above `7F` and node:crypto read it),
  BMPString an even number of octets and no surrogate code unit `D800`–`DFFF` (1.10.0: BMPString is UCS-2), UniversalString
  a multiple of four, each code point at most `10FFFF` and not a surrogate — `string`; UTCTime `YYMMDDHHMMSSZ` and
  GeneralizedTime `YYYYMMDDHHMMSSZ`, a date that exists (§11.7, §11.8; RFC 5280 §4.1.2.5 allows no fractional seconds and
  no other zone), and since 1.10.0 a GeneralizedTime from year 2050 on (RFC 5280 §4.1.2.5: "CAs conforming to this
  profile MUST always encode certificate validity dates through the year 2049 as UTCTime") — `time`; a UTCTime `YY` is
  19YY when `YY` ≥ 50 and 20YY otherwise (the same section);
- SET OF: the components in ascending order (§11.6) — `set_order`;
- the shape of RFC 5280 §4.1: Certificate = tbsCertificate, signatureAlgorithm, signature; tbsCertificate = version
  `[0]`, serialNumber, signature, issuer, validity (two times), subject, subjectPublicKeyInfo, then `[1]`, `[2]`, `[3]` in
  this order, each at most once (`tbs`); the version, when present, is v3 (`a0 03 02 01 02`: v1 is the DEFAULT, which
  X.690 §11.5 forbids to encode, and RFC 5280 §4.1.2.1 asks v3 when there are extensions) — `version`; the serial
  number positive (RFC 5280 §4.1.2.2: "The serial number MUST be a positive integer") — `serial`, asked of the leaf
  only: the anchor and the other certificates of `x5c` are read by openssl, not by this walk, because "there are a few
  roots in common trust stores (like certifi) that have `serial == 0`" (pyca/cryptography 50.0.2, `policy/mod.rs`, read
  on 2026-11-21; measured that day: an anchor with serial 0 validates a chain, a leaf with serial 0 is refused). RFC 5280
  adds "Certificate users SHOULD be prepared to gracefully handle such certificates": here the leaf is a named error,
  not a crash; subjectPublicKeyInfo
  an AlgorithmIdentifier and a BIT STRING, and that BIT STRING and the signature with no unused bit (they carry octets:
  RFC 5480 §2.2 maps the ECPoint, "an OCTET STRING", bit for bit onto the BIT STRING; Proposed Standard, March 2009,
  updated by RFC 8813 only, read the same day) — `bit_string`; an Extension is
  `extnID`, an optional `critical`, `extnValue`, and `critical`, when present, is TRUE (FALSE is the DEFAULT, §11.5) —
  `extension`; an AttributeValue of issuer and subject is a UTF8String, PrintableString, TeletexString, IA5String,
  UniversalString or BMPString (DirectoryString of RFC 5280 §4.1.2.4 and IA5String of its Appendix A) — `attribute_value`;
  1.10.0: a RelativeDistinguishedName holds at least one AttributeTypeAndValue (`SET SIZE (1..MAX)`, RFC 5280 §4.1.2.4)
  and no attribute type twice — `name`; the signature AlgorithmIdentifier of tbsCertificate is the same, octet for octet,
  as signatureAlgorithm (RFC 5280 §4.1.1.2: "This field MUST contain the same algorithm identifier as the signature field
  in the sequence tbsCertificate") and one of a closed list, with the parameters its specification asks —
  ecdsa-with-SHA256, -SHA384, -SHA512 with no parameters (RFC 5758 §3.2: "the encoding MUST omit the parameters field"),
  sha256-, sha384-, sha512WithRSAEncryption with NULL or no parameters (RFC 4055 §5: "the parameters MUST be NULL.
  Implementations MUST accept the parameters being absent as well as present"), Ed25519 with no parameters (RFC 8410 §3:
  "the parameters MUST be absent"); RSASSA-PSS, SHA-1 and every other algorithm are refused — `algorithm`; the
  subjectPublicKeyInfo of the leaf is an EC key on the named curve P-256 with an uncompressed point (`30 59 30 13 06 07
  2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04` and 64 octets: RFC 5480 §2.1.1 namedCurve and §2.2,
  ES256 only), and each of the two coordinates below the prime p of P-256 (RFC 5480 §2.2: "As specified
  in [SEC1]", there SEC 1 version 1.0 of September 2000; version 2.0 of May 2009, which secg.org lists as superseding
  it, read with 1.0 on 2026-11-22: in both §2.3.4 step 3 reads x and y by §2.3.6, "Output 'invalid' and stop if a does
  not lie in the interval [0, p − 1]") — `key`. RFC 4514, 4055, 5758, 8410 were read on rfc-editor.org on 2026-11-21
  (Proposed Standards, none obsoleted).
Not read by this walk: the contents of an OCTET STRING (an extension value: keyUsage and extendedKeyUsage are read by §6
step 7, which also applies X.690 §11.2.2 to it) and of a BIT STRING (the signature; of the public key the walk reads
the 65 octets of the `key` rule). Up to 1.9.0 each verifier left the question to its library:
cryptography (strict DER) for the reference, node:crypto (OpenSSL, which reads BER) for the JS verifier.

1.10.0, what a receipt says of the leaf, read from the walk the same way in both verifiers:
- `serial`: the contents of serialNumber as an unsigned number, in lowercase hexadecimal without leading zeros;
- `not_valid_before`, `not_valid_after`: the two times of validity as `YYYY-MM-DDTHH:MM:SSZ`, from their digits;
- `subject`, `issuer`: the name as RFC 4514 §2 writes it (Proposed Standard, June 2006, read 2026-11-21): the
  RelativeDistinguishedNames from the last to the first, joined by `,`; the AttributeTypeAndValues of one RDN in their
  DER order, joined by `+`; each as `type=value`. `type` is the short name of RFC 4514 §3 (CN, L, ST, O, OU, C, STREET,
  DC, UID) or, for the attribute types with a string syntax listed here, their descriptor in the IANA LDAP Descriptors
  registry (served by iana.org on 2026-11-21 and 2026-11-22, last updated 2017-12-04): the RFC 4519 ones whose syntax is
  Directory, Printable, IA5, Numeric or Telephone String — businessCategory 2.5.4.15, description 2.5.4.13,
  destinationIndicator 2.5.4.27, dnQualifier 2.5.4.46, generationQualifier 2.5.4.44, givenName 2.5.4.42, houseIdentifier
  2.5.4.51, initials 2.5.4.43, internationalISDNNumber 2.5.4.25, name 2.5.4.41, physicalDeliveryOfficeName 2.5.4.19,
  postalCode 2.5.4.17, postOfficeBox 2.5.4.18, serialNumber 2.5.4.5, sn 2.5.4.4, telephoneNumber 2.5.4.20, title
  2.5.4.12, x121Address 2.5.4.24 — and pseudonym 2.5.4.65 and emailAddress 1.2.840.113549.1.9.1 (registered with RFC
  3280). The dotted OID otherwise (§2.3: the short name when it "is known to be registered", "Otherwise the
  AttributeType is encoded as the dotted-decimal encoding"; "Implementations are not expected to dynamically update
  their knowledge of registered short names"): the registry holds other types with a string syntax, `mail`
  0.9.2342.19200300.100.1.3 (RFC 4524) and `dmdName` 2.5.4.54 (RFC 2256) among them, which this list does not, so they
  are written dotted. `organizationIdentifier` 2.5.4.97 (ITU-T X.520 (10/2019, in force with its Amendment 1 of 10/2024,
  read on itu.int on 2026-11-21) §6.4.4; the legal person identifier of qualified seals in ETSI EN 319 412-1
  §5.1.4) is not in that registry (read again on iana.org on 2026-11-22, last updated 2017-12-04: no
  `organizationIdentifier`, no 2.5.4.97), so it is written dotted, as §2.3 asks, though OpenSSL 3.0.22 prints that name.
  For a named type `value` is the string of the AttributeValue — UTF8String as UTF-8, BMPString as UTF-16BE,
  UniversalString as UTF-32BE, the others as ASCII — with, as RFC 4514 §2.4 asks, a `\` before `"`, `+`, `,`, `;`, `<`,
  `>`, `\`, before a leading space or `#` and before a trailing space, and every other character below U+0020 and U+007F
  written `\` and two uppercase hexadecimal digits (§2.4: "Other characters may be escaped"); for a dotted type `value`
  is `#` and the lowercase hexadecimal of the whole AttributeValue element (§2.4: "If the AttributeType is of the
  dotted-decimal form, the AttributeValue is represented by an number sign … followed by the hexadecimal encoding of
  each of the octets of the BER encoding"). An empty name is the empty string. A qualified seal subject reads
  `…,2.5.4.97=#0c1056415442452d30383736383636313432,…` for the identifier `VATBE-0876866142` of ETSI EN 319 412-1 V1.7.1
  (2026-05) §5.1.4 EXAMPLE 1, in a UTF8String.
- the public key: the 64 octets after `04`, as `x` and `y`; the verifier's library is asked whether that is a point of
  P-256 (cryptography's `EllipticCurvePublicNumbers`, node:crypto's `createPublicKey` from a JWK), and a point that is
  not is that artifact's error.
Up to the branch head before this (d76b66c) the reference took these from cryptography and the JS verifier from
node:crypto, and they differed: measured 2026-11-21 with the reviewer's structural generator (12 000 changes of five
leaves written back with minimal lengths, seeds 1 to 3), 989 leaves that passed the walk were a certificate for one
verifier only and 569 were accepted by both with a different `x5c_leaf` — AlgorithmIdentifier parameters (`ecdsa-with-
SHA256` followed by NULL: an artifact error for the reference, `valid: true` for the JS verifier), an empty or a
repeated RDN value, a TeletexString above `7F`, a BMPString surrogate pair, a GeneralizedTime of year 0000, a
multi-valued RDN joined by `+` or ` + `, an attribute type dotted or named by OpenSSL, a line feed as it is or `\0A`, an
empty name `""` or `"undefined"`; 6 of 175 real certificates were written differently. Each of them is in 1.9.0 too.
The verdicts and receipts this changes are listed in CHANGELOG (1.10.0).

### 2.1 AP2 delegation chains (NORMATIVE, 1.9.0)

**Source, read on 2026-11-18.** AP2 writes a delegation as a chain of SD-JWTs joined by `~~`: google-agentic-commerce/AP2
at `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (the last commit of `main` that day), `code/sdk/python/ap2/sdk/sdjwt/chain.py`
("dSD-JWT chain orchestration (draft-gco-oauth-delegate-sd-jwt-00 §6) … tokens are joined by `~~` … each hop's signing
key is the previous hop's `cnf.jwk`"), `sdjwt/kb_sd_jwt.py` (a hop after the first is a KB-SD-JWT: `typ` `kb+sd-jwt` for
the terminal hop, `kb+sd-jwt+kb` for an intermediate one, "Exactly one of `sd_hash` / `issuer_jwt_hash` is present and
matches the hash of `prev_token`", "Terminal hops do not contain `cnf`; intermediate hops do"; "No separate trailing
KB-JWT is used in the AP2 flow"), `sdjwt/common.py` (`sd_hash` over the previous hop's SD-JWT `<jwt>~<d>*~`,
`issuer_jwt_hash` over its issuer JWT) and `mandate.py` (`token.split('~~')`; the trailing `~` of a hop is removed before
`~~` is appended). The SDK is the description used here: "The core specification has been donated to FIDO" (AP2
`CONTRIBUTING.md` at that commit), no public text of it defining `~~` was found that day, and in the AP2 repository
`~~` appears in the SDK, its tests and the samples only (GitHub code search, 15 files, none under `docs/`). The
serialization itself is the Delegate SD-JWT draft's: the SDK cites draft-gco-oauth-delegate-sd-jwt-00 (an individual
draft of 21 April 2026 whose text expires on 23 October 2026; datatracker state "Replaced"), replaced by the OAuth
working group draft draft-ietf-oauth-delegate-sd-jwt-00 (dated 26 October 2026, "Expires: 29 April 2027", Standards
Track intended; datatracker read on 2026-11-18: Active, WG Document of `oauth`; SHA-256 of the text `96fb5590…`; an
Internet-Draft, not a standard). Its §5.1.1 writes `<SD-JWT>~~<KB-SD-JWT 1>~~...~~<KB-SD-JWT n>~`, a dSD-JWT, or the
same ending in `~<delegate KB-JWT>`, a dSD-JWT+KB ("exactly one empty component between the last component of each
SD-JWT or KB-SD-JWT and the following KB-SD-JWT"); its §5.1.4 names the types `kb+sd-jwt` and `kb-sd-jwt+kb`, and this
format accepts the four the SDK accepts (below). Read against that draft's §6, this section follows it where it and
the SDK agree, takes from it the two rules the SDK does not ask (one disclosed `delegate_payload` element, the type
before a delegate KB-JWT: **Hop rules**), and differs where stated: the delegate KB-JWT is verified whenever it is
present (§6 step 5 asks it "If Key Binding is required"), and `aud`, `nonce` and the times are recorded, not checked.
Up to 1.8.0 such a chain was refused as
`malformed disclosure: invalid base64url segment` (the 143 distinct chains found in 14 public repositories, 156
occurrences, measured 2026-11-18),
and a chain split by hand gave `holder_binding: not_evaluated` on every hop.

**Input (the reference `build`).** A token given for name `N` is a chain when, split on `~~`, it has at least two parts
and every part after the first begins with an issuer JWT (three dot-separated segments before its first `~`); `<jwt>~~`
(an empty component, RFC 9901 §4) is therefore never a chain and stays `sd_jwt_empty_component`. `ap2_chain_malformed`
(refused, never read another way): a first part that is empty; a last part with no `~` at all (`<open>~~<jwt>`: an AP2
chain whose last hop lost its `~`, or, read as one SD-JWT, an empty component before a KB-JWT — the refusal names both);
a part before the last that ends with a KB-JWT (in a chain the next hop is the key binding; only the last hop may carry
a KB-JWT — the delegate KB-JWT of a dSD-JWT+KB — which is then evaluated as §6 step 2 says, with the key that hop
delegates to: the `cnf.jwk` found by the rule of **Keys** below in that hop's resolved claims; that hop must be a
KB-SD-JWT+KB, **Hop rules**). The parts become the artifacts `N.0`, `N.1`, … in order, every part but the last with its
`~` put back; the build result lists them (`ap2_chains`). A name taken twice once the chains are split is refused.

**Keys.** `N.0` takes the key named for `N` (`--key N=…`, `--jwks-url N=…`) or its header, as any artifact (§2). Every
later hop `N.i` is verified with the `cnf.jwk` of `N.(i-1)`, found where the SDK looks (`ParsedToken._find_cnf`): `cnf`
of each object element of `delegate_payload`, then `cnf` at the top level of the resolved claims; each `cnf` found must
be an object with a `jwk` object (`chain_cnf_malformed`), none is `chain_cnf_missing`, two naming different keys
(`kty`, `crv`, `x`, `y`) are `chain_cnf_ambiguous` (the SDK takes the first: refusing is this format's rule). The key is
recorded as `{"jwk": {kty, crv, x, y}, "provenance_class": "chain_cnf", "chain_from": "N.(i-1)", "note": …}`;
`chain_from` is allowed with `chain_cnf` only, and `chain_cnf` requires it (§9.1). The `alg` of every hop must be
`ES256`, as for any artifact.

**Hop rules** (each that artifact's error; at `build` a refusal): `typ` one of `kb+sd-jwt`, `kb-sd-jwt` (terminal),
`kb+sd-jwt+kb`, `kb-sd-jwt+kb` (intermediate), compared as §13 says (`chain_hop_typ`); exactly one of `sd_hash` and
`issuer_jwt_hash` at the top level of the hop's resolved claims, equal to BASE64URL(SHA-256) of the previous hop's
`<jwt>~<d>*~` (its compact form without a KB-JWT) or of its issuer JWT (`chain_binding_mismatch`); a terminal hop with a
`cnf` in `delegate_payload` (`chain_terminal_with_cnf`), an intermediate one without (`chain_intermediate_without_cnf`);
a terminal hop without `iat` (`chain_terminal_without_iat`: the SDK's `verify_expected_claims`, `common.py`, which
`kb_sd_jwt.verify` runs on terminal types only — presence, which needs no context). Two rules are the working group
draft's, which the SDK does not ask: the hop's resolved `delegate_payload` is an array of exactly one element
(`chain_delegate_payload`; draft-ietf-oauth-delegate-sd-jwt-00 §6 step 3.2, "exactly one disclosed element in the
delegate_payload array"; every hop of the 107 public chains that verify and of the vectors has one, measured
2026-11-18), and a hop followed by a delegate KB-JWT is not a terminal type (`chain_kb_jwt_after_terminal_hop`; §6 step
4.2, "If the credential is a dSD-JWT+KB then the typ MUST be kb-sd-jwt+kb"). A hop of an intermediate type may be the
last (that draft's §4.2 and §6 step 4.2: Key Binding is optional for the final KB-SD-JWT).
Not checked, as for a KB-JWT (§6 step 2): `aud`, `nonce`, the values of `iat` and `exp` — transaction context and time an
offline verifier cannot know (goodmeta/ap2-conformance vectors `aud_mismatch`, `nonce_mismatch`, `expired` stay valid
here, declared).
Declared difference from the SDK: an item of `delegate_payload` that is a bare digest string, which the SDK resolves
against the hop's disclosures (`_resolve_delegate_payload`, "the CMWallet format"), is no reference under RFC 9901
(§4.2.4.2: an array element is referenced by `{"...": "<digest>"}`), so its disclosure is one no digest refers to and the
hop is refused (§7.1 step 5, "MUST be rejected"); `test_ap2_chains.py` holds the case.

**Verification.** For an artifact whose class is `chain_cnf`, the artifact named by `chain_from` must come before it in
`artifacts` and have verified (signature and claims), its `cnf.jwk` (the rule above, recomputed) must equal the recorded
key on `kty`, `crv`, `x`, `y`, and the hop rules hold; otherwise that artifact's error. The receipt's artifact entry then
carries `chain_hop: {"binding": "sd_hash" | "issuer_jwt_hash", "terminal": bool, "from": name}`. In `holder_binding`
(§6.9) such an artifact is an element, `verified`: the hop is the holder binding of the hop before it, checked under the
key that hop delegated to. In `issuer_identity` its key is `self_asserted`, as `supplied` (the previous hop, not a CA under
the relying party's anchor, vouches for it), so `self_asserted_only` stays true for a chain unless the format changes that
in a later revision. A 1.8.x verifier refuses a pack with a `chain_cnf` key (unknown class, unknown key `chain_from`).

**Outside a chain (declared).** For an artifact that is not a `chain_cnf` hop — a mandate presented alone, a hop of a
chain split by hand and given under a supplied key — a KB-JWT is evaluated as §6 step 2 says, under the `cnf.jwk` at the
top level of the resolved claims only: a `cnf` inside `delegate_payload` is the key of a hop to come, and no rule of
RFC 9901 or of the draft makes it the holder key of that artifact's own KB-JWT. Such a KB-JWT is `verified: null`,
`holder_key_unknown` (never a pass, never a failure), as before 1.9.0.

**A plain JWS.** An AP2 receipt is a JWS, not an SD-JWT; it enters as `<jwt>~`, an SD-JWT with no disclosures (RFC 9901 §4),
which the signature does not cover and does not change. `sd_jwt_no_separator` says so.

**Measured on 2026-11-18** (`test_ap2_chains.py`, vectors in `spec/vectors/ap2_chains/`): the 23 chain vectors of
goodmeta/ap2-conformance @41dff653 — the 3 valid ones and `aud_mismatch`, `nonce_mismatch`, `expired` built and valid
with `holder_binding` verified, the 17 others refused at `build` (6 of them for the vector's own reason that this format
did not check before: sd_hash mismatch, both binding claims, neither, wrong `typ`, terminal with `cnf`, intermediate
without; 5 `x5c` vectors, `valid_x5c` among them, for the base64url encoding of their certificates, RFC 7515 §4.1.6,
and the sixth for its `alg`, ES384); 145 tokens holding `~~` re-read from 15 public repositories (143 chains: in 107
every hop after the root verifies under the previous hop's `cnf.jwk` and these rules, 36 are refused by name; 1.8.0
read none); three chains emitted by the AP2 SDK (two built and valid, the mixed one refused as the SDK refuses it).

## 3. Canonicalisation and digest (NORMATIVE)

`evidence_digest_sha256 = HEX(SHA-256(canonical_bytes))` where `canonical_bytes`
is the JSON serialisation of the top-level object **excluding** the keys
`evidence_digest_sha256`, `rfc3161_timestamp`, `producer_signatures`, `anchors` (1.5.0; no 1.0–1.4 pack carries it, so
no digest of an earlier pack changes), with:

- keys sorted lexicographically, recursively;
- separators `(",", ":")` — no insignificant whitespace;
- ASCII-escaped output (`ensure_ascii`): every non-ASCII character as `\uXXXX`.

(The file's own indentation/escaping on disk is NOT significant — the digest
is over the canonical form, not the file bytes.) The time anchors and the
producer signatures are outside the digest so they can be attached after
sealing without changing what they attest.

### 3.1 Acceptance profile of the evidence file (NORMATIVE, 1.1.0)

So that every implementation computes the same canonical bytes or refuses the same
file, a verifier MUST refuse (a receipt with `valid: false`, never a crash) an evidence
file that: is not a regular file (a FIFO, a device, a directory — decided on the opened file, which is opened without
blocking and never read past 64 MiB + 1 byte; added 25/09/2026, 1.2.1); is not valid UTF-8 or starts with a BOM;
exceeds 64 MiB; is not a JSON object;
contains a duplicate object key at any depth; contains a number with a fraction or an
exponent (floats are not portable — use a string) or an integer outside ±(2^53−1);
contains `NaN`/`Infinity`; nests deeper than 512; contains an unpaired UTF-16 surrogate
escape (`\uD800`–`\uDFFF` not forming a pair). Non-ASCII text is in profile (the
canonical form escapes it). base64url segments of the SD-JWTs (RFC 7515 §2) and base64
values of the producer block (RFC 4648) are strict: alphabet only, no whitespace, no
padding on base64url, canonical trailing bits; a segment spelled any other way is a
verification failure of that artifact/signature, not a re-encoding.

A path that names no file, or a regular file this process is not allowed to read, is not an evidence file: the command line
reports it as a usage error (exit 2, one line on stderr, no receipt), as for `--tsa-cert` (1.10.0; up to 1.9.0 it was a
refusal of class `malformed`, a statement about a pack that was never read). A FIFO, a device or a directory is the
refusal above (`not a regular file`) whatever its permissions.

The same profile applies to the JSON INSIDE the SD-JWTs — the issuer JWT header and
payload, every disclosure, the KB-JWT header and payload: strict UTF-8, no BOM, no
duplicate keys, no floats, bounded integers and depth, no lone surrogate. A signed
payload with a duplicate key (`{"amount":"1","amount":"999"}`) is refused, not read
"last wins" by one verifier and "first wins" by another. Shapes are imposed, and a key
present with `null` is NOT the same as an absent key: `_sd` absent or a list of strings;
`_sd_alg` absent or exactly `"sha-256"`, and only at the top level of the issuer payload; an array placeholder
`{"...": d}` with `d` a string, and the key `...` nowhere else (1.8.1, §6 step 2); a disclosed claim name a string; `cnf` absent or an object, `cnf.jwk` absent or an
object (an empty object is a holder key that fails to parse, not an unknown holder);
JWK `x`/`y` exactly 32 bytes each (RFC 7518 §6.2.1) and, since 1.10.0, each below the prime p of P-256 (§6.2.1.2 and
§6.2.1.3 write a coordinate by SEC 1 §2.3.5, whose input is a field element in [0, p − 1]; up to 1.9.0 the reference's
library reduced an x written x + p to a point, node:crypto refused it; now `JWK x/y is not a point of P-256` in the
reference, refused by node:crypto in the JS verifier); `key.provenance_class` in the §2 enum;
`rfc3161_timestamp.anchored` a boolean; `producer_signatures.signatures[].sig_alg` a
string (any other type is a FAIL entry). A violation inside an artifact is that
artifact's error (the pack is not `valid`); a violation of a top-level shape is a refusal.

1.7.2 — numbers in the SD-JWT layer (NORMATIVE, both verifiers). The JSON texts inside an SD-JWT are written by another
producer under RFC 8259, and the AP2 schema types `payment.budget.max` as `number` (`open_payment_mandate.json`,
`$schema` 2020-12): the AP2 SDK at `e1ea56d` (`Budget.max: float`) writes `Budget(max=10)` as `"max":10.0`. JSON Schema
Core 2020-12 §6.3 says integer JSON numbers "SHOULD NOT be encoded with a fractional part"; this profile follows it on the
reader's side by default, and treats the exponent form (`1e2`), which §6.3 does not name, the same way, and gives the relying party an explicit option for the mandates already written that way.

- **Default.** In those texts — the issuer JWT header and payload, every disclosure, the KB-JWT header and payload — a
  number literal written with a fraction or an exponent is that artifact's error, the literal named first
  (`float '10.0' in the SD-JWT needs accept_integral_floats`), whatever its value. Same as 1.7.1 in effect
  (a 1.7.1 verifier refused such a token as `float '10.0' in the evidence file`); only the message changes.
  1.9.0: a literal the option would not read either (`0.1`, `1E400`) is named as that, with or without the option
  (`float '0.1' in the SD-JWT: not an integer within +/-(2^53-1)`); up to 1.8.x the default message sent the reader to
  an option that refuses the same token.
- **`accept_integral_floats`** (a boolean, default false; `--accept-integral-floats` on `build`, `verify` and
  `restriction`, `acceptIntegralFloats` / `--accept-integral-floats` in the JS verifier; in an expected file, a policy key,
  §7). Under it, such a literal whose value is an integer within ±(2^53−1) is READ as that integer: `10.0`, `1e2`,
  `250.00`, `-0.0` are 10, 100, 250, 0. The decision is taken on the decimal digits of the literal, exactly (the digits the
  point and the exponent leave below the units are all zero), never by binary64 arithmetic: `10.000000000000000001` is NOT
  an integer here, though `float()` and `Number()` make it 10. A literal whose value is not an integer (`0.29`, `1e-7`) or
  is an integer outside the range (`1e16`, `9007199254740992.0`, `1E400`) stays that artifact's error under the option too
  (`float '0.29' in the SD-JWT: not an integer within +/-(2^53-1)`). The option is REPORTED: the receipt carries
  `accept_integral_floats: true`, and each artifact entry `integral_literals_read`, the literals of its token read that
  way, in the order parsed (each cut to 30 characters); `build` reports the same two members. Without the option neither
  member is present, and the receipt is the 1.7.1 receipt except for the message of the default above.

Rules relied on for the reading: JSON Schema Validation 2020-12 §6.1.1 (`integer` "matches any number with a zero
fractional part"), RFC 8785 §3.2.2.3 (the canonical serialization of 10.0 is `10`), RFC 8259 §6 (integers in that range
are the numbers implementations "agree exactly" on). The signed bytes are never rewritten: the ES256 signature, the
disclosure digests and the KB-JWT `sd_hash` are checked over the base64url segments as received; the integer is what the
pack RECORDS (`resolved_claims`, under the file profile above, which has no literal with a fraction) and what §11
compares. A pack `build` writes under the option verifies only under the option (without it, that artifact's error):
the option is a decision of the relying party, stated each time, never a property the pack carries. The evidence file
itself is unchanged: a literal with a fraction or an exponent anywhere in the file, `10.0` included, is a refusal with or
without the option. Declared: a schema-valid AP2 budget with a fraction (`0.29`) cannot be carried by this format, and
its unit is open in AP2 (#339, #368, #377). Measured 2026-11-02, six open payment mandates minted by the AP2 SDK at
`e1ea56d` with `max` 10, 10.0, 0.29, 250, 1000 (JPY), 100 (EUR): the SDK wrote all six with a fraction (`10.0`, `10.0`,
`0.29`, `250.0`, `1000.0`, `100.0`); 1.7.1 refused all six; 1.7.2 refuses all six by default and, under the option,
carries the five integral ones and refuses `0.29`.

Direction read on 2026-11-03 (sources checked that day; this profile's reading, not a rule of AP2): money amounts are
converging on integers in ISO 4217 minor units — AP2's own `types/amount.json` (`amount`: "Amount in minor units") and
`payment.amount_range.max` (`integer`), Verifiable Intent (`agent-intent/verifiable-intent`, `spec/constraints.md` §4.5:
`mandate.payment.budget` `max` an `integer` in minor units; §4.4, on every amount of those constraints: "Using integers
eliminates decimal parsing ambiguity entirely"), and the proposal of AP2 #389 (make `budget.max` an integer in minor
units). In the #389 thread its author agreed that a migration note should state the reader rule "a reader may reject
`10.0` rather than coerce it" — in reply to a comment by this profile's author, naming this profile: not an
independent signal. The exception is the SDK's `Budget.max: float` in major units at `e1ea56d`, unchanged on
`main` since 2026-04-29; three open pull requests by different authors keep that type in major units — #340 states the major
unit in the schema's description, #368 and #377 fix the SDK's conversion to minor units — so a fractional budget such as `0.29` USD would stay legitimate there. The core specification has moved to
FIDO (AP2 `CONTRIBUTING.md`), where no public text on this was found. Hence the default refuses what Core §6.3 says not
to write and what the integer direction makes unnecessary, and `accept_integral_floats` carries the mandates already
written by the SDK; if the major-unit reading prevails, a fractional budget remains outside this format (declared above)
and the rule is revisited in a later revision.

1.9.0 — a number that is not an integer (declared, measured 2026-11-18). RFC 7519 §2 lets a JWT write a NumericDate
"that can represent non-integer values", and JSON numbers are not integers in general (RFC 8259 §6); 8 of 662 SD-JWTs found
in public repositories carry one (`iat: 1.673987547e+09`, `age: 24.6`, `0.1`), and this format refuses each, with or without
`accept_integral_floats` (8 tokens of 5 repositories; `1000.0` among them is carried under the option). The reason stays:
the pack records the resolved claims (`resolved_claims`) inside the sealed canonical form, which two verifiers in two
languages must reproduce byte for byte; this revision defines no canonical spelling of a non-integer number (Python and
JavaScript print binary64 values differently, e.g. `1e+21` and `1e21`), so a pack could not carry such a claim and stay
verifiable by both. A JWT with a non-integer number is outside this format, by this format's choice and not by RFC 7519;
a later revision may carry such claims as the literal text (RFC 8785 §3.2.2.3 gives one canonical form) — open.

1.7.1: the depth bound applies to the claims RESOLVED from an SD-JWT as well (§6 step 2): each JSON text of a token can be
within the profile while a chain of disclosures, each nested in the one before, resolves into claims as deep as the chain.
A producer MUST NOT write a pack this profile refuses: the reference `build` checks the pack under this profile — its
canonical form, and the size of the file it would write — before it asks any TSA, checks the size again with the TSA
blocks, and refuses (exit 1, one line `{"error": …}` on stderr, no file) what `verify` would refuse; `stamp` and
`sign_evidence` check the size of the pack with the block they add and refuse, the pack unchanged, one over 64 MiB. Up to
1.7.0 they wrote such packs — measured 2026-10-29: `build`, claims resolved 510 to 988 deep (510 to 990 on Python 3.13), a
`--key` JWK with a member nested 600 deep or a member that is a float, a pack of 116 670 431 bytes (a token with one 50 MB
disclosure); `stamp` and `sign_evidence`, a pack 200 bytes under the bound taken to 67 109 963 and 67 116 150 bytes.

### 3.2 RFC 3161 token check (NORMATIVE when `anchored`)

`rfc3161.verified` is `true` iff the token parses as a TimeStampResp, its status is
granted (0 or 1) and the TSTInfo `messageImprint` equals the recomputed
`evidence_digest_sha256`; `false` otherwise (a claimed-but-failing anchor rejects the
pack). `verified` states BINDING, not TSA authenticity: a self-forged TimeStampResp
with the right imprint satisfies it. TSA authenticity is `rfc3161.tsa_verified`: the
reference verifies the token's signature and chain with `openssl ts -verify -CAfile`
when the relying party passes `--tsa-cert <PEM>`. A SignerInfo may name its signer by issuerAndSerialNumber or by
subjectKeyIdentifier (RFC 5652 §5.3, Internet Standard, updated by RFC 8933 and 9629; status read on rfc-editor.org on
2026-11-17); `openssl ts` reads the token as PKCS #7 and refuses the second form with an ASN.1 error, so until 1.8.0 a
valid token of that form was `tsa_verified: false` (measured on 2026-11-17 with OpenSSL 3.0.22 on a token re-signed by
`openssl cms -sign -keyid -cades`). For that form (1.8.0, as cryptovalid-opencore SPEC §11 step 7) the same checks are
made one by one: the CMS signature and messageDigest (`openssl cms -verify -noverify`, the signer looked up in the token
and in the `--tsa-cert` file); the TSTInfo imprint; a signed ESS attribute signingCertificate (RFC 2634) or
signingCertificateV2 (RFC 5035), each one present with exactly one value, its first ESSCertID naming the signer
certificate (hash, and issuer and serial number when present) — 1.9.0, more than one ESSCertID: RFC 2634 §5.4 as RFC 5035
rewrites it (read on rfc-editor.org on 2026-11-18; 2634 updated by 5035, neither obsoleted), the first "MUST be the
certificate" that verifies the signature and the ones after it "limit the set of certificates that are used during
validation": every ESSCertID a known hash algorithm and a certHash of its length, no certificate listed twice, a later
one that hashes a certificate of the token naming it in its issuerSerial when it carries one, and the `-untrusted`
certificates below restricted to the token certificates a later ESSCertID names (with v1 and v2 both listing more than
one: the certificates both name); up to 1.8.x a list longer than one was refused ("exactly one is evaluated here"), so a
TSA listing its chain (openssl `ess_cert_id_chain = yes`) was `tsa_verified: false` on this path (`test_ap2_tsa_ess_ids.py`;
the issuerAndSerialNumber form is `openssl ts -verify`'s as before, which asks every ESSCertID to be in the chain it
builds); the TSTInfo `tsa` field, when present, naming the
signer's subject or one of its subjectAltName; the names (that issuer, that subject, a directoryName) compared as
OpenSSL's `X509_NAME_cmp` compares them (string values in UTF-8, white space trimmed and folded, ASCII letters
lowercased; the same RDNs in order), the serial number as an integer; and `openssl verify -purpose timestampsign -attime <genTime> -CAfile
<--tsa-cert> -no-CApath -no-CAstore -untrusted <the token's certificates>` over the signer certificate, which is the
chain `openssl ts -verify -CAfile` builds for the other form (no system store, no partial chain). An openssl that on this path is
killed by a signal, gives no answer within 30 s or cannot be started, or a temporary file it needs that cannot be
written, is a check not run here, `tsa_verified` `null`
(§6.10; 1.10.0 — up to 1.9.0 it was `false`, a finding about the token: measured 2026-11-20 with an openssl killed by
SIGKILL in `cms -verify` and in `verify`, with one answering after 45 s, and with a write of each of the two files of
this step failing with ENOSPC). Closed shapes (1.8.0,
measured on 2026-11-17 with the generative bench of omega-cra-evol's port of this step): exactly one SignerInfo (RFC
3161 §2.4.2: "The time-stamp token MUST NOT contain any signatures other than the signature of the TSA"; until this
correction a token with two SignerInfos, both verifying, was `tsa_verified: true` here, where `openssl ts -verify`
refuses two signers in the other form); every signed attribute `{attrType OID, attrValues SET}` and nothing else, a
SigningCertificate(V2) `{certs, policies?}` with `policies` a SEQUENCE OF PolicyInformation, the ESSCertID a SEQUENCE
(the CMS signature, checked first, already refused every such change: 536 generated variants, 0 accepted); an openssl
whose `verify` does not know `-no-CAstore` (before OpenSSL 3.0) is a check not run here: `tsa_verified: null` with the
note (§6.10), not `false`. The JS verifier cannot (no openssl)
and reports `null` (1.6.0: and states `time_anchor` `not_evaluated` with `instrument_failure`, §6.9). Under `--require-anchor --tsa-cert`, `tsa_verified` must be `true`
for `policy_ok` — so the JS verifier never passes that policy (declared divergence).
`tsr_b64` is strict base64 (RFC 4648) like the producer block. Both verifiers report the
TSTInfo `genTime` as `rfc3161.gen_time` (GeneralizedTime, UTC, or `null` when absent or
malformed); the reference validates the TSA chain **at that time** (`openssl ts -verify -attime`)
when the token carries a well-formed `genTime`, so a TSA certificate that expired after
issuing the token does not turn `tsa_verified` false years later; with no usable `genTime`
the chain is validated at the current time instead (an expired certificate then fails).
Revocation is not checked (declared).

**Signer certificate absent (1.8.1, 2026-11-18).** Before openssl runs, the reference looks for the certificate the
SignerInfo's `sid` names (RFC 5652 §5.3: issuerAndSerialNumber, the issuer compared as `X509_NAME_cmp` and the serial as
an integer; subjectKeyIdentifier, against the certificate's subjectKeyIdentifier extension) where the check would look:
the token's certificates, and for the subjectKeyIdentifier form also the `--tsa-cert` file (`openssl cms -verify
-certfile`; `openssl ts -verify -CAfile` does not look for the signer in the CA file). When every certificate there was
read and none is that one — a token requested with certReq FALSE (RFC 3161 §2.4.1), or one whose `[0] certificates` is
present and empty, as sigstore's TSA writes it — the signature cannot be evaluated: `tsa_verified` is `null`, never
`false`, with `tsa_reason: "signer_certificate_absent"` and a `tsa_note`, and `time_anchor` says `not_evaluated /
signer_certificate_absent` (§6.9). ETSI EN 319 102-1 V1.4.1 (2024-06) §5.2.3.3: "In case the signing certificate cannot
be identified, the output shall be the indication INDETERMINATE and the sub-indication NO_SIGNING_CERTIFICATE_FOUND";
cryptovalid-opencore SPEC v0.11 §11 step 6 reads such a token the same way. Anything not read keeps the check as
before. Effect on the time bounds, the same as `tsa_invalid`: under `--tsa-cert` only a `tsa_verified: true` token is
counted (§3.3), so this token gives no proven upper bound — `anchors_verified` does not count it, `existed_by` and the
§12 window take no time from it, `--require-anchor` / `--min-anchors` are unmet if it was the one needed; the binding
(`rfc3161.verified`) and `valid` do not change. Up to 1.8.0 such a token was `tsa_verified: false`,
`not_evaluated / tsa_invalid` — measured on 2026-11-18 on v1.8.0: freetsa's token of cryptovalid-opencore's
spec/vectors/rfc3161 with its certificates removed, the freetsa CA given, openssl "PKCS7_get0_signers:signer
certificate not found". The JavaScript verifier does not check a TSA (`instrument_failure`, as before).

### 3.3 Additional time anchors: `anchors` (NORMATIVE, 1.5.0)

One RFC 3161 token depends on one TSA key, which ages; mechanisms that fail in different ways (another TSA; in a later
revision another kind of commitment, such as an RFC 4998 renewal) can only add protection if the pack can carry more
than one. Before
1.5.0 it could not: a second token as a new top-level key changes the digest, and inside `rfc3161_timestamp` it is a
refusal (§9.1). `anchors` is the place for them.

- `anchors` is OPTIONAL; when present it is a non-empty list (an empty list, or a non-list, is a refusal).
- Each entry is a closed object (§9.1) with `mechanism` (string, MUST). This revision defines one mechanism:
  `"rfc3161"`, with `tsr_b64` (string, MUST: strict base64 of a DER TimeStampResp), `tsa_url` (string) and `note`
  (string). A `mechanism` this revision does not define is a refusal naming it — never skipped: a verifier that cannot
  check an anchor must not let the pack look as if it had one. A new mechanism is a new revision of this text.
  Order (1.5.4): each entry is checked in list order — not an object, then `mechanism` missing, then not a string, then
  not defined here (the refusal naming it), and only then the §9.1 scan of that mechanism's keys. The keys of an entry
  are listed PER MECHANISM, so for an undefined mechanism there is no list to scan against: an entry with an undefined
  mechanism and a key unknown to `rfc3161` is refused for its mechanism, not for the key (vector
  `anchors_unknown_mechanism`).
- Every `rfc3161` entry is checked exactly as §3.2 checks the `rfc3161_timestamp` token, against the RECOMPUTED digest:
  `verified`, `granted`, `imprint_ok`, `gen_time`, `tsa_verified` (`--tsa-cert` takes a PEM file that may hold the
  certificates of several TSAs). A claimed entry whose binding fails rejects the pack, like a failing
  `rfc3161_timestamp` token: an anchor is never ignored because another one verifies. An entry whose TSA signature does
  not verify under `--tsa-cert` is not counted (below): it does not reject the pack by itself, only through a policy it
  then fails to meet.
- Every `rfc3161` entry commits to the pack's digest, not to the anchors already present: a token added later proves
  existence from its own time only. It is not a renewal in the sense of RFC 4998 (which re-stamps the earlier evidence).
- The receipt lists one result per entry in `anchors` (same order), each carrying `mechanism`.
- **Counting.** An anchor COUNTS when its binding is verified and, when the relying party passed `--tsa-cert`, its TSA
  signature is verified too. `anchors_verified` (normative, an integer) is the number of DISTINCT counting anchors
  among the `rfc3161_timestamp` token and the `anchors` entries; two entries are the same anchor when the TSTInfo they
  carry — the eContent the TSA signed (RFC 3161 §2.4.2) — is byte-for-byte equal: a copied token is one anchor however it
  is re-wrapped (bytes after the TimeStampResp, a status string, a longer length encoding leave the signature valid).
  Distinct tokens from the same TSA share that TSA's key: this
  count does not establish that they fail independently — a relying party that needs that reads `gen_time` and the TSA
  of each entry (declared).
- `rfc3161_claimed` is true when the `rfc3161_timestamp` block is anchored OR `anchors` holds an `rfc3161` entry;
  `rfc3161_verified` is `null` when nothing is claimed, `false` when ANY claimed RFC 3161 token fails its binding, and
  `true` otherwise. On a pack without `anchors` both fields are what 1.4.x reports.
- **Policy.** `min_anchors` (a verifier input, integer ≥ 1; any other value is an error of the caller, never a weaker
  policy): `policy_ok` is false when `anchors_verified` < `min_anchors`.
  `require_anchor` is `min_anchors = 1` when no larger value is given. How many anchors a relying party requires is its
  decision; the pack never states it.
- The time at which §6 step 7 validates x5c chains is the EARLIEST `gen_time` among the counting anchors that are
  TSA-verified (the strongest existence bound the pack proves); with none, the current time, as before.

## 4. Bindings (NORMATIVE)

A binding records that one artifact commits to another **by value**: artifact
`A` binds `B` iff some string value anywhere in `A`'s resolved claims equals
`HEX(SHA-256(B.sd_jwt_compact))` (lowercase hex) or `BASE64URL(SHA-256(B.sd_jwt_compact))`
(no padding) — the hash of the exact compact serialization (the primary quantity, not a
proxy field). Each binding is the object
`{"in": A.name, "claim": <path>, "commits_to": B.name, "encoding": "hex" | "b64url"}`
where `<path>` locates the matching value in `A`'s resolved claims: object keys joined
with `.`, array positions as `[i]`, no leading separator (`cart.items[0].ref`, `intent_hash`).
An artifact never binds itself. The recorded `bindings` is a **set** (a JSON list whose
order carries no meaning): a verifier MUST recompute every binding and compare the two lists
as multisets of canonical entries (each entry in the §3 canonical form, sorted); any
difference fails the pack. 1.1.0 r4: an ordered comparison split the verdict between two
conformant verifiers on a pack the reference built (JavaScript enumerates array-index keys
such as `"0"` before the other keys, whatever the insertion order).

**Over the issuer JWT (1.9.0).** `A` also binds `B` iff some string value anywhere in `A`'s resolved claims equals
`HEX(SHA-256(B.issuer_jwt))` or `BASE64URL(SHA-256(B.issuer_jwt))`, where `B.issuer_jwt` is the first `~`-separated
component of `B.sd_jwt_compact` (the issuer-signed JWT, ASCII bytes, without disclosures or KB-JWT); that binding
carries one more member, `"over": "issuer_jwt"` (the object above without `over` is over the compact serialization, as
before; `over` with any other value is that pack's refusal, `unknown_member` style, §9.1). It is AP2's receipt rule: a
receipt's `reference` is "the SHA-256 of" the closed mandate's JWT, "so a receipt stays bound to the same closed mandate
regardless of how many delegation hops precede it or which open-mandate disclosures were revealed"
(google-agentic-commerce/AP2 `code/sdk/python/ap2/sdk/mandate.py`, `get_closed_mandate_jwt`, lines 402-417 at commit
`e1ea56db72a6385bce3e5c1112b3a56ce60acb43`, base64url, read on 2026-11-18). The two hashes of one `B` are over
different strings (the compact form always holds at least one `~` more), so one value is not both; a value may still
bind two different artifacts, and each binding found is recorded. Up to 1.8.0 a receipt issued by the AP2 SDK over a closed mandate of the pack bound nothing
(measured on 2026-11-18: `reference` = BASE64URL(SHA-256(closed issuer JWT)), not the hash of its compact form). A 1.8.x
verifier refuses a pack holding a binding with `over` (unknown key in a binding, §9.1).

**The recorded set, since 1.9.0.** A pack built before 1.9.0 records no binding over the issuer JWT, and such a pack
must stay verifiable. So the recorded `bindings` are the recomputed set (as above), or the recomputed set without EVERY
binding that carries `over` — all of them left out, never some; any other difference fails the pack (`bindings_ok`
false, `binding_mismatch`). When bindings over the issuer JWT are found and not recorded, the receipt of both verifiers
lists them in `bindings_not_recorded` (absent otherwise; sorted by canonical form, §3), and `require_binding` (§6.9) reads the recomputed set, so it
finds them. The reference `build` records every binding. Measured on 2026-11-18: a pack built by v1.8.0 from an AP2 SDK
chain split by hand and its receipt (`spec/vectors/ap2_chains/pack_built_by_1.8.0.json`), `valid: true` under 1.8.0, was
`binding_mismatch` under the first draft of this revision, which asked equality alone; it is `valid: true` with one entry
in `bindings_not_recorded`, and `require_binding receipt->closed` is met.

## 5. Producer signatures (NORMATIVE when present)

```json
{"scheme": "hybrid" | "classical-only",
 "over": "evidence_digest_sha256",
 "signatures": [{"sig_alg": "ed25519" | "ecdsa-p256" | "ml-dsa-65",
                 "public_key_b64": "<base64 raw key>",
                 "signature_b64": "<base64 signature>",
                 "post_quantum": bool}]}
```

Each signature is over the **ASCII bytes of the lowercase hex**
`evidence_digest_sha256` as **recomputed** by the verifier (never the declared
value — recompute-from-content is the rule). Key/signature encodings: `ed25519`
raw 32-byte key / 64-byte signature; `ecdsa-p256` X9.62 uncompressed point
(65 bytes, leading `0x04`) / raw `r||s` (64 bytes), SHA-256; `ml-dsa-65`
FIPS 204 **final** ML-DSA-65, external/pure interface, **empty context** —
raw 1952-byte key / ≈3309-byte signature. (The ML-DSA-65 path is checked
against NIST ACVP sigVer vectors in `pqcrypto/vectors/`: the 15 cases of the ML-DSA-65
external/pure group of usnistgov/ACVP-Server at a pinned commit, generated by
`make_acvp_mldsa65.py`; NIST's notice and the changes in `NIST-ACVP-NOTICE.txt`.)

Verification is fail-closed: any present-but-invalid signature makes the block
(and the pack) invalid; an unknown `sig_alg` or a missing PQ backend is a
verification GAP (skip), and a block with any gap or zero passing signatures is
never `ok`. 1.4.0 (§9.1): the block is a closed object — exactly `scheme` (one of the two
values above), `over` (exactly `"evidence_digest_sha256"`) and `signatures` (a list); any other
key, a missing key or a wrong type is a refusal of the file. Each entry is a closed object —
exactly `sig_alg` (string), `public_key_b64` (string), `signature_b64` (string),
`post_quantum` (boolean) — and an entry with any other key, a missing key, a wrong type, or
a `post_quantum` that contradicts `sig_alg` (`true` iff `sig_alg` is `ml-dsa-65`) is a FAIL
entry (the block is not `ok`). `scheme` is reconciled with the entries: `hybrid` requires at
least one entry with a classical `sig_alg` (`ed25519`/`ecdsa-p256`) AND at least one `ml-dsa-65`
entry; `classical-only` requires no `ml-dsa-65` entry; a block whose scheme does not match its
entries is not `ok` (measured 2026-10-10 on 1.3.0: `scheme: "hybrid"` over a lone Ed25519
signature was `producer_ok: true`). **Pinning:** an embedded key proves internal consistency, never
authenticity. When the relying party supplies a pinned trust set
(`{sig_alg: [public_key_b64, ...]}`), `producer_trusted` is `true` only if every
present signature's key is pinned; a valid-but-unpinned signature MUST reject
the pack even with no policy flags set. 1.10.0: a pinned set implies `require_producer` — a pack without a producer
block does not meet it (§6 step 6). Without a pinned set `producer_trusted`
is `null` and the pack MUST NOT be treated as authentic. `pq_protected` is true
only on a valid ML-DSA-65 signature whose key is pinned (or no pin set given).
1.5.4: both are statements about a block that verified. When the block is not `ok`, `producer_trusted` is `null`
(pinned set given or not) and `pq_protected` is `false` (a valid pinned ML-DSA-65 entry beside a failing entry
included); so `require_pq` (§6 step 6) is never met by a block that is not `ok`. Such a pack is not `valid` (§6 step
8, unchanged): 1.5.3 (measured on `f03abbc`) reported `producer_trusted` `true` when every key was pinned and the block
failed through an entry or its `scheme`, `false` when the block held a SKIP entry or no entry, `pq_protected` `true` on
any block holding a valid ML-DSA-65 entry whose key was pinned (or no pinned set), and so, under `require_pq`, `policy_ok`
`true` where both were `true` (vectors
`producer_mldsa_fails_pinned`,
`producer_classical_fails_pinned`, `producer_classical_fails_unpinned`).

## 6. Verification algorithm and verdict (NORMATIVE)

Inputs: the pack file, an optional pinned producer trust set, three policy
flags: `require_producer`, `require_pq`, `require_anchor`, and `min_anchors` (1.5.0, §3.3).

1. Parse under the profile (§3.1; duplicate keys reject). Refuse unless `evidence_format` is
   exactly `"ap2-evidence-pack/1.0"`, unless `honest_scope` matches the canonical scope of that version
   by SHA-256 (§1, §8), and unless `subject`, `created_utc`, `honest_scope` are strings
   (§1 MUSTs — 1.1.0 r5: a `…/2.0` pack used to be verified under the 1.0 rules, and a pack
   with no `honest_scope` produced a receipt with `honest_scope: null`). Recompute the digest (§3) → `digest_ok`.
2. For EVERY artifact: parse `sd_jwt_compact` (1.8.1, its grammar closed as RFC 9901 §4 writes it: `SD-JWT = JWT "~"
   *(DISCLOSURE "~")`, `SD-JWT-KB = SD-JWT KB-JWT`, `DISCLOSURE = BASE64URL` of at least one character; "In the case that
   there is no Key Binding JWT, the last element MUST be an empty string and the last separating tilde character MUST NOT
   be omitted". Split on `~`: no `~` → `sd_jwt_no_separator`; an empty component other than the last →
   `sd_jwt_empty_component`; a last component that is not empty and not three dot-separated segments →
   `sd_jwt_final_component_not_kb_jwt`; each that artifact's error, its name first in the message (the reference's receipt writes `Ap2EvidenceError: ` before
   it); vectors
   `sd_jwt_no_separator`, `sd_jwt_empty_component`, `sd_jwt_no_trailing_tilde`; its JSON under the §3.1 profile, numbers in the SD-JWT layer as its 1.7.2
   paragraph says, with or without `accept_integral_floats`); apply the JOSE rules of §9.2 to the
   protected header (`crit` → RFC 7515 §4.1.11, unknown parameters ignored and reported); 1.7.3, compare every key source
   of the header that is not the source of the snapshotted key (§2 (d)): a `jwk` or `x5c` naming another key, or not a
   key, is that artifact's error, and the names go to `ignored.key_material`; verify the ES256 signature with
   the snapshotted JWK over the JWS signing input — only when the signed header's `alg` is `"ES256"` (1.10.0, RFC 7515
   §5.2 step 8: the signature is validated "in the manner defined for the algorithm being used, which MUST be accurately
   represented by the value of the `alg` (algorithm) Header Parameter"); any other value, or none, is that artifact's
   error `issuer_alg_not_es256`, as `build` already refused it. Up to 1.9.0 verify checked ES256 whatever the header
   named: measured 2026-11-20, a header saying `none`, `HS256`, `ES384` or `RS256` over an ES256 signature of the issuer
   was `valid: true` in both verifiers; resolve disclosures
   fail-closed (unmatched, duplicate, or malformed disclosure → reject — for an UNMATCHED
   disclosure this is RFC 9901 §7.1 step 5 verbatim, "the SD-JWT MUST be rejected"; 1.7.0, a digest value encountered
   more than once while resolving — in an `_sd` array or as a `{"...": d}` array placeholder, in the payload or inside a
   disclosed value, whether or not a disclosure matches it (a decoy counts) — → reject at the second encounter, before
   anything under it is resolved, RFC 9901 §7.1 step 4 verbatim, "If any digest value is encountered more than once in
   the Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST be rejected" (vectors
   `sd_digest_repeated`, `sd_digest_repeated_sd`; up to 1.6.0 both verifiers expanded a repeated array placeholder twice,
   `valid: true`, the mandate twice in `resolved_claims.delegate_payload`, measured 2026-10-28); 1.7.0, a disclosure
   matched from an `_sd` array whose claim name is `_sd` or `...`, at any level, → reject, §7.1 step 3.c.ii.2 verbatim,
   "If the claim name is _sd or ..., the SD-JWT MUST be rejected" (vector `sd_claim_name_reserved`; up to 1.6.0 both
   verifiers inserted it as an ordinary claim, measured 2026-10-28) — the name `_sd_alg` is not in that rule: this
   format keeps a disclosure so named as an ordinary claim at every level (this format's declared reading, both
   verifiers); 1.8.1, the reserved names as PLAIN keys, in the payload and in every disclosed value, at any level: a key
   `...` anywhere but as the only key of an array element whose value is a string (the placeholder of RFC 9901
   §4.2.4.2) is kept as an ordinary claim and REPORTED — the receipt's artifact entry carries
   `reserved_names_in_clear: {"...": <count>}` (absent when there is none), in both verifiers, and the build result names
   the artifact — and a key `_sd_alg` in any object but the payload's top level →
   `sd_alg_not_top_level`, that artifact's error, its name first in the message. RFC 9901 §4.1 item 7: "The
   payload MUST NOT contain the claims _sd or ... except for the purpose of conveying digests as described in
   Sections 4.2.4.1 and 4.2.4.2"; §4.1.1: `_sd_alg` "MUST appear at the top level of the SD-JWT payload. It MUST NOT be
   used in any object nested within the payload" (text read on rfc-editor.org on 2026-11-18). Both are addressed to the
   Issuer and §7.1 gives the Verifier no rejection step for them: for `...` this format reports and does not refuse (a
   claim the Issuer signed is shown to the reader with its name; the choice omega-evidence makes from
   0.12.0, `reserved_names_in_clear`), for a nested `_sd_alg` refusing is this format's rule. Up to 1.8.0 both
   verifiers kept a plain `...` key as an ordinary claim and dropped a nested plain `_sd_alg` in silence, as the
   `sd-jwt` reference implementation 0.10.4 does in `SDJWTVerifier._unpack_disclosed_claims` (read in its source on
   2026-11-18, not run; it refuses `_sd` only in the Issuer's input). For an `_sd`
   that is not an array of digest strings and for an array placeholder whose value is not a digest
   string, §4.2.4.1 and §4.2.4.2 address the MUST to the Issuer and §7.1 gives the verifier no rejection
   step of its own — §7.1 step 3.b collects only well-formed shapes and step 3.e removes every `_sd`
   key — so refusing is this format's stricter choice, measured 23/09/2026 against the `sd-jwt` reference
   implementation, which drops a malformed `_sd` (`{}`, `[1]`), keeps `{"...": [1]}` as an ordinary array
   element of its verified payload, and refuses `_sd: null` as this format does); 1.7.1, resolved claims that nest
   deeper than 512 — the bound of §3.1, counted as §3.1 counts a JSON text: the payload object is at depth 1 and every
   object or array inside it, disclosed or not, one deeper than its parent — → reject (`disclosures_too_deep`), whatever
   the depth of each JSON text the claims come from (vector `sd_disclosures_too_deep`, a chain of 513 object disclosures;
   up to 1.7.0 nothing bounded the resolved claims: on a chain of 1500 or 20000 disclosures the reference reported the
   artifact's error as `RecursionError: maximum recursion depth exceeded`, and the JS verifier, on 20000, as `Maximum call
   stack size exceeded`, measured 2026-10-29; RFC 9901 sets no such bound, so this is this format's stricter choice); the
   canonical form of the resolved claims MUST equal the recorded
   `resolved_claims`; re-verify the KB-JWT when the issuer payload carries
   `cnf.jwk` (its ES256 signature under `cnf.jwk`, AND its `sd_hash` equal to BASE64URL(SHA-256) of
   `issuer-JWT~disclosure*~` — RFC 9901 §7.3 step 5.c and 5.g; a KB-JWT that fails either verifies FALSE; without `cnf.jwk` a present
   KB-JWT is recorded as unverifiable, never treated as verified-green (1.8.1: its `sd_hash` is still compared — this
   format's rule: §4.3.1 needs no key, and RFC 9901 §7.3 step 5.g asks it only when Key Binding is required — and a wrong one is that artifact's error, `sd_hash_mismatch`, in
   `verify` and in `build`: the KB-JWT is not bound to this presentation, whatever the key; a right one gives
   `kb_jwt.sd_hash_ok: true` with `verified: null`; a producer does not seal that member, so a 1.8.0 verifier reads the
   pack; up to 1.8.0 a wrong `sd_hash` without `cnf.jwk` was `valid: true`, vector `holder_sd_hash_mismatch_no_key`), and
   otherwise never fails the pack by itself — but a KB-JWT that verifies FALSE does, and a §3.1 profile
   violation in any of its three segments is that artifact's failure whether or not the holder
   key is known: the strict segment rule does not depend on being able to check the signature;
   1.4.0, likewise independent of the holder key: the KB-JWT header MUST carry `typ: "kb+jwt"`
   (since 1.8.0 compared as RFC 7515 §4.1.9 says and §13 states: ASCII case ignored, `application/` implied, so
   `KB+JWT` and `application/kb+jwt` are `kb+jwt`; up to 1.7.x byte for byte, and a header with `typ: "KB+JWT"`,
   which RFC 7515 makes the same type, was that artifact's error) and `alg: "ES256"`, and its payload MUST carry `iat` (integer), `aud` (string), `nonce`
   (string) and `sd_hash` (string) — RFC 9901 §4.3 REQUIRED and §7.3 step 5.d; a KB-JWT missing
   any of them is that artifact's error, whatever `cnf` says). A verifier records the
   KB-JWT `aud`/`nonce`/`iat` as present-but-not-validated, as the sealed scope states: their expected
   values are transaction context an offline verifier cannot know.
3. Recompute bindings (§4), compare → `bindings_ok`. 1.5.4: `bindings_ok` is `false` when ANY artifact fails step 2
   (an artifact error or a refusal), whatever `bindings` holds, `[]` included — the recomputation needs every
   artifact's verified claims, and an artifact that did not verify has none (vectors `header_crit_unknown`,
   `kb_jwt_typ_missing`: `bindings: []`, `bindings_ok: false`).
4. If `rfc3161_timestamp.anchored`: check the token's binding (§3.2) — status
   granted AND messageImprint == the **recomputed** digest → `rfc3161_verified`
   true/false (this needs no tooling: a DER walk). The TSA's signature and chain are
   verified only against a relying-party-supplied TSA certificate (`tsa_verified`
   true/false; `null` = not requested or no tooling, never a pass). A claimed token whose binding fails
   fails the pack (tamper, not a warning); one whose TSA signature does not verify is not counted (§3.3). 1.5.0: the same check for every `anchors` entry, and `anchors_verified` (§3.3).
5. Verify the producer block per §5 → `producer_ok`, `producer_trusted`,
   `pq_protected`.
6. Policy: `policy_ok` is false if `require_producer` and no valid producer
   block; 1.10.0, if a pinned producer set is given and the pack carries no producer block (the set implies
   `require_producer`; `policy.unmet` names `trusted_producer_keys`, not `require_producer`, which the relying party did
   not pass — both when it passed both; up to 1.9.0 the set was applied only to a block that was present: measured
   2026-11-20 on 1.9.0, the block removed from a pack whose producer key was pinned gave `valid: true` and
   `policy.unmet: []` in both verifiers); if `require_pq` and not (`pq_protected` and `producer_trusted` true);
   if `anchors_verified` < `min_anchors` (§3.3; `require_anchor` alone is `min_anchors = 1`, so missing,
   unverifiable and failing anchors all reject — "claimed" never upgrades to "proven").
   The receipt also carries `mldsa_backend` (informative): whether that verifier can check
   ML-DSA-65 at all. Without the backend a post-quantum producer signature is SKIP — never a pass —
   and the reader should not have to infer why.

7. `self_asserted_only` is FAIL-CLOSED: `true` if ANY artifact's key is still self-asserted — it is
   cleared only when EVERY artifact's key was reconciled to an
   `x5c` chain that VALIDATES to a trust anchor the relying party supplies (`--trust-anchor`,
   reported in `chain_verified`: `true`/`false`, or `null` when no anchor was given, the verifier
   cannot validate chains, or the check was not measurable — openssl absent). That anchor and nothing
   else (1.8.1): no default certificate store of the platform (system CAs, `SSL_CERT_FILE`, `SSL_CERT_DIR`) takes part —
   the reference runs `openssl verify -CAfile <anchor> -no-CApath -no-CAstore`, and an openssl that does not know those
   options (before 3.0) is a check not run here, `null` (§6.10). Up to 1.8.0 the default store was added: measured on
   2026-11-18, a leaf of a CA in that store was `ca_certified` under an unrelated anchor. 1.6.0: a verifier that cannot validate
   chains refuses `--trust-anchor` as a usage error instead of accepting a flag that does nothing (the JS verifier). The chain is validated
   at the `genTime` of a TSA-VERIFIED RFC 3161 token when the pack carries one, and at the current
   time otherwise (1.1.0 r9: a signing certificate lives 1-3 years, so at today's clock a leaf valid
   2020-2021 could never clear the flag — the one mechanism that clears it was unusable in the very
   scenario this format exists for). A cleared flag states that **a CA under YOUR anchor certified
   this key at that time** — never that the key belongs to the mandate's issuer: that binding is
   outside what an offline verifier can establish. For this reason a verifier MUST report the
   validated leaf's identity (`x5c_leaf`: subject and issuer DN, serial, validity, SHA-256 of the
   DER), so an auditor can see whether it says `CN=the-bank` or `CN=someone-else`. Offline and without an anchor, every class is
   self-asserted — `jwk_header`, `x5c_header`, `supplied`, `jwks_fetched` alike — and so is
   every refusal receipt. 1.1.0 r7 had made `supplied`/`jwks_fetched`/absent fail closed but
   still cleared the flag when the leaf's issuer DN differed from its subject DN; r8 measured
   that a leaf SELF-SIGNED with its own key, merely declaring `CN=DigiCert Global Root CA` as
   its issuer, cleared it in both verifiers while the pack stayed `valid`. Two DN strings the
   forger writes are not an issuance: only a validated chain is.
   (flag, not a failure: the verdict names the weakness instead of hiding it).
   1.10.0, the PURPOSE of the leaf: a validated chain clears the flag only when the leaf was issued for signing, read from
   the leaf's DER by both verifiers with the same rule and reported, with or without an anchor, as `x5c_leaf.key_purpose`
   = `{"signing": true|false, "reason": null|<code>, "matched": null|<OID>}` (`matched` since 1.10.0). RFC 5280 (Proposed Standard, May 2008; its updates RFC 6818, 8398,
   8399, 9549, 9598, 9608, 9618, 9925 and 10007 do not change §4.2.1.3 or §4.2.1.12; read on rfc-editor.org on
   2026-11-20; its two verified errata on §4.2.1.12, 5802 and 6414, change the comments of id-kp-serverAuth and
   id-kp-clientAuth, not the rule, read there on 2026-11-21) ties the use of the key to two extensions, and both are checked, each on its own (§4.2.1.12: "If a
   certificate contains both a key usage extension and an extended key usage extension, then both extensions MUST be
   processed independently and the certificate MUST only be used for a purpose consistent with both extensions"):
   - keyUsage present: it MUST assert digitalSignature (bit 0) or nonRepudiation, renamed contentCommitment (bit 1) —
     the two bits §4.2.1.3 gives to digital signatures "other than signatures on certificates (bit 5) and CRLs (bit 6)";
     otherwise `key_usage_not_signing`;
   - extendedKeyUsage present ("If the extension is present, then the certificate MUST only be used for one of the
     purposes indicated"): it MUST list one of a closed set, this format's choice, since RFC 5280 leaves the purpose an
     application requires to the application ("Certificate using applications MAY require ... that a particular purpose
     be indicated"; "Applications that require the presence of a particular purpose MAY reject certificates that
     include the anyExtendedKeyUsage OID but not the particular OID expected for the application"):
     `id-kp-documentSigning` (1.3.6.1.5.5.7.3.36, RFC 9336, Proposed Standard, December 2022, read the same day — the key
     "has been certified to be used for cryptographic operations on contents that are consumed by people": a mandate is
     content its user approves) or, since 1.10.0, the mDL Document Signer purpose `1.0.18013.5.1.2` (the name is that of
     oid-base.com, "Mobile Driving Licence (mDL) Document Signer (DS)", read on 2026-11-21; ISO/IEC 18013-5, which
     defines it, is sold and was not read): the sample certificate AP2 ships for SD-JWT signers,
     `code/samples/certs/ds_cert_sdjwt.pem` of google-agentic-commerce/AP2 (Apache-2.0, sha256 `a4b92cd6…`, unchanged at
     `e1ea56db`, read on 2026-11-21), carries exactly that EKU, critical, and before this change (branch head 95a8c30) this format called it
     `extended_key_usage_not_signing` (measured 2026-11-21). `anyExtendedKeyUsage` (2.5.29.37.0) is not a
     purpose here since 1.10.0: alone it is `extended_key_usage_not_signing`; beside an accepted purpose the leaf is
     accepted for that purpose. The certificate rules of 2026 forbid it in the certificates a signer holds — CA/Browser
     Forum TLS Baseline Requirements 2.3.1 §7.1.2.7.10 ("`anyExtendedKeyUsage` … MUST NOT"), S/MIME 1.0.17 §7.1.2.3
     ("… and `anyExtendedKeyUsage` SHALL NOT be present"), Code Signing 3.11.0 §7.1.2.3 ("the following EKUs MUST NOT be
     present: `anyExtendedKeyUsage`"), all read on 2026-11-21 — and RFC 9336 §1 calls it "bad practice for publicly
     trusted certificates"; pyca/cryptography 50.0.2 (its verifier, for end-entity certificates: "**must not** be the
     explicit `anyExtendedKeyUsage` EKU") and openssl 3.0.22 (`verify -purpose smimesign`, measured 2026-11-21) refuse it
     in the leaf; Go `crypto/x509` (`verify.go` read the same day: "The presence of anyExtendedKeyUsage overrides any other key
     usage") accepts it. Before this change (95a8c30) this format accepted it alone. Any other
     list is `extended_key_usage_not_signing`: `serverAuth` and `clientAuth` (TLS), `codeSigning` ("Signing of
     downloadable executable code"), `emailProtection`, `timeStamping`, `OCSPSigning`, and every KeyPurposeId this text
     does not name. RFC 9336 §1 records that `id-kp-emailProtection`, `id-kp-codeSigning` or a vendor-defined
     KeyPurposeId are the current practice for signing documents, and that changes made to the code signing and S/MIME
     ecosystems "may cause unexpected behaviors" on document signing; this format does not accept them. A leaf with no
     extendedKeyUsage at all is accepted (RFC 5280 does not require the extension; openssl 3.0.22 `verify -purpose
     smimesign` accepts such a leaf too, measured 2026-11-21). `key_purpose.matched` names the purpose that matched:
     the dotted OID of the first KeyPurposeId of the list that is in the closed set, `null` when the leaf has no
     extendedKeyUsage or is not issued for signing;
   - either extension twice (RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of a particular
     extension") → `duplicate_extension`; a keyUsage that is not one DER BIT STRING (unused bits 0–7 and zero) →
     `key_usage_malformed`; an extendedKeyUsage that is not one DER SEQUENCE of one or more OBJECT IDENTIFIERs →
     `extended_key_usage_malformed`; extensions that cannot be walked as `[3] SEQUENCE OF Extension` →
     `extensions_unreadable`. The first that applies, in this order: unreadable, duplicate, keyUsage, extendedKeyUsage.
     The walk reads DER: every length in its minimal definite form (X.690 §10.1), every element ending inside its
     parent, nothing after the certificate — a long form where the short one fits is `key_usage_malformed` or
     `extended_key_usage_malformed` inside those two values and `extensions_unreadable` anywhere else on the walk
     (keyUsage `03 81 02 07 80` is malformed; cryptography 50.0.2 refuses that value, openssl 3.0.22 reads it as
     digitalSignature, measured 2026-11-21). 1.10.0, also X.690 §11.2.2 ("the bitstring shall have all trailing 0 bits
     removed before it is encoded"; NOTE 2: no 1 bit is "a length of 1 and an initial octet set to 0"): a keyUsage whose
     last octet is zero, or whose lowest 1 bit is not the last bit in use, is `key_usage_malformed` (`03 02 00 80`,
     `03 03 07 80 00`, `03 02 00 00`), although openssl 3.0.22 and cryptography 50.0.2 read `03 02 00 80` as
     digitalSignature (measured 2026-11-21). Cost, measured the same day: of 170 real certificates that carry keyUsage
     (148 of the system store, 33 of the TLS chains of ten public sites, 173 distinct), 2 break the rule — two root CAs of
     one issuer, `03 03 07 06 00` — and none is an x5c leaf of this repository.
   Both extensions absent: `signing: true` (this format does not require the EKU). A chain that validates to a leaf that
   is not issued for signing keeps `chain_verified: true` (the chain did validate), leaves `self_asserted_only` true, and
   makes `issuer_identity` `contradicted` with `key_purpose_not_signing` (§6.9) — the certificate itself says the key is
   not for this use; like `chain_broken` it does not decide `valid`. The JS verifier reports `key_purpose` and, as it
   validates no chain, never clears the flag. Up to 1.9.0 neither extension was read: measured 2026-11-20 on 1.9.0, a leaf
   whose keyUsage is keyCertSign only and whose extendedKeyUsage is serverAuth only, under the relying party's anchor, gave
   `chain_verified: true`, `self_asserted_only: false`, `issuer_identity` `verified / ca_certified`.
8. `valid` = artifacts non-empty AND `digest_ok` AND every artifact verifies
   AND `bindings_ok` AND `rfc3161_verified` is not false AND producer block ok
   (when present) and trusted (when pinned) AND `policy_ok`.

The twelve **normative verdict fields** a conformant verifier must reproduce:
`valid`, `digest_ok`, `bindings_ok`, `policy_ok`, `pq_protected`,
`producer_present`, `producer_ok`, `producer_trusted`, `rfc3161_claimed`,
`rfc3161_verified`, `self_asserted_only` (tri-state fields use
true/false/null), and since 1.5.0 `anchors_verified` (an integer, §3.3).

### 6.9 The receipt: admission, states, policy (NORMATIVE, 1.6.0)

The twelve fields above keep their meaning (§9.1 changes the values of two vectors, not a meaning). Since 1.6.0 every
receipt of both verifiers also carries:

- `admission`: `"admitted"` or `"refused"`. Every refusal of this text (§1, §3.1, §3.3, §6 step 1, §9.1) is `"refused"`
  and carries `refusal_class`, one of:
  - `format_unsupported` — the pack names a revision or a mechanism this verifier does not implement: an
    `evidence_format` other than `"ap2-evidence-pack/1.0"` (also absent or not a string), an `honest_scope` that is not the canonical scope of that
    format (the scope is fixed by the format version, §1), an `anchors` mechanism this revision does not define (§3.3);
  - `unknown_member` — a key outside the closed list of an object of §9.1;
  - `malformed` — every other refusal (the §3.1 profile, a missing or mistyped MUST, a name that is not a non-empty
    unique string, …).

  `refusal_class` is `null` on an admitted pack. This use of admissibility for a format or revision mismatch is this
  format's own; the nearest rule of draft-krausz-verification-state-03 (work in progress) is §5.4.1(h), which treats a
  version the verifier does not implement as a limitation of the verifier, not a defect of the input. A refused pack was
  not evaluated: `states` and `policy` are `null`, and its twelve fields keep the values of a refusal (`digest_ok`,
  `bindings_ok`, `policy_ok`, `valid` false) BY CONSTRUCTION, not by measurement — a reader of those fields alone sees an
  altered pack; it must read `admission` (§10).
- `tsa_cert_sha256` (1.10.0): present on an admitted pack only when a TSA certificate file was given (`--tsa-cert`,
  `tsa_cert`): the lowercase hex SHA-256 of that file's bytes, as the check of §6.10 read them, so a receipt that says
  `tsa_invalid` names the certificate it was read against (another TSA's certificate and an altered token give the
  same reason). Both verifiers write it; the JavaScript one, which checks no TSA signature, records the file it was given.
- `states_vocabulary`: `"ap2-evidence-pack/states-1"`, the identifier of the vocabulary below, which this text defines.
  An identifier never changes meaning: a revision that changes a state or a reason defines a new one. The vocabulary is
  aligned with draft-krausz-verification-state-03 §3.1, §3.3 and §5.4.2 (an individual Internet-Draft, work in progress);
  the draft is not the identifier, and a later draft does not change this one.
- `states` (admitted packs): a closed object with exactly the five subjects of the table below. Each is
  `{"state": S, "reasons": [R, ...]}` with an optional `detail` (free text, informative, never compared). S is one of
  `verified`, `contradicted`, `indeterminate`, `not_evaluated` (krausz §3.1). `indeterminate` (reasons `divergence`,
  `absence`) is reserved: no check of this revision produces it.
- `policy` (admitted packs): `{"met": bool, "unmet": [...]}`. `unmet` names, in this order, each requirement of the
  relying party the pack does not meet: `require_producer`, `require_pq`, `require_anchor`, `min_anchors` (§6 step 6),
  `require_binding` (1.9.0, below), `trusted_producer_keys` (a pinned set is given and the producer block is absent —
  1.10.0, §6 step 6 — or present and not `trusted`, §5) and `trust_set_complete` (below). `met` is true iff `unmet` is empty. `policy_ok` keeps its §6 step 6
  meaning and, since 1.9.0, is also false when `require_binding` is unmet. A policy is a disposition of the relying party,
  not a state of the pack.
- `require_binding` (1.9.0; `--require-binding IN->TO`, repeatable, both verifiers; `require_bindings`, a list of
  `(in, commits_to)` pairs, in the library; `requireBindings` in the JS library): each pair must be a binding of the
  RECOMPUTED set (§4), which counts only when `bindings_ok` is true; a pair not held puts `require_binding` in `unmet`
  and lists the pairs not held in `policy.require_binding_missing`. A value that is not `IN->TO` with both names
  non-empty and one `->` is a usage error (exit 2). No default: which artifact must commit to which is a decision of the
  relying party (for a receipt and the closed mandate of an AP2 chain, `receipt->N.k`); inside an AP2 chain the hop
  rules of §2.1 already require the binding. Up to 1.8.0 no policy existed: measured on 2026-11-18, six goodmeta receipt
  vectors declared "reject" came out `valid: true`, four of them with no receipt→mandate binding or one to the wrong hop
  (`reference` of another mandate, payment and checkout; of the root hop; absent); under `require_binding receipt->N.k`
  those four are not valid (the other two are receipt contents this format does not read: `payment_id`, `error_code`).

**Elements and precedence.** Each subject is stated from its ELEMENTS — one per thing it covers (an artifact, a token, a
signature entry) — and takes the state of its highest element under: `contradicted` > `not_evaluated` with reason
`instrument_failure` > any other `not_evaluated` > `verified` (cf. krausz §5.4.1(j): malformed outranks unknown). The two `not_evaluated` ranks give the same
state; an `instrument_failure` element is never hidden by the rank, because `reasons` lists every element that is not
`verified`. A subject
is `verified` only when every element is. `reasons` lists one reason per element that is not `verified`, in element order;
on a `verified` subject it lists the qualifiers of its elements (in this revision only `ca_certified`). A subject with no
element is `not_evaluated` with `not_present`.

| subject | elements | `verified` | `contradicted` (reason) | `not_evaluated` (reason) |
|---|---|---|---|---|
| `sealed_content` | the digest (§3); each artifact (§6 step 2: issuer signature and claims); the binding set (§4), recomputed for this subject whenever every artifact's signature and claims verified — also when a KB-JWT failed, where `bindings_ok` is false by §6 step 3 | every element | `digest_mismatch`; `artifact_invalid` (an artifact error, a signature or claims that do not verify, or no artifact); `binding_mismatch` | — |
| `holder_binding` | each artifact that is not an error and carries a KB-JWT; since 1.9.0 also each `chain_cnf` artifact that is not an error (§2.1: `verified`) | its KB-JWT verifies under `cnf.jwk` | `kb_signature_invalid` (the signature does not verify, whatever `sd_hash`); `sd_hash_mismatch` (the signature verifies, `sd_hash` does not) | `holder_key_unknown` (no `cnf.jwk`: recorded, never fails the pack, §6 step 2 — except an `sd_hash` that does not match, an artifact error since 1.8.1); `not_present` |
| `time_anchor` | the `rfc3161_timestamp` token when `anchored`; each `anchors` entry | binding verified (§3.2) AND, under `--tsa-cert`, the TSA signature verified | `binding_mismatch` (an imprint was read and is another digest, whatever else fails); `token_invalid` (otherwise: not a parseable, granted token); `token_missing` (`anchored` with no `tsr_b64`, §6 step 4) | `tsa_not_checked` (binding verified, no TSA certificate given: a self-issued token satisfies the binding, §3.2); `tsa_invalid` (the TSA signature does not verify under the certificate given: not counted, §3.3); `signer_certificate_absent` (1.8.1, §3.2: the signer certificate is not found, the signature not evaluated: not counted); `instrument_failure`; `not_present` |
| `producer_signature` | each signature entry; the block itself | `PASS` with a key in the pinned set | `signature_invalid` (a `FAIL` entry; also a block with no entry, or whose `scheme` does not match its entries, §5, with a `detail`) | `self_asserted` (`PASS`, no pinned set: the key is carried by the pack — `valid` can be true without pins, a policy of this format, never a trust statement; krausz §5.4.2(a) has no resolved result without the relying party's trust material); `key_unresolved` (`PASS`, a pinned set that does not hold the key — not a failed signature); `backend_missing` (`SKIP`: no ML-DSA-65 backend, or a `sig_alg` this format does not define); `not_present` |
| `issuer_identity` | the key of each artifact that is not an error | an `x5c_header` key whose chain validates to the relying party's trust anchor and whose leaf is issued for signing (§6 step 7, 1.10.0) — qualifier `ca_certified`: a CA under YOUR anchor certified the key, never "this is the issuer" | `chain_broken` (openssl reports a certificate signature failure inside the chain, or an `x5c` entry is not strict base64); `key_purpose_not_signing` (1.10.0: the chain validates, the leaf's keyUsage or extendedKeyUsage does not allow signing or cannot be read as §6 step 7 requires — `x5c_leaf.key_purpose.reason` says which) | `self_asserted` (`jwk_header`, `supplied`, `jwks_fetched`, and since 1.9.0 `chain_cnf`, §2.1); `no_trust_anchor` (`x5c_header`, no anchor given); `chain_unresolved` (the chain does not reach the anchor given: not resolved in the relying party's material, not a defect of the input); `instrument_failure`; `not_present` |

An artifact that is an error is stated once, in `sealed_content` (`artifact_invalid`); `holder_binding` and
`issuer_identity` are stated over the artifacts that are not errors, and say `not_present` with a `detail` when none is.

`instrument_failure` (krausz §3.1: the verifier's instrument failed; never a result about the input): openssl absent,
openssl that cannot be started, is killed by a signal or does not answer, a temporary file openssl needs that cannot be
written, a verifier that
cannot make the check at all (the JS verifier under `--tsa-cert`). The `detail` names which. No producer check calls an
outside tool, so this revision never states it on `producer_signature`.

**The tokens of krausz §5.4.2.** This text reuses `key_unresolved`, `signature_invalid` and the trust-set completeness
input of krausz §5.4.2 as reason codes under the §3.1 states; krausz does not — it reports them as the receipt step's own
tokens. Here the cryptographic check against the key the pack carries RAN; `key_unresolved` means the key is not
resolved in the pinned set.

**`trust_set_complete`** (a verifier input, `--trust-set-complete`, default false — krausz §5.4.2 "Completeness input",
which credits the split between the keys a relying party holds and a list it declares complete to x402 TSC issue #4,
2026-09-24): the relying party declares its pinned set complete. An entry that is
`key_unresolved` then also puts `trust_set_complete` in `policy.unmet`. It never turns `key_unresolved` into
`signature_invalid`, and `valid` does not change (a pinned set that does not hold a key already makes the pack not
valid, §5).

**`valid` and the states.** `valid` keeps its §6 step 8 definition. On every admitted receipt it equals: no subject but
`issuer_identity` is `contradicted`, AND no producer entry is `SKIP` (`backend_missing`), AND `policy.met`. Two terms are
not those of the equation the design of this revision pre-registered (every subject; no `SKIP` term), and both come from
rules of earlier revisions this one does not change: an x5c chain never decided `valid` (§6 step 7: a flag, not a failure
— vector `issuer_x5c_chain_broken` is valid with `issuer_identity` contradicted, and since 1.10.0 also
`issuer_x5c_key_purpose_not_signing`), and §5 makes a block with a `SKIP` entry
not `ok` although no check failed (`producer_backend_missing`). Measured on 18/10/2026 by `verifiers/states_controls.py`
(the schema-mutant corpus plus the vectors under four pinned-set inputs, 22 967 receipts): the equation above holds on
every receipt; the pre-registered one fails on 7, all of them receipts of those two packs. Measured again on 2026-11-20
on revision 1.10.0 (24 651 receipts): the equation above holds on every receipt; the pre-registered one fails on 5, three
receipts of `producer_backend_missing` and two of `issuer_x5c_chain_broken` under `trust_anchor` — the two receipts of
`issuer_x5c_chain_broken` under a pinned producer set that failed it up to 1.9.0 (7 on 1.9.0, measured the same day) are
not `valid` since 1.10.0 (a pinned set without a producer block, §6 step 6), as both equations say. Measured on 2026-11-21 on the
code of 0af8737, with the vector `issuer_x5c_key_purpose_not_signing` added: 6 314 files, 25 349 receipts, 0 violations,
the same 5 failures of the pre-registered equation. In that run the vector was never under its trust anchor, so no
receipt carried `key_purpose_not_signing` (a derivation that ignores the key purpose left the run at 0 violations,
measured the same day). With the vector also run under `issuer_purpose_ca.crt` and under `issuer_other_ca.crt`: 6 316
files, 25 357 receipts, 0 violations, 7 failures of the pre-registered equation — the two more are that vector under
its anchor, `valid` with `issuer_identity` contradicted — and the derivation that ignores the key purpose is 4 violations.

**What no state can say.** A producer block that was removed and one that was never added give the same digest and
the same states (`producer_signature: not_evaluated`, `not_present`): only the SHA-256 of the whole file, or
`require_producer`, or since 1.10.0 a pinned producer set, tells them apart (§10).

### 6.10 Exit codes and the receipt (NORMATIVE, 1.6.0)

`0`: `valid`. `1`: not `valid`, OR refused — read `admission`. `2`: a usage error (no receipt; 1.6.0: also a `--tsa-cert` or `--trust-anchor` that is not a readable regular
file; and one that holds no PEM block labelled CERTIFICATE, X509 CERTIFICATE or TRUSTED CERTIFICATE whose base64 characters decode to a DER SEQUENCE (bytes outside the base64 alphabet are ignored: the blanks and control bytes openssl drops from a PEM line make no usage error; a file that passes and that openssl cannot read is `tsa_invalid` / `chain_unresolved`, as before) — until 1.10.0 an empty or non-PEM file reached openssl and read `tsa_invalid` / `chain_unresolved`, a statement about the pack, with no certificate given; the library functions `verify_evidence` and `verify_restrictions` raise `ValueError` for the same files, and for one that is not a regular file; `verifyEvidence` of the JavaScript verifier throws `TypeError`). `74`: one of two cases,
told apart by what is on stdout:

- a check the caller asked for could not be RUN on this machine (openssl that cannot be started, is killed by a signal or
  does not answer, a
  temporary file openssl needs that cannot be written): the COMPLETE receipt on stdout — that subject `not_evaluated` with
  `instrument_failure` and a `detail` beginning `check not run here`, every other subject evaluated — and one line on
  stderr beginning `check not run here:`. 1.5.2–1.5.4 gave 74 with no receipt here. The library raises `Ap2WriteError`
  whose `receipt` is that complete receipt;
- the receipt itself could not be written whole (a full disk, a file size limit, a reader that closed the pipe): nothing,
  or a cut JSON, on stdout and one line `receipt not written: …` on stderr.

openssl ABSENT is neither: as in 1.5.x the field is `null` (`tsa_verified`, `chain_verified`), the subject is
`not_evaluated` with `instrument_failure` (`detail`: openssl absent) and the exit follows `valid`. The JS verifier accepts
`--trust-set-complete` and refuses `--trust-anchor` (exit 2, §6 step 7).

## 7. Conformance (normative)

Run every `spec/vectors/ap2/<name>.json` under the policy in
`<name>.expected.json` and reproduce the `normative` block exactly
(`run_ap2_conformance.py` does this for the reference; exit 0 = conformant).
The set contains fifty-nine vectors (1.10.0: + 2 — `issuer_x5c_key_purpose_not_signing`, the key purpose of §6 step 7:
an x5c leaf with keyUsage keyCertSign only and extendedKeyUsage serverAuth only under `trust_anchor`
`issuer_purpose_ca.crt`, `valid`, `issuer_identity` `contradicted` `key_purpose_not_signing`, `self_asserted_only`
true, needs openssl; on eade795, before the rule, `verified` `ca_certified` and `self_asserted_only` false, measured
2026-11-21 — and `issuer_alg_not_es256`, the `alg` rule of §6 step 2 — an ES256
signature of the issuer under a signed header that says `"alg": "none"`, `valid: true` under 1.9.0 in both verifiers,
measured 2026-11-20; an artifact error, `sealed_content` `contradicted` `artifact_invalid`, no producer block; 1.8.1: + 4, the grammar of §6 step 2 — `sd_jwt_no_separator` and
`sd_jwt_empty_component`, both `valid` under 1.8.0 in both verifiers, and `sd_jwt_no_trailing_tilde`, an artifact error
under 1.8.0 too, with another reason — and `holder_sd_hash_mismatch_no_key` (§9.2), `valid` under 1.8.0 in both
verifiers; each an artifact error, `sealed_content` `contradicted` `artifact_invalid`, no
producer block; the error text is not part of the normative block; 1.7.3: + 3, the key sources of the header of §2 (d) — `key_header_jwk_differs`, a
`supplied` key beside a header `jwk` naming another key, and `key_header_x5c_differs`, a `jwks_fetched` key beside an `x5c`
whose leaf is another key, both an artifact error, `sealed_content` `contradicted` `artifact_invalid`; `key_material_not_used`,
a `supplied` key beside a header `jwk` and `x5c` of the same key and a `jku`, valid, with `report.ignored` — no producer block,
so no backend dependence; a 1.7.2 verifier, in both languages, reports the first two `valid` and the third with `ignored: {}`,
measured 2026-11-03; 1.7.2: + 4, the numbers of §3.1; 1.7.1: + 1, `sd_disclosures_too_deep`, the depth bound of §6 step 2 — an
artifact error, `sealed_content` `contradicted` `artifact_invalid`, no producer block, so no backend dependence; a 1.7.0
verifier reports `issuer_identity` `self_asserted` on it, measured 2026-10-29; 1.7.0: + 3, the SD-JWT processing rules of §6 step 2 that 1.6.0 did not enforce —
`sd_digest_repeated`, the same array placeholder twice in `delegate_payload`; `sd_digest_repeated_sd`, the same object
digest in the `_sd` of two objects; `sd_claim_name_reserved`, a disclosed claim named `_sd` — all three an artifact error,
`sealed_content` `contradicted` `artifact_invalid`, no producer block, so no backend dependence; 1.6.0: + 13, one for each cell of the §6.9 table the earlier vectors did not reach:
`holder_kb_signature_invalid`, `holder_sd_hash_mismatch`, `holder_key_unknown` — valid —, `sealed_binding_mismatch`,
`time_token_missing`, `time_tsa_verified` and `time_tsa_invalid` — anchor_valid's bytes under `tsa_cert` —,
`producer_backend_missing`, `producer_trust_set_complete`, `issuer_x5c_no_anchor` — valid —, `issuer_x5c_ca_certified`,
`issuer_x5c_chain_unresolved` and `issuer_x5c_chain_broken` — all three valid, under `trust_anchor`). Of the twenty-nine
earlier vectors: seven ACCEPTs (`valid_signed` — positive control — and `anchor_valid`,
a real RFC 3161 token from a probe TSA whose certificate ships beside it; since 1.4.0 also
`header_param_ignored`, a signed header with an unregistered parameter that RFC 7515 §4 says to
ignore, `kb_jwt_valid`, a holder-bound mandate whose KB-JWT verifies, and `key_jwk_member_ignored`,
a snapshotted JWK with an unregistered member; since 1.5.0 `anchors_two_valid`, two distinct anchors
under `min_anchors` 2, and `anchors_only`, an anchor carried only in `anchors`) and twenty-two
REJECTs — twenty-five with the three of 1.7.0, twenty-six with the one of 1.7.1 — (stripped-signature downgrade, valid-but-unpinned producer, digest mismatch,
anchor required-but-missing, anchor claimed-but-invalid, a real token for another digest; since
1.4.0: an unknown key at the top level, inside `rfc3161_timestamp`, inside an artifact entry and
inside a producer-signature entry — since 1.6.0 both refusals of class `unknown_member` —, a `crit` header parameter the verifier does not understand, and
a KB-JWT without the `kb+jwt` type; since 1.5.0 (§3.3): a copied token counted once, one anchor under
`min_anchors` 2, an `anchors` entry whose token is not a TimeStampResp, a real token for another
digest in `anchors`, an unknown mechanism, an unknown key in an entry, an empty `anchors`; since 1.5.4 (§5) a pinned
block whose ML-DSA-65 signature fails, a pinned block whose classical signature fails under `require_pq`, and the same
bytes with no pinned set). A vector
whose `requires` tooling is absent is reported SKIP, honestly unverified. 1.5.4: `requires_backend` lists the
cryptographic backends without which a verifier cannot reproduce the vector's `normative` block; this revision defines
one, `"ml-dsa-65"` (a verifier that can check FIPS 204 ML-DSA-65 — the receipt's `mldsa_backend`, §6 step 6). A verifier
without that backend reports such a vector SKIP — not a disagreement and never a pass — and does not claim conformance on
it. Twenty-one vectors carry it (1.5.4: twelve; 1.6.0: also `digest_mismatch` and the three
`producer_*_fails_*` vectors, whose `states` block depends on the backend, and five of the thirteen new vectors); which
ones is MEASURED, not chosen: the reference verifier is run on every vector with and
without its ML-DSA-65 backend, and the vectors it reproduces only with the backend are the ones marked
(`make_vectors_154.py --declare-backend`; the test suite repeats the measurement). The expected files are a closed
format: keys `vector`, `description`, `policy`, `normative` (all twelve fields), `report` (`ignored`, `refused`),
`requires`, `requires_backend` (`"ml-dsa-65"`), and since 1.6.0 `states` (REQUIRED: `admission`, `refusal_class`,
`subjects` — each of the five subjects with its `state` and `reasons`, `detail` excluded — and `policy`, `null` both on a
refusal; a conformant verifier reproduces it exactly); `policy` keys `trusted_producer_keys`, `require_pq`,
`require_producer`, `require_anchor`, `min_anchors`, with the types of §6 (`require_*` booleans, `min_anchors` a positive
integer, `trusted_producer_keys` null or an object mapping a `sig_alg` to a key or a non-empty list of keys), and since
1.6.0 `trust_set_complete` (boolean), `tsa_cert` and `trust_anchor` (the name of a file of the vector set, passed as
`--tsa-cert` / `--trust-anchor`), and since 1.7.2 `accept_integral_floats` (boolean, §3.1). The six vectors that pass `tsa_cert` or `trust_anchor` (five up to 1.9.0) list `"openssl"` in `requires`: a
verifier that cannot call openssl (the JS verifier) reports them SKIP. A runner that meets
any other key, backend name or policy type, a file that is not UTF-8 JSON or repeats a key, or a pack without its
expected file (or the reverse) stops with an error of the vector set, never ignoring it (`run_ap2_conformance.py`:
exit 2). When an
`<name>.expected.json` carries a `report` block, a conformant verifier also reproduces it: today it
holds `ignored`, the per-artifact list of names ignored under a standard's rule (§9.2), mapped
onto the reference receipt's `artifacts[i].ignored`; since 1.5.0 it may also hold `refused`, the EXACT
refusal text (§9.1/§3.3 fix its form), so a verifier that refuses for another reason does not pass.
Independent implementations: open a PR to be listed in the README conformance table.


## 8. Canonical scope statement for `ap2-evidence-pack/1.0` (NORMATIVE)

SHA-256 of the UTF-8 bytes of the decoded JSON string value (not of the escaped bytes on disk):
`a4b12a682847c23c4a136dd399c6aa0dfa69540a5c7200039d506e86ac31dfbf`

```text
Proves: these exact SD-JWT artifacts, with the snapshotted key material (see each key's provenance_class), verified at build time; the RFC 3161 token (if present) binds this digest to a TimeStampResp, and attests the TSA's clock only once the relying party has verified the TSA's signature (--tsa-cert): a self-issued token satisfies the binding alone. Does NOT prove the issuer authorised the key beyond what the provenance class states, does NOT confer eIDAS qualified-archive legal presumption, and does NOT by itself validate x5c chains to a trust anchor — that is an act of the relying party at verification time, with `--trust-anchor`, reported in `chain_verified` and in each artifact's `x5c_leaf` (SPEC §6.7): the x5c bytes are sealed inside the signed header, the validation RESULT never is — and never proves the truth of the recorded transaction itself. When a producer signature is present, it protects the SEALED CONTENT (the file minus the digest, the anchor block and the signatures themselves - so a removed or downgraded time anchor is caught only under a require-anchor policy), and authenticity ONLY for a relying party that has PINNED the producer public key out of band (an embedded key alone proves consistency, not authenticity), across the retention window (hybrid: a classical signature + FIPS-204 ML-DSA-65, surviving the quantum transition per NIST IR 8547); it does NOT retro-protect the underlying ES256 mandate signature - for the existed-before-a-quantum-adversary claim you still need a trusted time anchor (RFC 3161 / RFC 4998 renewal). 'valid' means each artifact verifies and the SEALED CONTENT is intact — NOT that the file as a whole is unaltered (the anchor block lies outside the digest), NOT that the mandates form a bound chain (read `bindings`) nor that self-asserted keys prove issuer identity (read `provenance_classes`/`self_asserted_only`). KB-JWT holder binding is verified when the issuer payload carries cnf.jwk; without cnf.jwk it is recorded as present-but-unverifiable, never painted green. KB-JWT aud/nonce/iat are RECORDED for the auditor, not validated — their expected values are transaction context this tool cannot know offline.
```

## 9. Closed schema (NORMATIVE, 1.4.0)

A verifier of this format is a precision instrument: whoever reads its `valid` trusts it. On
2026-10-10 the 1.3.0 verifiers were measured accepting, with `valid: true` and no trace in the
receipt, a key they had never heard of inside `rfc3161_timestamp`, inside `producer_signatures`
and inside every `signatures[i]` entry (an unknown top-level key was caught only because the
digest covers it — a pack SEALED with one verified). Nothing in this text said what to do with
the unknown, so both implementations did the same thing: nothing. This section closes every
object the format defines and states, for every object a standard defines, which rule of that
standard applies. The principle: **a key the verifier does not understand is never silent** —
in a closed object it is a refusal with a reason; in a standard's object it is ignored as the
standard requires AND reported.

### 9.1 Objects of this format — closed, unknown = refusal with a reason

Every key of every object below is listed with its type; a key not in the list, a listed key
of another type, or a listed MUST key that is absent, has the outcome in the last column.
"Refusal" is a receipt with `valid: false`, `admission: "refused"` (1.6.0, §6.9: `refusal_class` `unknown_member` for an
unknown key, `malformed` for a wrong type or a missing key) and `refused` naming the object and the key
(`<object>: unknown key "x" (SPEC §9.1)`; with several unknown keys, the first by Unicode code point —
1.4.1); "artifact error" is `artifacts[i].error` for that artifact (the pack is not `valid`); "FAIL
entry" is `status: FAIL` for that producer signature (the block is not `ok`, the pack is not
`valid`), whose `note` names the unknown keys and the missing keys, each list sorted by code point
(1.4.1: in 1.4.0 the note did not name them; an entry that is not an object has no keys and no note). Keys are compared exactly (case-sensitive,
after JSON unescaping — `"subj\u0065ct"` IS `subject`).

| Object | Keys (type) | Unknown / wrong type / missing MUST |
|---|---|---|
| top level | `evidence_format` (string, MUST), `subject` (string, MUST), `created_utc` (string, MUST), `artifacts` (list, MUST), `bindings` (list; absent reads as `[]`), `honest_scope` (string, MUST), `evidence_digest_sha256` (string, MUST), `rfc3161_timestamp` (object), `producer_signatures` (object), `anchors` (non-empty list, 1.5.0), `not_before` (object, 1.8.0, closed at every level as §12.2 states) | refusal |
| `anchors[i]` (1.5.0) | `mechanism` (string, MUST, one of the mechanisms of §3.3: `"rfc3161"`); for `rfc3161`: `tsr_b64` (string, MUST), `tsa_url` (string), `note` (string); an entry that is not an object | refusal (an unknown `mechanism` is named: `anchors[i]: mechanism "x" is not defined by this revision (SPEC §3.3)`) |
| `rfc3161_timestamp` | `anchored` (boolean, MUST), `tsr_b64` (string; when `anchored` is true and it is ABSENT the §6.4 rule applies: `rfc3161_verified: false`, not a refusal; when `anchored` is false and it is PRESENT: refusal, 1.10.0), `tsa_url` (string), `tsa` (string, 1.0–1.3 spelling), `note` (string) | refusal |
| `producer_signatures` | `scheme` (`"hybrid"` or `"classical-only"`, MUST), `over` (`"evidence_digest_sha256"`, MUST), `signatures` (list, MUST) | refusal |
| `producer_signatures.signatures[i]` | `sig_alg` (string, MUST), `public_key_b64` (string, MUST), `signature_b64` (string, MUST), `post_quantum` (boolean, MUST, `true` iff `sig_alg == "ml-dsa-65"`); an entry that is not an object | FAIL entry; an UNKNOWN key: refusal (1.6.0, below) |
| `bindings[i]` | `in` (string), `claim` (string), `commits_to` (string), `encoding` (`"hex"` or `"b64url"`) — all four MUST; `over` (exactly `"issuer_jwt"`, 1.9.0, §4); an entry that is not an object | refusal |
| `artifacts[i]` | `name` (non-empty string, MUST), `sd_jwt_compact` (string, MUST), `header` (object, MUST, canonically equal to the decoded protected header), `key` (object, MUST), `resolved_claims` (MUST, canonically equal to the recomputed claims), `kb_jwt` (object, MUST), `verified_at_build` (object, MUST) | artifact error (a `name` that is not a non-empty string stays a refusal, §2); an UNKNOWN key: refusal (1.6.0, below) |
| `artifacts[i].key` | `jwk` (object, MUST), `provenance_class` (string in the §2 enum, MUST), `note` (string), `x5c_chain_sha256` (list of strings), `jwks_url` (string), `jwks_sha256` (string), `fetched_utc` (string), `chain_from` (string, with `chain_cnf` only, 1.9.0, §2.1) | artifact error; an UNKNOWN key: refusal (1.6.0) |
| `artifacts[i].kb_jwt` | `present` (boolean, MUST, equal to "the compact serialization ends with a KB-JWT"), `verified` (boolean or null), `signature_ok` (boolean), `sd_hash_ok` (boolean), `note` (string or null), `claims_recorded_not_validated` (object); each of `verified`, `signature_ok`, `sd_hash_ok`, `claims_recorded_not_validated` that is present MUST be canonically equal (§3) to the value the verifier recomputes from the KB-JWT (§6) — a recorded value the KB-JWT does not support, or a key the recomputation does not produce, is that artifact's error, like the `header` copy (added on review, 2026-10-11) | artifact error; an UNKNOWN key: refusal (1.6.0) |
| `artifacts[i].verified_at_build` | `signature_ok` (exactly `true`, MUST), `disclosures_ok` (exactly `true`, MUST) | artifact error; an UNKNOWN key: refusal (1.6.0) |

`resolved_claims` and `bindings` are closed by construction (they MUST equal a recomputation);
the two rows above make the reason explicit instead of leaving a bare `claims_match: false`.

**1.6.0 — an unknown key is a refusal in every object of this section (NOT additive).** 1.4.0–1.5.4 made an unknown key
inside `artifacts[i]`, `artifacts[i].key`, `artifacts[i].kb_jwt`, `artifacts[i].verified_at_build` an artifact error and
inside `producer_signatures.signatures[i]` a FAIL entry. A reader of the twelve fields then saw an altered artifact or a
failed signature where the verifier had met a key it did not know — which a later revision of this format may define.
Since 1.6.0 such a key is a refusal of class `unknown_member` (§6.9), with the text
`artifacts[i]: unknown key "x" (SPEC §9.1)` (`artifacts[i].key`, `artifacts[i].kb_jwt`, `artifacts[i].verified_at_build`,
`producer_signatures.signatures[i]` likewise; the first unknown key by code point). The scan runs after the closed checks
of the top level, `rfc3161_timestamp`, `producer_signatures`, `bindings[i]` and `anchors[i]`, artifacts in list order
(each entry, then its `key`, `kb_jwt`, `verified_at_build`), then the signature entries. Only the unknown-key rule moves:
a wrong type or a missing key in these objects stays an artifact error or a FAIL entry (a FAIL entry's `note` names its
missing keys). This changes the twelve fields of two vectors: `unknown_key_artifact` (`digest_ok` and `policy_ok`
true → false) and `unknown_key_producer_entry` (`digest_ok`, `bindings_ok`, `policy_ok` true → false, `producer_present`
true → false, `producer_ok` false → null). `valid` does not change on any pack: a pack with such a key was never valid. The exit code
(1) changes in one branch: under `--tsa-cert` or `--trust-anchor` where openssl cannot run, 1.5.x reached that check
first (exit 74, no receipt); 1.6.0 refuses before any check runs (exit 1). A verifier conformant to the 1.5.x vectors is therefore not conformant to 1.6.0 on these two. The rule
applies to the objects of THIS section only: the objects of §9.2 keep their standard's rule (an unknown header parameter
or JWK member is ignored and reported — `header_param_ignored`, `key_jwk_member_ignored` stay valid — and an unknown
`crit` extension stays the artifact's error, RFC 7515 §4.1.11).

### 9.2 Objects defined by a standard — the standard's rule, and a report

| Object | Standard and its rule for the unknown | What this format does |
|---|---|---|
| issuer JWT protected header | RFC 7515 §4: "all Header Parameters not defined by this specification MUST be ignored when not understood", unless listed in `crit`; §4.1.11: a `crit` naming an extension the recipient does not understand makes the JWS INVALID; `crit` MUST NOT be `[]`, MUST NOT list registered names, duplicates, or names absent from the header | names this format understands: `alg`, `jku`, `jwk`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`, `typ`, `cty`, `crit` (those defined by RFC 7515 §4.1 and RFC 7519 §5; other names of the IANA JOSE registry are not understood here, so they are ignored and reported like any other). This format understands NO extension: a `crit` that is present and well-formed is therefore always that artifact's error, and a malformed `crit` (not a list of strings, empty, duplicate, registered or absent names) is one too. Every other unregistered name is ignored and reported in `artifacts[i].ignored.header` |
| `jwk` in the header, `key.jwk`, `cnf.jwk` | RFC 7517 §4: "Additional members can be present in the JWK; if not understood by implementations encountering them, they MUST be ignored" | registered members: `kty`, `use`, `key_ops`, `alg`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256` (RFC 7517 §4) and `crv`, `x`, `y`, `d` (RFC 7518 §6.2). Others ignored and reported in `ignored.header_jwk` / `ignored.key_jwk` / `ignored.cnf_jwk` |
| key sources of the issuer JWT protected header: `jku`, `jwk`, `x5u`, `x5c` (1.7.3) | RFC 7515 §4.1.2, §4.1.3, §4.1.5, §4.1.6 define each as naming the key that signed the JWS; draft-ietf-oauth-sd-jwt-vc-27 §2.5: the key comes from a mechanism "permitted for the given Issuer according to policy", and inputs of other mechanisms MUST NOT be treated as identifying the Issuer unless policy binds them — neither makes one it does not use an error | the one the snapshotted key came from (`jwk` for `jwk_header`, `x5c` for `x5c_header`) is reconciled as §2 says; every other one present is not used for the key and is reported in `ignored.key_material`; a `jwk` or `x5c` among them must name the snapshotted key (§2 (d)), otherwise that artifact's error — this format's choice, not the standards' |
| issuer JWT payload | RFC 7519 §4: "all claims that are not understood by implementations MUST be ignored" | every claim is RECORDED: the resolved payload is the pack's content and `resolved_claims` lists it in full, so nothing is reported twice; the SD-JWT shapes of RFC 9901 (`_sd`, `_sd_alg`, `...`) are imposed as in §3.1 |
| `cnf` | RFC 7800 §3.1: "all confirmation members that are not understood by implementations MUST be ignored" | understood: `jwk`, `jwe`, `jku`, `kid` (the members RFC 7800 defines, §3.2–§3.5; other confirmation methods of the IANA registry, e.g. `x5t#S256` of RFC 8705 or `jkt` of RFC 9449, are not understood here). Others ignored and reported in `ignored.cnf` |
| KB-JWT header | RFC 7515 as above; RFC 9901 §4.3: `typ` REQUIRED, MUST be `kb+jwt`; `alg` REQUIRED | `typ` missing, not a string, or not `kb+jwt` as RFC 7515 §4.1.9 compares media types (§13; since 1.8.0, byte for byte before) is that artifact's error (RFC 9901 §4.3; RFC 9901 §7.3 step 5.d asks a Verifier to check it when Key Binding is required — this format checks every KB-JWT it carries, whether or not the holder key is known); `alg` not `"ES256"` is that artifact's error by this format's profile (§6 step 2: `alg: "ES256"`; RFC 9901 §4.3 only forbids `none`); `crit` as above; other unregistered names ignored and reported in `ignored.kb_jwt_header` |
| KB-JWT payload | RFC 7519 §4 (ignore); RFC 9901 §4.3: `iat`, `aud`, `nonce`, `sd_hash` REQUIRED | the four REQUIRED claims must be present with their RFC 9901 types (`iat` integer, the others strings) — absence or wrong type is that artifact's error; the VALUES of `iat`, `aud`, `nonce` are recorded, not validated (sealed scope); `sd_hash` is compared with the presentation (§6 step 2), with or without `cnf.jwk` since 1.8.1 (`sd_hash_ok` in the receipt). Registered names: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` (RFC 7519 §4.1), `nonce`, `sd_hash` (RFC 9901). Others ignored and reported in `ignored.kb_jwt_claims` |

`artifacts[i].ignored` is an object present on every artifact that verified; each slot above is
a list of the ignored names sorted by code point and appears only when non-empty, so an
artifact with nothing ignored carries `ignored: {}`. The report is informative for the verdict
(it never changes `valid`) and normative for conformance when a vector's `expected.json` carries
it (§7): two conformant verifiers report the same names.

### 9.3 Generative proof

`verifiers/schema_mutants.py` derives, from every conformance vector and from freshly signed
packs, mutations at every level of every object listed in §9.1 and §9.2 — unknown keys (ASCII,
Unicode, `__proto__`, `constructor`, empty, case-variants of known keys, escaped spellings),
every known key replaced by each hostile type, duplicate keys, key-order permutations, escaped
spellings of known keys, boundary numbers and out-of-grammar files — and computes each
mutation's EXPECTED class from the two tables above, not from a verifier. Both verifiers must
give that class and must agree with each other on every compared field. Run against the 1.3.0
verifiers the same corpus is the positive control: measured 2026-10-10, of 12 818 mutations (full
corpus) 8 186 passed SILENTLY on 1.3.0 in BOTH verifiers — `valid` unchanged, nothing in the receipt
— and the two verifiers agreed with each other on every one of them (0 differential disagreements):
agreement between two implementations by one author is not correctness. On 1.4.0: 12 818/12 818
met their class, 0 disagreements (details in CHANGELOG 1.4.0). 1.5.0 adds `anchors` (the top-level key and every
entry): measured 2026-10-11, 16 503 mutations from 37 sources, each met its class in both verifiers, 0 disagreements on
16 540 files. Against the 1.4.1 verifiers the same corpus leaves 788 (Python) and 689 (JS) mutations without their
class, all from the two accepting `anchors` sources: 1.4.1 refuses the `anchors` key (as its §9 requires) and, in Python,
444 runs of `anchors_two_valid` stop at a `TypeError` (the 1.4.1 API has no `min_anchors`) — a check that the bench reaches
these sources, not a measure of the §3.3 rules; the mutants of the new code are that measure (CHANGELOG 1.5.0). 1.6.0 moves the
unknown keys of `artifacts[i]` (and its `key`, `kb_jwt`, `verified_at_build`) and of `signatures[i]` to the refusal class,
and checks `refusal_class: unknown_member` on every unknown-key mutation: measured 2026-10-18, 23 486 mutations from 59
sources, each met its class in both verifiers, 0 disagreements on 23 545 files; with the 1.6.0 refusal of `artifacts[i]`
and `signatures[i]` removed from a copy of the reference, 2 520 of them do not.

## 10. Reading a receipt as a relying party (INFORMATIVE)

This section changes no rule of §1–§9. It says, for a party that decides something on the strength of a pack (a dispute
provider, an auditor, an issuer years later), what each field of the receipt establishes and what it leaves to that
party, so that a dispute specification can cite it instead of restating it.

**What to record.** Record the fields, not the names of the conformance vectors: the vectors are examples, the verifier
does not emit their names. Since 1.6.0 the receipt states its verdict in four fields — `admission` (with
`refusal_class`), `states_vocabulary`, `states` and `policy` (§6.9) — beside the twelve fields of §6; in both verifiers
`producer_present`, `producer_ok` and `producer_trusted` are `producer_signatures.present`, `.ok` (always present since
1.6.0, `null` when there is no producer block) and `.trusted`, and `rfc3161_claimed` and `rfc3161_verified` are
`rfc3161.claimed` and `.verified`. A reference to a pack by `evidence_digest_sha256` alone does not identify one file: the
digest covers the sealed content (§3), not `rfc3161_timestamp`, `producer_signatures` or `anchors`, so a copy with a
signature or an anchor removed, or re-signed, has the same digest (and a copy with its producer block removed has the
states of a pack that never had one, §6.9). Record the SHA-256 of
the whole file, or verify with pinned producer keys (since 1.10.0 they imply `require_producer`, §6 step 6), plus `require_anchor` or `min_anchors` when
a ground rests on the pack's time.

**First, was the pack evaluated at all: `admission`.** `refused` means the verifier did not evaluate the pack; its
`digest_ok`, `bindings_ok`, `policy_ok` and `valid` are `false` by construction, not measured, and a reader of those
fields alone sees tampering that nobody measured. `refusal_class` says why: `format_unsupported` (a revision or an anchor
mechanism this verifier does not implement — a verifier of that revision may accept the pack), `unknown_member` (a key
outside a closed list: it can come from a later revision as well as from an injection, and the receipt cannot tell which),
`malformed`. A refusal is not evidence of tampering and not evidence against the submitting party.

**Exit codes.** `1` is both "not valid" and "refused"; `2` is a usage error. `74` with a complete JSON receipt on stdout
means a check asked for could not be run on this machine (the subject says `instrument_failure`): verify again where it can
run. `74` with nothing or a cut JSON means the receipt was not written. Read the receipt, not the exit code (§6.10).

**Then the states** (an admitted pack, §6.9).

| state | what it establishes | what the relying party does |
|---|---|---|
| `contradicted` on `sealed_content`, `holder_binding`, `time_anchor` or `producer_signature` | a check ran and failed: the sealed content is not what was sealed, an artifact or a KB-JWT does not verify, a claimed anchor does not bind this digest, a producer signature fails; `valid` is `false` whatever the policy | do not rely on the pack; the submitting party may supply a conformant one |
| `contradicted` on `issuer_identity` (`chain_broken`) | a certificate signature inside an x5c chain fails; `valid` is unchanged (a chain never decides `valid`, §6 step 7) | do not rely on that key's certificate for the issuer's identity |
| `not_evaluated` | the property was not established HERE — never a pass, never tampering | supply what the reason names and verify again: `instrument_failure` — a verifier and machine that can run the check; `backend_missing` — a verifier with ML-DSA-65; `self_asserted` or `key_unresolved` on the producer — the producer's key, obtained out of band and pinned; `tsa_not_checked` or `tsa_invalid` — the certificate of a TSA you trust (`--tsa-cert`); `no_trust_anchor`, `chain_unresolved` or `self_asserted` on the issuer — your trust anchor, or the out-of-band key comparison below; `holder_key_unknown` — the holder binding is not established by this pack; `not_present` — the pack carries no such element |
| `verified` | the check ran and passed, within its scope: `producer_signature` — signed by a key YOU pinned; `time_anchor` — every token binds this digest and is signed by a TSA whose certificate you gave, at its `gen_time`; `issuer_identity` (`ca_certified`) — a CA under your anchor certified each key, never that the key is the issuer's: `x5c_leaf` names the certificate holder, which you match to the issuer | rely on that property, in that scope |

`policy.unmet` names what the pack lacks for THIS relying party (`require_producer`, `require_pq`, `require_anchor`,
`min_anchors`, `trusted_producer_keys`, `trust_set_complete`): the content may be intact; ask for the missing element or
decide without the ground that needed it. `valid` is `true` without pinned keys (`producer_signature: self_asserted`): that
is a policy of this format, not a trust statement.

**Signatures and identity.** `self_asserted_only: true` (and `issuer_identity` other than `verified`) means the mandate
signatures were checked against key material carried in the pack: they prove the artifacts are consistent with those
keys, not who the issuer is — for a valid pack too. For keys embedded in the signed headers (`jwk_header`) the relying
party compares them with the issuer's published keys out of band and records that it did. With the JS verifier,
`--tsa-cert` gives `time_anchor: not_evaluated/instrument_failure` and counts no anchor, and `--trust-anchor` is a usage
error: both checks need the reference verifier (openssl).

**Time.** `time_anchor: not_present` means the pack claims no anchor (1.10.0: a token under `anchored: false` is a refusal, §9.1).
`anchors_verified` counts the distinct anchors whose token binds this digest; with `--tsa-cert` only those whose TSA
signature also verifies (§3.3). `tsa_not_checked` is a binding a self-issued token satisfies (§3.2): it says nothing about
a TSA's clock. A time-based ground needs `time_anchor: verified` under the certificate of a TSA the relying party trusts,
read with its `gen_time`, or an independent timestamp.

**ACP SEP #303 §7.4a.** The Agentic Commerce Protocol dispute RFC (agentic-commerce-protocol/agentic-commerce-protocol
PR #316, `rfcs/rfc.dispute_resolution.md` at commit 6710a3a, 2026-10-17, a proposal under review) maps nine of the twelve fields (`bindings_ok`,
`pq_protected` and `policy_ok` are not named in §7.4a) and the `anchors` binding to admissibility. Its rows, and the 1.6.0 fields that carry the same condition:

| §7.4a at 6710a3a | 1.6.0 fields |
|---|---|
| `valid: true` under the provider's policy → Admissible, apply 7.4 normally | `admission: admitted`, `valid: true`, `policy.met: true` — and `producer_signature` read as below: without pinned keys it is `self_asserted`, which the table's rows do not distinguish from a pinned producer |
| `digest_ok: false`, or `rfc3161_verified: false` / a failed `anchors` binding → Not admissible (tamper) | `sealed_content: contradicted` (`digest_mismatch`); `time_anchor: contradicted` (`binding_mismatch`, `token_invalid`, `token_missing`) |
| `producer_present: false` → only facts the mandate's own signature proves | `producer_signature: not_evaluated` (`not_present`) |
| `producer_ok: true`, `producer_trusted: false` → Consistency-only, MUST NOT be the sole basis for an `overturn` | `producer_signature: not_evaluated` (`key_unresolved`); the same standing applies to `self_asserted` (no keys pinned: `producer_trusted` is `null`, in no row) |
| `anchors_verified: 0` with `rfc3161_claimed: false` → a time-based ground needs an independent timestamp | `time_anchor: not_evaluated` (`not_present`); `tsa_not_checked` and `tsa_invalid` likewise prove no TSA time |
| policy 3: "A verifier result meaning "no check ran" is not tamper. `key_unresolved` (…) **MUST NOT** be treated as `signature_invalid`" | every `not_evaluated` reason; `key_unresolved` is never `contradicted`, and `--trust-set-complete` records the relying party's disposition in `policy.unmet`, never as a failed signature (§6.9) |
| policy 3: "A missing counterparty record (`no_record`) maps to `not_responded`; silence **MUST NOT** be treated as acceptance" | outside this format: the receipt holds no counterparty record and no field stands for a response; an absent pack is not a pack that verified |
| — (no row) | `admission: refused` (any `refusal_class`): not evaluated — not tamper; the pack is not used as submitted, the submitting party may resubmit in a format the provider's verifier implements; record `refused` and `refusal_class` |
| — (no row) | any subject `not_evaluated` with `instrument_failure` (or exit 74 with a receipt): no result about the pack; re-run in a working environment before relying on the absence of that property |

The RFC's requirement that "the determination **MUST** record the verifier output fields for each pack" is met, for a
1.6.0 receipt, by recording `admission`, `refusal_class`, `states_vocabulary`, `states` and `policy` with the twelve fields.

**draft-xg-payment-dispute-profile-02 (informative mapping; 1.9.0, was -01).** That Internet-Draft (revision -02, 16
November 2026, expires 20 May 2027, Intended status Informational, read on the IETF datatracker on 2026-11-18, SHA-256 of
the text `e1c9345c…`; -02 "Retargeted from an Independent Submission vendor profile to consideration by the SCITT working
group", Appendix B; no IETF consensus) carries agent-native facts in an `agent_anchors` block — "AP2 mandate_hash, TAP
agent_id, approval event hash, receipt signature" (§8.2) — and a `scope_conformance` field, "one of in_scope,
BREACH:<field>, or not_evaluated", which "MUST be re-derived by the verifier from recorded inputs, never asserted without
re-derivation" (§8.2). Its §10 names this format ("ap2-evidence-pack 1.6.0 … publishes an informative mapping of its
receipt fields to -01"). Read against an ap2-evidence-pack receipt:

- `mandate_hash`: -02 does not define its preimage (its §5, "Field Constructions", does not list it). Where a profile takes it as the SHA-256 of a mandate's compact
  serialization, that is the value §4 of this format computes for that artifact (lowercase hex), and
  `sealed_content: verified` states that the artifact verified with that exact serialization.
- `scope_conformance`: no field of this receipt re-derives the intent scope against an executed action. A receipt of this
  format establishes which mandates were signed, bound and sealed — not whether an action stayed within them — so a
  profile that fills `scope_conformance` from it alone can state only `not_evaluated`, and none of this format's
  `not_evaluated` reasons may become `in_scope`.
- `settlement_anchor` (§8.3): outside this format; a pack carries no settlement artifact.
- Keys: -02 §4 requires that "Keys MUST be resolved out of band"; that is this format's `self_asserted` /
  `key_unresolved` → pinned-key rule, for the producer and for the issuer.

## 11. Restriction record (profile `io.github.robertolocatelli81.restriction/1`, revision 1.7.0, 2026-10-29, reference as a constraint)

Status: a profile of THIS repository, named in its own namespace as AP2 recommends for extensions ("It is RECOMMENDED to
use a collision-resistant naming approach, for example via a rDNS prefix controlled by the specifying entity",
`docs/ap2/agent_authorization.md` at google-agentic-commerce/AP2 `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`). It is not
part of AP2 and AP2 has not reviewed it. Released with 1.7.0; not in a conformance vector, and the JS verifier does not
implement it (declared). §1–§10 are unchanged: a pack that carries a restriction record is built, sealed and verified
exactly as any other pack, and its twelve fields and states do not depend on this section.

**Why.** AP2 at `e1ea56d` defines no way to restrict or revoke a mandate once issued: its normative text has no
restriction, revocation, amendment or supersession of a mandate (searched 2026-10-27 in `docs/ap2/*.md` and
`code/sdk/schemas/ap2/*.json`; the only "revoke" in the repository is `revoke_payment_credential` in the samples and the
web client, which revokes a payment token). `implementation_considerations.md` "Mandate Management" says the Shopping Agent "SHOULD provide a mechanism to
manage active Mandates"; the Delegate SD-JWT draft (GarethCOliver/gco-delegate-sd-jwt `0c1d686`, "Delegate SD-JWT
Revocation") says that revocation "present[s] a practical challenge as, unlike a traditional Issuer, an individual Holder
can not easily distribute revocation information to Verifiers". This profile records, in a pack, that the issuer of an
open mandate later signed narrower terms for it — and lets a verifier check that they ARE narrower.

### 11.1 The record

A restriction record R is an SD-JWT artifact (§2, ES256, verified as every artifact is) whose Mandate Content (below), after
disclosure resolution, holds in its `constraints` list exactly one constraint of the type of this profile:

`{"type": "io.github.robertolocatelli81.restricts", "issuer_jwt_hash": H}`, H = BASE64URL(SHA-256(ASCII bytes of the
original's Issuer-signed JWT)), no padding

— the original O being another artifact of the same pack. The constraint has exactly these two keys, and it is a plain
element of the list in the token as signed: not an array-element disclosure, no selectively disclosable key inside it, no
`_sd` key inside it (the signed element IS the resolved constraint; a `_sd_alg` key inside it makes the token no
SD-JWT since 1.8.1, §6 step 2, `sd_alg_not_top_level`, so it never reaches this rule). `constraints` itself MAY be a property
disclosure: a mandate without it is no typed mandate (`constraints` is required in `open_payment_mandate.json` /
`open_checkout_mandate.json`; measured 2026-10-28 with the SDK at `e1ea56d`: the token with that disclosure left out is
refused at `constraints`). In the `delegate_payload` form, `delegate_payload` MUST be a plain key of the payload: as a
property disclosure the holder could leave the whole content out, and with a mandate signed at the top level beside it the
token minus that one disclosure verifies in the SDK's typed path as an ordinary `OpenPaymentMandate` with the top-level
terms (measured, same commit). The same disclosure in O gives O two readings — the pack's (the content, every disclosure
present: §11.3 step 5) and the one its holder can present without it (the top-level terms; measured 2026-10-29, same
SDK: a top-level `max` of 10, and of 1000000, beside a content with `max` 20000 — the token minus that disclosure is
accepted with the top-level value, narrower or wider than the content) — and a verdict against one reading says nothing
about the other: R is then `not_evaluated` (`original_disclosable`, §11.3 step 6). What makes the two readings is that
the token minus that disclosure is read as ANOTHER set of signed terms (the top level), not as the content with fewer
elements: a presentation of O that leaves out elements of a selectively disclosable array (`allowed`, `acceptable_items`:
AP2's `x-selectively-disclosable-array`, the form of the documentation's tokens) is the content as signed with those
elements undisclosed — the SDK applies the elements shown (measured 2026-10-29, same SDK: the content of the open payment
mandate of `payment_mandate.md`, re-signed in the same form, minus its one `allowed` payee is accepted with `allowed: []`,
and `check_payment_constraints` then refuses the payee it admitted with the disclosure) — and is not a second set of signed terms: the verdict is about the
signed terms with every disclosure present (§11.3 step 5; declared in §11.5). The SDK issues `delegate_payload` as a
plain key holding an array-element disclosure (`sd_jwt.create`, `selectively_disclosable_claims`; measured, same
commit): the property-disclosure form is hand-built.

**Why a constraint and not a claim** (draft change of 2026-10-28; the first draft put the reference at the top level of
the payload). An AP2 verifier that does not implement this profile ignores an unknown JWT claim (RFC 7519 §4: "all
claims that are not understood by implementations MUST be ignored"), so it sees a record with a top-level reference as a
second valid mandate — and AP2 counts `payment.budget` per mandate ("tracking the total amount spent using this Payment
Mandate", `payment_mandate.md`), so O and R would each carry their own budget. Measured 2026-10-28 with the AP2 SDK at
`e1ea56d` (sd-jwt 0.10.4, pydantic 2.12.5): such a record verifies alone (`SdJwtMandate.from_sd_jwt`, `MandateClient.verify`,
`PaymentMandateChain.parse` + `verify`), the claim is not part of the typed mandate, and its constraints are evaluated as
an ordinary mandate's. An unknown constraint type is different: "Any unknown Constraints MUST be treated as failing
evaluation" (`agent_authorization.md`, "Verification and Processing Rules"), and the SDK refuses a mandate that carries
one where it reads the mandate as a type (measured: `pydantic.ValidationError` at `constraints[n]` from
`SdJwtMandate.from_sd_jwt`, `MandateClient.verify` with `payload_type` on a single token (on a chain `payload_type` is not applied: the hops come back as payloads), `PaymentMandateChain.parse` — the `constraints`
field of the generated `OpenPaymentMandate` / `OpenCheckoutMandate` is a closed union of the AP2 types). Where the SDK
does not read the open mandate as a type — `sd_jwt.verify`, `verify_chain` / `MandateClient.verify` without
`payload_type` on a chain (on a single token it raises `ValueError`), which check signatures, disclosures, key binding and time claims and return the payloads, and the
sample roles that validate only the closed hop (`credentials_provider_agent`, `merchant_agent`) — R passes like any
token and no constraint of any open mandate is evaluated there (measured, same commit: a closed mandate chained to R
passes `verify_chain` and the sample roles' path exactly as one chained to O — those paths evaluate no mandate's terms, O's
included). So a verifier that does not know this profile cannot EVALUATE R as a mandate: where it evaluates the
constraints of an open mandate, R fails; where it does not, it applies no mandate's terms. A verifier that knows the
profile reads R as what it is. The plain-element rule keeps it that way: a constraint the holder could leave undisclosed
would turn R back into an ordinary mandate for such a verifier. This is the `issuer_jwt_hash` of the Delegate SD-JWT draft
("verify that the `issuer_jwt_hash` is present and matches the base64url encoded digest of the preceding Issuer-signed
JWT or KB-SD-JWT+KB", section "Verification" of `draft-ietf-oauth-delegate-sd-jwt.md` at `0c1d686`) and of the AP2 SDK
(`compute_issuer_jwt_hash`, `code/sdk/python/ap2/sdk/sdjwt/common.py` at `e1ea56d`): it commits to the signed issuer JWT
and not to the disclosures a copy carries. (AP2's own example `payment.reference` hashes the whole compact serialization
instead — measured 2026-10-28: `FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8` in `payment_mandate.md` is the SHA-256 of the
open checkout example token including its disclosures and final `~` — the value the KB-JWT of the same example carries as
`sd_hash`, `checkout_mandate.md`. The two forms are different values; this profile uses only the first.)

R carries the restricted Mandate Content in the same FORM as O. The forms are those of the AP2 SDK's `from_sd_jwt`
(`code/sdk/python/ap2/sdk/mandate.py` at `e1ea56d`): when the payload has no `delegate_payload`, the payload itself is the
Mandate Content; when it has one, it MUST be a list of exactly one object, and that object is the Mandate Content (the
SDK requires exactly one disclosed item). A `delegate_payload` list of another shape is `form_unsupported` (§11.3 step 6)
— for O when its `delegate_payload` is a plain key (a property disclosure is `original_disclosable` first: step 6), and for R when one of its object elements holds the reference (§11.2) and §11.3 step 2 passed (two references, or
a malformed one, are `restricts_malformed` first); a list with no object element holding it (empty, or of other values)
makes no record, and the payload's own `constraints` are not read in this form. One that is not a list at all holds no
Mandate Content for §11.2, so such a token is no record here (the SDK at `e1ea56d` reads such a payload itself as the
mandate — `from_sd_jwt`, `isinstance(delegate_payload, list)`; stricter here, declared). In both cases the name of §11.2 at
the top level of the payload still makes a record (`restricts_misplaced`).
A record is evaluated only against the Mandate Content it carries; R and O in different forms
are `not_evaluated` (`form_differs`).

### 11.2 Evaluation and receipt

`ap2_evidence.py restriction <pack> [--tsa-cert PEM]` (library: `verify_restrictions(path, tsa_cert=None)`) verifies the
pack under §6 with the default policy (and `--tsa-cert` passed through), then evaluates every artifact that is a
restriction record: a constraint whose `type` is that of §11.1 in the `constraints` list of its Mandate Content (when
`delegate_payload` is a list that is not exactly one object, of any of its object elements, so that §11.3 step 6 can name
the form), or the name `io.github.robertolocatelli81.restricts` at the top level of its payload (the first draft's place:
§11.3 step 2). The receipt is one JSON object:

| field | meaning |
|---|---|
| `restriction_profile` | `"io.github.robertolocatelli81.restriction/1"` |
| `constraint_type` | `"io.github.robertolocatelli81.restricts"` |
| `admission`, `refusal_class`, `valid` | the §6.9/§6 values of the pack |
| `time_anchor` | the §6.9 `time_anchor` subject of the pack (`null` on a refusal) |
| `existed_by` | the earliest `gen_time` among the anchors whose binding AND TSA signature verified (§3.3), else `null`. It can be set while `time_anchor` is not `verified` (another anchor of the pack failed): the proof of §11.5 needs `time_anchor` `verified` |
| `restrictions` | one entry per restriction record, in artifact order (below) |
| `met` | `true` iff `restrictions` is non-empty and every entry is `verified` |

Each entry: `in` (the record's artifact name), `restricts` (the `issuer_jwt_hash` value as found when the record has
exactly one constraint of §11.1, or `null` when there is not exactly one or the value is not a string),
`original` (the name of the artifact it was evaluated against, or `null`), `same_issuer_jwt` (the other artifacts with
the same issuer JWT, sorted), `state`, `reasons`, `reported`. `reasons` lists, in evaluation order, one object
`{"state", "reason", "at"}` per check that did not pass (`at` is a path inside the Mandate Content or the payload, or
`"original"` / `"restriction"`). `state` is the highest state among `reasons`: `contradicted` > `not_evaluated` >
`verified`; `verified` only with no reason. `reported` lists `{"reason", "at"}` for what the rules below accept but name
(never a change of state).

The words are those of §6.9 with this meaning here: **`verified`** — R is bound to O (§11.3) and, under every rule of
§11.4, no broader than O; **`contradicted`** — a rule of §11.3/§11.4 is not met (R is not shown bound to O, or not shown
within it under that rule; a rule stricter than AP2 can contradict a record AP2 would find equivalent — declared in
§11.4); **`not_evaluated`** — this profile cannot judge (the pack is not valid, the original is not in the pack, hidden
content, an original with two readings, a name or a type outside the closed lists of §11.4). Nothing else is `verified`; a record is NEVER `verified`
when it is broader than O or not bound to it.

Exit: `0` iff `met`; `1` otherwise (refusal included); `2` usage; `74` as §6.10 (a check asked for could not be run here:
the complete receipt on stdout, one line `check not run here:` on stderr; or the receipt was not written).

### 11.3 Binding (in this order)

1. The pack is admitted and `valid` (§6 step 8, default policy) — else every entry is `not_evaluated` `pack_not_valid` and
   nothing else is evaluated: a record in a pack that does not verify is not evidence of anything.
2. The reference is well-formed (§11.1) — else `contradicted`, in this order: the name at the top level of the payload,
   `restricts_misplaced`; not exactly one constraint of the type of §11.1, a key other than `type` and `issuer_jwt_hash`
   in it, or `issuer_jwt_hash` not a string that decodes, as strict base64url (§3.1: alphabet only, no padding, canonical
   trailing bits), to 32 bytes, `restricts_malformed`; the constraint not a plain element of the signed `constraints`
   list (an array-element disclosure, a disclosure or an `_sd` key inside it, or `delegate_payload` itself a
   property disclosure: §11.1), `restricts_disclosable` (up to 1.8.0 also a `_sd_alg` key inside it; since 1.8.1 such a
   token is refused before, §6 step 2).
3. An artifact of the pack has an issuer JWT whose hash (§11.1) equals it — else `not_evaluated` `original_not_in_pack`.
   Several artifacts with that same issuer JWT are one signed mandate presented with different disclosures: the one with
   the fewest undisclosed digests (step 5), then the first in pack order, is O; the others are listed in `same_issuer_jwt`.
4. Same issuer key: R's and O's snapshotted `key.jwk` are equal on `kty`, `crv`, `x`, `y` — else `contradicted`
   `issuer_key_differs`. This states that the holder of the key that signed O also signed R; what that key proves about
   identity is §6 step 7 (self-asserted unless chained to the relying party's anchor), unchanged.
5. Nothing hidden: every digest of the issuer payload (the `_sd` entries and the `{"...": d}` array placeholders, also
   inside disclosed values) has its disclosure, in O and in R — else `not_evaluated` `undisclosed_digests` (`at`:
   `original` or `restriction`). RFC 9901 §4.2.5: "An Issuer MAY add additional digests to the SD-JWT payload that are not
   associated with any claim" (decoys): a verifier cannot tell a decoy from a hidden constraint, so a hidden element is
   never assumed absent. The census is the resolver's of §6 step 2 (one rule, one implementation): the digests it
   encounters minus the disclosures it matches. A digest encountered more than once is therefore that artifact's error
   under §6 step 2 (RFC 9901 §7.1 step 4) and the pack is not valid: that token's Mandate Content cannot be resolved, so
   it is read as no record at all (no entry), and every other record of the pack is `not_evaluated` `pack_not_valid`
   (step 1); a caller that reaches this step with such a token directly (`evaluate_restriction`, bypassing §6) gets
   `not_evaluated` `original_malformed` for O, `contradicted` `malformed` for R. Up to the draft of 2026-10-28 this step kept a census of its own because the
   1.6.0 resolver did not reject a repeated digest.
6. Same form (§11.1), and each form readable: first, O's `delegate_payload` a property disclosure of its payload (O has
   two readings, §11.1) is `not_evaluated` `original_disclosable` (`at`: `original`) and nothing further is evaluated;
   then `delegate_payload` present but not a list of exactly one object is `not_evaluated` `form_unsupported` (`at`:
   `original` / `restriction`); different forms are `not_evaluated` `form_differs`.
7. A chain is as strong as its weakest link: when O is itself a restriction record of the pack whose state is not
   `verified`, R is at most `not_evaluated` (`original_not_verified`, `at`: `original`) — R may be narrower than O and
   still broader than the mandate O claims to restrict. Applied after every record is evaluated, along the whole chain.

Several records naming the same original are each evaluated against it; the profile does not order or combine them
(each is a set of terms the issuer signed — under AP2's conjunctive evaluation a relying party can apply all of them).

### 11.4 No broader (rules)

**Principle, from AP2.** An open mandate is checked conjunctively: "Extract claims from open Mandate Content and verify the
closed Mandate Content has these values unchanged" and "Extract each Constraint from each open Mandate Content and
evaluate them against the closed Mandate Content based on the Constraint Type" (`agent_authorization.md`, "Verification
and Processing Rules"; the SDK's `check_payment_constraints` / `check_checkout_constraints` collect the violations of
every constraint, `constraints.py`). So R is no broader than O when every requirement of O is met by a requirement of R at
least as strict: a requirement R adds can only remove closed mandates, except where a rule below says otherwise. A value of
R canonically equal (§3) to the value of O always meets it. Integers are JSON integers (`type(x) is int`, not a boolean);
since 1.7.2, under `accept_integral_floats` only, a literal with a zero fractional part inside a token is read as its
integer (§3.1), so the AP2 documentation example `1000.00` (`payment_mandate.md`, line 214 at `e1ea56d`) is 1000 there
and an artifact error by default, while `100.50` (line 186) cannot be carried either way (declared; the SDK's own
`AmountRange.max: int` refuses it too, measured 2026-11-02).

**Top-level claims of the payload** (in the `delegate_payload` form: beside `delegate_payload`; in the other form the
payload is the Mandate Content and the content rules apply to it):

- `exp`: when O has it, R has it, an integer ≤ O's (`contradicted` `time_widened`); `nbf`: when O has it, R has it, an
  integer ≥ O's (`time_widened`). R may add either. A non-integer in R is `contradicted` `malformed`, in O `not_evaluated`
  `original_malformed`.
- `iss`, `sub`, `aud`, `vct`, `cnf`: present in both with canonically equal values, or absent in both (`contradicted`
  `claim_changed`; for `cnf` `cnf_differs`: the record binds the same agent key).
- `iat`, `jti`: not compared (a new token has its own), but typed — `iat` an integer, `jti` a string (RFC 7519 §4.1.6,
  §4.1.7): another type is `contradicted` `malformed` in R, `not_evaluated` `original_malformed` in O. `iat` is the
  issuer's statement, never a proven time (§11.5).
- any other name: RFC 7519 §4 — "all claims that are not understood by implementations MUST be ignored" — governs the
  processing of the JWT, which is not rejected; whether such a claim narrows or widens is not known here, so a name this
  list does not hold is matched only when it is canonically equal in O and R; otherwise `not_evaluated` `unknown_name`.

**Mandate Content.** Supported `vct`: `mandate.payment.open.1` and `mandate.checkout.open.1` (`payment_mandate.md`,
`checkout_mandate.md`). R's `vct` MUST equal O's (`contradicted` `claim_changed`). Content of any other `vct` is matched
only when canonically equal; otherwise `not_evaluated` `vct_not_supported`.

- Known keys: the properties of `open_payment_mandate.json` (`vct`, `constraints`, `cnf`, `payee`, `payment_amount`,
  `payment_instrument`, `pisp`, `execution_date`, `risk_data`, `iat`, `exp`) and of `open_checkout_mandate.json` (`vct`,
  `constraints`, `cnf`, `iat`, `exp`). Another key is matched only when canonically equal in both; otherwise `not_evaluated`
  `unknown_name`.
- `cnf`: canonically equal (`cnf_differs`). `exp`, `iat`: as at the top level.
- Pre-set values — every other known key (`payee`, `payment_amount`, `payment_instrument`, `pisp`, `execution_date`,
  `risk_data`): present in O → present and canonically equal in R (`contradicted` `preset_changed`; AP2 rule 2 above);
  absent in O → R may add it (one more value the closed mandate must carry unchanged).
- `constraints`: a list in R (`contradicted` `malformed`) and in O (`not_evaluated` `original_malformed`). The
  constraints of the type of §11.1 are not compared, in R (the binding, §11.3) nor in O (O may be a restriction record of
  a third mandate: §11.3 step 7). For EACH other constraint c of O, R holds a constraint that meets it: canonically equal, or of the same `type` and within c by the table
  below. R holds none of that type: `contradicted` `constraint_removed`; of that type but none within: `contradicted`
  `constraint_widened` (`at`: c's path in O). c of a type outside the table: met only by an equal copy, else
  `not_evaluated` `unknown_name`; c malformed (a type of the table with a missing required key, a wrong type, or a key
  outside its schema): met only by an equal copy, else `not_evaluated` `original_malformed`.
- Each other constraint of R that is not an equal copy of a constraint of O: a type of the table MUST be well-formed — required
  keys present, every key in the schema's `properties`, JSON types exact (`contradicted` `malformed`: the SDK's pydantic
  models would coerce `"999999"` into an integer, so a mistyped bound could be read wider than it looks; a key outside the
  schema is `not_evaluated` `unknown_name`). A type outside the table is ACCEPTED and listed in `reported`
  (`unknown_constraint_added`): AP2 — "Any unknown Constraints MUST be treated as failing evaluation" (same section) — so
  it can only remove closed mandates. `payment.agent_recurrence` absent from O and present in R is `not_evaluated`
  `recurrence_added`: AP2 says it "Provides conditions for the agent to reuse this Payment Mandate multiple times" and does
  not say whether a mandate without it may be reused, so adding it may grant reuse.

| `type` (schema keys) | c' (in R) is within c (in O) when |
|---|---|
| `payment.amount_range` (`type`, `currency` string, `max` integer — required; `min` integer) | same `currency`; `max'` ≤ `max`; when c has `min`, c' has `min'` ≥ `min` ("If absent, there is no minimum") |
| `payment.budget` (`type`, `currency` string, `max` — required; `max` is `number` in the schema, read here as an integer by the rule above (1.7.2: `10.0` is that artifact's error by default and 10 under `accept_integral_floats`; a fraction is that artifact's error either way, §3.1) — the AP2 SDK takes it in major units, `int(self.constraint.max * 100)`, `constraints.py`, unlike `amount_range`; the same unit on both sides keeps the comparison sound) | same `currency`; `max'` ≤ `max` |
| `payment.agent_recurrence` (`type`, `frequency` enum — required; `max_occurrences` integer) | `frequency'` no more frequent, in the order `ON_DEMAND` < `DAILY` < `WEEKLY` < `BIWEEKLY` < `MONTHLY` < `QUARTERLY` < `ANNUALLY` (this profile's reading of "sufficiently separated in time from the previous presentation to meet the `frequency` definition", `payment_mandate.md`; AP2 states no order and the SDK does not evaluate `frequency`); when c has `max_occurrences`, c' has one ≤ it |
| `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.allowed_pisps`, `checkout.allowed_merchants` (`type`, `allowed` list of objects — required) | every element of `allowed'` is canonically equal to an element of `allowed` (stricter than AP2's matching — `merchant_matches` compares `id`, or `name`+`website`; an element spelled differently that AP2 would match the same is `constraint_widened` here, declared) |
| `payment.execution_date` (`type` required; `not_before`, `not_after` strings) | when c has `not_before`, c' has one ≥ it; when c has `not_after`, c' has one ≤ it. Comparable values are `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ` (ASCII digits, a real calendar date and time), both of the SAME form; another form or two forms is `not_evaluated` `date_form` |
| `payment.reference` (`type`, `conditional_transaction_id` string — required) | equal `conditional_transaction_id` |
| `checkout.line_items` (`type`, `items` non-empty list of `{id` string, `acceptable_items` list of objects, `quantity` integer > 0`}` — required) | same number of `items`; at each position (the list is compared in ORDER: a reordered `items` is `constraint_widened` here where AP2's maximal flow would find it equivalent, declared) the same `id` and the same `quantity`, and every element of `acceptable_items'` canonically equal to an element of `acceptable_items`; an EMPTY list on one side only is `constraint_widened`: the AP2 text matches an item "if its ID is present in the revealed `acceptable_items`" (`checkout_mandate.md`), so an empty list admits no item, while the SDK treats it as a wildcard (`max_flow_helper.py`: `req_is_wildcard = not req.acceptable_items`) — under one of the two readings the record is broader. An `items` entry cannot be added or removed: the constraint "is met if the maximal flow equals the total constraint `items` quantity and the total checkout `items` quantity" (`checkout_mandate.md`), so another set of entries admits other checkouts, not fewer |

### 11.5 What a `verified` record proves, and what it does not (declared)

Proves, within a valid pack: the key that signed O signed R; R names O by the hash of O's signed issuer JWT; under §11.4,
every closed mandate R admits, O admits too; and — only with `time_anchor` `verified` (the TSA's certificate given,
§3.2) — R existed by `existed_by`.

Does NOT prove: that the agent, the merchant, the credential provider or any verifier RECEIVED R or applies it; that O
stopped being valid — AP2 has no revocation, O stays a mandate a verifier that holds only O will accept within O's terms;
the time R was signed (`iat` is the issuer's statement; only the anchor gives an upper bound, and only for the pack); who
the key belongs to (§6 step 7); what a holder of O shows: the verdict is about O's signed terms with every disclosure
present (§11.3 step 5), and a presentation of O with elements of a selectively disclosable array left out is read by the
SDK with the elements shown — narrower (`allowed`: no payee admitted) or wider (`acceptable_items`: a wildcard, §11.4) than
the signed terms (§11.1, measured). R is NOT a mandate on its own for an AP2 verifier that does not implement this profile
and evaluates constraints: the constraint of §11.1 fails evaluation there by AP2's rule (§11.1, measured with the SDK at
`e1ea56d`; a path that evaluates no constraint passes a closed mandate under R as under O, §11.1). This is intended:
such a verifier cannot apply the restriction, so it must not count R as authority of its own; O stays what it was for it.
How a verifier that implements this profile evaluates the constraint against a closed mandate in a payment flow is not
defined here: this section defines it as evidence (§11.3, §11.4) only. Not covered: restrictions of a delegated hop (a KB-SD-JWT of the chain), closed mandates, the `payment.budget`
and `payment.agent_recurrence` STATE (amounts already spent, uses already made: a restriction narrows the terms, it does
not account for what O already authorised), and AP2 revisions after `e1ea56d`. AP2's matching rules are looser than
the equalities of §11.4 in three places (allowed lists, date forms, the order of `checkout.line_items` entries): there the
profile can say `contradicted` or `not_evaluated` where AP2 would find the terms equivalent — never `verified` where they
are broader.

## 12. Not-before block `not_before` (revision 1.8.0, 2026-11-18; NORMATIVE when present)

### 12.1 Why, what binds the payment today, and what is ours
Up to 1.7.3 a pack has an upper time bound only: an RFC 3161 token over the digest (§3.2, §3.3) shows the sealed content
existed by the TSA's time. Nothing bounds it from below: `created_utc` is the producer's statement. A value published by a
randomness beacon at time T and unpredictable before T, placed INSIDE the sealed content, bounds the sealing from below.

What binds the payment today, measured on 1.7.3 and on AP2 at `e1ea56d` (the head of `main` of
google-agentic-commerce/AP2 on 2026-11-16, `git ls-remote`; `code/sdk/schemas/ap2/payment_mandate.json`,
`types/amount.json`, `types/merchant.json`, `types/payment_instrument.json`): the AP2 Payment Mandate carries
`payment_amount` `{amount (integer, ISO 4217 minor units), currency (ISO 4217 code)}`, `payee` `{id, name[, website]}` (the
merchant), `payment_instrument` `{id, type[, description]}`, optionally `pisp`, and `transaction_id` (a hash of the
checkout); its issuer signs it (ES256, an SD-JWT) and the holder's KB-JWT signs its `sd_hash`. The payer is not named by a
field: it is the holder of the key in `cnf`. AP2 defines no IBAN and no bank account field (no member named or described
as one in the schemas or in `docs/ap2/*.md` at `e1ea56d`). These mandates are AP2's (Google's), NOT ours: this section
changes nothing in them. OURS is the pack: its top level and §3 digest, which covers every artifact's `sd_jwt_compact` and
`resolved_claims` byte for byte, and the producer signatures over that digest (§5).

Against the minimum of a transfer of funds within the Union in Regulation (EU) 2023/1113 Art. 5(1) (OJ L 150, 9.6.2023;
in force, applicable from 30 December 2024 (Art. 40), repealing Regulation (EU) 2015/847 (Art. 39); EUR-Lex lists one
consolidated version, of 9.6.2023, so no amendment; Art. 5(1)-(2) read on EUR-Lex on 2026-11-16: "at least the payment
account number of both the payer and the payee or, where Article 4(3) applies, the unique transaction identifier"; on
request within three working days the information of Art. 4 above EUR 1 000, at least the names and the account numbers
up to it, Art. 5(2)), a 1.7.3 pack binds: the amount and currency (the mandate's issuer signed them); a unique id of
AP2's (`transaction_id`); NOT the payer's or payee's IBAN (no field); the payee's name in clear (`payee.name`, the
merchant, signed by the issuer); no payer name. The block below adds, in OUR layer, the missing items and the beacon.

When the mandate is paid in crypto-assets (for example a stablecoin through AP2's x402 path), the transfer is a transfer
of crypto-assets under the same Regulation, Art. 14 (read on CELLAR, English OJ text, on 2026-11-17): the originator's
crypto-asset service provider "shall ensure that transfers of crypto-assets are accompanied by" the originator's name,
distributed ledger address and crypto-asset account number where one is used, address with country, official personal
document number and customer identification number (or date and place of birth) and, where available, LEI (Art.
14(1)); the beneficiary's name, distributed ledger address and account number, and LEI where available (Art. 14(2));
"in advance of, or simultaneously or concurrently with, the transfer" and not necessarily attached to it (Art. 14(4)).
This pack binds none of these items for a crypto-asset transfer: the `not_before` block below speaks of IBANs and of a
transfer of funds. A stated limit of 1.8.0, not a check made here.

### 12.2 The block (closed at every level, §9.1; inside the digest: §3 does not exclude it)
```
"not_before": {
  "profile": "ap2-evidence-pack.not-before/1",
  "payment": {"payment_id": <1..35 characters>, "amount": <decimal string>, "currency": <3 capital letters>,
              "payer_iban_commitment": <64 lowercase hex>, "payee_iban_commitment": <64 lowercase hex>,
              "record_salt": <32..128 lowercase hex, an even number>,
              "beacon": {"source": "nist-beacon-2.0", "chain_index": <integer ≥ 0>, "pulse_index": <integer ≥ 1>,
                         "output_value": <128 hex digits, either case>},
              "payer_name_commitment"?, "payer_details_commitment"?, "payee_name_commitment"?: <64 lowercase hex>},
  "mandate": {"artifact": <name of an artifact of this pack>, "amount_claim": <path in its resolved claims, §4 syntax>},
  "pulses":  {"pulse": <the NIST pulse `pulse_index`, as served under "pulse">,
              "previous_pulse": <the pulse before it, as served>,
              "certificate": <the PEM certificate served at /beacon/2.0/certificate/<certificateId>>}
}
```
Every member is MUST except the three marked `?`. A key outside these lists: refusal `unknown_member`; a missing key, a
wrong JSON type (a boolean is not an integer, a number is not an amount string) or a value of another form: refusal
`malformed`, naming the member and the reason. The commitment encoding and the names of the five commitment members are
the ones of cryptovalid-opencore SPEC §18 (`cryptovalid-payment/1`); the other members are this block's own, and 12.6
lists where they differ from cryptovalid's payment entry.

**No personal data in clear in the pack.** The IBANs, the names and the payer's details are recorded only as salted
commitments (Regulation (EU) 2016/679 Art. 5(1)(c), 17 — in force; EUR-Lex lists one consolidated version, 4.5.2016; the
general "Digital Omnibus" that would amend it, COM(2025) 837, procedure 2025/0360(COD), is a proposal: "Awaiting
committee decision" on the European Parliament's Legislative Observatory, read on 2026-11-17; the separate Regulation
(EU) 2026/1744, "Digital Omnibus on AI" (OJ L 24.7.2026, in force on the third day after publication), amends Regulations
(EU) 2024/1689, 2018/1139 and 2023/1230, not 2016/679; both read on the primary sources that day; and the retention of
Regulation (EU) 2024/1624 (AMLR; OJ L 19.6.2024; English OJ text read on CELLAR on 2026-11-17): Art. 90, "It shall
apply from 10 July 2027", 10 July 2029 for the obliged entities of Art. 3 point (3)(n) and (o); Art. 77(3), the records
"retained for a period of 5 years" from the end of the business relationship or the occasional transaction, after which
"obliged entities shall delete personal data"). The
clear values and their salts stay with the payment service provider, outside the pack. To disclose (Regulation (EU)
2023/1113 Art. 5(2)) the provider gives `{member, salt, value}` and anyone checks it (`check_disclosure`); to delete, the
provider destroys values and salts: the pack, its digest, its signatures and its time anchors stay intact and the
commitments can no longer be opened. Amount, currency, payment id, record salt and beacon value stay in clear; whether
they are personal data depends on what else their holder keeps (EDPB Guidelines 02/2025 on processing of personal data
through blockchain technologies, version 2.0 adopted 2026-07-07, §52: a salted hash "will also be considered personal
data, as will any other identifiers that might exist"; after deletion of the salt it "should not be linkable to the
original data" under the conditions that paragraph sets); this format does not decide it. What the AP2 artifacts themselves carry is AP2's, sealed byte for byte and not changed here: a Payment Mandate
writes the merchant's name in clear (`payee.name`), and a destroyed salt does not remove it.

- Commitment: 64 lowercase hex = SHA-256(ASCII "cryptovalid-payment/1/" || the member's name in ASCII || 0x00 || salt
  (exactly 16 bytes, drawn at random by the provider for this member of this payment) || UTF-8 of the value). The member
  name in the hashed bytes keeps a commitment from being opened as another member; the 0x00 ends the name, the salt has a
  fixed length, so the hashed bytes split one way only. Value: for `payer_iban_commitment` and `payee_iban_commitment`
  the IBAN normalised — a value with a character outside ASCII refused first ("ß" in upper case is "SS"), then every
  space (U+0020) removed and the letters in upper case — and checked by the IBAN rule BEFORE it is committed; for the
  name and details members the text in Unicode NFC. A value is a non-empty string of at most 1024 characters, every one
  a code point assigned in Unicode 13.0.0 (as cryptovalid-opencore §18): NFC of such a string is the same in every
  later Unicode version, and of a code point assigned later it is not (measured on 2026-11-16: "a" U+1E08F U+0316 is
  reordered by CPython 3.13 and not by 3.9; U+105D2 U+0307 is composed by Node 22, Unicode 17.0, and by no CPython from
  3.9 to 3.13), so the two verifiers of this repository, or two Python versions, would otherwise disagree on a
  disclosure. Another value is refused (a disclosure outside the grammar; an error for the writer).
- Disclosure: exactly `{"member": <one of the five commitment members>, "salt": <32 lowercase hex>, "value": <string>}`.
  It matches when the commitment recomputed from it (the value normalised as above) equals the pack's member byte for
  byte (`disclosure_mismatch` otherwise); for an IBAN member the normalised value must also pass the IBAN rule
  (`disclosure_iban_invalid`, checked first). A disclosure of a member the pack does not carry: `member_absent`.
- IBAN rule (ISO 13616-1:2020 electronic form — edition 2, which replaced ISO 13616-1:2007, per the ISO catalogue as
  quoted by search results on 2026-11-16; iso.org refused a direct read, 403): two capital letters, check digits 02-98,
  then 11 to 30 capital letters or digits, 15 to 34 characters; ISO/IEC 7064 MOD 97-10 = 1 (the 2003 edition is the one
  cited; whether it is still the current one was not confirmed on 2026-11-16). Reasons: `iban_charset`, `iban_length`, `iban_check_digits`,
  `iban_checksum`. The SWIFT registry's per-country length and BBAN structure are not checked (12.6).
- `record_salt`: at least 128 bits drawn at random by the provider for this payment, so that the members in clear (amount,
  id, beacon value) cannot be searched behind the pack's digest either. Kept in the pack (it is not deleted with the
  commitments' salts).
- `amount`: a string, `0` or 1 to 18 digits not starting with 0, then optionally `.` and 1 to 4 digits; greater than zero.
- `currency`: three capital letters A-Z (NB2 compares it with the mandate; minor units: 12.3).
- `payment_id`: 1 to 35 characters (ISO 20022 Max35Text) of the SEPA Latin set `A-Z a-z 0-9 / - ? : ( ) . , ' +` and space,
  not starting or ending with a space (the set as commonly published, NOT re-read against the EPC rulebook or the ISO
  20022 schema today). Uniqueness is the producer's: a verifier sees one pack.
- `beacon.source` a closed list (`nist-beacon-2.0`); the pulses are closed as `ap2_nist_beacon.check_grammar` states (their
  fifteen members, `external` three, `listValues` the five types once each, fixed-length hex, the `uri` naming its own
  chain and index, `cipherSuite` 0, `version` "2.0", a `timeStamp` that is a real calendar time); the certificate one PEM
  block with an RSA key, whose `notBefore` and `notAfter` are each a UTCTime `YYMMDDHHMMSSZ` (RFC 5280 §4.1.2.5.1,
  `YY` ≥ 50 is 19YY) or a GeneralizedTime `YYYYMMDDHHMMSSZ` (§4.1.2.5.2) of ASCII digits naming a real calendar time
  (month 1-12, a day of that month, hour 0-23, minute and second 0-59); anything else is `certificate_time`, an error of
  the block. 1.8.1: up to 1.8.0 a value of the right digits that is no calendar time (month 13, measured on 2026-11-18 on
  the PyPI wheel 1.8.0 with the real NIST certificate so altered) ended the reference with a traceback, exit 1 and no
  receipt; the JavaScript verifier already refused it as `certificate_time`.
A producer does not write a block this section refuses, nor one whose NB1 or NB2 is not `verified` at build.
`build_evidence` takes the clear values and makes the commitments (`make_payment`); it never writes a clear IBAN or name.

### 12.3 Checks (receipt member `not_before`, present only when the pack carries the block)
- NB1 (beacon), the checks of cryptovalid-opencore SPEC §19 rules 2-9 written again here (`ap2_nist_beacon.verify_pair`):
  `statusCode` 0 in both pulses (`status_not_supported`); one chain, consecutive indexes (`pulse_mismatch`); equal
  `period` and `certificateId` (`chain_inconsistent`); for each pulse, the certificate's SHA-512 = `certificateId`
  (`certificate_not_the_certificate_id`), that id pinned for the chain in the closed list `ap2_nist_beacon.PINNED`
  (`certificate_not_pinned_for_chain`; chain 2, the certificate measured 2026-11-16, valid 2026-10-21 to 2027-03-20), the
  pulse time inside its validity, the RSA PKCS#1 v1.5 SHA-512 signature (`pulse_signature_invalid`) and outputValue =
  SHA-512(signed message || signature) (a failure of the predecessor is named `previous_<reason>`); the named pulse's
  `previous` = the predecessor's outputValue (`previous_mismatch`), its time = the predecessor's + period
  (`period_mismatch`), SHA-512(its localRandomValue) = the predecessor's `precommitmentValue` (`commitment_mismatch`); and
  `payment.beacon` names that pulse and carries its outputValue (compared as bytes; `beacon_value_mismatch`).
- NB2 (the amount, against the mandate) `mandate.artifact` names an artifact of the pack (`failed:mandate_not_in_pack`)
  whose issuer signature and claims verified (§6 step 2; else `not_evaluated:mandate_not_verified`); the value at
  `amount_claim` is an object of exactly `amount` and `currency` (`failed:amount_claim_not_found` when there is none), its
  currency is `payment.currency`, and its integer amount equals `payment.amount` in minor units (`failed:amount_not_the_
  mandate_amount`), with the minor unit of the closed table `MINOR_UNITS` (EUR, USD, GBP, CHF 2; JPY 0 — the ISO 4217 minor units of those
  five currencies, five facts and not a copy of the list: `test_ap2_currency_table.py` compares them with ISO 4217 list
  one when the caller gives its own download, `CV_ISO4217_LIST`; measured on 2026-11-17 against list one published
  2026-09-17; no list is distributed here, as cryptovalid-opencore SPEC §18 "Currencies"); another currency:
  `not_evaluated:currency_minor_unit_unknown`, the check not made). The receipt names the mandate's `payee` (top level or
  `delegate_payload[0]`, informative). The IBANs are not compared with the mandate: the pack holds only their commitments
  (a disclosed IBAN can be searched in the mandate's claims by the relying party).
- NB3 (window) T = the named pulse's `timeStamp`. A `created_utc` that matches the §1 pattern but is no calendar time
  (`2026-02-30T00:00:00Z`): `failed:created_utc_not_a_time` (§1 checks the pattern only; up to the first draft of this
  section the reference stopped there with a traceback). `created_utc` before T: `failed:created_before_beacon`. The upper bound
  is the earliest TSA-verified genTime of §3.2/§3.3 (a token whose TSA signature verified with the relying party's
  `--tsa-cert`): genTime before T `failed:window_inverted` (compared exactly, whatever the number of fraction digits) (one of the two time sources is wrong or was subverted;
  cryptovalid-opencore §19.5 uses the same name); genTime = T is one instant; no such token:
  `not_evaluated:no_verified_time_anchor` (the window stays open above). A TSA-verified genTime that is no calendar time
  — second 60 or 61, which `-attime` accepts (a leap second is written `…235960Z`) — cannot be compared with T:
  `not_evaluated:verified_time_not_a_time`, the window stays open above (1.8.1; up to 1.8.0 the reference stopped there
  with a traceback, found by reading the code: Python's `time.strptime` accepts second 60 and 61, its `datetime` does not;
  not reproduced with a real TSA). NB3 runs only when NB1 is `verified`.
`state` is `failed` when any of NB1-NB3 failed, `verified` when all three are, else `not_evaluated`. A pack whose
`not_before` state is `failed` is not `valid`. `window`: `{"not_before": T, "not_before_operator_promise": T − period,
"not_after": the genTime or null}`, the first two filled only when NB1 and NB2 are `verified`. `covers` lists the fields
the bound covers.

### 12.4 What a verified block proves, worded exactly
With NB1, NB2 and NB3 `verified`: "the sealed content of this pack — the AP2 artifacts byte for byte, among them the mandate
whose issuer signed amount A in currency C at path P, and, written by the producer in one object with the beacon value,
the commitments to the payer's and payee's IBANs (and to the names and details when present), the amount, the currency,
the payment id and the record salt — was put together
after T against anyone but NIST or whoever controls its engine or key before T, after T − 60 s if NIST kept its freshness
promise, and existed by the TSA's genTime; against a NIST that breaks its promises there is no lower bound" (the bounds of
cryptovalid-opencore §19.4, on the promises of NIST IR 8213 — an Initial Public Draft of May 2019, still a draft on
csrc.nist.gov on 2026-11-16, with no final version; NIST names the service "NIST Randomness Beacon (Version 2.0 Beta)", "a beta release" (csrc.nist.gov
Projects/interoperable-randomness-beacons/beacon-20, updated 5 November 2026, read on 2026-11-16): every input of outputValue
is in NIST's hands; the commitment only shows the local random value was fixed by T − period). It is technical evidence,
not a time stamp with a legal category.
A disclosure that matches proves the disclosed IBAN or name is the one committed in that sealed content. It does NOT
prove: that the mandate was SIGNED after T (its issuer did not sign the beacon value; a mandate signed earlier can be
sealed later); that the committed IBANs are the accounts of the payer and payee, or the names those of the parties (they
are the producer's statements, sealed with the digest and signed by the producer's key when §5 signatures are present;
AP2's issuer did not sign them); that any money moved; anything about a value whose salt was destroyed. A change after
sealing (a commitment, the amount, the id) breaks the digest; the same change re-sealed by the
producer after the TSA's token is no longer the content that token binds (§3.2) — the window is what shows a later change.

### 12.5 Tests (test_ap2_not_before.py, test_js_not_before.py)
Real pulses and certificates (`spec/vectors/beacon/`, fetched 2026-11-16, with SHA256SUMS); the IBANs are the published
examples of the SWIFT IBAN registry (`GB82WEST12345698765432`, `DE89370400440532013000`; a changed IBAN is the other
example); mandates, names, details and amounts are test data. Positive control first: the 1.7.3 verifier refuses a pack
with the block (`unknown_member`, top level) and, with `ap2_nist_beacon.py` beside it, 27 of the 30 tests of
`test_ap2_not_before.py` fail on 1.7.3 (the three that pass there: the vectors' hashes, the pulse-pair rules of the beacon
module, a pack without the block); 23 of the 30 fail on the first draft of this section, which wrote the IBANs in clear
(measured on 2026-11-16, before the corrections of the section's second review). Generative cases: no clear IBAN or name anywhere in a
built pack (the file is searched for each value); the beacon outside the sealed content (beside the seal in
`rfc3161_timestamp`, in `anchors`: refused); every payment member changed after sealing (digest); amount and currency
re-sealed against the mandate (NB2), and the producer refusing to build them; the mandate's amount or currency changed; the
mandate named wrongly; disclosures: right value and salt, another value, another salt, another member's salt, the value of
one member against another member (the member name is in the hashed bytes), an IBAN with spaces and lower case (normalised),
an IBAN that fails MOD 97-10 (`disclosure_iban_invalid`), NFC and NFD of one name, a member the pack does not carry, an
unknown key, wrong types; a known-answer test of the encoding written out by hand; a pulse of chain 1 (refused, "Version
2.0"), the certificate of chain 1, another chain index, the output value in lower case (accepted, as cryptovalid); a
genTime before T (window inverted) and equal to T; `created_utc` before T; one bit flipped in each hex field of both pulses;
an unknown key at every level; a missing required key at every level, the three optional ones absent; every member with
each wrong JSON type; malformed amounts, currencies, payment ids, record salts and commitments; a duplicate key in the file;
a copy of the verifier without the beacon module (refused, `format_unsupported`). The rules of the predecessor that no real
NIST pair can break with valid signatures are tested on the pulses of a TEST beacon made by the test (a throwaway RSA key
and certificate, pinned only there). The JavaScript verifier: `test_js_not_before.py` runs the not_before cases of
`verifiers/differential_oracle.py` (the variants above, generated, plus the window rule with genTimes before, at and
after T and the disclosures, called directly in both); positive control: with the JavaScript verifier as it was before it read the
block (2026-11-16) it fails, 278 disagreements of 281.

### 12.6 Open
Both verifiers read the block (1.8.0): `verifiers/js/ap2-verify.mjs` checks the same closed grammar,
the same pulse pair, the same NB1-NB3 codes and receipt, and exports the same commitment encoding and disclosure check
(`paymentCommitment`, `checkDisclosure`). One difference stays, the one the format already declares for every TSA check:
the JS verifier cannot verify a TSA signature (no openssl), so it never has a TSA-verified genTime and its NB3 is at best
`not_evaluated:no_verified_time_anchor` where the reference, given `--tsa-cert`, closes the window; the window rule itself
is the same, compared by calling both functions with the same genTimes (`verifiers/js/nb_parity.mjs`). Measured by
`verifiers/differential_oracle.py`: 232 not_before packs + 1 positive control + 48 function cases, 0 disagreements of 281
(`test_js_not_before.py`). cryptovalid-opencore does not carry a copy of this verifier (since its 0.18.0 it uses the installed
ap2-evidence-pack, `>=1.6.0,<2`): with 1.7.3 installed a pack with the block is refused there as here by 1.7.3 (an
unknown top-level member), until 1.8.0 is installed. The SWIFT registry's
per-country BBAN rules; ISO 4217 minor units beyond the closed table; the payment-id character set re-read on the official
schema; a second beacon (CURBy, drand); the relying party's own pinned certificates; the KB-JWT `nonce` (RFC 9901 §4.3,
chosen by the verifier; RFC 9901, Proposed Standard, November 2025, per datatracker on 2026-11-16) as the place where a beacon value would be inside bytes the HOLDER signs — a profile of AP2's flow,
not of this pack. `ap2_nist_beacon.py` is a prototype, to be replaced by the beacon verifier of cryptovalid-opencore.
Alignment with cryptovalid-opencore SPEC §18-§19, re-read on 2026-11-16 in the version that adds the beacon payment
entry (v0.10, not yet released; its second review's corrections included): the
same commitment encoding (domain, member name, 0x00, 16-byte salt, normalised value; non-ASCII IBAN refused before upper
case; code points of Unicode 13.0.0), the same five commitment member names, the same disclosure grammar and outcome
names, the same `record_salt`. Different: `payment_id` (cryptovalid: a version 4 UUID in lowercase canonical form; here:
Max35Text of the SEPA set); the beacon (cryptovalid: `beacons`, a list of 1 to 8 values with `chain_index` 2 and
`output_value` in upper case; here: one `beacon` object, any `chain_index` ≥ 0 that `ap2_nist_beacon.PINNED` then must
pin, either case; the pulses' hex values: cryptovalid accepts either case and compares bytes, here they must be
as the service serves them, `certificateId` in lower case and the other values in upper case); the commitments
(cryptovalid: 13 members, the IBANs optional with at least one party identifier, and
`execution_date`, `payee_entity_id`, `psp_id` in clear; here: 5 members, both IBANs required); `currency` (cryptovalid:
three capital letters, and exactly the ISO 4217 minor units only with a currency table the caller pins; here: any three capital letters and up to 4 decimals,
NB2 comparing against the mandate with its closed table); `payment_id` uniqueness (cryptovalid: within a ledger; a pack
holds one payment).

## 13. JOSE header profile (1.8.0; library functions, NORMATIVE for what they answer)

A relying party that receives a JWT from another ecosystem (a key proof, a key attestation, an SD-JWT VC, a Key Binding
JWT) needs the header checked against the type and the algorithms its profile names, before any key is looked up. RFC
8725 §3.11 (Best Current Practice, February 2020; status read on rfc-editor.org on 2026-11-17; its revision
draft-ietf-oauth-rfc8725bis is at -10, a draft, not in force) recommends explicit typing.

- `decode_jose_header(segment)`: the first segment of a JWS compact serialization, base64url as §9.1 reads it (RFC 7515
  §2: no padding, no whitespace, canonical trailing bits), decoded as UTF-8, a JSON object with no member twice (the
  closed reader of §3.1). Anything else is `Ap2EvidenceError` naming why.
- `check_jose_header(header, expected_typ, allowed_algs)` returns `{"ok", "why", "typ", "alg"}` and never raises on the
  header; `why` is the first of, in this order: `header_not_object`; `crit_not_understood` (RFC 7515 §4.1.11: a `crit`
  member is present, and this function understands no extension); `alg_missing`, `alg_not_string`, `alg_not_allowed`
  (`alg` not in `allowed_algs`); `typ_missing`, `typ_not_string`, `typ_mismatch`. `allowed_algs` is a non-empty list
  of strings without "none" (RFC 8725 §3.2) and `expected_typ` a non-empty string; otherwise ValueError.
- **The `typ` comparison** (RFC 7515 §4.1.9, Proposed Standard, May 2015): `typ` is a media type, compared without
  regard to ASCII case, and "a recipient ... MUST treat it as if 'application/' were prepended to any 'typ' value not
  containing a '/'" — the same normalisation is applied to `expected_typ`, then the two strings must be equal. Only
  the letters A–Z are folded (media type names are ASCII letters, digits and a few signs, RFC 6838 §4.2, Best Current Practice, January
  2013, updated by RFC 9694; status read on rfc-editor.org on 2026-11-17): `\u212aB+JWT` (KELVIN SIGN) is not `kb+jwt`,
  though Python's `str.lower` and JavaScript's `toLowerCase` make it so (measured on 2026-11-17; the first wording of
  `check_jose_header` used `str.lower` and accepted it). The KB-JWT of §7.3 uses this comparison.
  `Key-Attestation+JWT` and `application/key-attestation+jwt` are `key-attestation+jwt`; `JWT` is not.
  **Parameters (1.8.1).** RFC 7515 §4.1.9 (text read on rfc-editor.org on 2026-11-18): "Per RFC 2045, all media type
  values, subtype values, and parameter names are case insensitive. However, parameter values are case sensitive unless
  otherwise specified for the specific parameter." Both values are read with the grammar of RFC 9110 (Internet Standard,
  June 2022, not obsoleted or updated on 2026-11-18) §8.3.1 and §5.6.6 — `type "/" subtype *( OWS ";" OWS [ parameter ] )`,
  `parameter = name "=" ( token / quoted-string )` — with one rule of this format, stricter than RFC 9110: every `;` is
  followed by a parameter (see the end of this paragraph), ASCII only (no obs-text), no whitespace around `=` and none after the last parameter
  unless a `;` follows; a quoted-string is read without its quotes and with each quoted-pair replaced by the character
  after the backslash (§5.6.4), equal to the token of the same value (§5.6.6: "The quoted and unquoted values are
  equivalent"); `application/` is prepended only when the whole value has no `/`. The type, subtype and parameter names
  are folded A–Z, the values are not; parameters are compared in any order (this format's reading: neither RFC makes the
  order significant); a parameter named twice makes the value no media type. A `typ` that is no media type is
  `typ_mismatch`; an `expected_typ` that is none is a ValueError. So `x+jwt;p=A` is not `x+jwt;p=a`, and `KB+JWT; P="a"`
  is `kb+jwt;p=a`. Up to 1.8.0 the whole value was folded and the parameters compared byte for byte after that: the
  first pair was equal and the second not, against the sentence of 1.8.0 here that parameters were compared as written
  (measured on 2026-11-18, `test_ap2_media_type.py`). None of the profiles below has a parameter; a KB-JWT `typ` with one
  is not `kb+jwt`, as before. **A `;` with no parameter after it** (`kb+jwt;`, `kb+jwt ;`, `kb+jwt;;`, `x+jwt;p=a;`)
  makes the value no media type here, though RFC 9110 §5.6.6 allows an empty parameter (`[ parameter ]`): this format's
  rule, so that the patch release accepts nothing 1.8.0 refused (1.8.0 compared those values byte for byte after folding
  and refused them; the openwallet-foundation-labs sd-jwt-python verifier, commit c5fda01 of 2026-08-17, compares the
  KB-JWT `typ` byte for byte too). A KB-JWT whose `typ` is `kb+jwt;` is that artifact's error, as under 1.8.0.
- **Profiles** (`check_jose_profile(header, profile, allowed_algs)`; an unknown profile is `profile_unknown`), each with
  its source and version, read on 2026-11-17:

  | profile | typ | source |
  |---|---|---|
  | `openid4vci-proof` | `openid4vci-proof+jwt` | OpenID for Verifiable Credential Issuance 1.0, Final, 16 September 2025, Appendix F.1 (`typ` REQUIRED; `alg` "MUST NOT be none or an identifier for a symmetric algorithm (MAC)") |
  | `key-attestation` | `key-attestation+jwt` | same, Appendix D.1 (same rule on `alg`) |
  | `sd-jwt-vc` | `dc+sd-jwt` | draft-ietf-oauth-sd-jwt-vc-27 (current revision on the IETF datatracker, 16 November 2026), §2.2.1 |
  | `kb-jwt` | `kb+jwt` | RFC 9901 (Proposed Standard, November 2025) §4.3 |

  For the two OpenID4VCI profiles an `allowed_algs` with a symmetric algorithm (HS256, HS384, HS512) is a ValueError.
- `parse_sd_jwt` names how many dots it found when the issuer JWT does not have three segments (1.8.0: the message
  said only that three were needed).

The JavaScript verifier has no counterpart of these functions (they are not part of verifying a pack).
