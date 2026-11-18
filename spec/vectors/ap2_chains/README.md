# AP2 delegation chains and receipts (SPEC §2.1, §4, §6.9; 1.9.0)

Test vectors for `test_ap2_chains.py`. Nothing here is executed; the files are read as data.

| file | sha256 | source |
|---|---|---|
| `goodmeta_chain.json` | `a4b19caf166c63bc9a4d60d59074708ca445aa80b2957b1d70ceadfe61c2fe4c` | goodmeta/ap2-conformance, `vectors/chain.json` at commit `41dff653dea4a3025ca6e1d5339121cd8a1623a5` (Apache-2.0, read on 2026-11-18), verbatim |
| `goodmeta_receipts.json` | `fb86bc52a3e7ab9a3d69726069671a77db9a8f1a1f985490f87789573cb992da` | same repository and commit, `vectors/receipts.json`, verbatim |
| `GOODMETA-NOTICE.txt` | `8f59d0d52c2efff8b49e67a34919961eb3d77b167c8d1b2e2c975fe02e7d6884` | the NOTICE of that repository at that commit, verbatim (Apache-2.0 §4(d)) |
| `sdk_chainA.txt`, `sdk_chainB.txt`, `sdk_chain_mixed.txt`, `sdk_receiptA.jwt`, `sdk_issuer_pub.json`, `sdk_mpp_pub.json` | in `SHA256SUMS` beside this file | emitted on 2026-11-18 by the AP2 SDK (google-agentic-commerce/AP2 `code/sdk/python` at `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`, Apache-2.0), run in a sandbox with keys generated there for this purpose; only public keys are kept. `chain_mixed` is the open mandate of chain A followed by the closed mandate of chain B (the AP2 SDK refuses it: sd_hash mismatch) |

The goodmeta vectors are, per their NOTICE, "minted from the AP2 (Agent Payments Protocol) reference SDK at commit
e1ea56db72a6385bce3e5c1112b3a56ce60acb43". Their `x5c` vectors encode certificates in base64url, which RFC 7515 §4.1.6
does not allow ("base64-encoded ... -- not base64url-encoded"); this format refuses them for that reason, and the test
says so. Their receipt `reference` is the hash of the closed hop's compact form; the AP2 SDK's `get_closed_mandate_jwt`
(`mandate.py` lines 402-417 at e1ea56d) hashes the closed hop's issuer JWT alone (`sdk_receiptA.jwt`): both are bindings
here (SPEC §4, `over`).
