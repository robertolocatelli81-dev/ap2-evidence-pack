# AP2 sample certificates (third-party, Apache-2.0)

`ds_cert_sdjwt.pem` and `issuer_cert_sdjwt.pem` are copied verbatim from google-agentic-commerce/AP2,
`code/samples/certs/`, at commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` (the head of `main` on 2026-11-21; the two
files last changed in `b4587ac`, 2026-04-28, "feat: Release Ap2 v0.2"). License: Apache-2.0 (the repository's
`LICENSE`, read on 2026-11-21; the repository has no NOTICE file). sha256:

- `ds_cert_sdjwt.pem` `a4b92cd66960d4ddcdcb8ca8b2887dafdec06cbcd42bc10fcc8ede41ffef1306`
- `issuer_cert_sdjwt.pem` `120abde3087907911c3c9de00c536657a6a503a88849a24653f6c35030c982ba`

Used by `test_ap2_x5c_purpose.py` (SPEC §6 step 7, 1.10.0): the signer certificate carries keyUsage digitalSignature
and the extendedKeyUsage `1.0.18013.5.1.2` (mDL Document Signer), both critical; it is valid from 2025-04-25 to
2026-04-25 and chains to `issuer_cert_sdjwt.pem`. No private key is published with them, so no pack is built on them.
