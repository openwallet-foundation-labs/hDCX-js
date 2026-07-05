# Spec Version Matrix

The single source of truth for the specification versions this SDK implements and tracks. Every row
is implemented in **both** the Kotlin and Swift trees unless noted, and verified against shared golden
vectors (`vectors/`) and live interop where available.

Legend: ✅ implemented · 🟡 partial · ⬜ not yet.

## Formats & crypto

| Spec | Anchor version | Status |
|---|---|---|
| CBOR | RFC 8949 (deterministic encoding §4.2.1) | ✅ `cbor` / `CborCose` — RFC 8949 Appendix A vectors pass both languages; bytewise + length-first key ordering profiles |
| COSE | RFC 9052 §4.2 `COSE_Sign1` · RFC 9053 ES256/384/512 · RFC 9360 x5chain | ✅ verify (JCA / swift-crypto) + sign (`CoseSigner` → `SecureArea` port); COSE-WG Sign1 vectors pass |
| JOSE / JWS | RFC 7515 / 7518 subset (compact, ES256/384/512) | ✅ `sdjwt` / `SdJwt` — in-house, fixed-`alg` verification (no negotiation) |
| JWE | RFC 7518 ECDH-ES direct + A128/192/256GCM | ✅ Concat KDF (RFC 7518 Appendix C vectors) — encrypts `direct_post.jwt` / `dc_api.jwt` responses |
| SD-JWT | RFC 9901 | ✅ issue / present / verify, KB-JWT, recursive & array disclosures; RFC example vectors pass both languages |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc | ✅ `SdJwtVcVerifier` — typ/iss/vct enforcement, time validation, issuer-key resolution (`.well-known/jwt-vc-issuer` + x5c), holder binding, status extraction |
| ISO/IEC 18013-5 mdoc | :2021 | ✅ `mdoc` / `MDoc` — `IssuerSigned`/MSO, `DeviceResponse`, selective disclosure, device signature, reader auth (§9.1.4) |
| X.509 PKIX | RFC 5280 | ✅ `trust` / `Trust` — chain validation (path build, validity, basic constraints), SAN, x509_san_dns / x509_hash |

## Issuance (OpenID4VCI)

| Spec | Anchor version | Status |
|---|---|---|
| OpenID4VCI | 1.0 Final (2025-09-16) | ✅ `openid4vci` — pre-authorized & authorization-code (+PAR), offer resolution, scope-preferred; **live-issued a real PID from `issuer.eudiw.dev`** (see `INTEROP.md`) |
| PKCE | RFC 7636 (S256) | ✅ |
| DPoP | RFC 9449 | ✅ jti/htm/htu/ath + DPoP-Nonce retry |
| OAuth Attestation-Based Client Auth | draft (wallet attestation + PoP) | ✅ WUA client authentication during issuance |
| HAIP | 1.0 Final | ✅ **issuance profile complete, both languages** — PAR/DPoP/PKCE required, wallet attestation, key attestation, batch, deferred, notification, refresh-token reissuance, signed metadata policy |

## Presentation (OpenID4VP & proximity)

| Spec | Anchor version | Status |
|---|---|---|
| OpenID4VP | 1.0 Final (2025-07-09), DCQL | ✅ `openid4vp` — DCQL engine (null wildcard, values, claim_sets, credential_sets), JAR request resolution, `vp_token` (SD-JWT+KB-JWT and mdoc `DeviceResponse`), `direct_post` + `direct_post.jwt` (JWE), reader trust for signed requests |
| ISO/IEC 18013-5 device retrieval | :2021 §9 | ✅ `proximity` / `Proximity` — QR engagement, ECDH session keys (HKDF), `SessionEstablishment`/`SessionData` framing, encrypted exchange, reader authentication; BLE/NFC transport is a host port |
| ISO/IEC 18013-7 / DC API handover | :2025 Annex C | ✅ origin-bound mdoc `SessionTranscript` for the Digital Credentials API |
| W3C Digital Credentials API | browser-mediated (dc_api / dc_api.jwt) | ✅ `wallet.presentation.startDcApi` — no HTTP, response object returned to the platform |

## Status & audit

| Spec | Anchor version | Status |
|---|---|---|
| IETF Token Status List | draft-ietf-oauth-status-list | ✅ `statuslist` / `StatusList` — fetch + verify status token (signature + issuer chain), cached, index lookup |
| Transaction log (ARF / GDPR) | ARF transaction logging | ✅ `txlog` / `TransactionLog` — relying party (id/name/trusted/chain), per-document disclosed claims, history/query |

## Not yet / roadmap

| Item | Status |
|---|---|
| LOTL Level 2 · CRL / OCSP real-time revocation | ⬜ trust hardening |
| Wallet Provider backend end-to-end (WUA issue → verify loop) | 🟡 backend exists (`wallet-provider/`); e2e loop closure pending |
| BLE / NFC on-device `ProximityTransport` adapters | ⬜ device-only integration (engine complete) |
