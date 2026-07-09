# Spec Version Matrix

The single source of truth for the specification versions this SDK implements and tracks. Every row
is implemented in **both** the Kotlin and Swift trees unless noted, and verified against shared golden
vectors (`vectors/`) and live interop where available.

Last full spec audit: **2026-07-09** (all six anchor specs cross-checked clause-by-clause against both
language trees — see [Detailed coverage & known gaps](#detailed-coverage--known-gaps) below).

Legend: ✅ implemented · 🟡 partial · ⬜ not yet.

## Formats & crypto

| Spec | Anchor version | Status |
|---|---|---|
| CBOR | RFC 8949 (deterministic encoding §4.2.1) | ✅ `cbor` / `CborCose` — RFC 8949 Appendix A vectors pass both languages; bytewise + length-first key ordering profiles |
| COSE | RFC 9052 §4.2 `COSE_Sign1` · RFC 9053 ES256/384/512 · RFC 9360 x5chain | ✅ verify (JCA / swift-crypto) + sign (`CoseSigner` → `SecureArea` port); COSE-WG Sign1 vectors pass. `COSE_Mac0` verify-only (no MAC generation) |
| JOSE / JWS | RFC 7515 / 7518 subset (compact, ES256/384/512) | ✅ `sdjwt` / `SdJwt` — in-house, fixed-`alg` verification (no negotiation) |
| JWE | RFC 7518 ECDH-ES direct + A128/192/256GCM | ✅ Concat KDF (RFC 7518 Appendix C vectors) — encrypts `direct_post.jwt` / `dc_api.jwt` responses |
| HPKE | RFC 9180 base mode — DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM | ✅ `mdoc` `Hpke` / `MDoc` — seals the `org-iso-mdoc` DC API response (ISO 18013-7 Annex C); RFC 9180 A.3 test vector passes both languages. Seal only — no verifier-side `open` |
| SD-JWT | RFC 9901 | ✅ issue / present / verify, KB-JWT, recursive & array disclosures, decoys; RFC disclosure vectors (73 entries) pass both languages. Gaps: KB-JWT `iat` presence-only (no §7.3 time-window check), §7.1(6) `exp`/`nbf` enforced only in the VC layer, §8 JWS JSON serialization absent (optional) |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc | 🟡 `SdJwtVcVerifier` — typ/iss/vct enforcement, time validation, issuer-key resolution (`.well-known/jwt-vc-issuer` + x5c), holder binding, status extraction. **Type Metadata (§4) and `vct#integrity` entirely unimplemented**; transitional `vc+sd-jwt` typ rejected |
| ISO/IEC 18013-5 mdoc | :2021 | ✅ `mdoc` / `MDoc` — `IssuerSigned`/MSO, `DeviceResponse`, selective disclosure, device signature, reader auth (§9.1.4). `deviceMac` is **verify-only** (reader side); MSO digest SHA-256 only; `DeviceResponse` errors/status semantics not modeled |
| X.509 PKIX | RFC 5280 | ✅ `trust` / `Trust` — chain validation (path build, validity, basic constraints), SAN, x509_san_dns / x509_hash; x5c adapters for SD-JWT VC issuers, mdoc issuer/reader, and signed issuer metadata |

## Issuance (OpenID4VCI)

| Spec | Anchor version | Status |
|---|---|---|
| OpenID4VCI | 1.0 Final (2025-09-16) | ✅ `openid4vci` — pre-authorized & authorization-code (+PAR), offer resolution, scope-preferred; **signed metadata** (§12.2.2 `Accept` negotiation + §12.2.3 `application/jwt` with `typ`/`alg`/`sub`/`iat`/`exp` rules); **live-issued a real PID from `issuer.eudiw.dev`** and **live-verified signed metadata from `dev.issuer-backend.eudiw.dev`** (see `INTEROP.md`). Gaps: credential response encryption, `attestation` proof type, `credential_identifiers`, deferred `interval` — see audit below |
| PKCE | RFC 7636 (S256) | ✅ |
| DPoP | RFC 9449 | ✅ jti/htm/htu/ath + DPoP-Nonce retry |
| OAuth Attestation-Based Client Auth | draft (wallet attestation + PoP) | ✅ WUA client authentication during issuance |
| HAIP | 1.0 Final | ✅ **issuance profile complete, both languages** — PAR/DPoP/PKCE required, wallet attestation, key attestation, batch, deferred, notification, refresh-token reissuance, signed metadata policy (OpenID4VCI §12.2.2/§12.2.3) |

## Presentation (OpenID4VP & proximity)

| Spec | Anchor version | Status |
|---|---|---|
| OpenID4VP | 1.0 Final (2025-07-09), DCQL | ✅ `openid4vp` — DCQL engine (null wildcard, values, claim_sets, credential_sets), JAR request resolution, `vp_token` (SD-JWT+KB-JWT and mdoc `DeviceResponse`), `direct_post` + `direct_post.jwt` (JWE), reader trust for signed requests. Gaps: DCQL `multiple`/`trusted_authorities`/`require_cryptographic_holder_binding`, `expected_origins`, §8.5 error responses, `transaction_data` partial — see audit below |
| ISO/IEC 18013-5 device retrieval | :2021 §9 | 🟡 `proximity` / `Proximity` — QR **and NFC static handover** engagement, ECDH session keys (HKDF, salt = SHA-256 of the tag-24 SessionTranscript), `SessionEstablishment`/`SessionData` framing, encrypted exchange, reader authentication; **holder and reader** sides (`wallet.reader`). Device auth: `deviceSignature` end-to-end; `deviceMac` **verify-only** (holder cannot produce it; no automated test — live Multipaz interop only). BLE (both modes) + NFC APDU transports are **Android demo host adapters only — no iOS transport**. **Live device-to-device interop with Multipaz** (BLE both modes + NFC, see `INTEROP.md`) |
| ISO/IEC 18013-7 / DC API handover | :2025 Annex C | ✅ origin-bound mdoc `SessionTranscript` + **HPKE-sealed `org-iso-mdoc` response** for the Digital Credentials API. Annex B implemented per OpenID4VP 1.0 Final handover (not the TS-literal `OID4VPHandover`); Annex A (website REST retrieval) not implemented — see audit below |
| W3C Digital Credentials API | browser-mediated (dc_api / dc_api.jwt) | ✅ `wallet.presentation.startDcApi` — no HTTP, response object returned to the platform |

## Status & audit

| Spec | Anchor version | Status |
|---|---|---|
| IETF Token Status List | draft-ietf-oauth-status-list | ✅ `statuslist` / `StatusList` — fetch + verify status token (signature + issuer chain), cached, index lookup |
| Transaction log (ARF / GDPR) | ARF transaction logging | ✅ `txlog` / `TransactionLog` — relying party (id/name/trusted/chain), per-document disclosed claims, history/query |

## Detailed coverage & known gaps

Findings of the 2026-07-09 clause-by-clause audit. Unless noted, every gap is symmetric — present
(or absent) in **both** the Kotlin and Swift trees, which remain line-for-line ports of each other.
Only what is 🟡/⬜ is listed; everything else in the tables above verified clean.

### RFC 9901 (SD-JWT) — coverage: high

| Gap | Spec ref | Detail |
|---|---|---|
| KB-JWT `iat` time window | §7.3(5.e) | 🟡 `iat` checked for presence only; no acceptable-window validation (`SdJwt.kt` / `SdJwt.swift` verifyKeyBinding) |
| `exp`/`nbf` on processed payload | §7.1(6) | 🟡 lives only in the VC layer (`JwtTimeValidator`), not the core `SdJwtVerifier` |
| Holder rejects SD-JWT+KB from Issuer | §7.2 | ⬜ no guard in `SdJwtHolder` |
| Explicit `alg=none` rejection | §7.1(2a) | 🟡 only implicit via fixed-alg matching |
| JWS JSON serialization | §8 (optional) | ⬜ compact only |
| End-to-end RFC vectors | Appendix A | 🟡 RFC vectors cover disclosures only (73 entries); no full issuer-JWT/presentation/KB fixture — E2E tests self-issue |

### SD-JWT VC — coverage: verifier core complete, Type Metadata absent

| Gap | Spec ref | Detail |
|---|---|---|
| **Type Metadata — all of it** | §4 | ⬜ no vct resolution/retrieval, `extends`, display/rendering (simple or svg_templates), claim metadata, or JSON-schema validation; §4.7 processing never runs in verification |
| `vct#integrity` / `#integrity` | §2.2.2.2, §5 | ⬜ never read or validated |
| Transitional `vc+sd-jwt` typ | §2.2.1 | 🟡 rejected despite spec's should-accept guidance; docstrings in both trees falsely claim it is accepted |
| Metadata resolver edge cases | §3.1/§3.2 | 🟡 jwks-XOR-jwks_uri not enforced; trailing-`/` in path-bearing `iss` not stripped |
| did-based key resolution | §2.5 (optional) | ⬜ |

### OpenID4VCI 1.0 — coverage: high

| Gap | Spec ref | Detail |
|---|---|---|
| Credential response encryption | §8.2/§10 | ⬜ no `credential_response_encryption` request object, response never JWE-decrypted |
| `attestation` proof type | §8.2.1.3 | ⬜ only `jwt` proofs sent (key attestation rides in the `key_attestation` JOSE header, which **is** implemented) |
| `credential_identifier(s)` issuance flow | §3.4/§6.2/§8.2 | ⬜ requests always use `credential_configuration_id`; token-response `authorization_details` parsed-but-ignored (Kotlin) / not parsed (Swift) |
| Deferred `interval` backoff | §8.3/§9.2 | ⬜ not parsed or honored (REQUIRED alongside `transaction_id`) |
| `tx_code` constraints | §4.1.1 | 🟡 length/input_mode advertised values not validated against the supplied code |
| `mso_mdoc` format | §3.3.1 | 🟡 opaque-string passthrough; live-tested Kotlin only, untested in Swift |

### OpenID4VP 1.0 — coverage: core solid

| Gap | Spec ref | Detail |
|---|---|---|
| DCQL `multiple` | §6.1/§8.1 | ⬜ not parsed; vp_token structurally always emits one presentation per query |
| DCQL `trusted_authorities` | §6.1.1 | ⬜ not parsed or matched |
| DCQL `require_cryptographic_holder_binding` | §6.1 | ⬜ wallet always binds (KB-JWT / device signature); unbound presentations unsupported |
| Client ID prefixes `verifier_attestation` / `decentralized_identifier` / `openid_federation` | §5.9.3/§12 | ⬜ trust verifier handles x509_san_dns/x509_hash/redirect_uri only |
| DC API `expected_origins` | Appendix A.2 | ⬜ replay check (spec MUST) not implemented |
| Error responses to verifier | §8.5 | ⬜ local typed errors only; no OAuth `error=` POST to `response_uri`, no spec error-code taxonomy |
| `fragment` response mode | §8 | ⬜ rejected as unsupported |
| `transaction_data` | §8.4/B.3.3 | 🟡 SD-JWT VC KB-JWT hashes wired; no unsupported-type rejection, no `credential_ids` binding, no mdoc path, no test coverage |
| JAR hardening | §5.10/RFC9101 | 🟡 `typ=oauth-authz-req+jwt` not enforced; `wallet_nonce` not sent/validated |
| Response-encryption details | §8.3 | 🟡 ECDH-ES only; no `alg`==jwk.alg check, no `kid` echo in the JWE header |

### ISO/IEC 18013-5:2021 — coverage: data model & session crypto solid, transports thin

| Gap | Spec ref | Detail |
|---|---|---|
| `deviceMac` generation | §9.1.3.5 | 🟡 verify-only (`CoseMac0` has no MAC creation; `MdocPresenter` always signs); no automated test — Multipaz live interop only |
| NFC negotiated handover | §8.2.2.1/§9.1.5.1 | ⬜ static handover only (`[Hs, null]` hardcoded); no ReaderEngagement / Handover Request |
| Session termination | §9.1.1.4 | ⬜ status 20 never sent, `status` ignored on decode, session keys not destroyed; BLE `End` only in the demo client |
| BLE / NFC transports | §8.3.3.1 | 🟡 core SDK exposes a transport port only; GATT (both modes, MTU chunking) + NFC APDU live in the **Android demo**; **no iOS/Swift transport**; BLE Ident characteristic absent |
| MSO digest algorithms | §9.1.2.5 | 🟡 SHA-256 only (readers must also support SHA-384/512) |
| Ephemeral-key curves | §9.1.5.2 Table 22 | 🟡 P-256 only |
| `DeviceResponse` errors/status | §8.3.2.1.2.2-.3 | ⬜ `errors`/`documentErrors`/status-code semantics not parsed or emitted (holder always sends `status: 0`) |
| MSO optional fields | §9.1.2.4 | 🟡 `expectedUpdate`, `keyAuthorizations`, `keyInfo` not parsed |
| Wi-Fi Aware · server retrieval (WebAPI/OIDC) | §8.3.3.1.3/§8.3.3.2 (optional) | ⬜ |
| Shared mdoc golden vectors | — | ⬜ `vectors/` covers CBOR/COSE only; cross-language mdoc equivalence rests on round-trip tests + live interop |

### ISO/IEC TS 18013-7:2025 — coverage: Annex C complete, Annex B via OID4VP Final, Annex A absent

| Gap | Spec ref | Detail |
|---|---|---|
| Annex B handover form | B.4.4 | 🟡 implements OpenID4VP 1.0 Final's `OpenID4VPHandover`/`OpenID4VPDCAPIHandover` (jwk-thumbprint form), not the TS-literal `OID4VPHandover` (clientIdHash/responseUriHash + `mdocGeneratedNonce`) — deliberate alignment with the published OID4VP Final, but not letter-of-TS |
| `mdocGeneratedNonce` + `apu`/`apv` JWE headers | B.4.3.3/B.5.3 | ⬜ response JWE sent without apu/apv (the `Jwe` primitive supports them) |
| mdoc MAC auth in OID4VP | B.4.5 | ⬜ OID4VP mdoc path signs only |
| Annex B curve set | B.5.2 Table B.8 | 🟡 P-256/384/521 only; no Brainpool / Curve25519/448 (P-256 satisfies the mdoc-side minimum) |
| **Annex A — all of it** | Annex A | ⬜ website REST retrieval (`RestApiOptions`, HTTP POST `application/cbor`), `OriginInfo`/domain origin, `EngagementToApp`, `MacKeys` (v1.1) — none implemented |
| Verifier-side HPKE decryption | C.4 Table C.3 | ⬜ `Hpke` seals only; no `open` (wallet-side complete, reader/verifier side cannot unseal) |
| Origin abort | C.5 | 🟡 origin is a required parameter folded into the transcript, but no explicit empty-origin abort |
| Server retrieval | §6.4 | n/a — the TS adds no requirements beyond 18013-5 |

## Not yet / roadmap

| Item | Status |
|---|---|
| SD-JWT VC Type Metadata (§4: vct resolution, `extends`, display, claim metadata, schema) + `vct#integrity` | ⬜ largest single gap; §4.7 is a step of the verification algorithm |
| OpenID4VP hardening: `expected_origins` (MUST), §8.5 error responses, JAR `typ`/`wallet_nonce`, DCQL `multiple`/`trusted_authorities` | ⬜ |
| `deviceMac` generation (holder side) + automated deviceMac test | ⬜ verify-only today |
| iOS proximity transport (CoreBluetooth / CoreNFC) + BLE Ident characteristic + session termination (status 20) | ⬜ Android demo adapters only |
| OpenID4VCI: credential response encryption, `attestation` proof type, `credential_identifiers`, deferred `interval` | ⬜ |
| NFC negotiated handover · 18013-7 Annex A (website REST retrieval) | ⬜ |
| LOTL Level 2 · CRL / OCSP real-time revocation | ⬜ trust hardening |
| Wallet Provider backend end-to-end (WUA issue → verify loop) | 🟡 backend exists (`wallet-provider/`); e2e loop closure pending |
| BLE / NFC transport production hardening | 🟡 demo adapters + live Multipaz interop done; reconnect / timeout / MTU / cancellation hardening pending |
| Shared mdoc golden vectors (MSO / DeviceResponse / SessionTranscript / deviceMac) | ⬜ cross-language equivalence currently via round-trip tests + live interop |
