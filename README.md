# EUDI Wallet SDK

A **from-scratch** EUDI (European Digital Identity) wallet SDK for issuing, storing, and presenting
digital credentials under **eIDAS 2.0** (ARF / HAIP). It ships as two native implementations —
**Kotlin** and **Swift** — that share only an API contract, with a pure core that builds and tests on
plain Linux.

## Concept

- **Headless** — no UI. A B2B library your app embeds; you own the screens.
- **Native two-fold** — a Kotlin implementation and a Swift implementation, each idiomatic to its
  platform, sharing only an API shape (no common runtime).
- **Full scratch** — the EU reference wallet is an interop target, not a dependency. Every layer
  (CBOR/COSE, SD-JWT VC, mdoc, OpenID4VCI/VP, X.509 trust) is implemented in-house.
- **Ports & adapters** — the core is pure and Linux-testable; the host injects thin platform
  capabilities (keys, storage, HTTP, BLE) via constructor injection — no DI framework.

Everything is reached through a single assembled `Wallet` facade: `credentials`, `issuance`,
`presentation`, `proximity`, `transactions`. See **[SPEC-MATRIX.md](SPEC-MATRIX.md)** for the exact
standards and versions implemented, and **[INTEROP.md](INTEROP.md)** for a live PID issuance against
the official EUDI reference issuer.

## Repository layout

| Path | What |
|---|---|
| `kotlin/` | Kotlin SDK (pure JVM, Gradle multi-module) |
| `swift/` | Swift package (no Apple-framework imports; Linux-buildable) |
| `demo/` | Android debug wallet app (Compose) — consumes `kotlin/` via a composite build |
| `docs/` | Docusaurus developer docs (English + 한국어) |
| `wallet-provider/` | NestJS Wallet Provider backend (WUA / wallet-unit attestation) |
| `vectors/` | Shared golden test vectors consumed by both test suites |

**Core rule:** everything under `kotlin/` and `swift/` builds and tests on plain Linux. Platform
features (secure hardware, storage, BLE, DC API) live behind ports.

## Modules

Each concern is a separate module (Kotlin name / Swift target), tested in isolation.

| Module | Purpose | Key files |
|---|---|---|
| `cbor` / `CborCose` | CBOR (RFC 8949) + COSE | `Cbor`, `CborEncoder`/`CborDecoder`, `cose/CoseSign1`, `CoseKey`, `EcPublicKey`, `Der` |
| `sdjwt` / `SdJwt` | SD-JWT VC + JOSE (JWS/JWE) | `SdJwt`, `SdJwtIssuer`, `SdJwtHolder`, `SdJwtVerifier`, `SdJwtVcVerifier`, `Jose` (JWS + `SecureAreaJwsSigner`), `Jwe`, `Jwk`, `JsonValue`, `Base64Url` |
| `mdoc` / `MDoc` | ISO 18013-5 mdoc | `Mdoc` (`IssuerSigned`/MSO), `DeviceRequest` (`ReaderAuth`), `DeviceResponse`, `MdocPresenter`, `MdocReader`, `MdocVerifier`, `MdocSessionTranscript` |
| `openid4vci` / `OpenID4VCI` | OpenID4VCI issuance | `Openid4VciClient`, `Models`, `ClientAttestation`, `SignedMetadata`; `MockIssuer` (test fixtures) |
| `openid4vp` / `OpenID4VP` | OpenID4VP presentation | `Openid4VpClient`, `DcqlEngine`, `Request`, `HeldSdJwtVc`/`HeldMdoc`, `Oid4vpSessionTranscript`; `MockVerifier`/`MockMdocVerifier`/`MockDcApiVerifier` (fixtures) |
| `trust` / `Trust` | X.509 PKIX trust | `X509ChainValidator`, `X509Support`, `X509RequestVerifier`, `X5cIssuerKeyResolver`, `X5cMdocReaderTrust`, `TrustAnchors`; `TestCerts` (fixtures) |
| `statuslist` / `StatusList` | IETF Token Status List | `StatusListClient` (fetch + verify + index lookup) |
| `credential-store` / `CredentialStore` | Persisted credential store | `CredentialStore`, `Envelope`, `EnvelopeCodec` (deterministic CBOR) |
| `proximity` / `Proximity` | ISO 18013-5 session | `ProximitySessionTranscript`, `SessionEncryption` (ECDH+AES-GCM), `SessionMessages`, `Hkdf` |
| `txlog` / `TransactionLog` | Audit log (ARF/GDPR) | `TransactionLog` (record/history/query), `TransactionLogCodec`, `RelyingParty`, `LoggedDocument` |
| `wallet-api` / `WalletAPI` | Port SPI + shared types | `spi/` ports (`SecureArea`, `StorageDriver`, `HttpTransport`, `ProximityTransport`, …), `Types`, `SecureAreaCoseSigner` |
| `wallet` / `Wallet` | **The facade** | `Wallet`, `WalletConfig`, `WalletPorts`, `CredentialsService`, `IssuanceService`/`Session`, `PresentationService`/`Session`, `ProximityService`/`Session`, `Credential`, `WalletError` |
| `testkit` / `WalletTestKit` | Test doubles | `SoftwareSecureArea`, `InMemoryStorageDriver`, mock issuer/verifier/reader, `TestCerts` |

## Build & test

```bash
# Kotlin — pure JVM
cd kotlin && ./gradlew test

# Swift — on this Linux host, point clang at a GCC dir that has libstdc++-dev:
cd swift && swift test \
  -Xcc --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11 \
  -Xcxx --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11 \
  -Xlinker -L/usr/lib/gcc/x86_64-linux-gnu/11
# (CI images `swift:6.x` need no extra flags.)

# Android demo → APK
cd demo && ./gradlew :app:assembleDebug     # app/build/outputs/apk/debug/app-debug.apk
```

## Docs

The developer documentation (guides, API reference, both languages, Kotlin + Swift examples) lives in
`docs/` as a Docusaurus site:

```bash
cd docs
npm install
npm start                 # dev server (English)
npm start -- --locale ko  # dev server (한국어)
npm run build             # static build of both locales → build/ and build/ko/
```
