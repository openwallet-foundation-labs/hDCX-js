# SDK TODO

Triage of the 2026-07-11 remaining-work audit (**iOS platform work excluded**). Item numbers (`#N`)
match that audit's list so they stay traceable; full context per item is in
[`SPEC-MATRIX.md`](SPEC-MATRIX.md) → *Detailed coverage & known gaps*. Every item applies to **both**
the Kotlin and Swift trees unless noted.

Buckets, most important first: **P1 (do now)** · **P2 (scoped)** · **Deferred** · **Won't do** ·
**Separate tracks** (not triaged in this pass).

---

## Done (2026-07-11)

- [x] **#12 · DC API: abort on a blank origin — 18013-7 C.5** — commit `3fd4ff9`.
  `MdocSessionTranscript.dcApiIsoMdoc` and `Request.resolveDcApi` reject a blank/whitespace origin before
  it is used to bind the response (the origin is platform-supplied via `startDcApi`/`respondDcApiMdoc`;
  a blank one cannot bind, so it is refused). Tests for both paths, both languages.
- [x] **#3 · Holder rejects an SD-JWT+KB received from the Issuer — RFC 9901 §7.2** — commit `61d4e5d`.
  New `SdJwt.parseFromIssuer` rejects an SD-JWT carrying a KB-JWT; enforced at ingestion in
  `IssuanceService.persistIssued` (the single chokepoint for immediate / deferred / reissued credentials)
  via `rejectIssuerBoundKb`, before storage. `decode()` stays a pure format/bytes helper. Unit-tested both
  languages.
- [x] **#6 · NFC negotiated handover — 18013-5 §8.2.2.1 / §9.1.5.1** — commits `ef12416` + `5106e8d`.
  Message + transcript layer: `MdocNfcEngagement.buildHandoverRequest`/`parseHandoverRequest` +
  `readerEngagement`, and `nfcHandover(hs, hr)` binding `[Hs, Hr]` (static stays `[Hs, null]`, default).
  Wired into the wallet services: `ProximityService.present` and `ProximityReaderService.read` gained an
  optional `handoverRequestNdef` (default null → static). Negotiated round-trip e2e both languages (first
  e2e coverage of the service NFC path). **Transport choreography — done** (see transport hardening: TNEP
  over Type-4 HCE, `NfcEngagementProcessor` / `MdocNfcHandover`, device-verified negotiated read).
- [x] **#5 · DeviceResponse status on the reader — 18013-5 §8.3.2.1.2.3** — commit `74b2cb3`.
  Spike → scoped to **status only**. `MdocReader.verifyDeviceResponse` and `ProximityReaderService.read`
  surface a non-zero DeviceResponse status (Table 8: 10/11/12 → no documents, with a reason) instead of
  silently reporting an empty list. **Deliberately skipped:** the `documentErrors` / per-document `errors`
  maps (mostly ErrorCode 0 = "not returned", which the reader deduces from request↔response), and
  holder-side emit (selective disclosure + decline/terminate already cover our holder). Tested both languages.

**P1 done; #5, #6 done — P2 clear.** Next: the Deferred backlog / trust cluster, when picked up.

---

## Deferred

Grouped; revisit after P1/P2. Rationale per line.

| # | Item | Spec | Why deferred |
|---|---|---|---|
| #1 + #2 | **SD-JWT VC Type Metadata (§4) + `vct#integrity`** | SD-JWT VC §4, §2.2.2.2/§5 | Largest single feature; deferred **together** (integrity is meaningless without Type Metadata). Own workstream later. |
| #7 | metadata resolver edge cases (jwks XOR jwks_uri, trailing-`/` in `iss`) | SD-JWT VC §3.1/§3.2 | Minor hardening; no interop pressure. |
| #8 | `credential_identifiers` multi-dataset expansion | VCI §6.2/§8.2 | SDK maps a config 1:1 to a credential; multi-dataset is a rare issuer shape. |
| #9 | `mso_mdoc` issuance — Swift test parity | VCI §3.3.1 | Kotlin live-tested; Swift path works, just untested. Backlog. |
| #10 | MSO optional fields `expectedUpdate` / `keyInfo` | 18013-5 §9.1.2.4 | `keyAuthorizations` already parsed; the rest are unused by current flows. |
| #11 | `fragment` response mode | OpenID4VP §8 | Not needed for our flows (direct_post(.jwt) / dc_api(.jwt) only). |
| #13 | Curve expansion (Brainpool / X25519 / X448) | 18013-7 B.5.2 / 18013-5 §9.1.5.2 | P-256/384/521 already cover the mdoc minimum; **curves later**. |
| #14 | JWS JSON serialization | RFC 9901 §8 | OPTIONAL in the spec. |
| #15 | `did`-based issuer key resolution | SD-JWT VC §2.5 | OPTIONAL; `.well-known/jwt-vc-issuer` + x5c cover our issuers. |

---

## Won't do

| # | Item | Why |
|---|---|---|
| #4 | `exp`/`nbf` in the **core** `SdJwtVerifier` (§7.1(6)) | Not needed — time validation already runs in the SD-JWT **VC** layer (`JwtTimeValidator`), which is where our credentials are verified. Duplicating it in the bare RFC-9901 verifier adds no value for our use. |

---

## Separate tracks (not triaged in this pass)

These were in the broader audit but outside the 1–15 spec-conformance list walked here. Listed so they
are not lost; each deserves its own triage.

- **Wallet Provider / HAIP attestation** (audit #23–#28) — **← in progress**.
  - [x] **Phase 1 — WUA client auth wired to the backend, §4.4.1 (the named correctness bugs).**
    - `android/attestation`: `WalletProviderAttestation` (reference `WalletAttestationProvider` talking to
      `wallet-provider/`: nonce → register(integrity) → instance-key PoP → wallet-attestation) +
      `IntegrityTokenProvider`/`DevIntegrityTokenProvider`. Gated integration test verified against the local
      backend (real WUA, cnf binds instance key; batch key attestation). Commit `4a9a05b`.
    - SDK glue: `ClientAuthProvider` seam (vci), `AttestationClientAuth` — persistent instance key +
      **fresh WUA per issuer** (`sub` = clientId, non-unique). Wired in `Wallet.kt` when a provider is present.
      Fixes the two flagged §4.4.1 bugs (no WUA reused across issuers; `sub` not instance-unique).
    - **Residual (approach A, documented):** the instance key is persistent, so the WUA `cnf` is stable across
      issuers → colluding issuers could still correlate. Full unlinkability needs a **per-use key batch**
      (HAIP wallet-attestation batch) — a later refinement (approach C).
    - **Remaining in Phase 1:** demo on-device wiring (inject the adapter; WP URL reachable from the device;
      avoid breaking issuance when the WP is down) + **Swift parity**.
  - [x] **Phase 2 — Android Key Attestation (real):** `AndroidKeystoreSecureArea.createKey` bakes
    `KeySpec.attestationChallenge`; `attestation()` returns the real Keystore X.509 chain (`android-keystore-x5c`,
    concatenated DER leaf→root), or null when no challenge was set (was a `null` stub). **Device-verified**
    (instrumented test on SM-F731N): a challenged key yields a full chain with the Android Key Attestation
    extension (OID 1.3.6.1.4.1.11129.2.1.17) and the leaf key matches; a challenge-less key attests nothing.
  - [x] **WP verifies the Android Key Attestation chain** (the flagged `iso_18045_high`-on-faith bug).
    `wallet-provider` `android-key-attestation.ts` (`@peculiar/x509` + `asn1-android`): validates the chain
    signatures, roots it in a trusted Google attestation root (SHA-256 pinned), and parses the leaf's
    KeyDescription for the storage security level + challenge. `issueKeyAttestation` now derives `key_storage`
    from evidence — `iso_18045_high` only when a chain verifies (TEE/StrongBox + challenge = nonce); tampered
    chains rejected; no chain → honest `iso_18045_moderate`. Verified against a **real device chain** captured
    from SM-F731N (jest, 3 cases). `/key-attestation` DTO gains `keyAttestations` (base64 chains).
  - [x] **Phase 3 — Play Integrity (real):** client `PlayIntegrityTokenProvider` (android/attestation) requests
    a real Play Integrity token bound to the WP nonce + cloud project number, attempt→log→**dev fallback**
    (`fallback = null` in production so a failed check surfaces). Backend `IntegrityService` gains a real
    `verifyPlayIntegrity` path (Google `decodeIntegrityToken`, checks app/device verdicts + nonce) gated on
    `PLAY_INTEGRITY_PACKAGE_NAME` + Application Default Credentials; the `dev-integrity:<nonce>` stub stays the
    default. **Device-verified end-to-end** against a real Google Cloud project (`hopae-wallet`, project number
    1048824403731) + a service account: the app (`com.hopae.axle.wallet`) requested a real token, and
    `decodeIntegrityToken` returned the expected verdict. Both distribution paths confirmed on-device:
    side-loaded debug → `appIntegrity: UNRECOGNIZED_VERSION` / `appLicensingVerdict: UNEVALUATED`; a signed
    release AAB installed via a **Play Console internal-testing** track → **`appIntegrity: PLAY_RECOGNIZED`**
    (cert = the Play app-signing key) / **`LICENSED`**. `deviceIntegrity: MEETS_DEVICE_INTEGRITY` in both.
    Decode helper: `wallet-provider/tools/decode-integrity.mjs`; setup guide: `wallet-provider/PLAY-INTEGRITY.md`.
    Release signing: `demo/keystore.properties` (gitignored) → `./gradlew :app:bundleRelease`.
  - [x] **Swift parity — platform-agnostic layer.** `ClientAuthProvider` protocol (`WalletClientAuth`
    conforms), vci `clientAuth` takes it; `AttestationClientAuth` (Wallet — persistent instance key,
    fresh WUA per issuer, §4.4.1) wired in `Wallet.swift`; new `WalletProvider` SPM target with the reference
    `WalletProviderAttestation` (actor) + `IntegrityTokenProvider`/`DevIntegrityTokenProvider`. Offline +
    §4.4.1 unit tests pass; existing `ClientAttestationTests` green.
  - [ ] **Track follow-ups:** OpenID4VCI `key_attestation` proof wiring — the wallet side (create proof keys
    with the c_nonce as the attestation challenge → send the chains in `keyAttestations` → issuer verifies the
    WP JWT); iOS platform layer (App Attest / SecureEnclave `SecureArea` attestation — Swift equivalents of
    Phase 2/3); demo on-device wiring; full §4.4.1 unlinkability (per-use WUA key batch).
- **Trust cluster** (audit #16–#20): DCQL `trusted_authorities` (`aki` → `etsi_tl` → `openid_federation`),
  the `verifier_attestation`/`decentralized_identifier`/`openid_federation` client-ID prefixes, LOTL/CRL/OCSP.
  Already **deliberately sequenced last** in `SPEC-MATRIX.md` (needs standing trust infrastructure).
- **Transport hardening**, non-iOS (audit #29–#31) — **done** (all items below; only NFC negotiated
  Multipaz cross-check remains as a bonus verification):
  - [x] **#30 BLE Ident characteristic** (§8.3.3.1.1.4) — SDK `bleIdent`/`eDeviceKeyBytes` (both languages,
    tested); demo reader exposes 00000008, holder reads + verifies (central client mode); **device-verified**.
  - [x] **#29 timeouts + cancellation/failure cleanup** — `receive`/peer-wait/notify bounded; connect tears
    down a half-open GATT/scanner on failure or cancellation. MTU already negotiated.
  - [x] **#29 initial connect retry** (commit `7aac4e7`) — the GATT client retries the flaky first
    `connectGatt` (Android GATT_ERROR 133) up to 3× with fresh per-attempt state; timeout retryable,
    cancellation aborts; stale callbacks guarded by `g === gatt`. Device-verified (happy path + clean
    cancellation). Note: this is the only meaningful "reconnect" — mdoc has no *session* resumption
    (keys/counters bound to the connection), so a mid-session drop restarts from engagement, by design.
  - [x] **NFC HCE foreground routing preference** — the NDEF Type-4 AID (`D2760000850101`) is shared by every
    mdoc/NFC wallet, so with several installed Android shows an HCE routing-conflict picker on tap. While the
    holder presents over NFC, `NfcEngagementService.requestForeground(activity)` calls
    `CardEmulation.setPreferredService` (released in `onDispose`), making our service the deterministic tap
    target. Device-verified: `dumpsys nfc` foreground service flips `null` → our service while armed, and the
    physical two-phone tap no longer raises the conflict dialog.
  - [x] **NFC negotiated-handover transport (TNEP)** — the SDK bound `[Hs, Hr]` but the on-wire choreography was
    unimplemented, so the demo only ever ran static handover. Added, in the **SDK** (`kotlin/proximity`, pure +
    unit-tested): TNEP records (`NfcTnep`), the holder Type-4 HCE state machine (`NfcEngagementProcessor`,
    static XOR negotiated, `hr→hs` suspend callback), and the reader driver (`MdocNfcHandover`, auto-detects
    static vs the TNEP dance: Service Select → status → Hr↔Hs). `android/proximity` is a thin bridge
    (`NfcEngagementService` async `sendResponseApdu`; `NfcReader` over IsoDep). Demo: holder `NFC·Nego` chip
    (static stays default + untouched), reader auto-detects. `present`/`read` unchanged. Device-verified: two
    phones, holder in negotiated mode → reader auto-detected TNEP, bound `[Hs, Hr]`, read 1 document (decryption
    success ⇒ transcripts matched). Loopback unit test covers static + negotiated + read-only + reset.
  - **#31 promote demo adapters into supported Android library modules** — new `android/` composite build:
    - [x] Phase 1: `android/core` (`com.hopae.eudi.android:core`) — SecureArea, Storage, TxLogStore, Http
      adapters; `OkHttpTransport` decoupled from `LogStore` via an injected `WalletLogger`. Device-verified (`c10e9a8`).
    - [x] Phase 2: `android/proximity` (`com.hopae.eudi.android:proximity`) — BLE (GATT client/server, Ident,
      retry) + NFC (HCE service, reader) transports; BLE `LogStore`→`WalletLogger`; library manifest merges the
      BLE/NFC permissions + HCE service. android/ modules use group `com.hopae.eudi.android` (avoids clashing
      with the SDK's `com.hopae.eudi:proximity`). Builds + launches on device (`337ca1a`).
    - [x] Phase 3: `android/dcapi` (`com.hopae.eudi.android:dcapi`) — decomposed (no single SDK port):
      `DcApiRegistrar` (CredMan registration + matcher, bundled asset w/ override), `DcApiRequest` (envelope
      parse + origin), `DcApiResult` (marshalling). **Selector branding** (`DcApiBranding` — default logo,
      auto-scaled, + per-credential override; demo uses its app icon). Thin `GetCredentialActivity` + consent
      UI stay in the app. Device-checked (registration + branding) (`d0ed915`).
  **#31 complete** — all three android/ modules (core, proximity, dcapi) extracted + device-checked.
  **Transport hardening track complete** (non-iOS). Remaining bonus: verify NFC **negotiated** handover
  against Multipaz (static + BLE already cross-verified in `INTEROP.md`; negotiated is our↔our only so far).
- **Test infrastructure** (audit #21–#22): shared mdoc golden vectors; RFC 9901 end-to-end fixtures.
- **iOS** (explicitly out of scope here): CoreBluetooth/CoreNFC transport, session termination on that
  transport, iOS demo app.
