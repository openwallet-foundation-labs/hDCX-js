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
  e2e coverage of the service NFC path). **Not done — separate track:** the demo/host NFC transport
  choreography for negotiated (reader writes Hr → holder reads → holder writes Hs); see transport track.
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

- **Wallet Provider / HAIP attestation** (audit #23–#28). ⚠️ Two of these are **correctness**, not
  enhancements: the WUA is reused across issuers and its `sub` can carry an instance-unique id — both
  violate HAIP §4.4.1, so the "HAIP issuance profile complete" claim is currently overstated. Also:
  `issueKeyAttestation` asserts `iso_18045_high` without verifying anything; `SecureArea.attestation()`
  has no path to the wallet-provider; `IntegrityService` is a dev stub (no Play Integrity / Android Key
  Attestation chain verification). Recommend triaging this track next.
- **Trust cluster** (audit #16–#20): DCQL `trusted_authorities` (`aki` → `etsi_tl` → `openid_federation`),
  the `verifier_attestation`/`decentralized_identifier`/`openid_federation` client-ID prefixes, LOTL/CRL/OCSP.
  Already **deliberately sequenced last** in `SPEC-MATRIX.md` (needs standing trust infrastructure).
- **Transport hardening**, non-iOS (audit #29–#31) — **partly done** (commit `d3e4e61`):
  - [x] **#30 BLE Ident characteristic** (§8.3.3.1.1.4) — SDK `bleIdent`/`eDeviceKeyBytes` (both languages,
    tested); demo reader exposes 00000008, holder reads + verifies (central client mode); **device-verified**.
  - [x] **#29 timeouts + cancellation/failure cleanup** — `receive`/peer-wait/notify bounded; connect tears
    down a half-open GATT/scanner on failure or cancellation. MTU already negotiated.
  - [x] **#29 initial connect retry** (commit `7aac4e7`) — the GATT client retries the flaky first
    `connectGatt` (Android GATT_ERROR 133) up to 3× with fresh per-attempt state; timeout retryable,
    cancellation aborts; stale callbacks guarded by `g === gatt`. Device-verified (happy path + clean
    cancellation). Note: this is the only meaningful "reconnect" — mdoc has no *session* resumption
    (keys/counters bound to the connection), so a mid-session drop restarts from engagement, by design.
  - [ ] **#31 promote demo adapters into a supported Android library module** — not started (needs a new
    AGP library module; the pure-Kotlin `kotlin/` tree can't host `android.bluetooth`).
- **Test infrastructure** (audit #21–#22): shared mdoc golden vectors; RFC 9901 end-to-end fixtures.
- **iOS** (explicitly out of scope here): CoreBluetooth/CoreNFC transport, session termination on that
  transport, iOS demo app.
