# Live Interop — Issuing a real PID from issuer.eudiw.dev

This records how we issued **and verified a real PID (SD-JWT VC)** from the official EUDI
reference issuer using only this SDK's from-scratch stack (CBOR/COSE/JOSE/SD-JWT/OpenID4VCI).

**Result (2026-07-04):** real PID issued and verified end to end. The issuer signs the
SD-JWT VC with an **x5c certificate chain** (`CN=PID DS - 01`, EUDI Wallet Reference
Implementation), `vct=urn:eudi:pid:1`, holder-bound via `cnf`, with a token-status-list ref.

## Fully headless (recommended) — `tools/headless-interop/run.sh`

The reference issuer's authentication is the **FormEU** test path (select country `FC`, fill a
test-PID form, click Authorize). That's a plain web form, so headless Chrome can drive it — no
human browser step. `tools/headless-interop/` scripts a real Chrome to do exactly the clicks a
person would, and the Kotlin harness does the crypto/protocol parts:

```sh
cd tools/headless-interop
npm install            # puppeteer-core, uses the system Chrome (CHROME_PATH to override)
./run.sh
```

Pipeline: Chrome drives the offer portal → Kotlin PAR (`step1_prepare`) → Chrome drives FormEU
auth and captures `…/cb?code=…` → Kotlin token+credential exchange (`step2_finish`) → x5c
verification (`VerifySavedPidTest`). Test attributes are `drive.js`'s `DEFAULT_DATA` (override
with `auth … --data file.json`). The issued credential lands at `$TMPDIR/eudi-credential.txt`.

**Why the portal 500s under plain curl:** the checkbox page (frontend `issuer.eudiw.dev`) posts
to the backend (`backend.issuer.eudiw.dev`), and the session cookie is host-only for the
backend — a cross-host dance a real browser handles but curl does not. Chrome sidesteps it.

### Pre-authorized code variant — `run-preauth.sh` (no authorization endpoint at all)

The portal's checkbox page has a **Pre-Authorization Code Grant** radio (`#check2`). Selecting
it skips the country/authorization step entirely: Chrome fills the FormEU test form and
authorizes, and the QR page yields a **pre-authorized** offer plus a 5-digit **transaction
code** (PIN). The wallet then redeems `pre-authorized_code` + `tx_code` directly at the token
endpoint — no authorization endpoint, no redirect.

```sh
cd tools/headless-interop && ./run-preauth.sh
```

Pipeline: Chrome drives the portal in pre-auth mode (`drive.js preauth`) → captures offer +
tx_code → Kotlin `issueWithPreAuthorizedCode` (`preAuthIssue`) → x5c verification. This is the
simplest live path: the only browser work is producing the offer; issuance itself is a plain
token-endpoint exchange.

## Manual variant (one human browser step)

The same Kotlin harness (`kotlin/openid4vci/src/test/.../LiveIssuanceTest.kt`, env-gated so it
never runs in normal CI) also works with a human doing the auth in a browser, per the steps
below — useful when you don't want to script the FormEU form.

## Procedure

### 0. Get a credential offer from the portal

Open <https://issuer.eudiw.dev/credential_offer>, pick **PID** in the **SD-JWT VC** format,
authenticate/fill the test form, and copy the offer deep link it shows (QR or link):

```
haip-vci://credential_offer?credential_offer=%7B%22credential_issuer%22:%22https://issuer.eudiw.dev%22,%22credential_configuration_ids%22:%5B%22eu.europa.ec.eudi.pid_vc_sd_jwt%22%5D,%22grants%22:%7B%22authorization_code%22:%7B%22issuer_state%22:%22<uuid>%22%7D%7D%7D
```

It's an `authorization_code` grant carrying an `issuer_state` bound to your portal session.
The `issuer_state` is single-use — a fresh offer is needed per attempt.

### 1. Build the authorization URL (machine)

```sh
cd kotlin
EUDI_LIVE=prepare EUDI_OFFER='<the haip-vci://... link>' \
  ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.step1_prepare' --rerun-tasks
```

This resolves the offer (`resolveCredentialOffer`), fetches issuer + AS metadata, pushes a
real PAR (`prepareAuthorizationCodeIssuance`), and prints an authorization URL like:

```
https://issuer.eudiw.dev/oidc/authorization?client_id=wallet-dev&request_uri=urn:uuid:...
```

Holder keys (proof + DPoP) and the PKCE verifier are persisted to `/tmp/eudi-live-issuance.json`.

**Key detail:** the issuer 500s on `authorization_details`; it wants **`scope`** (matches the
EUDI reference wallet's `authorizeIssuanceConfig = .favorScopes`). `prepareAuthorizationCodeIssuance`
favors `scope` when the config advertises one. `client_id=wallet-dev` is what the reference
wallet uses (`WalletKitConfig.swift`).

### 2. Authenticate (human, in a browser)

Open the printed URL, authenticate. You'll be redirected to
`https://example.org/cb?code=<CODE>&state=...` (example.org just shows the URL — that's fine).
Save the **full redirect URL** to a file so the code isn't transcribed by hand:

```sh
printf '%s' '<full redirect URL from the address bar>' > /tmp/eudi-redirect.txt
```

Authorization codes are short-lived — do step 3 right away.

### 3. Complete issuance (machine)

```sh
EUDI_LIVE=finish ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.step2_finish' --rerun-tasks
```

`step2_finish` extracts + URL-decodes the `code` from the redirect file, then
`exchangeAuthorizationCode` does: DPoP-bound token request → c_nonce → key-proof JWT →
credential request. The credential is **saved to `/tmp/eudi-credential.txt` before any
verification** so a verify error never loses it.

### 4. Verify the captured PID (machine, offline)

```sh
./gradlew :openid4vci:test --tests '*VerifySavedPidTest*' --rerun-tasks
```

The live issuer signs with **x5c**, not the `.well-known/jwt-vc-issuer` metadata endpoint, so
`VerifySavedPidTest` resolves the issuer key from the **leaf certificate** in the x5c header
(`X5cLeafKeyResolver`) and runs the full `SdJwtVcVerifier`. This confirms: issuer signature,
disclosure digest resolution, `typ=dc+sd-jwt`, `vct`, time claims, and `cnf` holder binding.

## Presenting to the live verifier — `run-vp.sh`

The reverse direction: present the issued PID to the reference **verifier** (verifier.eudiw.dev)
over OpenID4VP, fully headless.

```sh
cd tools/headless-interop && ./run-vp.sh
```

Pipeline: issue a PID (pre-auth, persisting the holder key) → Chrome drives the verifier wizard
(pick PID, `dc+sd-jwt`, Specific attributes → Given/Family name, OpenID4VP + GET, Submit) and
grabs the `openid4vp://…` request from "Open with your wallet" (`drive.js verifier`) → Kotlin
`VpPresentTest` resolves the request (fetches the signed request object via `request_uri`),
DCQL-matches the PID, builds the `vp_token` + KB-JWT (bound to the verifier `client_id` + nonce),
**encrypts it as a JWE** (`direct_post.jwt`) to the verifier's key from `client_metadata.jwks`,
and POSTs to `response_uri`.

Observed live request: `response_mode=direct_post.jwt`, `client_id=x509_hash:…`, DCQL
`{query_0: dc+sd-jwt, vct urn:eudi:pid:1, [family_name, given_name]}`. The verifier **accepts the
encrypted response (HTTP 200)** — the JWE decrypts with its key and the SD-JWT + KB-JWT verify.

Notes: the verifier uses `client_id_scheme = x509_hash` (not `x509_san_dns`); we parse the request
and present, but full request-signature/chain trust (x509_hash + chain to IACA) is the trust
module's job (M3, tracked in `SPEC-MATRIX.md`). The holder key must come from the same issuance
(its public key is the credential's `cnf`); `preAuthIssue` persists it to `eudi-holder-key.json`.

## mdoc (ISO 18013-5) — same three flows

Every flow works headless for **both** `dc+sd-jwt` and `mso_mdoc` PID (3 flows × 2 formats = 6 e2e):

| Flow | SD-JWT VC | mdoc |
| --- | --- | --- |
| VCI authorization code | `run.sh` | `run-mdoc.sh` |
| VCI pre-authorized code | `run-preauth.sh` | `run-preauth-mdoc.sh` |
| OpenID4VP presentation | `run-vp.sh` | `run-vp-mdoc.sh` |

The driver takes `--config <credential_configuration_id>` (issuer checkbox, default `…pid_vc_sd_jwt`;
mdoc is `eu.europa.ec.eudi.pid_mdoc`) and `--format <dc+sd-jwt|mso_mdoc>` (verifier). The issuance
path is shared: pre-auth uses the offer's config id, auth-code takes `EUDI_CONFIG_ID`. mdoc
credentials come back as base64url CBOR `IssuerSigned`; verify with `verifyRealMdocWithChain`
(issuerAuth + valueDigests + chain to the EUDI IACA) and present with `presentMdocWithTrust`
(DeviceResponse + DeviceSigned over the OpenID4VP-handover SessionTranscript, JWE to response_uri).

Observed mdoc request: `mso_mdoc`, `doctype_value=eu.europa.ec.eudi.pid.1`, claims
`[eu.europa.ec.eudi.pid.1, family_name]` / `[…, given_name]` — the verifier **accepts the
encrypted DeviceResponse (HTTP 200)**, i.e. our DeviceSigned verifies over the handover it
reconstructs. Note the two PID forms use different field names (mdoc `birth_date` +
`nationality[…]`, SD-JWT `birthdate` + `nationalities[…]`); `DEFAULT_DATA` fills a superset.

## Signed Credential Issuer Metadata (OpenID4VCI §12.2.2 / §12.2.3)

`signed_metadata` — the JSON member our implementation originally looked for — **does not exist in
OpenID4VCI 1.0 Final**; it was dropped in draft 16. The final spec carries signed metadata by content
negotiation instead: the wallet's `Accept` signals what it supports, and the issuer answers with either
an unsigned `application/json` document (MUST) or a signed `application/jwt` whose payload *is* the
metadata (MAY), typed `openidvci-issuer-metadata+jwt` and carrying `sub` (= the Credential Issuer
Identifier) and `iat`.

Of the reference deployments, only **`dev.issuer-backend.eudiw.dev`** signs:

| Host | `application/jwt`? |
| --- | --- |
| `issuer.eudiw.dev` (the issuance e2e target) | ✗ unsigned JSON only |
| `ec.dev.issuer.eudiw.dev` | ✗ unsigned JSON only |
| `dev.issuer-backend.eudiw.dev` | ✓ fully conformant |

Its JWT is `ES256`, `typ=openidvci-issuer-metadata+jwt`, `iss = sub = credential_issuer`, freshly
`iat`-stamped per request, with an `x5c` leaf (`CN=Kotlin Issuer Signer Dev, O=Niscy`) chaining to
`PID Issuer CA 02` (**EU**, `certs/pid_issuer_ca_eu_02.der` — a different country CA than the UT one
that signs PID document signers). `LiveTrustE2eTest.verifySignedIssuerMetadata` proves the whole path:

```sh
cd kotlin && EUDI_SIGNED_METADATA=1 ./gradlew :trust:test \
  --tests '*LiveTrustE2eTest.verifySignedIssuerMetadata' --tests '*LiveTrustE2eTest.unsignedMetadataStillWorks'
# *** LIVE SIGNED ISSUER METADATA VERIFIED (x5c -> PID Issuer CA 02 EU) ***
```

`IssuerMetadataPolicy.RequireSigned(X5cSignedMetadataVerifier(validator))` negotiates `application/jwt`,
validates the chain, enforces the §12.2.3 rules, and takes the payload as the metadata;
`IgnoreSigned` (the default) asks for `application/json` and never sees a JWT.

## Proximity (ISO 18013-5) — device-to-device interop with Multipaz

Separate from the headless remote flows above, the proximity stack was verified **phone-to-phone**
against the **Multipaz** reference wallet/reader (`org.multipaz.testapp`) on two real devices
(Samsung `R3CW70VFWMR` + `R3KL1044XHZ`), both directions, all transports:

| Direction | Transport | Result |
| --- | --- | --- |
| our **reader** ← Multipaz **holder** | BLE peripheral-server mode | ✅ read + verified (issuer chain + `deviceMac`) |
| our **holder** → Multipaz **reader** | BLE peripheral-server & central-client | ✅ accepted |
| our ↔ our | BLE both modes + NFC static handover | ✅ end-to-end |

Three interop bugs this surfaced, each fixed against the ISO text confirmed by reading Multipaz
source (not just logs):

- **HKDF salt.** ISO §9.1.1.4 derives the session keys with `salt = SHA-256(SessionTranscriptBytes)`
  where `SessionTranscriptBytes = #6.24(bstr(SessionTranscript))`. We were hashing the *raw*
  transcript — self-consistent (our-to-our worked) but incompatible with any conformant peer, so the
  AES-GCM open failed. Fixed to wrap in tag 24 before hashing (`SessionEncryption.transcriptSalt`).
- **BLE mode flags.** A BLE `DeviceRetrievalMethod` must carry **both** option keys `0`
  (peripheral-server-supported) **and** `1` (central-client-supported); Multipaz reads both with a
  throwing map lookup and crashed (`key 1 doesn't exist`) when we emitted only key 0. Fixed so
  `bleRetrievalMethod` always emits both flags.
- **deviceMac.** Multipaz (and any key-agreement `DeviceKey` wallet) authenticates the device with
  `deviceMac` (COSE_Mac0, §9.1.3.5), not `deviceSignature`. Added `CoseMac0` + the `EMacKey`
  derivation (`HKDF(ECDH(EReaderKey, DeviceKey), salt = transcript, info = "EMacKey")`) so the reader
  verifies either form.

## Known gaps this exercise surfaced

- **x5c issuer-key resolution is production-needed, not just metadata.** The real issuer uses
  x5c. `X5cLeafKeyResolver` currently lives in tests (JVM `CertificateFactory`) and extracts
  the leaf key **without chain validation**. The production resolver — both languages, with
  chain validation against IACA/LOTL trust anchors — lands with the **trust module (M3)**
  (Swift needs `swift-certificates`). Tracked in `SPEC-MATRIX.md`.
- Full live issuance still needs the browser step; only that one step isn't headless.
