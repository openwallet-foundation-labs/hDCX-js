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

## Known gaps this exercise surfaced

- **x5c issuer-key resolution is production-needed, not just metadata.** The real issuer uses
  x5c. `X5cLeafKeyResolver` currently lives in tests (JVM `CertificateFactory`) and extracts
  the leaf key **without chain validation**. The production resolver — both languages, with
  chain validation against IACA/LOTL trust anchors — lands with the **trust module (M3)**
  (Swift needs `swift-certificates`). Tracked in `SPEC-MATRIX.md`.
- Full live issuance still needs the browser step; only that one step isn't headless.
