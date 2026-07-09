# iOS Digital Credentials API — feasibility and plan

Researched 2026-07-09. Question: **can this SDK serve both `openid4vp-v1-*` and `org-iso-mdoc` over the
Digital Credentials API on iOS, the way it already does on Android?**

> **Status (2026-07-09):** not started. Blocked on P0, which is blocked on the Apple toolchain — no Mac
> or iOS device on the current dev machine. Picking up once that environment exists; P1–P4 will be done
> in the same pass rather than piecemeal on Linux.

## Answer

**No — and not because of anything in our code.** Apple's platform routes exactly one DC API protocol
to third-party wallets: `org-iso-mdoc` (ISO/IEC TS 18013-7:2025 Annex C). OpenID4VP over the browser
DC API is unreachable on iOS today.

What *is* reachable, and what we should build, is the `org-iso-mdoc` provider extension. Every
cryptographic and CBOR primitive it needs already exists in our Swift core and is byte-for-byte
identical to what the EUDI reference implementation does. The work is a platform adapter, not
protocol work.

Meanwhile `openid4vp` on iOS is not lost — it is served through the same-device deep link and
cross-device `request_uri` flows we already support (`wallet.presentation.start(requestUri)`). Only
the *browser-mediated* variant is unavailable.

### The platform ceiling, precisely

From Apple's own documentation (iOS/iPadOS 26.0, macOS 26.0):

- `IdentityDocumentServicesUI.IdentityDocumentRequestScene` — **Conforming Types:
  `ISO18013MobileDocumentRequestScene`** (one).
- `IdentityDocumentServices.IdentityDocumentWebPresentmentRequest` (a *closed* protocol) —
  **Conforming Types: `ISO18013MobileDocumentRequest`** (one).

The W3C DC API community reference states it plainly for iOS/iPadOS: "ISO 18013-7 Annex C for
presentation. OpenID for Verifiable Presentations (Annex D) is not supported."

At W3C TPAC (Nov 2025) the FedID WG froze the protocol list to `openid4vp-v1-unsigned`,
`openid4vp-v1-signed`, `openid4vp-v1-multisigned`, `org-iso-mdoc`, and `openid4vci-v1`. Apple has
implemented one of them. There is no public Apple roadmap for the others as of 2026-07.

Alternative browser engines under the EU DMA do not change this: wallet registration goes through the
OS `IdentityDocumentProviderRegistrationStore`, which only models mobile documents.

### Protocol matrix

| Protocol | Android (Credential Manager) | iOS (IdentityDocumentServices) | SDK entry point |
| --- | --- | --- | --- |
| `openid4vp-v1-unsigned` | ✅ shipping | ❌ platform | `wallet.presentation.startDcApi(json, origin)` |
| `openid4vp-v1-signed` | ✅ shipping | ❌ platform | `wallet.presentation.startDcApi(json, origin)` |
| `org-iso-mdoc` | ✅ shipping | ✅ **buildable** | `wallet.proximity.respondDcApiMdoc(deviceRequest, encryptionInfo, origin)` |
| SD-JWT VC over DC API | ✅ (openid4vp) | ❌ mdoc-only registration | — |

The `openid4vp` code paths stay compiled and tested on both platforms. On iOS they simply have no
browser caller until Apple ships a second scene type. If that happens, the adapter grows a branch;
the core does not change.

## What we already have

Verified against the tree at `b82baeb`. The core is complete for `org-iso-mdoc` in **both** languages:

| Piece | Swift | Kotlin |
| --- | --- | --- |
| HPKE base-mode seal (RFC 9180, DHKEM-P256 / HKDF-SHA256 / AES-128-GCM) | `Sources/MDoc/Hpke.swift:29` | `mdoc/…/Hpke.kt:40` |
| Annex C SessionTranscript `[null, null, ["dcapi", SHA-256(CBOR([encInfoB64, origin]))]]` | `Sources/MDoc/MdocSessionTranscript.swift:10` | `mdoc/…/MdocSessionTranscript.kt:14` |
| Holder flow: decode DeviceRequest → match → DeviceResponse → HPKE seal → `["dcapi", {enc, cipherText}]` | `Sources/Wallet/ProximityService.swift:99` | `wallet/…/ProximityService.kt:125` |
| OpenID4VP DC API handover + resolve/respond (Android-only caller) | `Oid4vpSessionTranscript.swift:25`, `Openid4VpClient.swift:49,74` | same |
| Reader auth verification (ISO 18013-5 §9.1.4) against configured anchors | `ProximityService.verifyReader` | same |

Our wire format matches `av-lib-ios-w3c-dc-api` v0.20.1 exactly — same handover, same `info =
CBOR(SessionTranscript)`, same empty `aad`, same `["dcapi", {enc, cipherText}]` envelope, same
`CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)`. See `IOS-DC-API-REFERENCE.md` for the
reference teardown.

## What is missing

### P0 — Apple platform adapters (blocks everything else)

Two implementations of ports that already exist in `swift/Sources/WalletAPI/Ports.swift`:

1. **`SecureEnclaveSecureArea: SecureArea`** — `createKey / publicKey / sign / keyAgreement /
   attestation / deleteKey`.
2. **A Keychain (or App Group container) `StorageDriver`** — `put / get / delete / keys / transaction`.

Today `swift/Sources` has **no Apple adapter at all** — only `WalletTestKit.SoftwareSecureArea`, which
is what its name says it is. The reference puts this logic inside
`DcApiHandler(serviceName:accessGroup:)`, which builds a `KeyChainStorageService` and registers secure
areas itself. Our ports model is cleaner: the extension builds a `Wallet` from the same adapters the
app uses, pointed at the same shared group.

#### Why it blocks DC API

The provider extension is a **separate process**. The browser wakes the *extension*, not the app, and
it must read credentials the app issued and sign a `DeviceResponse` with that credential's device key.
Both processes must see the same keys and the same storage, and that has to be true from the moment
the adapters are written.

`kSecAttrAccessGroup` is **fixed when the key is created and cannot be changed afterwards.** If the app
ships keys created without a shared group, no later extension can ever sign with them, and there is no
migration path — Secure Enclave private keys cannot be exported, so the only remedy is re-issuance.
This is why it is a prerequisite rather than a feature to bolt on.

#### Known sharp edges

- **Signature encoding.** The port returns raw `r||s` (`Ecdsa.verify(rawSignature:)`).
  `SecKeyCreateSignature` returns DER ECDSA. `Sources/CborCose/Ecdsa.swift` has `verify` and `leftPad`
  only — no DER→raw converter — so the adapter must carry one.
- **Secure Enclave is P-256 only.** `capabilities.algorithms = [.es256]`; es384/es512 are impossible.
  No practical impact (mdoc device keys and SD-JWT holder keys are ES256) but the capability must be
  declared honestly.
- **`attestation` starts as `nil`.** The port returns `KeyAttestation?`, so this is legal. Apple key
  attestation is App Attest (`DCAppAttestService`), a different animal from an SE key attestation, and
  our HAIP key attestation already routes through the wallet-provider backend
  (`WalletAttestationProvider`). Wire App Attest later, alongside the WP production integrity adapter.
- **`keyAgreement`** is `SecKeyCopyKeyExchangeResult(.ecdhKeyExchangeStandard)` → 32-byte x-coordinate.
  Proximity session encryption and JWE ECDH-ES depend on it.
- **Keychain has no transactions.** `StorageDriver.transaction` must be emulated.
- **Build isolation.** Core is Linux-testable and that is the PR gate. Importing `Security` /
  `LocalAuthentication` breaks the Linux build, so these adapters need a **new Apple-only target**
  (say `WalletApple`) excluded from the Linux lane. `Package.swift` also declares `iOS(.v14)` while
  `IdentityDocumentServices` is iOS 26 — `@available(iOS 26, *)` guards, or a separately-versioned
  target.

#### Definition of done

Our existing rule applies: **adapter qualification = passing the shared contract suite.** Run
`WalletTestKit.SecureAreaContract.verify(_:)` and `StorageDriverContract` against both adapters on a
real device.

The contract suites only exercise a **single process**, and the process boundary is the thing that
actually blocks DC API. So add two checks on top:

1. a key created by the **app** can be signed with by the **extension** (shared `kSecAttrAccessGroup`);
2. storage written by the **app** is readable by the **extension** (shared App Group).

Once those pass, P1–P3 are ordinary work.

#### Prerequisites (environment)

Our dev machine is Linux, so none of this compiles or runs here.

- a Mac with Xcode;
- an iOS 26 device — the Secure Enclave itself works on Apple Silicon simulators, but extensions,
  entitlements, and App Group sharing need real hardware;
- an Apple Developer account, including an **approved** special entitlement for
  `com.apple.developer.identity-document-services.document-provider.mobile-document-types`, with every
  servable doctype listed. Approval takes lead time — request it when the machine is set up.

#### Apple Developer setup (done 2026-07-09)

The portal side is configured. Signing uses the team's shared Account Holder Apple ID, added only to
**Xcode → Settings → Accounts** — the Mac's iCloud login and the iPhone's Apple ID are irrelevant to
code signing.

| | Value |
| --- | --- |
| Team | Hopae Inc., Organization |
| Team ID (`$(AppIdentifierPrefix)`) | `P3A48743C4` |
| App ID (app) | `com.hopae.eudi.wallet.demo` |
| App ID (extension) | `com.hopae.eudi.wallet.demo.idprovider` |
| App Group | `group.com.hopae.eudi.wallet.demo` |
| Keychain access group | `P3A48743C4.com.hopae.eudi.wallet.demo` |

An extension's bundle ID must be prefixed by its host app's. The App Group is enabled on **both** App
IDs; the keychain group is an Xcode capability only and has no portal entry.

**Capability split**, mirroring the reference: the app gets App Groups + *Digital Credentials API -
Mobile Document Provider*; the extension gets App Groups only. The doctype entitlement belongs on the
app because the app is what calls `IdentityDocumentProviderRegistrationStore`. Do **not** enable *ID
Verifier - Display Only* — that is `ProximityReader` (tapping an Apple Wallet ID with an iPhone),
unrelated to our ISO 18013-5 BLE reader, and it drags in a business review.

*Digital Credentials API* is the only managed (approval-gated) capability here. Ticking it saved
without a request prompt, which suggests the team already has it — **unconfirmed until a build proves
it.** First thing on the Mac:

```bash
codesign -d --entitlements :- "/path/to/EUDI Wallet Demo.app"
```

Expect `com.apple.developer.identity-document-services.document-provider.mobile-document-types` with a
non-empty array. The portal capability only *permits* the key; the doctypes must be written into the
app's `.entitlements` by hand, and a doctype absent from that array cannot be registered or served:

```xml
<key>com.apple.developer.identity-document-services.document-provider.mobile-document-types</key>
<array>
  <string>eu.europa.ec.eudi.pid.1</string>
  <string>org.iso.18013.5.1.mDL</string>
</array>
```

Entitlements are enforced at runtime, not only at distribution — without this one the extension
installs but never registers, so Safari never offers the wallet. **P0 does not need it** (App Groups +
Keychain Sharing suffice), so adapter work is not gated on approval.

Test device: iPhone on iOS 26.5.2, Developer Mode on. Xcode registers the UDID automatically; the team
allows 100 devices per type per membership year, counter resetting 2027-05-25.

BLE, camera, and NFC are **not** portal capabilities. Proximity needs
`NSBluetoothAlwaysUsageDescription` in Info.plist plus the `bluetooth-peripheral` background mode (we
run peripheral server mode). ISO 18013-5 NFC engagement would require HCE — region-restricted, out of
scope.

Finally: **never create keys under a Personal Team.** `kSecAttrAccessGroup` is fixed at key creation
and Secure Enclave keys cannot be exported, so a wrong team means re-issuing every credential.

#### Scope note

P0 is not DC-API-specific. It *is* the hardware `SecureArea` work deferred since M1 ("platform
artifacts"). The Android demo likewise still runs on `SoftwareSecureArea` + `FileStorageDriver`
(`demo/app/.../adapters`). Doing P0 unblocks iOS DC API and **production key custody on both
platforms** at once. DC API is simply the first consumer that forces the issue.

### P1 — small API impedance mismatches

- `respondDcApiMdoc` returns **base64url `String`**. Apple's `ISO18013MobileDocumentResponse` takes raw
  `Data`. Add a `Data`-returning variant (or have the adapter `Base64Url.decode`). Android wants the
  base64url form, so keep both.
- **Origin normalization.** The reference trims a trailing `/` from `originUrl` before hashing it into
  the handover. `context.requestingWebsiteOrigin?.absoluteString` can carry one. We take `origin`
  verbatim, so a trailing slash silently changes the SessionTranscript hash and the verifier rejects
  the response. Normalize in the SDK, not in each app.
- `Credential` exposes `format.docType` but not the MSO `validUntil`, which registration wants for
  `invalidationDate`. It is optional (the reference passes the document's `validUntil`; we can pass
  `nil` initially), but exposing it is the right fix.

### P2 — the extension itself

Mirror Android's `demo/app/.../DcApiRegistrar.kt` with a Swift `DcApiRegistrar` plus a provider
extension target in the demo:

```swift
@main
struct WalletDocumentProvider: IdentityDocumentProvider {
  var body: some IdentityDocumentRequestScene {
    ISO18013MobileDocumentRequestScene { context in ConsentView(context: context) }
  }
}
```

Registration, on issue and on delete:

```swift
try await IdentityDocumentProviderRegistrationStore().addRegistration(
  MobileDocumentRegistration(
    mobileDocumentType: docType,                     // from CredentialFormat.msoMdoc(docType:)
    supportedAuthorityKeyIdentifiers: [akiFromIssuerAuthChain],
    documentIdentifier: credential.id.value,
    invalidationDate: mso.validUntil))
```

Note there is **no matcher** on iOS — the OS owns matching and the credential picker. That deletes the
whole WASM matcher problem we have on Android.

Ship gate for customers: `com.apple.developer.identity-document-services.document-provider.mobile-document-types`
is an Apple-approved special entitlement, and each servable doctype must be listed in it.

### P3 — where we should beat the reference

Apple's flow is two-phase, and the reference leaves both halves under-defended:

1. **Pre-consent** the extension only has the OS-parsed `context.request`. Its
   `requestAuthentications.first?.authenticationCertificateChain` is enough to run our
   `X509ChainValidator` against the configured reader anchors and show a *verified* requester identity
   on the consent screen. The reference just prints the certificate's subject without validating it.
2. **Post-consent**, inside `context.sendResponse { rawRequest in … }`, the raw `DeviceRequest` appears.
   Only there can `readerAuth` be signature-verified, because it is bound to the SessionTranscript.
   We already do this (`ProximityService.verifyReader`) — but today only to populate the transaction
   log, *after* the response is built. On iOS it should gate: throw before returning bytes.
3. `validateConsistency(request:rawRequest:)` is an **empty function** in the reference
   (`// proposed function in the wwdc video, to be implemented`). It is the check that what the OS
   showed the user matches what we are about to sign. We decode the `DeviceRequest` anyway, so
   comparing doctype / namespace / element sets against `context.request` is nearly free. Implement it.

Also worth knowing: neither the reference nor our `respondDcApiMdoc` supports per-claim consent — both
disclose `requested ∩ held`. If per-claim selection is a requirement, `respondDcApiMdoc` needs the
resolve/respond split the remote and proximity flows already have.

### P4 — API shape

`respondDcApiMdoc` living on `wallet.proximity` while `startDcApi` lives on `wallet.presentation` is
an artifact of where the CBOR lived, not a model the caller recognizes. A `wallet.dcApi` service with
a single protocol-tagged entry point would let one app codebase target both platforms and absorb a
future Apple `openid4vp` scene without touching call sites:

```swift
switch request {
case .openid4vp(let json, let origin):            // Android today, iOS if Apple ships it
case .isoMdoc(let deviceRequest, let encInfo, let origin):   // both platforms
}
```

Not urgent; do it when the iOS adapter lands, so both callers move at once.

## Verdict

Supporting both protocols *simultaneously* is already true of the SDK core and true on Android in
production. On iOS it is capped at `org-iso-mdoc` by Apple, and no amount of work on our side lifts
that cap. The tractable goal is **`org-iso-mdoc` parity on iOS**, gated on P0 (Apple SecureArea +
shared-keychain storage). The reference implementation is a usable blueprint for the extension
plumbing and a *non*-blueprint for its security checks.

Watch item: if Apple adds an OpenID4VP scene, `startDcApi` is already implemented, tested, and
verified against `verifier.eudiw.dev` on Android. The iOS adapter would grow one `case`.

## Sources

- [IdentityDocumentServices](https://developer.apple.com/documentation/identitydocumentservices) /
  [IdentityDocumentServicesUI](https://developer.apple.com/documentation/identitydocumentservicesui) — Apple
- [iOS/iPadOS platform notes](https://digitalcredentials.dev/docs/references/platforms/ios/) — digitalcredentials.dev
- [Online Identity Verification with the Digital Credentials API](https://webkit.org/blog/17431/online-identity-verification-with-the-digital-credentials-api/) — WebKit
- [Digital Credentials API: Secure and private identity on the web](https://developer.chrome.com/blog/digital-credentials-api-shipped) — Chrome
- [Digital Credentials API (2026): Chrome, Safari & Firefox](https://www.corbado.com/blog/digital-credentials-api) — Corbado
- `eu-digital-identity-wallet/av-lib-ios-w3c-dc-api` @ v0.20.1 — the reference `org-iso-mdoc` handler
