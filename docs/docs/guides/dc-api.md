---
title: Digital Credentials API (Android)
---

# Digital Credentials API (Android)

The [W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/) lets a website (or
app) request a credential and the OS mediate a wallet selector — no QR, no HTTP. The SDK's
`wallet.presentation.startDcApi(requestJson, origin)` already does the OpenID4VP-over-DC-API work
(match → consent → holder-bound response). This guide wires it into the **Android Credential Manager**
so a browser can invoke your wallet.

Two halves:

- **SDK (cross-platform)** — `startDcApi(requestJson, origin)` takes the verifier's request object and
  caller origin and returns the response object. Nothing platform-specific.
- **Android provider plumbing** — register your credentials with the Credential Manager and answer the
  `GET_CREDENTIAL` intent. That's what this page covers.

:::note
The provider uses `androidx.credentials.registry` (alpha) and pulls in Google Play Services, so DC API
works on GMS devices. Every other capability (issuance, remote/proximity presentation) is unaffected
without it.
:::

## 1. Dependencies

```kotlin
implementation("androidx.credentials:credentials:1.5.0")
implementation("androidx.credentials.registry:registry-provider:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-provider-play-services:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-digitalcredentials-openid:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-digitalcredentials-mdoc:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-digitalcredentials-sdjwtvc:1.0.0-alpha04")
```

## 2. Register credentials

Map your stored credentials to `SdJwtEntry` / `MdocEntry` and register them as an **OpenID4VP** holder.
`OpenId4VpRegistry` bundles the default matcher — the OS runs it to filter your credentials against an
incoming request, so you don't ship a WASM matcher. Re-register whenever credentials change.

```kotlin
suspend fun register(context: Context, wallet: Wallet) {
    val entries = wallet.credentials.list().mapNotNull { c ->
        val issued = c.lifecycle as? Lifecycle.Issued ?: return@mapNotNull null
        val display = setOf(VerificationEntryDisplayProperties(title(c), c.issuer?.displayName ?: "", icon(), "", ""))
        when (val f = c.format) {
            is CredentialFormat.SdJwtVc -> SdJwtEntry(
                verifiableCredentialType = f.vct,
                claims = issued.claims.map { SdJwtClaim(it.path, null, emptySet(), true) },
                entryDisplayPropertySet = display,
                id = c.id.value,
            )
            is CredentialFormat.MsoMdoc -> MdocEntry(
                docType = f.docType,
                fields = issued.claims.mapNotNull { cl ->
                    val ns = cl.path.getOrNull(0) ?: return@mapNotNull null
                    MdocField(ns, cl.path.getOrNull(1) ?: cl.path.last(), null, emptySet())
                },
                entryDisplayPropertySet = display,
                id = c.id.value,
            )
        }
    }
    RegistryManager.create(context).registerCredentials(OpenId4VpRegistry(entries, "my-wallet-openid-v1"))
}
```

:::caution
The display-set parameter is named `entryDisplayPropertySet` (not `displayProperties`), and the DC API
types require `@OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)`.
:::

## 3. Provider activity

Declare an activity for the `GET_CREDENTIAL` intent — no UI is needed (the OS selector is the consent):

```xml
<activity
    android:name=".GetCredentialActivity"
    android:exported="true"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <intent-filter>
        <action android:name="androidx.credentials.registry.provider.action.GET_CREDENTIAL" />
    </intent-filter>
</activity>
```

Extract the request + origin, run the SDK, return the response:

```kotlin
val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull() ?: return
val origin = request.callingAppInfo.getOrigin(privilegedAllowlistJson) ?: appOrigin(request)

lifecycleScope.launch {
    val session = wallet.presentation.startDcApi(option.requestJson, origin)
    val resolved = session.state.first { it is RequestResolved || it is Failed } as RequestResolved
    session.respond(PresentationSelection.auto(resolved.request))
    val done = session.state.first { it.isTerminal } as PresentationState.Completed
    PendingIntentHandler.setGetCredentialResponse(
        resultData, GetCredentialResponse(DigitalCredential(done.dcApiResponse!!)),
    )
    setResult(RESULT_OK, resultData); finish()
}
```

## 4. Verifier origin

`callingAppInfo.getOrigin(allowlistJson)` returns the **web origin** (e.g. `https://verifier.example`)
when the caller is a privileged browser in your allowlist. Bundle Google's published list (Chrome et al.)
from `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json` as an asset. For a **native app**
verifier the origin is empty — derive it from the caller's signing certificate:

```
android:apk-key-hash:<base64url SHA-256 of signingCertificateHistory[0]>
```

The SDK binds this origin into the mdoc `SessionTranscript` (ISO 18013-7 Annex C) / SD-JWT KB-JWT, so
the response is bound to the caller.

## 5. Test

1. Register runs on app start (log `registered N credential(s)`), so the wallet is now a provider.
2. Open a DC-API verifier site in Chrome (e.g. `verifier.eudiw.dev`, "same device" / browser flow).
3. The site calls `navigator.credentials.get({ digital })` → the OS shows a wallet selector including
   yours → pick it → your `GetCredentialActivity` runs `startDcApi` and returns the response.

:::note
Some Chrome builds gate this behind `chrome://flags` → "Digital Credentials API". The response may still
be rejected by the verifier's own issuer-trust policy — that's verifier-side, not the wallet.
:::
