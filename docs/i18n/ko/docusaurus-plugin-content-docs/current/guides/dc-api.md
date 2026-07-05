---
title: Digital Credentials API (Android)
---

# Digital Credentials API (Android)

[W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/)는 웹사이트(또는 앱)가 크리덴셜을 요청하면 OS가 월렛 선택창을 중재하는 방식이에요 — QR도 HTTP도 없습니다. SDK의 `wallet.presentation.startDcApi(requestJson, origin)`가 이미 OpenID4VP-over-DC-API 처리(매칭 → 동의 → 홀더 바인딩 응답)를 하고요. 이 가이드는 그걸 **Android Credential Manager**에 붙여서 브라우저가 우리 월렛을 부를 수 있게 합니다.

두 부분:

- **SDK (크로스플랫폼)** — `startDcApi(requestJson, origin)`이 verifier 요청 객체 + 호출자 origin을 받아 응답 객체를 반환. 플랫폼 무관.
- **Android provider 배선** — 크리덴셜을 Credential Manager에 등록하고 `GET_CREDENTIAL` 인텐트에 응답. 이 페이지가 다루는 부분.

:::note
provider는 `androidx.credentials.registry`(alpha)를 쓰고 Google Play Services에 의존해서, GMS 기기에서 동작해요. 이게 없어도 나머지 기능(발급, 원격/근접 제시)은 그대로 됩니다.
:::

## 1. 의존성

```kotlin
implementation("androidx.credentials:credentials:1.5.0")
implementation("androidx.credentials.registry:registry-provider:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-provider-play-services:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-digitalcredentials-openid:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-digitalcredentials-mdoc:1.0.0-alpha04")
implementation("androidx.credentials.registry:registry-digitalcredentials-sdjwtvc:1.0.0-alpha04")
```

## 2. 크리덴셜 등록

저장된 크리덴셜을 `SdJwtEntry` / `MdocEntry`로 매핑해 **OpenID4VP** 홀더로 등록합니다. `OpenId4VpRegistry`가 기본 matcher를 번들해요 — OS가 이걸 실행해 들어온 요청과 우리 크리덴셜을 필터링하므로, WASM matcher를 직접 넣을 필요가 없습니다. 크리덴셜이 바뀌면 다시 등록하세요.

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
display-set 파라미터 이름은 `entryDisplayPropertySet`(displayProperties 아님)이고, DC API 타입은 `@OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)`가 필요해요.
:::

## 3. Provider 액티비티

`GET_CREDENTIAL` 인텐트를 처리할 액티비티를 선언해요 — UI 불필요(OS 선택창이 동의 역할):

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

요청 + origin 추출 → SDK 실행 → 응답 반환:

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

`callingAppInfo.getOrigin(allowlistJson)`은 호출자가 allowlist에 있는 privileged 브라우저일 때 **웹 origin**(예: `https://verifier.example`)을 반환해요. Google이 공개한 목록(Chrome 등)을 `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json`에서 받아 asset으로 번들하세요. **네이티브 앱** verifier면 origin이 비어서, 호출자 서명 인증서로 도출합니다:

```
android:apk-key-hash:<signingCertificateHistory[0]의 base64url SHA-256>
```

SDK가 이 origin을 mdoc `SessionTranscript`(ISO 18013-7 Annex C) / SD-JWT KB-JWT에 바인딩해서, 응답이 호출자에 묶입니다.

## 5. 테스트

1. 앱 시작 시 등록 실행(로그 `registered N credential(s)`) → 이제 월렛이 provider.
2. Chrome에서 DC-API verifier 사이트 열기(예: `verifier.eudiw.dev`, "same device" / 브라우저 방식).
3. 사이트가 `navigator.credentials.get({ digital })` 호출 → OS가 우리 월렛 포함 선택창 표시 → 선택 → `GetCredentialActivity`가 `startDcApi` 실행 후 응답 반환.

:::note
일부 Chrome 버전은 `chrome://flags` → "Digital Credentials API" 활성화가 필요해요. verifier의 이슈어 트러스트 정책 때문에 응답이 거부될 수도 있는데, 그건 verifier 쪽 문제예요.
:::
