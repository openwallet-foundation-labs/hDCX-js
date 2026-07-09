# iOS 레퍼런스 월렛의 W3C Digital Credentials API 지원 현황

조사일: 2026-07-09. 대상은 `upstream/main` (fetch 후 조사, merge 안 함):

| repo | 커밋 | 날짜 |
| --- | --- | --- |
| `eudi-app-ios-wallet-ui` | `ad1ce948` | 2026-07-06 |
| `eudi-lib-ios-wallet-kit` | `a0ef9caf` | 2026-07-07 |
| `eudi-lib-ios-openid4vp-swift` | `96d9c69` | 2026-06-19 |

## 결론

iOS 레퍼런스 월렛은 DC API를 **지원한다.** 단, 세 가지 단서가 붙는다.

1. 프로토콜은 **`org-iso-mdoc` (ISO/IEC TS 18013-7:2025 Annex C) 하나뿐**이다. `openid4vp-v1-signed` / `openid4vp-v1-unsigned`는 없다.
2. **SDK(wallet-kit) 기능이 아니라 앱 레벨 기능**이다. wallet-kit에도 openid4vp-swift에도 DC API 코드가 없다.
3. 실제 프로토콜 구현은 EUDI가 별도로 관리하는 **`av-lib-ios-w3c-dc-api`** 패키지에 있다 (Age Verification 앱 계열).

이 셋 중 (1)은 EUDI의 선택이 아니라 **Apple 플랫폼의 제약**이다. 아래 "왜 openid4vp가 없나" 참고.

## 구조

앱 레포에 `EudiReferenceWalletIDProvider`라는 별도 익스텐션 타겟이 있다. 최초 커밋은 2026-03-19 (`3c65e3e2` "Register documents by using IdentityDocumentProviderRegistrationStore", `c6ca5ad5` "Authorization view for dc api")이고 계속 다듬어지는 중이다.

```
EudiReferenceWalletIDProvider/
  DocumentProviderExtension.swift          # @main, IdentityDocumentProvider
  WalletIdProvider.plist                   # EXExtensionPointIdentifier =
                                           #   com.apple.identity-document-services.document-provider-ui
  EudiReferenceWalletIDProvider.entitlements  # App Group + keychain-access-groups
  Domain/DI/LogicIDPModule.swift           # DcApiHandler 조립
  Domain/Interactors/RequestAuthorizationInteractor.swift   # 요청 처리 핵심
  UI/Authorization/…                       # 동의 화면
Modules/logic-core/Sources/DocumentRegistrationManager/
  DocumentRegistrationManager.swift        # IdentityDocumentProviderRegistrationStore 래퍼
  DocumentRegistrationManagerNoOp.swift    # iOS 26 미만
```

익스텐션 진입점은 정확히 이게 전부다:

```swift
@main
struct DocumentProviderExtension: IdentityDocumentProvider {
  var body: some IdentityDocumentRequestScene {
    ISO18013MobileDocumentRequestScene { context in
      RequestAuthorizationView(with: .init(context: context))
    }
  }
}
```

### 요청 처리 흐름

`RequestAuthorizationInteractor`:

- `loadRequestData(context:)` → `dcApiHandler.validateRequest(context.request)` → 동의 화면용 `[DocClaimsModel]`. 요청자 이름은 `context.requestingWebsiteOrigin` 우선, 없으면 리더 인증서에서 뽑은 이름.
- `acceptVerification(context:)` → `context.sendResponse { rawRequest in … }` 안에서
  `validateConsistency(request:rawRequest:)` → `buildAndEncryptResponse(rawRequest:originUrl:)` →
  `ISO18013MobileDocumentResponse(responseData:)`.

즉 **OS가 파싱해 준 타입 안전한 `context.request`는 UI 표시용**이고, **실제 서명·암호화는 `sendResponse` 클로저 안에서 넘어오는 raw 요청 바이트로** 한다. Apple이 의도한 2단계 구조다.

### 등록 흐름

`WalletKitController.registerForDocumentIdentityExtension`이 발급/삭제 시 호출:

```swift
if #available(iOS 26.0, *), document.docDataFormat == .cbor {
  try await documentRegistrationManager.addRegistration(
    mobileDocumentType: document.docType,
    supportedAuthorityKeyIdentifiers: [],       // ← 비어 있음: 이슈어 필터링 없음
    documentIdentifier: document.id,
    invalidationDate: document.validUntil)
}
```

`DocumentRegistrationManagerImpl`이 `IdentityDocumentProviderRegistrationStore().addRegistration(MobileDocumentRegistration(...))`을 호출한다. iOS 26 미만은 `DocumentRegistrationManagerNoOp`.

**mdoc(CBOR) 문서만 등록된다.** SD-JWT VC는 iOS DC API로 제시할 수 없다.

앱 `EudiWallet.entitlements`에 선언된 문서 타입:

```
com.apple.developer.identity-document-services.document-provider.mobile-document-types
  org.iso.18013.5.1.mDL
  eu.europa.ec.eudi.pid.1
  eu.europa.ec.av.1
  org.iso.23220.photoid.1
  org.iso.23220.1.jp.mnc
```

이 entitlement는 Apple 승인이 필요한 special entitlement다 (`wiki/GO_LIVE.md:875`가 "Confirm entitlement approval"을 프로덕션 체크리스트에 올려둠).

### 익스텐션 ↔ 앱 데이터 공유

익스텐션은 별도 프로세스라 지갑 저장소를 직접 열어야 한다. `DcApiHandler(serviceName:accessGroup:)`가 `KeyChainStorageService`를 그 자리에서 만들고, `SecureAreaRegistry`에 SecureEnclave/Software secure area를 등록한다. 그래서 **App Group + Keychain Sharing이 필수**이고, 앱과 익스텐션의 `SHARED_APP_GROUP_IDENTIFIER`가 정확히 일치해야 한다. 설정 절차는 `wiki/CONFIGURATION.md:693` 이하.

## 실제 구현체: `av-lib-ios-w3c-dc-api`

- 저장소: `github.com/eu-digital-identity-wallet/av-lib-ios-w3c-dc-api`
- 앱이 핀한 버전: **v0.20.1** (`353b103ebe1c0be447d0175f466c145459dd9ff5`, 2026-06-02)
- 모듈명 `DcApi18013AnnexC`, 플랫폼 **iOS 26+ / macOS 26+**
- 의존성: `swift-log`, `eudi-lib-ios-iso18013-data-transfer`, `eudi-lib-ios-wallet-storage`, **`leif-ibsen/SwiftHPKE`**
- 소스 4파일 **340줄**이 전부

공개 API는 `public actor DcApiHandler` 하나:

```swift
init(serviceName: String, accessGroup: String, transactionLogger: (any TransactionLogger)? = nil)
func validateRequest(_:) async throws -> ([DocClaimsModel], DocumentRequestSet, [UInt8], String?)
func validateConsistency(request:rawRequest:) async throws          // ← 빈 함수
func buildAndEncryptResponse(rawRequest:originUrl:zkSystemRepository:) async throws -> Data
```

### 와이어 포맷 (그대로 옮겨 쓸 수 있는 수준)

**요청** — `rawRequest.requestData`는 JSON:

```json
{ "deviceRequest": "<base64url CBOR DeviceRequest>",
  "encryptionInfo": "<base64url CBOR>" }
```

`encryptionInfo` CBOR = `["dcapi", { "recipientPublicKey": <COSE_Key EC2 P-256> }]`.
핸들러는 `crv == 1`(P-256)만 받고 `-2`/`-3`에서 x/y를 뽑는다.

**SessionTranscript**:

```
origin       = originUrl.trimmingCharacters(in: "/")            // 뒤 슬래시 제거
dcapiInfo    = CBOR([ encryptionInfoBase64Url, origin ])
handover     = ["dcapi", SHA-256(dcapiInfo)]
transcript   = [null, null, handover]
```

**응답**:

```
plaintext = CBOR(DeviceResponse)
(enc, ct) = HPKE.seal(recipientPublicKey,
                      info: CBOR(SessionTranscript),   // aad = 빈 배열
                      pt:   plaintext)
responseData = CBOR([ "dcapi", { "enc": enc, "cipherText": ct } ])   // 원시 Data
```

HPKE 스위트는 `CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)` = RFC 9180 DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, base mode.

이건 우리 SDK의 `Hpke.sealBaseP256` + `MdocSessionTranscript.dcApiIsoMdoc` 설계와 **바이트 단위로 동일**하다. 좋은 교차검증.

## 왜 openid4vp가 없나 — Apple 플랫폼 제약

EUDI의 선택이 아니다. Apple 프레임워크 자체가 안 열어준다.

`IdentityDocumentServicesUI` (iOS/iPadOS 26.0):

- `IdentityDocumentRequestScene` 프로토콜의 **Conforming Types = `ISO18013MobileDocumentRequestScene` 단 하나**

`IdentityDocumentServices` (iOS/iPadOS/macOS 26.0):

- `IdentityDocumentWebPresentmentRequest` (closed protocol)의 **Conforming Types = `ISO18013MobileDocumentRequest` 단 하나**

W3C DC API 커뮤니티 문서도 명시한다: iOS/iPadOS는 "ISO 18013-7 Annex C for presentation. **OpenID for Verifiable Presentations (Annex D) is not supported.**" Chrome은 openid4vp + org-iso-mdoc 둘 다 라우팅하지만, Safari(및 iOS의 모든 WebKit 브라우저)는 `org-iso-mdoc`만 라우팅한다.

2025-11 W3C FedID WG(TPAC)에서 프로토콜 목록을 스펙에 하드코딩하기로 합의했고 (`openid4vp-v1-unsigned`, `openid4vp-v1-signed`, `openid4vp-v1-multisigned`, `org-iso-mdoc`, 발급용 `openid4vci-v1`), Apple이 이 중 하나만 구현한 상태다. 2026-07 현재 Apple이 openid4vp를 추가하겠다는 공개 로드맵은 없다.

## 프로토콜 매트릭스

| | Android (Chrome + Credential Manager) | iOS (Safari + IdentityDocumentServices) |
| --- | --- | --- |
| `openid4vp-v1-unsigned` | ✅ | ❌ 플랫폼 미지원 |
| `openid4vp-v1-signed` | ✅ | ❌ 플랫폼 미지원 |
| `org-iso-mdoc` | ✅ | ✅ |
| 매처 | 월렛이 WASM matcher 제공 | 불필요 — OS가 매칭·선택 UI 소유 |
| 등록 단위 | 크리덴셜 DB(CBOR) + 프로토콜 목록 | `MobileDocumentRegistration` (docType 단위) |
| 제시 가능 포맷 | mdoc + SD-JWT VC | **mdoc만** |

iOS에서 대안 브라우저 엔진(EU DMA)이 열려도 달라지지 않는다. 월렛 등록은 OS의 `IdentityDocumentProviderRegistrationStore`를 거치고, 그건 mdoc만 안다.

## 프로덕션 관점 갭

레퍼런스 코드를 그대로 가져오면 안 되는 지점들.

1. **`validateConsistency`가 빈 함수다.** 주석에 `// proposed function in the wwdc video, to be implemented`. OS가 파싱해서 사용자에게 보여준 `context.request`와, 실제로 서명 대상이 되는 `rawRequest`가 일치하는지 확인하는 단계다. 미구현이면 동의 화면에 보여준 것과 다른 데이터가 서명될 여지가 열린다. Apple이 WWDC에서 직접 권고한 검사다.

2. **Reader authentication 검증이 없다.** `validateRequest`는 인증서 체인의 리프에서 SAN/subject(표시용 이름)와 authority key identifier만 뽑는다. 체인 검증도, `readerAuth` COSE 서명 검증도 하지 않는다. 트랜잭션 로그에도 `isVerified: false, certificateChain: [], readerAuth: nil`로 남는다. 등록 시 `supportedAuthorityKeyIdentifiers: []`라 OS 레벨 필터링도 없다.

3. **`hpkeEncrypt`에 `try!`가 두 번.** 리더가 잘못된 `recipientPublicKey`를 보내면 익스텐션이 크래시한다 (P256 raw representation 파싱, DER 변환).

4. `buildAndEncryptResponse`가 `getDeviceResponseToSend`를 **두 번** 호출한다 (한 번은 `selectedItems: nil`로 유효 요청 항목을 얻고, 그 결과를 `expandSelections`로 확장해 다시 호출). 사용자 선택을 반영하는 경로가 아니라 "요청∩보유"를 자동 공개하는 구조다. 동의 화면은 목록만 보여줄 뿐 항목별 선택을 반영하지 않는다.

## 출처

- [IdentityDocumentServices | Apple Developer Documentation](https://developer.apple.com/documentation/identitydocumentservices)
- [IdentityDocumentServicesUI | Apple Developer Documentation](https://developer.apple.com/documentation/identitydocumentservicesui)
- [iOS/iPadOS | Digital Credentials Developer](https://digitalcredentials.dev/docs/references/platforms/ios/)
- [Online Identity Verification with the Digital Credentials API | WebKit](https://webkit.org/blog/17431/online-identity-verification-with-the-digital-credentials-api/)
- [Digital Credentials API: Secure and private identity on the web | Chrome for Developers](https://developer.chrome.com/blog/digital-credentials-api-shipped)
- [Digital Credentials API (2026): Chrome, Safari & Firefox — Corbado](https://www.corbado.com/blog/digital-credentials-api)
- `github.com/eu-digital-identity-wallet/av-lib-ios-w3c-dc-api` @ v0.20.1
