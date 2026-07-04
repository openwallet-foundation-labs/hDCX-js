# EUDI Wallet SDK — 마스터 플랜

작성: 2026-07-04 · 상태: v0 초안 (논의용)

## 1. 확정된 방향 (2026-07-04 결정)

| 축 | 결정 |
|---|---|
| 제품 형태 | **헤드리스 SDK** — 고객사 앱에 임베드하는 B2B 코어. UI 없음, 데모/하네스 앱은 별도 |
| 플랫폼 | **네이티브 2벌** — Kotlin(Android) + Swift(iOS), API 계약만 크로스플랫폼으로 공유 |
| EUDI ref 재사용 | **풀 스크래치** — EUDI 코드는 dependency가 아니라 ①설계 레퍼런스 ②인터롭 테스트 상대 |
| 타깃 프로파일 | **EU eIDAS 2.0 우선** — ARF/HAIP 준수가 1차 기준, 타 시장은 프로파일 확장으로 |

## 2. "스크래치"의 경계

프로토콜·포맷·오케스트레이션 로직은 전부 자체 구현하되, 저수준 프리미티브는 검증된 것을 쓴다 (보안 감사 관점에서도 이게 정답):

- **자체 구현**: OpenID4VCI/VP 플로우, DCQL 엔진, SD-JWT/SD-JWT VC 처리, mdoc 데이터 모델(MSO/DeviceResponse), 세션 암호화, deterministic CBOR/COSE 인코딩, 상태 확인, trust 평가, 문서 스토어
- **플랫폼/검증 라이브러리 사용**: 암호 프리미티브(Android Keystore/StrongBox, iOS SecureEnclave/CryptoKit), TLS/HTTP(OkHttp 또는 Ktor / URLSession), BLE 스택, X.509 파싱(플랫폼 우선)
- **CBOR/COSE는 자체 구현 추천**: mdoc 인터롭의 성패가 deterministic encoding(RFC 8949 §4.2) 바이트 정합성에 달려 있어서, 작고 명세가 닫힌 이 모듈은 직접 소유할 가치가 있음. RFC 8949/9052 테스트 벡터 + EUDI ref가 생성한 아티팩트를 골든 벡터로 사용. (규모: 플랫폼당 2–3주 + 벡터 스위트)

## 3. 스펙 앵커 (2026-07-04 확인)

| 스펙 | 버전/상태 | 비고 |
|---|---|---|
| OpenID4VP | **1.0 Final** (2025-07-09) | DCQL 포함, Presentation Exchange 제거됨 |
| OpenID4VCI | **1.0 Final** (2025-09-16) | OIDF 자체 인증 프로그램 2026-02 개시 |
| HAIP | **1.0 Final** | OIDF 인터롭 테스트 98% 통과 사례 있음 — 우리 conformance 기준 |
| SD-JWT | **RFC 9901** (2025-11) | draft 아님, RFC 기준으로 구현 |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc-16+ | 아직 draft — 버전 핀 고정 + 어댑터 포인트 필요 |
| Token Status List | IETF 최종 단계 | M6 시작 시점에 RFC 여부 재확인 |
| ISO/IEC 18013-5 | :2021 (+18013-7 remote) | proximity 단계에서 -7/23220 시리즈 재확인 |
| ARF | 2.7.x (2026 iteration 진행 중) | 마이너 릴리스가 빠름 → 버전 매트릭스를 repo에 코드로 관리 |

원칙: **버전 매트릭스를 spec 레포에 파일로 두고**, 릴리스마다 "이 SDK 버전은 무슨 스펙 버전을 구현하는가"를 명시. draft에 앵커된 부분(SD-JWT VC 등)은 모듈 내 어댑터 포인트로 격리.

## 4. 아키텍처 — 코어/어댑터 분리 (ports & adapters)

**핵심 제약 (2026-07-04 추가)**: 코어는 **Linux 데스크탑에서 앱 디펜던시 없이 빌드·테스트 가능**해야 한다. Ubuntu CI에서 `./gradlew test`(Kotlin/JVM)와 `swift test`(Swift 6 툴체인)가 그린인 것이 모든 PR의 게이트. 플랫폼 기능은 전부 포트(인터페이스)로 정의하고, SDK 사용자가 생성자 주입으로 어댑터를 넣는다. **DI 프레임워크는 SDK에 포함하지 않음** — 코어는 무프레임워크, 앱은 자기 DI(Hilt/Koin/수동)로 조립. 이 구조 덕에 SDK가 모바일 앱 외에도 데스크탑/서버/CLI에서 쓰일 수 있다.

### 모듈 구조

```
eudi-wallet-sdk-core     ← 순수 Kotlin/JVM (java-library, AGP 금지) · 순수 Swift (Apple 프레임워크 import 금지)
├── wallet-api           퍼블릭 파사드 + 포트(SPI) 정의, 이벤트 스트림, 트랜잭션 로그
├── cbor-cose            deterministic CBOR(RFC 8949) + COSE(RFC 9052/9053 서브셋)
├── format-sdjwtvc       RFC 9901 + SD-JWT VC: disclosure, KB-JWT, vct 메타데이터
├── format-mdoc          IssuerSigned/MSO 검증, DeviceSigned(deviceAuth), SessionTranscript 변형들
├── openid4vci           발급: auth code + PAR, DPoP, proof(jwt), batch(단일사용 키), deferred,
│                        notification, wallet/client attestation (HAIP 요구)
├── openid4vp            원격 제시: DCQL 엔진, JAR(request_uri), x509_san_dns,
│                        direct_post.jwt(JARM), transaction_data
├── proximity-core       18013-5 세션 레이어: engagement 파싱, SessionEstablishment, 세션 암호화
│                        — 추상 바이트 채널(DeviceChannel 포트) 위에서 동작, BLE 자체는 코어 밖
├── credential-store     문서 모델·수명주기 (저장 드라이버는 StorageDriver 포트)
├── trust                X.509 체인 정책, ETSI TS 119 612 trusted list(LOTL) 소비, RP 등록 증명 —
│                        TrustSource 플러그인 구조 (ARF trust 인프라가 아직 움직이므로)
├── status               Token Status List
└── testkit              SoftwareSecureArea, 인메모리 스토리지/채널, 고정 Clock·RNG, 골든 벡터 로더

eudi-wallet-sdk-android (AAR) · eudi-wallet-sdk-apple (SPM 타깃)   ← "배터리 포함" 어댑터 아티팩트
├── secure-area          AndroidKeystore/StrongBox + key attestation · SecureEnclave
├── storage              EncryptedFile/SQLite · Keychain/FileProtection
├── transport            OkHttp · URLSession
├── proximity            BLE GATT/NFC engagement · CoreBluetooth/CoreNFC
└── dcapi                CredentialManager registry · IdentityDocumentServices

harness-app ×2 (+ Linux CLI 하네스)   SDK 소비자 관점 검증용 (제품 아님)
```

### 포트 (코어가 정의, 호스트가 주입)

| 포트 | 계약 | 모바일 어댑터 | Linux/테스트 어댑터 |
|---|---|---|---|
| `SecureArea` | 키 생성·서명·ECDH·attestation 획득 | Keystore/StrongBox · SecureEnclave | `SoftwareSecureArea` (인메모리 키) |
| `StorageDriver` | 암호화 블롭 CRUD | EncryptedFile · Keychain/FileProtection | 파일/인메모리 |
| `HttpTransport` | 요청/응답, 리다이렉트 제어 | OkHttp · URLSession | 스텁 서버/목 |
| `DeviceChannel` | 근접 바이트 스트림 | BLE GATT · CoreBluetooth | 인메모리 파이프 → 18013-5 세션 암호화를 Linux에서 테스트 |
| `WalletAttestationProvider` | WUA/키 attestation 발급 (월렛 프로바이더 백엔드) | 고객사 백엔드 클라이언트 | 스텁 attestation |
| `Clock` / `Rng` / `Logger` | 시간·난수·로그 | 시스템 | 고정 시드 → 결정적 테스트 |

**크립토 경계 규칙**: 공개키 검증·해시·HKDF·JWE 등 "키 보관이 필요 없는" 연산은 코어 안(JVM: JCA `java.security`, Swift: swift-crypto) — Linux에서 그대로 돈다. 개인키가 관여하는 연산(서명·ECDH)은 전부 `SecureArea` 포트 뒤 — 하드웨어든 소프트웨어든 어댑터가 결정.

**의존성 허용목록**:
- Swift 코어: `swift-crypto`(CryptoKit API 호환, Linux=BoringSSL, Apple=CryptoKit 재수출), `swift-certificates`+`swift-asn1`(X.509, Security.framework 대체), Foundation. `CryptoKit`/`Security`/`Keychain`/`CoreBluetooth`/`LocalAuthentication` 직접 import는 어댑터 전용 — CI import 린트로 강제.
- Kotlin 코어: kotlin-stdlib, kotlinx-coroutines, kotlinx-serialization, JCA. BouncyCastle은 testkit(SoftwareSecureArea)까지만. AGP 플러그인 사용 금지(plain JAR 발행 → 서버사이드 재사용 가능).

### 조립 예시 (개발자 경험)

```kotlin
val wallet = Wallet {
    secureArea = AndroidKeystoreSecureArea(context)   // 데스크탑/서버: SoftwareSecureArea()
    storage    = EncryptedFileStorage(context)
    transport  = OkHttpTransport()
    consent    = { req -> ui.askUser(req) }
}
```
```swift
let wallet = Wallet(
  secureArea: SecureEnclaveArea(),                    // Linux: SoftwareSecureArea()
  storage:    KeychainStorage(),
  transport:  URLSessionTransport(),
  consent:    { req in await ui.askUser(req) })
```

### 설계 원칙
1. **API 계약은 스펙 문서로 관리** — 마크다운 계약(타입/시그니처/에러 모델) → Kotlin/Swift 미러링. suspend fun↔async, Flow↔AsyncSequence, sealed class↔enum(assoc values). 계약 변경은 양 플랫폼 동시 PR 규칙.
2. **에러 모델을 1급 시민으로** — EUDI ref의 약점 중 하나. 스펙 에러코드와 1:1 매핑되는 타입드 에러 + 진단 컨텍스트. B2B SDK의 DX 차별화 포인트.
3. **포트 계약 테스트 공유** — 같은 계약 테스트 스위트를 CI에선 테스트 어댑터로, 디바이스 랩에선 실제 어댑터로 실행. "어댑터 자격 = 계약 테스트 통과".

### Linux에서 안 되는 것 (정직한 목록)
StrongBox/SE 실키 경로, biometric userAuth 바인딩, key attestation 체인, BLE 라디오, NFC, DC API — 전부 어댑터 영역이며 디바이스 랩(M5)에서 계약 테스트로 검증. 코드 기준 약 85–90%가 Linux CI로 커버되는 구조.

## 5. 로드맵

기간은 플랫폼당 1–2명 풀타임 가정. Android/iOS는 같은 마일스톤을 락스텝으로 가되, 벡터/계약을 공유해 drift 방지.

| 단계 | 내용 | 규모 | 완료 기준 |
|---|---|---|---|
| **M0 파운데이션** | API 계약 v0 (EudiWallet/wallet-kit API keep-change-drop 분석 기반), 레포/CI(Ubuntu 게이트), 포트 인터페이스 확정, 스펙 버전 매트릭스, cbor-cose 모듈 + 골든 벡터 | 2–3주 | Ubuntu CI에서 양 언어 코어 테스트 그린 + RFC 8949/9052 벡터 100% 통과 |
| **M1 키·저장** | keystore(SecureArea 추상화, attestation, userAuth), credential-store(암호화 envelope) — **코어 완료 (2026-07-04)**: SoftwareSecureArea(3커브) + 포트 계약 스위트 + SecureArea×COSE E2E + credential-store(엔벨로프 CBOR v1 크로스언어 골든, OneTime/Rotate 소비). 하드웨어 어댑터(Keystore/SE)와 attestation E2E는 플랫폼 아티팩트 단계에서 | 2–3주 (M0 후반과 병렬) | 키 생성→서명→attestation 검증 E2E |
| **M2 SD-JWT VC + VCI 발급** | RFC 9901 구현, VCI(HAIP 서브셋: PAR, DPoP, proof jwt, batch, wallet attestation) — **코어 완료 (2026-07-04)**: SD-JWT(83벡터)+KB-JWT+decoy, SD-JWT VC 프로파일 검증기, 시간검증, OpenID4VCI pre-auth 그랜트 E2E(DPoP·proof·토큰·credential, mock issuer 프로토콜 검증). 잔여: authorization code(브라우저) 그랜트 + **실제 ref issuer 인터롭** | 4–6주 | EUDI ref issuer(issuer.eudiw.dev)에서 PID(SD-JWT VC) 발급 성공 |
| **M3 OpenID4VP 원격 제시** | DCQL 엔진(null/values 매칭 처음부터 스펙대로), JAR, x509_san_dns, direct_post.jwt, KB-JWT, transaction_data — **코어 완료 (2026-07-04)**: `openid4vp` 양 언어(DCQL·JWE·요청해석·vp_token·direct_post/.jwt·세션), mock verifier E2E. 잔여: 실 verifier.eudiw.dev 인터롭, Swift x509_san_dns(swift-certificates) | 4–6주 | EUDI ref verifier(verifier.eudiw.dev)와 E2E + OIDF conformance suite VP 통과 |
| **M4 mdoc** | format-mdoc 전체, VCI로 mdoc 발급 수령, VP에서 mdoc 제시(SessionTranscript/Handover — DC API Handover 변형 포함) | 4–6주 | PID 양포맷 + mDL 발급·제시 — **"eIDAS 원격 플로우 코어 완성" 마일스톤** |
| **M5 근접 제시** | 18013-5: engagement(QR/NFC), BLE, session encryption. 실기기 인터롭 매트릭스 | 4–8주 | EUDI ref 앱·상용 reader와 실기기 교차 검증 |
| **M5b DC API** | Android: CredMan registry 등록 + Intent ingress 어댑터, OpenID4VP-over-DC-API 응답 경로. iOS: IdentityDocumentServices(iOS 26+) 익스텐션 어댑터. 코어는 M4의 Handover 변형 재사용 | 3–4주 (M5와 병렬 가능) | Chrome/Android 데모 verifier와 DC API E2E |
| **M6 Trust·상태·하드닝** | trust 모듈(LOTL, RP 인증), status list, 트랜잭션 로그, 삭제/백업 정책, 보안 감사 준비, 문서화 — **trust 코어 완료 (2026-07-04, M3에서 선행)**: X.509 체인 검증(양 언어), x5c 이슈어 키, VP 요청 x509_san_dns/x509_hash, 실물 EUDI IACA 라이브 검증. M6 잔여: LOTL 자동 소비, CRL/OCSP, status list, 감사 | 4–6주 | 외부 보안 리뷰 + 고객 인증 지원 문서 패키지 |
| **M7+** | ZKP(longfellow 동향 관망), remote WSCD, TS/RN 바인딩 레이어, 월렛 프로바이더 백엔드(WUA 발급 서비스) 레퍼런스 구현, 타 시장 프로파일 | — | — |

대략 M0–M4 ≈ 4–5개월(원격 플로우 완성), M5–M6 +2–3개월. 리스크 최대 구간은 M4–M5(mdoc 바이트 정합성 + BLE 기기 파편화).

순서 근거:
- **SD-JWT VC를 mdoc보다 먼저**: 포맷이 단순하고, Hopae가 sd-jwt-js 메인테이너로서 스펙 전문성을 이미 보유. 빠른 첫 E2E로 파이프라인 전체(키→발급→저장)를 조기 검증.
- **VCI를 VP보다 먼저**: 제시할 크리덴셜이 있어야 제시 테스트가 실물이 됨. EUDI 공개 issuer가 있어 상대방 구현 없이 시작 가능.
- **proximity를 뒤로**: 원격 플로우(eIDAS 파일럿/데모의 90%)를 먼저 완성. BLE는 실기기 랩이 필요해 병렬 준비.

## 6. EUDI ref 레포의 새 역할

dependency가 아니므로 ~/eudi-ref 포크들의 용도 재정의:

1. **스펙 해석 크로스체크** — 모호한 스펙 조항에서 ref 구현의 해석 확인 (단, ref가 틀린 경우도 있음 — DCQL null 매칭이 그 사례)
2. **인터롭 상대** — ref 앱/issuer/verifier와의 E2E가 1차 인터롭 사다리. android.md/ios.md의 로컬 빌드 노하우 재활용
3. **골든 벡터 소스** — ref가 생성한 mdoc/SD-JWT 아티팩트를 캡처해 우리 파서의 테스트 벡터로
4. fork 브랜치(`feat/dcql-null-match`)는 upstream 머지 압박 불필요 — 단 Android ref와 인터롭 테스트할 때 ref 쪽 버그 우회용으로는 유지

## 7. 테스트·인터롭 전략

- **공유 벡터 저장소**: 플랫폼 중립 JSON/CBOR 골든 벡터 레포 → Kotlin/Swift 테스트가 같은 벡터 소비. 네이티브 2벌의 정합성을 지키는 핵심 장치. Lukas의 DCQL null/values 엣지케이스들을 1일차 conformance 케이스로 등재.
- **인터롭 사다리**: 유닛(벡터) → EUDI ref 라이브러리와 페어 테스트(로컬) → ref 공개 인스턴스 E2E → OIDF conformance suite(VCI/VP — 2026-02부터 자체 인증 개시됨) → EUDI 인터롭 이벤트/파일럿
- **CI**: PR마다 벡터 스위트(Ubuntu, 양 언어), nightly로 ref 공개 인스턴스 E2E — `SoftwareSecureArea`로 Linux에서 헤드리스 실행(에뮬레이터 불필요), 실기기 BLE는 M5부터 디바이스 랩

## 8. 리스크

| 리스크 | 대응 |
|---|---|
| 풀 스크래치 볼륨 (특히 mdoc/BLE) | 벡터 우선 개발, ref 아티팩트 캡처, M5에 실기기 랩 조기 확보 |
| ARF 마이너 릴리스 속도 | 스펙 버전 매트릭스 파일 + draft 앵커 부분(SD-JWT VC, status list, trust 인프라)은 어댑터로 격리 |
| 네이티브 2벌 API drift | 계약 문서 + 동시 PR 규칙 + 공유 벡터 |
| iOS 제약 | SE는 P-256 전용(ES256이라 무방), 백그라운드 BLE 제한 → M5에서 UX 가이드로 흡수 |
| Swift/Linux 갭 (CryptoKit·Security 부재) | 코어 크립토를 swift-crypto·swift-certificates로 통일, Apple 프레임워크는 어댑터 전용 + import 린트로 강제 |
| 인증 범위 오해 | 인증 대상은 wallet **solution**(고객 제품)이지 SDK가 아님 — SDK 제품에 "인증 지원 증적 패키지"(문서/테스트 리포트) 포함 |
| SD-JWT VC가 아직 draft | vct/메타데이터 처리를 버전 태그로 격리, draft 갱신 시 어댑터만 교체 |

## 9. 바로 다음 액션

1. ~~API 계약 v0~~ → **완료 (2026-07-04)**: `API-CONTRACT.md` 초안 작성·커밋 — keep/change/drop 분석 + 파사드/세션/포트/에러 계약. 리뷰 후 확정. (참고: 동의는 PresentationConsent 포트가 아니라 세션 상태 머신으로 처리하기로 변경)
2. ~~레포 부트스트랩~~ → **완료 (2026-07-04)**: `~/eudi-wallet-sdk` 생성(git, main 브랜치). 당분간 spec/문서 + 골든 벡터 홈. 플랫폼 레포(`eudi-wallet-sdk-android`/`-ios`) 분리는 코드 스캐폴드 시점에 확정.
3. ~~cbor-cose 스파이크~~ → **완료 (2026-07-04)**: 양 언어 deterministic CBOR 코어(`kotlin/cbor`, `swift/Sources/CborCose`)가 RFC 8949 Appendix A 공식 코퍼스 통과 — 양 플랫폼 동일 수치(82 디코드 / 59 값비교 / 65 라운드트립) + deterministic 전용 테스트 12종. **리스크 판정: 낮음.** MapKeyOrder는 8949 bytewise 기본 + 7049 length-first 옵션으로 구현해둠(mdoc 인터롭 시 M4에서 핀 고정). 다음 확장: COSE(RFC 9052 Sign1) + 벡터.
4. ~~COSE Sign1~~ → **완료 (2026-07-04)**: RFC 9052 COSE_Sign1 — 검증은 코어(JCA/swift-crypto), 서명은 `CoseSigner` 추상화(SecureArea 어댑터 자리). cose-wg 공식 벡터(sign-pass-01/02/03 + sign-fail-02) 양 언어 통과, Sig_structure 바이트 일치("Redo protected" h'A0'→h'' 정규화 포함). 포트 SPI도 코드화됨(`kotlin/wallet-api` · `swift/WalletAPI`) — 계약 v0.1 델타 반영.
5. ~~M1 코어~~ → **완료 (2026-07-04)**: testkit(`SoftwareSecureArea`·`InMemoryStorageDriver`·계약 스위트) + `SecureAreaCoseSigner` E2E(3커브) + credential-store(엔벨로프 스키마 v1, 크로스언어 골든 벡터, OneTime/Rotate `consumeInstance`). 저장 암호화는 StorageDriver 어댑터 소관(코어는 평문 CBOR를 암호화 드라이버에 위임).
6. ~~SD-JWT 코어~~ → **완료 (2026-07-04)**: `sdjwt` 모듈(Kotlin·Swift) — 자체 JsonValue(순서보존·바이트안정 직렬화), 자체 JWS(compact, alg 고정 검증), disclosure(재귀·배열 요소), 발급 DSL, 홀더 선택 제시(조상 자동 포함), KB-JWT(sd_hash), RFC 9901 예제 83벡터.
7. ~~OpenID4VCI 코어~~ → **완료 (2026-07-04)**: `openid4vci` 모듈(양 언어) — 오퍼/메타데이터 파싱, PKCE, DPoP(RFC 9449, nonce 재시도), key proof(§8.2.1), pre-authorized code 그랜트 E2E over HttpTransport. mock issuer가 DPoP·proof 서명·ath·aud·nonce를 실제 검증하고 진짜 SD-JWT VC 발급 → SdJwtVcVerifier로 왕복 검증. + SD-JWT VC 프로파일 검증기 + JwtTimeValidator.
8. ~~VCI authorization code 그랜트 + 실전 인터롭~~ → **완료 (2026-07-04)**: PAR 기반 auth code 그랜트(prepare→브라우저→finish, PKCE+DPoP) 양 언어. **실제 issuer.eudiw.dev 라이브 인터롭 통과** — 27개 config 실물 메타데이터 파싱 + 실 PAR 왕복으로 request_uri 수령(`RealIssuerInteropTest`, EUDI_INTEROP=1 env-gated). 브라우저 인증 이후의 전체 발급은 하네스 앱 단계.
9. 다음: **M3 착수** — OpenID4VP(DCQL 엔진, JAR, direct_post.jwt) + **JWE**(응답 암호화, M3 필수경로). VP는 M2에서 발급한 크리덴셜을 제시하므로 이제 실물로 테스트 가능.
10. 팀/기간 확정 후 마일스톤 날짜 부여
