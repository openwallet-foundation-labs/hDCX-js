# Spec Version Matrix

이 SDK가 구현·추적하는 스펙 버전의 단일 소스. 릴리스마다 이 파일이 함께 태깅된다 (PLAN.md §3 운영 원칙).

| 스펙 | 앵커 버전 | 구현 상태 (0.0.x) |
|---|---|---|
| CBOR | RFC 8949 (deterministic encoding §4.2.1) | ✅ `cbor` — Appendix A 82벡터 양 언어 통과, 8949 bytewise + 7049 length-first 키 정렬 프로파일 |
| COSE | RFC 9052 §4.2 COSE_Sign1 · RFC 9053 ES256/384/512 · RFC 9360 x5chain | ✅ 검증(JCA/swift-crypto) + 서명(CoseSigner → SecureArea 포트 위임). cose-wg sign1 벡터 통과 |
| OpenID4VCI | **1.0 Final** (2025-09-16) | ✅ `openid4vci` — **실제 issuer.eudiw.dev에서 진짜 PID(SD-JWT VC) 발급·검증 완료 (2026-07-04)**. authorization code+PAR 그랜트, scope 선호(favorScopes), 오퍼 딥링크 해석. 절차는 `INTEROP.md`. deferred·batch·notification은 잔여 |
| DPoP | RFC 9449 | ✅ `openid4vci` — jti/htm/htu/ath + DPoP-Nonce 재시도 |
| PKCE | RFC 7636 (S256) | ✅ `openid4vci` |
| OpenID4VP | **1.0 Final** (2025-07-09), DCQL | ✅ `openid4vp` (양 언어) — DCQL 엔진(null 와일드카드·values·claim_sets·credential_sets), 요청 해석(JAR request_uri), vp_token 제시(SD-JWT+KB-JWT), direct_post + direct_post.jwt(JWE), 제시 세션. mdoc 제시는 M4 |
| JWE | RFC 7518 ECDH-ES direct + A128/192/256GCM | ✅ `sdjwt` (양 언어) — Concat KDF RFC 7518 Appendix C 벡터 통과, direct_post.jwt 응답 암호화 |
| HAIP | **1.0 Final** | ⬜ M2–M3 기본값에 반영 (PAR·DPoP Required 등) |
| JOSE (JWS) | RFC 7515/7518 서브셋 (compact, ES256/384/512) | ✅ `sdjwt` — 자체 구현, alg 고정 검증(협상 금지) |
| SD-JWT | **RFC 9901** | ✅ `sdjwt` — 발급/제시/검증, KB-JWT, 재귀·배열 disclosure, RFC 예제 83벡터 양 언어 통과 |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc | ✅ `SdJwtVcVerifier` — typ/iss/vct 강제, 시간 검증(JwtTimeValidator), 이슈어 키 해석(.well-known/jwt-vc-issuer), 홀더 바인딩, status 추출. x5c 이슈어 키 해석은 trust(M3) |
| Token Status List | IETF 최종 단계 — M6 시작 시 RFC 여부 재확인 | ⬜ M6 |
| ISO/IEC 18013-5 | :2021 (+ 18013-7 / DC API Handover) | ⬜ M4–M5 |
| W3C Digital Credentials API | Android CredMan / iOS 26 IdentityDocumentServices | ⬜ M5b (어댑터) |
| Trust (X.509) | RFC 5280 PKIX 체인 검증, SD-JWT VC issuer x5c, OpenID4VP x509_san_dns/x509_hash | ✅ **`trust` 모듈 양 언어 완료** — 체인 검증(Kotlin JCA / Swift swift-certificates), X5cIssuerKeyResolver, X509RequestVerifier(san_dns+hash). **실물 EUDI IACA(PID Issuer CA-UT 02)에 이슈어 PID + verifier 요청 둘 다 체인 검증 통과.** LOTL 자동 소비·CRL/OCSP는 M6 |
| mdoc (ISO/IEC 18013-5) | IssuerSigned/MSO, issuerAuth 검증, DCQL 매칭, DeviceResponse 제시, 실물 e2e | ✅ **완료 (2026-07-04) 양 언어 + 실물 검증** — P1: IssuerSigned/MSO, COSE_Sign1 issuerAuth 검증, digest 매칭, deviceKey holder 바인딩, trust `MdocIssuerTrust`. P2: DCQL 매칭(HeldMdoc, mso_mdoc path 규칙). P3: 제시(DeviceResponse+DeviceSigned over OpenID4VP handover SessionTranscript, PresentableCredential 통합). **P4 실물 e2e**: issuer.eudiw.dev서 mso_mdoc PID 발급(auth-code+pre-auth 양쪽)→IACA 체인검증→verifier.eudiw.dev에 DeviceResponse 제시·수락(HTTP 200). SD-JWT VC와 함께 **3플로우×2포맷=6 e2e 전부 헤드리스 통과** |
| DC API (W3C Digital Credentials API) | OpenID4VP over DC API — origin 바인딩 handover, dc_api/dc_api.jwt resolve+respond | 🔶 **코어 완료 (2026-07-04) 양 언어** — `Oid4vpSessionTranscript.dcApi`(OpenID4VPDCAPIHandover=`["OpenID4VPDCAPIHandover",SHA256([origin,nonce,jwkThumbprint])]`) + `.dcApiIsoMdoc`(ISO org-iso-mdoc `["dcapi",SHA256([encInfo,origin])]`), PresentationContext.origin, `resolveDcApiRequest`(unsigned JSON/signed, response_uri 없음, 플랫폼 origin), `respondDcApi`(dc_api→{vp_token}, dc_api.jwt→{response:JWE}, POST 안 함). mdoc DeviceResponse가 origin-bound handover로 서명. Kotlin 3 + Swift 3 테스트. **잔여(플랫폼 아티팩트): Android CredMan 등록+Intent, iOS IdentityDocumentServices 익스텐션** |
| 근접 제시 세션 암호화 (ISO 18013-5) | HKDF-SHA256 세션키, ECDH, AES-256-GCM 세션 암호, 근접 SessionTranscript, DeviceEngagement | 🔶 **코어 완료 (2026-07-05) 양 언어** — `proximity` 모듈: `Hkdf`(RFC 5869, **양 언어 RFC 5869 A.1 벡터 통과** → 크로스플랫폼 세션키 일치), `EphemeralKeyPair`(P-256 ECDH), `SessionEncryption`(§9.1.1: SKDevice/SKReader = HKDF(salt=SHA256(SessionTranscriptBytes), info="SKDevice"/"SKReader"), IV=8B식별자(mdoc …01/reader …00)+4B카운터, AES-256-GCM), `ProximitySessionTranscript`([DeviceEngagementBytes, EReaderKeyBytes, Handover]), `DeviceEngagement.qr`. mdoc DeviceResponse가 근접 transcript로 deviceSignature 서명(MdocPresenter 재사용). Kotlin 5 + Swift 5 테스트. **잔여(하드웨어): BLE/NFC 실전송, DeviceRequest 파싱, NFC handover** |
| ARF | 2.7.x 추적 | 문서 단계 |

미결 인터롭 포인트 (구현은 양쪽 다 있음, 핀만 남음):
- **mdoc 맵 키 정렬**: RFC 8949 bytewise(기본) vs RFC 7049 length-first(옵션) — M4에서 EUDI ref 아티팩트로 확정.

## 알려진 갭 레지스터 (자체 모듈 = 범용 lib가 아니라 스펙-필요 서브셋. 갭은 여기서 추적)

| 갭 | 필요 시점 | 상태 |
|---|---|---|
| **JWE** (ECDH-ES + A128/256GCM — VP 응답 암호화 direct_post.jwt) | **M3 필수 경로** | 계획됨 |
| Status List (크리덴셜 폐기/실효성) | IETF Token Status List — statuslist+jwt 페치·서명검증·zlib 압축해제·비트 인덱싱·TTL 캐시 | ✅ **완료 (2026-07-04) 양 언어** — `statuslist` 모듈: StatusList(bits 1/2/4/8, 최하위비트=최저인덱스), StatusListClient(fetch→서명검증[IssuerKeyResolver 재사용, trust x5c 연동]→sub/exp/typ 검사→TTL 캐시), StatusReference.fromClaims(status.status_list.idx/uri). Kotlin=java.util.zip.Inflater / **Swift=시스템 zlib(CZlib systemLibrary, Linux·macOS 공통)**. **JWT(statuslist+jwt)+CWT(statuslist+cwt COSE_Sign1, CWT claim 키 sub=2/exp=4/ttl=65534/status_list=65533) 둘 다** — `StatusListClient`(JWT, IssuerKeyResolver) + `CwtStatusListClient`(CWT, CoseStatusKeyResolver), StatusReference.fromClaims(JSON)/fromCbor(mdoc CBOR status). Kotlin 15 + Swift 15 테스트. SD-JWT VC·mdoc 양 포맷. 잔여: 실이슈어 인터롭 |
| 트랜잭션 로그 (감사 추적 / GDPR 투명성) | 발급·제시 기록, relying party·공개 클레임·raw req/resp, 쿼리, 영속 store 포트 | ✅ **완료 (2026-07-04) 양 언어** — `txlog` 모듈: TransactionLogEntry(type/status/relyingParty{id·name·trusted·certChain}/documents{format·type·claims}/raw), TransactionLogStore 포트+InMemory, TransactionLog facade(recordPresentation/Issuance, history 최신순, query[type/rp/window]), JSON 코덱(크로스언어 동일 포맷). idGenerator/clock 주입(no ambient). Kotlin 4 + Swift 4 테스트. 잔여: openid4vp/vci 흐름과 자동 배선(현재 앱이 조립) |
| Trust list(LOTL/ETSI TS 119 612) 자동 소비 provider | M6 하드닝 | **Level 1(동적 앵커 소스) 완료 (2026-07-04)** — X509ChainValidator가 `TrustAnchorSource`(suspend/async)를 validate마다 조회. **Level 2(LOTL 서명검증+캐시+TTL provider)는 M6 잔여(TODO)** |
| CRL/OCSP 인증서 실효성 검사 | M6 하드닝 (**LOTL 완성 후로 연기 — TODO**) | 계획됨. LOTL Level 2가 완전해진 뒤 인증서 체인 각 단계의 실효성(CRL 분산점/OCSP)을 X509ChainValidator에 옵션으로 추가 |
| **mdoc DCQL claim path 규칙** (M4) | M4 (mdoc 포맷과) | 계획됨. mso_mdoc claim path는 **앞 두 요소가 반드시 문자열**(namespace + element_id). base 스펙은 정확히 2, 그러나 **Lukas의 릴렉스(`>=2`, upstream iOS 머지)를 채택** — 세 번째부터는 element의 구조화된 값 안으로 들어가는 index/**null 와일드카드**/values 허용(null-match 기능의 본질). `intent_to_retain`은 mdoc 전용. 현행 DcqlEngine 경로 해석기는 이미 >=2·와일드카드를 지원하므로, M4에선 mso_mdoc 쿼리에 "앞 둘=문자열" 검증만 추가하면 됨 |
| VCI deferred(transaction_id 폴링), batch(>1 proof), notification 엔드포인트 | 실전 심화 | 계획됨 (auth code·PAR·PKCE·DPoP는 ✅ 라이브 검증) |
| VCI 전체 발급까지 라이브 E2E (브라우저 인증 필요) | 실기기/앱 통합 | 헤드리스 불가 — 실 PAR 왕복까지 검증, 이후 단계는 하네스 앱에서 |
| PAR dpop_jkt 바인딩(인가코드↔DPoP키 결속) | 하드닝 | 계획됨 |
| vct#integrity, vct 타입 메타데이터 해석 | SD-JWT VC 심화 | 계획됨 |
| COSE_Key 파싱, COSE_Mac0 (mdoc deviceAuth MAC) | M4 | 계획됨 |
| Status List의 CWT 변형 | M6 검토 | 미정 |
| RSA(RS/PS), EdDSA, HMAC 서명 | — | **의도적 제외** (HAIP/ARF 요구는 ES256 계열; 필요 시 알고리즘 레지스트리로 확장) |
| SD-JWT VC 전환기 `vc+sd-jwt` typ 수용 | — | **의도적 제외** (draft §3.1은 dc+sd-jwt를 MUST로 지정; vc+sd-jwt는 2024-11 이전 옛 값. 전환기 수용은 스펙 권고이나 기본 미지원, 특정 이슈어 대응 필요 시 옵트인 추가) |
| `_sd_alg` sha-384/512 | — | 의도적 제외 (HAIP는 sha-256; 명시적 거부함) |
| JSON: >2^53 비정수 정밀도(BigDecimal), JWS JSON 직렬화 변형 | — | 의도적 제외 (토큰 페이로드에 불필요) |

해결된 갭 (이 레지스터가 작동한 기록, 전부 2026-07-04): JSON 중복 키 거부(claim smuggling 방어) · JWS 미지 `crit` 거부 · **decoy digests 발급 생성** · **JWS x5c 헤더 파싱** · **SD-JWT VC typ에서 레거시 `vc+sd-jwt` 제거** · **VCI authorization code + PAR 그랜트** · **scope 선호 인가요청**(authorization_details는 EUDI 이슈어가 500 — favorScopes로 수정) · **오퍼 딥링크 해석**(resolveCredentialOffer) · **실제 PID 라이브 발급·검증 완료** · **trust 모듈 양 언어 완료**(x5c 이슈어 키+체인검증, VP 요청 x509_san_dns/x509_hash, 실물 EUDI IACA에 이슈어+verifier 둘 다 라이브 체인검증) — 실 인프라 인터롭에서 발견·수정, 테스트 포함.
