# 화상회의 프로그램 보안 개선을 위한 선행연구 조사

- 조사일: 2026-05-14
- 조사 주제: Zoom 취약점 분석 및 Jitsi Meet/WebRTC 기반 화상회의 보안 강화
- 팀 프로젝트와의 연결: 저장소의 보안 실습 주제인 암호화, 인증, 세션 관리, 데이터 유출 방지, STRIDE/ZAP 분석을 선행연구 관점에서 보완한다.

## 1. 조사 범위와 검색 경로

본 조사는 팀 프로젝트가 다루는 "화상회의 프로그램의 보안 취약점과 보완 방안"에 맞춰 다음 경로를 중심으로 진행했다.

| 경로 | 검색어 예시 | 확보한 자료 성격 |
|---|---|---|
| Google Scholar / arXiv / IACR / RFC Editor | `WebRTC security`, `video conferencing end-to-end encryption`, `SFrame MLS`, `Zoom E2EE protocol` | 국제 표준 문서, 암호 프로토콜 논문, 기술 백서 |
| DBpia / KCI | `WebRTC 화상회의 보안`, `WebRTC 원격협업 암호화`, `WebRTC 화상 강의 시스템` | 국내 WebRTC 기반 화상회의/원격협업 연구 |
| RISS | `WebRTC VC`, `화상회의 WebRTC`, `SAML WebRTC video conference` | 국내 학술논문 서지 및 초록, 인증/접근성 관련 연구 |
| 정부/기관 보고서 | `video conferencing guidance`, `Zoom FTC encryption` | 화상회의 운영 보안 지침, Zoom 보안 이슈 사례 |

## 2. 핵심 결론

유사 연구들은 대체로 네 가지 축으로 문제를 해결하고 있다.

첫째, WebRTC 표준 자체의 보안 기능을 사용한다. WebRTC는 DTLS-SRTP, ICE consent freshness, 브라우저 권한 모델을 통해 네트워크 도청과 임의 트래픽 전송을 줄인다. 다만 SFU 기반 다자간 회의에서는 미디어 서버가 복호화된 RTP payload를 볼 수 있어 "진짜 종단 간 암호화"와는 차이가 있다.

둘째, SFU가 미디어 내용을 보지 못하도록 미디어 프레임에 추가 E2EE 계층을 올린다. 대표적으로 Jitsi Meet은 WebRTC Insertable Streams 기반으로 프레임을 암호화하고, IETF SFrame은 SFU가 라우팅에 필요한 메타데이터만 보도록 설계한다.

셋째, 다자간 회의의 핵심은 키 관리와 참가자 상태 동기화다. MLS는 그룹 키 갱신을 효율적으로 수행하는 표준이며, Zoom E2EE 분석 논문은 실시간 회의에서 참가자 목록, 퇴장/차단, 키 갱신이 빠르게 반영되는 liveness 속성이 중요하다고 본다.

넷째, 암호화만으로는 충분하지 않다. SSO/SAML, MFA, 짧은 수명의 JWT, 대기실, 회의 암호, 랜덤 회의 ID, 세션 만료, 녹화/채팅/파일 공유 정책, STRIDE와 ZAP 기반 점검을 함께 적용해야 한다.

## 3. 선행연구 및 기술보고서 정리

| 번호 | 자료 | 기존 연구자들의 해결 방식 | 장점 | 단점/한계 | 개선 아이디어 |
|---:|---|---|---|---|---|
| 1 | RFC 8826, RFC 8827: WebRTC 보안 고려사항/보안 아키텍처 | 브라우저 기반 실시간 통신에서 DTLS-SRTP, ICE, STUN consent freshness, 카메라/마이크 권한 동의, IdP 기반 신원 확인을 사용한다. | WebRTC 구현체가 기본적으로 암호화된 미디어/데이터 채널을 강제한다. 브라우저 권한 모델 덕분에 무단 장치 접근 위험도 줄일 수 있다. | 신호 서버가 MITM을 시도할 수 있고, SFU 구조에서는 서버가 미디어 payload를 볼 수 있다. 메타데이터와 사용자 UI 오해 문제는 남는다. | 기본 WebRTC 보안 위에 SFrame/Jitsi식 E2EE를 추가한다. SDP fingerprint 검증, 회의 참가자 신원 확인, 회의별 보안 상태 표시를 UI에 반영한다. |
| 2 | Feher et al., "The Security of WebRTC" | WebRTC 구조를 disruption, modification, eavesdropping 관점에서 분석하고 실제 WebRTC 환경에서 공격 시나리오를 시험한다. | 화상회의 보안 위협을 단순 암호화 문제가 아니라 통신 중단, 변조, 도청 전체로 볼 수 있게 한다. | 2016년 연구라 최신 SFrame, MLS, 브라우저 E2EE API 변화는 반영되어 있지 않다. | STRIDE 모델과 연결해 Spoofing, Tampering, Information Disclosure, DoS 항목별로 WebRTC 보안 점검표를 만든다. |
| 3 | Jitsi Meet E2EE Whitepaper / Jitsi Security 문서 | WebRTC Insertable Streams를 이용해 인코딩된 미디어 프레임을 전송 전 암호화한다. Jitsi Videobridge는 라우팅만 하고 평문 미디어를 보지 못하게 한다. | 오픈소스 구현을 참고할 수 있고, Jitsi 기반 프로젝트에 직접 적용하기 쉽다. SFU 신뢰 문제를 줄인다. | E2EE 적용 범위가 주로 음성/영상/화면공유에 집중된다. 채팅, 투표, 녹화, 자막 등 부가기능은 별도 보안 설계가 필요하다. 브라우저 지원과 키 배포 UX도 한계다. | 우리 프로젝트에서는 "E2EE 활성화 시 보호되는 기능/보호되지 않는 기능"을 명확히 표시한다. 회의 입장 시 SAS 또는 참가자 키 지문 확인 절차를 넣는다. |
| 4 | RFC 9605: SFrame | SFU가 라우팅에 필요한 메타데이터만 접근하고 미디어 프레임 본문은 종단 간 암호화되도록 한다. 키 관리는 SFrame 밖의 MLS, Signal, Olm 등에 맡긴다. | SFU 구조와 호환되며, RTP뿐 아니라 다른 실시간 전송에도 적용 가능하다. 프레임 단위 암호화라 패킷 단위보다 효율적일 수 있다. | SFrame 자체는 키 관리를 정의하지 않는다. 또한 per-sender authentication이 부족하고, KID/CTR 같은 헤더 메타데이터 노출 가능성이 있다. | SFrame과 MLS를 함께 사용하고, 참가자 입장/퇴장/강퇴 시 키를 즉시 갱신한다. sender signing 또는 참가자별 서명키를 추가해 발신자 위조 위험을 줄인다. |
| 5 | RFC 9420: Messaging Layer Security (MLS) | 트리 기반 그룹 키 합의로 다자간 그룹에서 forward secrecy와 post-compromise security를 효율적으로 제공한다. | 그룹 크기가 커져도 키 갱신 비용이 로그 규모로 줄어든다. 표준화된 그룹 E2EE 키 관리 기반을 제공한다. | MLS는 메시징 중심 표준이므로 실시간 회의의 "누가 지금 화면에 있고 누가 차단됐는가" 같은 liveness는 별도 설계가 필요하다. | 회의 roster와 MLS epoch를 강하게 묶고, UI에 현재 epoch/참가자 상태를 반영한다. 강퇴된 참가자는 새 epoch 키를 받지 못하도록 테스트한다. |
| 6 | Dodis et al., "End-to-End Encrypted Zoom Meetings" | Zoom E2EE 프로토콜을 formal security model로 분석하고, 실시간 회의에서는 key secrecy뿐 아니라 roster/key/media freshness가 중요하다고 제안한다. | 실제 상용 화상회의의 E2EE 설계를 검증한 연구라 현실성이 높다. 참가자 변경이 빠르게 반영되어야 한다는 관점을 제공한다. | Zoom의 구조는 host/leader 역할과 중앙 인프라 의존성이 남는다. E2EE 활성화 시 클라우드 녹화, PSTN 참가 등 일부 기능과 충돌할 수 있다. | 우리 프로젝트도 "차단 후 키 접근 차단 시간", "참가자 목록과 키 상태 불일치"를 테스트 케이스로 넣는다. |
| 7 | Zoom Cryptography Whitepaper / FTC Zoom 사건 | Zoom은 E2EE 설계를 공개 백서로 관리하고 버전을 갱신한다. FTC 사건은 E2EE를 실제보다 강하게 설명하면 사용자에게 허위 보안감을 줄 수 있음을 보여준다. | 공개 백서는 외부 검토가 가능하고, 상용 서비스도 암호 설계를 문서화해야 한다는 좋은 사례다. | 과거 Zoom은 서버가 키를 가질 수 있었는데도 E2EE 표현을 사용해 규제 리스크가 발생했다. | 우리 문서와 UI에서는 "전송 암호화", "서버 경유 암호화", "종단 간 암호화"를 구분해 표현한다. 보안 주장에는 구현 근거와 제한사항을 함께 적는다. |
| 8 | Park et al., "End-to-End Post-Quantum Cryptography Encryption Protocol for Video Conferencing System Based on GPKI" | Zoom과 SFrame의 E2EE 구조를 비교하고, 공공 PKI 기반 화상회의에서 PQC KEM을 키 교환에 적용하는 방안을 제안한다. | 미래 양자컴퓨터 위협을 고려한 고보안 회의 모드를 설계할 수 있다. GPKI 같은 강한 신원 인증과 E2EE를 연결한다. | PQC 알고리즘 표준, 성능, 브라우저 지원이 아직 일반 서비스에 바로 적용하기 어렵다. | 기본 모드는 ECDH/MLS, 고보안 모드는 hybrid ECDH + ML-KEM 같은 실험 옵션으로 분리하고 핸드셰이크 지연을 측정한다. |
| 9 | Yang, "Achieve Fully Decentralized End to End Encryption Meeting via Blockchain" | 중앙 서버가 회의 키/참가자 상태를 통제하지 못하도록 블록체인 기반 완전 분산 E2EE 회의 구조를 제안한다. | 중앙 인프라 신뢰 문제를 과감하게 줄이려는 접근이다. 참가자/키 상태를 투명하게 검증하려는 아이디어를 준다. | 블록체인은 실시간 회의의 지연, 비용, 복잡도와 충돌할 수 있다. 실제 구현/사용성 검증이 제한적이다. | 블록체인 전체 도입보다는 key transparency log나 append-only audit log처럼 가벼운 검증 로그만 차용한다. |
| 10 | 김경재, "WebRTC 기반의 온라인 원격 화상 강의 시스템 연구" (DBpia, 2023) | 교육용 화상강의에서 다대다 대신 일대다 방식을 쓰고, 참가자 수에 따라 해상도와 frame rate를 동적으로 조절한다. | 서버/클라이언트 자원 사용량을 줄이고 품질 저하를 완화할 수 있다. | 상호작용이 많은 회의에는 일대다 구조가 맞지 않을 수 있다. 보안 설계는 핵심 주제가 아니다. | E2EE와 adaptive bitrate를 함께 고려한다. 참가자 수가 많을 때 암호화 비용까지 포함해 성능 테스트한다. |
| 11 | 이관희·김지인·권구락, "WebRTC를 이용한 현장 적응형 다자간 원격협업 시스템 개발" (DBpia/KCI, 2021) | 산업현장 원격협업에 WebRTC 기반 실시간 영상/음성 공유와 영상 내 암호화를 적용한다. | 실제 산업현장 요구사항과 다자간 원격협업 기능을 반영한다. 보안 기능을 활용도 향상 요소로 본다. | 초록 수준에서는 암호화 방식, 키 관리, 위협 모델이 구체적으로 드러나지 않는다. | "영상 내 암호화"를 구현할 때 알고리즘, 키 관리, 회의 입장/퇴장 시 갱신, 녹화 정책을 명시한다. |
| 12 | 이경민·조진용·공정욱, "WebRTC VC응용의 접근성 및 편의성 향상기술 구현" (RISS, 2016) | SAML 기반 federated identity management와 SSO를 적용해 조직 계정으로 VC 애플리케이션에 접근하게 하고, REST API로 회의 생성/참여/모니터링을 관리한다. | 조직 계정과 연동되어 사용자 관리가 편하고, 개인정보 관리 부담을 줄일 수 있다. | SSO는 "누구인지"를 확인할 뿐 "회의에 들어와도 되는지"와 "세션이 안전한지"를 모두 보장하지 않는다. IdP 탈취 시 위험이 크다. | SSO에 MFA, 짧은 수명의 JWT, 회의별 권한, 대기실 승인, 세션 재인증, 토큰 폐기 목록을 결합한다. |
| 13 | CISA/FBI 화상회의 보안 지침, FTC Zoom settlement | 회의 암호, 대기실, 화면공유 제한, 회의 링크 공개 금지, 보안 프로그램 구축, 허위 보안 주장 금지 등 운영 통제를 강조한다. | 기술적 암호화 외에 실제 사고를 줄이는 설정과 운영 방법을 제시한다. 사용자 실수로 인한 침입을 줄이는 데 효과적이다. | 설정이 사용자에게 맡겨지면 누락되기 쉽다. 조직마다 적용 강도가 다르면 보안 수준이 흔들린다. | 기본값을 보안적으로 설정한다. 랜덤 회의 ID, 비밀번호 필수, host 승인 전 입장 차단, 화면공유 host-only, 회의 종료 시 토큰 폐기를 기본 정책으로 둔다. |

## 4. 세 가지 관점별 정리

### 4.1 기존 연구자들은 어떤 방식으로 문제를 해결하고 있나?

1. WebRTC 표준 보안 계층을 활용한다. RFC 8826/8827은 DTLS-SRTP, ICE consent freshness, 브라우저 권한 모델, IdP 신원 확인을 기본 보안 토대로 삼는다.
2. SFU 신뢰 문제는 추가 E2EE 계층으로 해결한다. Jitsi는 Insertable Streams, SFrame은 프레임 단위 암호화로 SFU가 미디어 평문을 보지 못하게 한다.
3. 다자간 키 관리는 MLS, Olm, Zoom식 continuous group key agreement 등으로 해결한다.
4. 인증과 접근통제는 SAML/SSO, MFA, JWT, 회의 암호, 대기실, role-based permission으로 다룬다.
5. 성능 문제는 SFU/MCU/mesh 선택, 일대다 구조, 동적 해상도/frame rate, adaptive bitrate로 완화한다.
6. 운영 보안은 CISA/FBI 지침처럼 링크 공개 금지, 화면공유 제한, 녹화/채팅 정책, 사용자 교육을 결합한다.

### 4.2 기존 방식의 장점과 단점

| 방식 | 장점 | 단점/한계 |
|---|---|---|
| WebRTC 기본 DTLS-SRTP | 브라우저가 기본 암호화를 강제하고 구현 비용이 낮다. | SFU가 미디어 payload를 볼 수 있고, 신호 서버 MITM/메타데이터 문제는 남는다. |
| Jitsi/Insertable Streams E2EE | Jitsi 기반 구현에 적용하기 쉽고 SFU 도청 위험을 줄인다. | 브라우저 호환성, 키 배포 UX, 녹화/자막/채팅 등 부가기능 보안이 어렵다. |
| SFrame + MLS | 표준 기반이며, 대규모 다자간 회의에서 키 갱신을 체계화할 수 있다. | SFrame은 키 관리를 직접 정의하지 않고, per-sender authentication/메타데이터 노출 문제가 남는다. |
| SSO/SAML/MFA/JWT | 조직 사용자 관리와 접근통제가 쉬워진다. | IdP 탈취, 토큰 재사용, 회의별 권한 미흡 시 우회가 가능하다. |
| 운영 보안 설정 | Zoombombing, 링크 유출 같은 현실적 사고를 줄인다. | 사용자가 설정을 놓치면 효과가 급격히 떨어진다. |
| PQC/GPKI | 장기 보안과 공공기관 수준 신원 인증에 유리하다. | 현재 일반 브라우저/서비스에 적용하기에는 성능과 표준 성숙도가 과제다. |

### 4.3 단점 및 한계 개선 아이디어

우리 팀 프로젝트에는 다음 개선안을 우선순위로 반영하는 것이 적절하다.

1. 보안 용어를 명확히 구분한다. "전송 암호화", "서버 경유 암호화", "종단 간 암호화"를 README와 UI에서 분리해 설명한다.
2. Jitsi 기반 E2EE를 핵심 개선 축으로 둔다. 음성/영상/화면공유는 Insertable Streams 또는 SFrame 계열로 암호화하고, 채팅/파일/녹화는 별도 정책을 둔다.
3. 회의 입장/퇴장 이벤트와 키 갱신을 결합한다. 참가자가 들어오거나 나가거나 강퇴될 때 새 epoch/key를 발급하고, 이전 키 접근을 차단한다.
4. 참가자 검증 UX를 넣는다. SAS, 키 지문, host 승인, 조직 계정 표시를 통해 "누가 같은 키를 공유하는지" 확인하게 한다.
5. 인증은 SSO + MFA + 짧은 수명 JWT로 설계한다. 회의 ID만 알면 들어오는 구조를 막고, 방 생성 권한과 참가 권한을 분리한다.
6. 세션 관리를 강화한다. Secure/HttpOnly/SameSite cookie, 토큰 회전, idle timeout, 회의 종료 시 토큰 폐기, 재사용 탐지를 적용한다.
7. 데이터 유출 방지를 기능 단위로 설계한다. 회의 링크, 참가자 목록, 채팅, 녹화 파일, 화면공유 권한, 로그에 대해 최소 수집/마스킹/보존기간을 둔다.
8. 보안 테스트를 자동화한다. STRIDE로 설계 위협을 정리하고, ZAP baseline scan으로 웹 취약점을 반복 점검한다.
9. 고보안 모드 실험을 둔다. 향후 과제로 MLS + SFrame 또는 hybrid PQC key exchange를 프로토타입하고 지연시간/CPU 사용량을 측정한다.

## 5. 팀 프로젝트 적용 제안

### 5.1 1차 구현 범위

| 영역 | 적용할 내용 |
|---|---|
| 암호화 | WebRTC 기본 DTLS-SRTP 위에 Jitsi E2EE 또는 SFrame 스타일 프레임 암호화 적용 검토 |
| 인증 | 조직 계정/SSO 개념을 단순화해 JWT + MFA + 짧은 TTL로 구현 |
| 회의 접근통제 | 랜덤 회의 ID, 비밀번호, 대기실, host 승인, 화면공유 권한 |
| 세션 관리 | 토큰 회전, idle timeout, 회의 종료 시 세션 폐기 |
| 데이터 보호 | 참가자 정보/회의 링크/로그 마스킹, 녹화 파일 암호화 및 보존기간 제한 |
| 보안 평가 | STRIDE 체크리스트와 OWASP ZAP baseline scan 결과 비교 |

### 5.2 검증 시나리오

| 시나리오 | 확인할 점 |
|---|---|
| 무단 참가자가 회의 링크만 알고 접근 | 비밀번호/대기실/host 승인으로 차단되는가 |
| 참가자 강퇴 후 미디어 수신 시도 | 새 키/epoch로 갱신되어 복호화가 실패하는가 |
| SFU 또는 서버가 미디어를 관찰 | 평문 미디어에 접근하지 못하는가 |
| 토큰 탈취 후 재사용 | 짧은 TTL, 세션 폐기, 토큰 회전으로 막히는가 |
| 녹화/채팅/파일 공유 | E2EE 적용 여부와 보존/마스킹 정책이 명확한가 |
| ZAP baseline scan | OWASP Top 10 관련 경고가 줄어드는가 |

## 6. 참고자료

1. E. Rescorla, "Security Considerations for WebRTC", RFC 8826, 2021. https://www.rfc-editor.org/rfc/rfc8826.html
2. E. Rescorla, "WebRTC Security Architecture", RFC 8827, 2021. https://www.rfc-editor.org/rfc/rfc8827.html
3. Ben Feher et al., "The Security of WebRTC", arXiv:1601.00184, 2016. https://arxiv.org/abs/1601.00184
4. Jitsi, "End-to-End Encryption Whitepaper", 2021. https://jitsi.org/e2ee-whitepaper/
5. Jitsi, "Security & Privacy". https://jitsi.org/security/
6. E. Omara et al., "Secure Frame (SFrame): Lightweight Authenticated Encryption for Real-Time Media", RFC 9605, 2024. https://www.rfc-editor.org/rfc/rfc9605
7. R. Barnes et al., "The Messaging Layer Security (MLS) Protocol", RFC 9420, 2023. https://www.rfc-editor.org/rfc/rfc9420.html
8. Yevgeniy Dodis et al., "End-to-End Encrypted Zoom Meetings: Proving Security and Strengthening Liveness", IACR ePrint 2023/1829, 2023. https://eprint.iacr.org/2023/1829
9. Zoom, "Zoom Cryptography Whitepaper". https://github.com/zoom/zoom-e2e-whitepaper
10. Federal Trade Commission, "FTC Requires Zoom to Enhance its Security Practices as Part of Settlement", 2020. https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement
11. Yeongjae Park et al., "End-to-End Post-Quantum Cryptography Encryption Protocol for Video Conferencing System Based on Government Public Key Infrastructure", Applied System Innovation, 2023. https://doi.org/10.3390/asi6040066
12. Tan Yang, "Achieve Fully Decentralized End to End Encryption Meeting via Blockchain", arXiv:2208.07604, 2022. https://arxiv.org/abs/2208.07604
13. 김경재, "WebRTC 기반의 온라인 원격 화상 강의 시스템 연구", 동국대학교 학위논문, 2023. DBpia: https://www.dbpia.co.kr/journal/detail?nodeId=T16816377
14. 이관희, 김지인, 권구락, "WebRTC를 이용한 현장 적응형 다자간 원격협업 시스템 개발", 스마트미디어저널, 10(4), 9-14, 2021. DBpia/KCI: https://www.dbpia.co.kr/journal/articleDetail?nodeId=NODE11322998
15. 이경민, 조진용, 공정욱, "WebRTC VC응용의 접근성 및 편의성 향상기술 구현", 한국정보통신학회논문지, 20(8), 1478-1486, 2016. RISS: https://m.riss.kr/search/detail/DetailView.do?control_no=d74fc61446ea50f8c85d2949c297615a&p_mat_type=1a0202e37d52c72d
16. CISA, "Video Conferencing Guidance", 2020. https://www.cisa.gov/resources-tools/resources/video-conferencing-guidance
