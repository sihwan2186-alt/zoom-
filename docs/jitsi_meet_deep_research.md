# Jitsi Meet 기능, 효과, 문제점 심층 조사

- 작성일: 2026-06-03
- 목적: 화상회의 프로그램 중 Jitsi Meet의 기능, 기대 효과, 한계와 보안 문제를 연구 보고서에 바로 활용할 수 있도록 정리한다.
- 범위: Jitsi Meet 웹/모바일 사용 경험, self-hosted 배포, Jitsi 구성요소, 보안·개인정보·운영 관점
- 실제 Docker lab 검증 결과: `docs/jitsi_meet_full_validation_report.md`

## 1. 핵심 요약

Jitsi Meet는 WebRTC 기반 오픈소스 화상회의 플랫폼이다. 사용자는 브라우저 또는 모바일 앱으로 회의에 참여하고, 운영자는 공개 서비스인 `meet.jit.si`를 이용하거나 Docker/Debian 패키지로 직접 서버를 운영할 수 있다. 공식 문서는 Jitsi Meet를 웹 UI, XMPP 신호 서버인 Prosody, 회의 제어 구성요소인 Jicofo, 미디어 라우터인 Jitsi Videobridge, 녹화/송출 구성요소인 Jibri 등 여러 프로젝트의 결합으로 설명한다.

기능 측면에서는 음성·영상 회의, 화면 공유, 채팅, 참가자 관리, 로비, 녹화, 라이브 스트리밍, 소회의실, 화이트보드, IFrame API 기반 임베드, JWT 인증 연동, E2EE 옵션을 제공한다. 효과 측면에서는 오픈소스 기반의 투명성, 자체 호스팅에 따른 데이터 통제, 비교적 빠른 구축, 외부 서비스 의존도 감소, 교육·소규모 조직·공공기관 실습에 적합하다는 장점이 있다.

다만 Jitsi Meet의 장점은 설정이 올바르게 되었을 때 크게 나타난다. 공개 회의방 이름 노출, 인증 없는 회의 생성, 로비와 권한 설정 미흡, JWT 설정 오류, TLS/방화벽/NAT 구성 문제, Jibri 녹화 리소스 부담, 대규모 회의 확장 난이도, E2EE 지원 범위와 사용자 인식 문제는 연구에서 반드시 문제점으로 다루어야 한다.

## 2. 연구 질문

| 구분 | 연구 질문 |
| --- | --- |
| 기능 | Jitsi Meet는 일반 화상회의 기능과 보안 기능을 어느 범위까지 제공하는가? |
| 효과 | 자체 호스팅 가능한 오픈소스 화상회의가 비용, 데이터 통제, 접근성, 확장성 측면에서 어떤 효과를 주는가? |
| 문제점 | 공개 회의방, 인증, 미디어 라우팅, E2EE, 운영 설정, 녹화 저장, 취약점 관리에서 어떤 위험이 남는가? |
| 실증 | 로컬 self-hosted Jitsi Meet 환경에서 기능과 보안 문제를 어떤 방법으로 검증할 수 있는가? |

## 3. Jitsi Meet 구조

Jitsi Meet는 단일 프로그램이라기보다 여러 구성요소가 함께 동작하는 화상회의 스택이다.

| 구성요소 | 역할 | 연구 관점 |
| --- | --- | --- |
| Jitsi Meet Web UI | 브라우저에서 실행되는 React 기반 회의 화면 | 사용자 기능, 보안 헤더, CSP, 임베드 정책, UI 권한 |
| Prosody | XMPP 기반 신호 서버 | 회의방 생성, 참가자 상태, 인증, 토큰 검증 |
| Jicofo | 회의 제어 및 포커스 컴포넌트 | 회의 생성, 참가자와 미디어 세션 조정, Videobridge 선택 |
| Jitsi Videobridge | WebRTC 미디어 라우터 | 오디오·비디오 패킷 전달, SFU 확장성, UDP 10000 포트 |
| Jibri | 녹화 및 스트리밍 | 녹화 리소스, 저장소, 개인정보, 운영 비용 |
| Jigasi | SIP 게이트웨이 | 전화망 연동, 별도 포트와 인증 관리 |

공식 Docker self-hosting 문서는 외부 방화벽에서 `80/tcp`, `443/tcp`, `10000/udp`를 열어야 한다고 설명한다. 이 중 `10000/udp`는 Jitsi Videobridge의 RTP 미디어 전송에 해당하므로, 운영 환경에서는 방화벽, NAT, TURN relay, 네트워크 품질이 회의 품질과 보안에 직접 영향을 준다.

## 4. 주요 기능 분석

### 4.1 회의 생성과 참여

Jitsi Meet의 기본 사용 방식은 회의 이름을 만들고 링크를 공유하는 구조다. 별도 회원가입 없이도 빠르게 회의를 시작할 수 있다는 점은 접근성의 장점이다. 그러나 회의방 이름이 사실상 접근 경로가 되므로, 단순한 이름이나 공개 SNS에 노출된 링크는 원치 않는 참가자 유입으로 이어질 수 있다.

연구에서는 회의 생성 기능을 단순 편의 기능으로만 보지 말고, 회의방 이름이 인증 토큰과 유사한 민감 정보처럼 작동한다는 점을 함께 다루어야 한다.

### 4.2 음성·영상 회의와 화면 공유

Jitsi Meet는 WebRTC를 통해 브라우저에서 음성·영상 통신을 제공한다. 1대1 회의에서는 P2P 모드가 사용될 수 있고, 다자 회의에서는 Jitsi Videobridge가 SFU 방식으로 미디어를 라우팅한다. SFU 방식은 모든 참가자의 영상을 서버가 하나의 합성 영상으로 인코딩하는 MCU 방식보다 서버 CPU 부담을 줄일 수 있다. 대신 참가자 수가 늘면 네트워크 송수신량과 클라이언트 디코딩 부담이 커지므로, 화질·대역폭·참가자 수의 균형이 중요하다.

### 4.3 참가자 관리와 회의 통제

Jitsi Meet는 음소거, 강제 퇴장, 권한 부여, 로비, 참가자 패널, 모더레이터 기능을 제공한다. IFrame API 명령에는 원격 참가자 음소거, 참가자 강퇴, 모더레이터 권한 부여, 로비 모드 전환, 소회의실 생성 같은 기능이 포함된다.

다만 공개 `meet.jit.si`와 자체 구축 환경의 권한 모델은 다르게 이해해야 한다. 공식 보안 안내는 공개 서비스에서 모든 사용자가 모더레이터가 되는 상황을 설명하며, 강한 모더레이션이 필요하면 자체 배포와 인증 설정을 권장한다. 따라서 보안 연구에서는 공개 서비스 사용과 self-hosted 운영을 분리해서 분석해야 한다.

### 4.4 로비, 인증, JWT

Jitsi Meet는 인증된 사용자만 회의방을 만들고, 익명 사용자는 게스트로 참여하도록 구성할 수 있다. 공식 토큰 인증 문서는 유효한 토큰을 가진 사용자만 새 회의방을 만들게 하고, 이후 익명 도메인의 사용자가 참여할 수 있는 구성을 설명한다. 또한 `persistent_lobby`, `muc_wait_for_host`, `token_verification` 같은 Prosody 모듈을 통해 로비와 호스트 대기 정책을 구성할 수 있다.

연구 관점에서 JWT 인증은 핵심 보안 주제다. 토큰에는 사용자, 회의방, 역할, 만료 시간, 발급자, 대상 도메인 같은 정보가 들어갈 수 있으므로 토큰이 회의방과 역할에 제대로 바인딩되지 않으면 권한 상승이나 무단 회의 생성 위험이 생긴다.

### 4.5 녹화, 라이브 스트리밍, 전사

Jibri는 Jitsi Meet 회의를 녹화하거나 스트리밍하기 위한 구성요소다. 공식 요구사항 문서는 Jibri 한 인스턴스가 한 회의 녹화에 대응하며, 녹화는 영상 인코딩 때문에 일반 Jitsi Meet 서버보다 RAM, CPU, 디스크 요구가 크다고 설명한다. 따라서 녹화 기능은 단순 부가기능이 아니라 운영 비용과 개인정보 리스크를 함께 키우는 기능이다.

보고서에서는 녹화 기능을 다음 세 가지 관점으로 다루면 좋다.

| 관점 | 확인할 내용 |
| --- | --- |
| 성능 | 동시 녹화 수, Jibri 인스턴스 수, CPU/RAM/디스크 사용량 |
| 개인정보 | 녹화 고지, 저장 위치, 보존기간, 접근 권한 |
| 보안 | 녹화 파일 URL 노출, 클라우드 저장 연동, 로그와 메타데이터 |

### 4.6 소회의실, 화이트보드, 채팅, 설문

Jitsi Meet는 소회의실, 그룹 채팅, 개인 채팅, 설문, 화이트보드 등 협업 기능을 제공한다. 이 기능들은 교육과 회의 생산성을 높이지만, 보안 분석에서는 별도 데이터 흐름으로 보아야 한다. 예를 들어 채팅과 설문은 XMPP 메시지나 애플리케이션 상태로 전달되며, 화이트보드는 외부 협업 도구와 연동될 수 있다. 기능이 많을수록 취약점 표면도 함께 넓어진다.

실제로 Jitsi Meet GitHub 보안 권고에는 2022년 설문 투표 조작 문제가 포함되어 있다. 이는 설문 기능이 단순 UI 요소가 아니라 신원, 메시지, 상태 검증과 연결된 보안 대상임을 보여준다.

### 4.7 IFrame API와 서비스 임베드

Jitsi Meet의 IFrame API는 외부 웹 서비스에 회의 기능을 삽입할 수 있게 한다. `roomName`, `jwt`, `userInfo`, `configOverwrite`, `interfaceConfigOverwrite`, 장치 설정, 이벤트, 명령을 통해 서비스에 맞게 회의를 제어할 수 있다.

이 기능은 LMS, 상담 시스템, 사내 포털과 결합하기 쉽다는 장점이 있지만 다음 위험도 갖는다.

| 위험 | 설명 |
| --- | --- |
| 프레임 정책 | CSP `frame-ancestors`, `X-Frame-Options` 설정이 부적절하면 클릭재킹 위험이 생길 수 있음 |
| JWT 전달 | 임베드 페이지가 토큰을 안전하게 발급·보관하지 않으면 회의 권한 탈취 가능 |
| 출처 혼합 | 외부 스크립트, 이미지, 캘린더, 파일 공유 연동이 개인정보 흐름을 넓힘 |
| 권한 오남용 | API 명령으로 녹화, 강퇴, 권한 부여 같은 기능을 제어하므로 호출 권한 관리 필요 |

### 4.8 E2EE

Jitsi Meet는 브라우저의 Insertable Streams를 이용한 E2EE 옵션을 제공한다. 공식 보안 문서는 Chromium 기반 브라우저와 Electron 클라이언트에서 E2EE를 사용할 수 있다고 설명한다. 다만 기본 WebRTC 전송 암호화와 E2EE는 구분해야 한다. 다자 회의에서 일반 DTLS-SRTP 전송 암호화는 네트워크 구간을 보호하지만, Jitsi Videobridge가 미디어 라우팅을 위해 패킷을 처리한다. E2EE를 켜면 추가 암호화 계층이 적용되어 Videobridge가 내용을 볼 수 없게 하는 것이 목표다.

문제는 사용자 인식이다. E2EE가 꺼져 있어도 "암호화된 화상회의"라고 단순 표현하면 오해가 생길 수 있다. GitHub 보안 권고에는 지원되지 않는 클라이언트에서 E2EE 음성 안내가 잘못 재생되어 사용자가 E2EE가 켜졌다고 오해할 수 있는 문제가 있었다. 따라서 연구에서는 "전송 구간 암호화", "서버 라우팅", "종단 간 암호화"를 분리해서 설명해야 한다.

## 5. 기대 효과

| 효과 | 설명 | 근거로 삼을 수 있는 관찰 지표 |
| --- | --- | --- |
| 접근성 향상 | 브라우저 링크 중심 회의로 설치 부담 감소 | 회의 시작 절차, 게스트 참여 가능 여부 |
| 데이터 통제 | 자체 서버 운영 시 회의 데이터와 로그를 조직이 통제 | self-hosted 구성, 로그/녹화 저장 위치 |
| 비용 절감 가능성 | 라이선스 비용 없이 오픈소스 기반 운영 가능 | 서버 비용, 운영 인력, 동시 사용자 수 |
| 확장성 | Jitsi Videobridge를 수평 확장할 수 있음 | JVB 수, CPU, 네트워크, 참가자 수 |
| 통합성 | IFrame API와 SDK로 기존 서비스에 삽입 가능 | LMS/포털 연동, JWT 인증 흐름 |
| 보안 학습 효과 | WebRTC, XMPP, JWT, CSP, STRIDE, ZAP 실습에 적합 | 로컬 Docker 실습, ZAP/Nmap/헤더 분석 결과 |

효과를 과장하지 않으려면 "무료라서 무조건 저비용"이라고 쓰기보다, 라이선스 비용은 줄일 수 있지만 서버·대역폭·운영·보안 업데이트·녹화 인프라 비용은 남는다고 정리하는 편이 정확하다.

## 6. 주요 문제점

### 6.1 공개 회의방과 링크 노출

회의방 URL은 참가 권한처럼 동작한다. 짧고 흔한 회의방 이름을 사용하거나 공개 채널에 링크를 올리면 원치 않는 사용자가 들어올 수 있다. 공식 보안 문서는 회의 이름을 민감 정보로 보고 보호해야 한다고 안내한다.

대응 방안:

| 문제 | 대응 |
| --- | --- |
| 단순 회의방 이름 | 자동 생성된 긴 회의 이름 사용 |
| 공개 링크 노출 | 회의 링크 재사용 제한, 초대 대상 제한 |
| 무단 참가 | 로비, 비밀번호, 인증, 호스트 승인 |
| 회의 중 방해 | 모더레이터 권한 제한, 강퇴 로그, 신고 절차 |

### 6.2 공개 서비스와 self-hosted의 보안 차이

`meet.jit.si`는 빠른 회의에는 편리하지만 조직 내부 회의의 세밀한 권한 통제에는 한계가 있다. 강한 인증, 제한된 모더레이터, 내부 로그 정책, 회의방 생성 제한이 필요하면 self-hosted 환경이 더 적합하다. 반대로 self-hosted 환경은 운영자가 TLS, 방화벽, 업데이트, 인증, 로그, 녹화 저장소를 직접 책임져야 한다.

### 6.3 E2EE의 범위와 오해

Jitsi Meet는 기본적으로 WebRTC 전송 암호화를 사용하지만, 다자 회의의 일반 구성에서는 Videobridge가 미디어 라우팅을 수행한다. E2EE는 추가로 켤 수 있는 기능이며 브라우저 지원과 설정 상태에 따라 달라진다. 따라서 "Jitsi는 무조건 E2EE"라고 쓰면 부정확하다.

보고서 표현 예시:

```text
Jitsi Meet는 WebRTC 기반 전송 암호화를 제공하며, 지원 브라우저에서는 E2EE 옵션을 사용할 수 있다. 다만 다자 회의의 일반 SFU 구조에서는 Jitsi Videobridge가 미디어 라우팅을 수행하므로, E2EE 활성화 여부와 클라이언트 지원 여부를 별도로 확인해야 한다.
```

### 6.4 인증과 JWT 설정 오류

JWT 인증은 강력하지만 설정 오류가 발생하면 위험이 커진다. 예를 들어 토큰 만료 시간이 길거나, 회의방 이름과 역할이 토큰에 정확히 묶이지 않거나, 발급 서버의 비밀키가 노출되면 공격자가 다른 회의방을 만들거나 모더레이터 권한을 얻을 수 있다.

점검 항목:

| 항목 | 확인 방법 |
| --- | --- |
| `exp` 만료 시간 | 짧은 유효기간과 재발급 정책 확인 |
| `room` 클레임 | 특정 회의방에만 유효한지 확인 |
| 역할 클레임 | 모더레이터와 일반 참가자 분리 확인 |
| 발급자/대상 | `iss`, `aud`, `sub` 검증 |
| 비밀키 관리 | `.env`, 로그, 클라이언트 노출 여부 확인 |

### 6.5 네트워크와 방화벽 구성 문제

Jitsi Meet 운영은 웹 서버만 여는 일반 웹앱보다 까다롭다. HTTPS가 필요하고, Jitsi Videobridge의 UDP 미디어 포트가 열려야 하며, NAT 환경에서는 `PUBLIC_URL`, `JVB_ADVERTISE_IPS`, TURN relay 구성이 중요하다. 공식 self-hosting 개요도 WebRTC 기반 서비스는 HTTPS가 필요하고, 사설망·자체 서명 인증서·모바일 클라이언트에서 문제가 생길 수 있다고 설명한다.

대표 문제:

| 문제 | 영향 |
| --- | --- |
| 자체 서명 인증서 | 모바일 앱이나 브라우저에서 접속 실패 가능 |
| UDP 10000 차단 | 영상·음성 연결 불량 또는 TURN 의존 증가 |
| 잘못된 공개 URL | 초대 링크, WebSocket, 미디어 연결 오류 |
| 모든 인터페이스 포트 공개 | 의도하지 않은 외부 접근 가능 |
| TURN 미구성 | 엄격한 NAT 환경에서 연결 실패 |

### 6.6 녹화와 저장소 리스크

녹화는 회의 내용을 장기 보관 가능한 데이터로 바꾼다. Jibri는 한 녹화당 높은 리소스를 요구하며, 녹화 파일은 개인정보와 업무정보를 포함할 수 있다. 따라서 연구에서는 녹화 성공 여부만 확인하지 말고 보존기간, 접근 권한, 파일명, 다운로드 링크, 클라우드 연동, 삭제 절차를 함께 봐야 한다.

### 6.7 확장성과 품질의 운영 난이도

Jitsi Videobridge는 SFU 방식으로 확장성을 확보하지만, 대규모 운영은 초보 관리자에게 쉽지 않다. 공식 scalable setup 문서도 수평 확장이 가능하다고 설명하면서, 여러 Videobridge를 구성하고 디버깅할 수 있는 Linux 운영 역량이 필요하다고 안내한다. 실제 품질은 서버 위치, 참가자 네트워크, CPU, 업로드 대역폭, UDP 연결성, 브라우저 성능에 좌우된다.

### 6.8 취약점 관리

Jitsi Meet는 오픈소스이므로 보안 권고와 릴리스를 지속적으로 추적해야 한다. GitHub 보안 권고 기준으로는 다음 사례가 연구에 직접 사용할 만하다.

| 연도 | 권고 | 영향 | 연구 의미 |
| --- | --- | --- | --- |
| 2025 | DOM Redirect on Microsoft OAuth Flow, CVE-2025-64754 | Microsoft OAuth 인증 창 하이재킹 가능 | 외부 인증 연동은 리디렉션 검증이 중요 |
| 2022 | Poll vote manipulation | 회의 내 설문과 투표 조작 가능 | 협업 기능도 신원·권한 검증 대상 |
| 2022 | Misleading E2EE cues on unsupported clients | E2EE 지원 여부에 대한 사용자 오인 | 보안 상태 표시는 정확해야 함 |

## 7. 실증 연구 설계

기존 STRIDE-ZAP 연구와 연결하되, 이번 확장 연구는 Jitsi Meet 자체만 대상으로 삼는다. 실험은 허가된 로컬 self-hosted 환경에서만 수행한다.

| 단계 | 내용 | 산출물 |
| --- | --- | --- |
| 1 | Docker 기반 Jitsi Meet 구성 | `.env`, 실행 로그, 컨테이너 목록 |
| 2 | 기능 확인 | 회의 생성, 참여, 로비, 인증, 채팅, 화면 공유, 녹화 가능 여부 표 |
| 3 | 네트워크 점검 | `80/tcp`, `443/tcp`, `10000/udp`, TURN 사용 여부 |
| 4 | HTTP 보안 점검 | CSP, HSTS, Referrer-Policy, Permissions-Policy, X-Frame-Options |
| 5 | 인증 점검 | 비로그인 회의 생성 가능 여부, JWT 만료/회의방/역할 검증 |
| 6 | WebRTC 점검 | ICE 후보, P2P 여부, TURN relay 여부, 브라우저 WebRTC 내부 로그 |
| 7 | ZAP Baseline | 웹 UI의 보안 헤더와 설정 오류 |
| 8 | 녹화 점검 | Jibri 리소스, 녹화 파일 저장 위치, 접근 권한 |
| 9 | STRIDE 정리 | Spoofing, Tampering, Repudiation, Information Disclosure, DoS, EoP별 위협 |

## 8. Jitsi Meet 전용 STRIDE 초안

| STRIDE | Jitsi Meet 위협 예시 | 대응 방향 |
| --- | --- | --- |
| Spoofing | 회의방 이름 추측, 가짜 사용자명, 탈취된 JWT로 참여 | 긴 회의방 이름, JWT 검증, 로비, 표시명 정책 |
| Tampering | 설문/채팅 메시지 조작, 임베드 API 명령 오남용 | XMPP 세션 기반 검증, API 호출 권한 제한 |
| Repudiation | 강퇴·권한 변경·녹화 시작 행위 추적 불가 | 관리자 로그, 회의 이벤트 감사 로그 |
| Information Disclosure | 회의 링크, ICE 후보 IP, 녹화 파일, 채팅 내용 노출 | 링크 보호, TURN relay, 로그 마스킹, 보존기간 |
| Denial of Service | 대량 참가, UDP 포트 공격, 녹화 리소스 고갈 | rate limit, 방화벽, 모니터링, Jibri 분리 |
| Elevation of Privilege | 일반 사용자가 모더레이터 권한 획득 | 역할 클레임 검증, 권한 분리, 호스트 인증 |

## 9. 보고서에 넣기 좋은 결론 문장

```text
Jitsi Meet는 오픈소스 기반의 WebRTC 화상회의 플랫폼으로, 브라우저 접근성, 자체 호스팅, API 임베드, 인증 연동, 녹화·스트리밍 등 다양한 기능을 제공한다. 특히 자체 운영 환경에서는 조직이 회의 데이터와 접근 정책을 직접 통제할 수 있어 교육, 연구, 공공기관, 내부 협업 시스템에 활용 가치가 있다.
```

```text
그러나 Jitsi Meet의 보안성은 제품 자체의 존재만으로 보장되지 않는다. 회의방 이름 관리, 로비와 인증 설정, JWT 권한 검증, UDP 미디어 포트와 TLS 구성, E2EE 지원 여부, 녹화 저장소 관리, 지속적인 보안 업데이트가 함께 이루어져야 한다. 따라서 Jitsi Meet 연구는 기능 소개보다 기능이 실제 운영 환경에서 어떤 신뢰 경계와 위험을 만드는지 분석하는 방향으로 진행되어야 한다.
```

## 10. 참고 자료

- Jitsi Meet Handbook, Architecture: <https://jitsi.github.io/handbook/docs/architecture>
- Jitsi Meet Handbook, Docker Self-Hosting Guide: <https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-docker/>
- Jitsi Meet Handbook, Self-Hosting Overview: <https://jitsi.github.io/handbook/docs/devops-guide/>
- Jitsi Meet Handbook, Token Authentication: <https://jitsi.github.io/handbook/docs/devops-guide/token-authentication/>
- Jitsi Meet Handbook, IFrame API: <https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-iframe/>
- Jitsi Meet Handbook, IFrame Commands: <https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-iframe-commands/>
- Jitsi Meet Handbook, Configuration: <https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-configuration/>
- Jitsi Meet Handbook, Requirements: <https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-requirements/>
- Jitsi Meet Security & Privacy: <https://jitsi.org/security/>
- Jitsi E2EE 안내: <https://jitsi.org/e2ee-in-jitsi/>
- Jitsi Videobridge Performance Evaluation: <https://jitsi.org/jitsi-videobridge-performance-evaluation/>
- Jitsi Meet GitHub Security Advisories: <https://github.com/jitsi/jitsi-meet/security/advisories>
