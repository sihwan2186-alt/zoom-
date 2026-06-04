# Jitsi Meet 전체 검증 보고서

- 검증일: 2026-06-03
- 대상: Docker 기반 Jitsi Meet 자체 호스팅 실험 환경
- 사용 릴리스: `jitsi/docker-jitsi-meet stable-10978`
- 범위: Jitsi Meet 웹, Prosody, Jicofo, JVB, JWT/내부 인증, ICE/TURN 후보, Jibri 녹화 구성

## 1. 핵심 결론

Jitsi Meet는 자체 호스팅 기준으로 회의 생성, 브라우저 기반 WebRTC 접속, 내부 인증, JWT 인증, JVB 기반 미디어 라우팅, Jibri 녹화 인프라까지 구성 가능한 완성도 높은 화상회의 플랫폼이다. 특히 Docker 배포판은 `web`, `prosody`, `jicofo`, `jvb`, `jibri`를 분리해 운영할 수 있어 구조 분석과 보안 점검에 적합했다.

다만 기본 또는 최소 설정 상태에서는 다음 보안 이슈가 뚜렷했다.

| 영역 | 확인 결과 | 영향 |
| --- | --- | --- |
| 인증 | 내부 인증은 호스트 도착 전 게스트 대기를 정상 수행 | 공개 회의 생성 통제에 효과 있음 |
| 게스트 입장 | 호스트가 방을 만든 뒤에는 게스트가 바로 입장 가능 | 엄격한 승인제 회의에는 추가 로비/정책 필요 |
| JWT | 토큰 보유자는 방 생성 가능, 토큰 없는 사용자는 호스트 전 대기 | `ENABLE_GUESTS=1`이면 방 생성 후 익명 입장 가능 |
| 권한 | JWT 인증 성공과 관리자 권한은 항상 동일하지 않음 | 녹화/보안 메뉴 권한 검증 필요 |
| WebRTC | TURN relay 없이 host ICE 후보만 관찰 | 사설 IP/인터페이스 정보 노출 가능 |
| 웹 보안 헤더 | CSP, Anti-clickjacking, Referrer-Policy, COOP/COEP 미흡 | 브라우저 방어층 보강 필요 |
| 포트 | `80/443` 역할의 웹 포트와 `10000/udp` 미디어 포트 필요 | 방화벽/노출면 관리가 핵심 |
| Jibri | 컨테이너 기동 및 health OK, Jicofo에서 available 감지 | 실제 녹화 시작 전 recorder 도메인/권한 추가 검증 필요 |

## 2. 실험 환경

Docker Compose로 Jitsi Meet를 실행했다. 웹은 `8000/tcp`, `8443/tcp`, 미디어는 `10000/udp`에 노출되었고, Jicofo REST와 JVB Colibri는 로컬호스트에만 바인딩되었다.

| 구성요소 | 이미지 | 역할 | 관찰 포트 |
| --- | --- | --- | --- |
| web | `jitsi/web:stable-10978` | nginx 기반 웹 UI | `8000/tcp`, `8443/tcp` |
| prosody | `jitsi/prosody:stable-10978` | XMPP signaling | 컨테이너 네트워크 내부 |
| jicofo | `jitsi/jicofo:stable-10978` | 회의 focus, 인증/권한 조정 | `127.0.0.1:8888` |
| jvb | `jitsi/jvb:stable-10978` | 미디어 라우터 | `10000/udp`, `127.0.0.1:8080` |
| jibri | `jitsi/jibri:stable-10978` | 녹화/스트리밍 | 외부 포트 미노출 |

공식 Docker 가이드는 외부 방화벽에서 웹 UI용 `80/tcp`, `443/tcp`, RTP 미디어용 `10000/udp`를 열도록 설명한다. 이 구조 때문에 실제 운영에서는 `10000/udp`의 노출 범위, NAT, TURN fallback, 모니터링이 중요하다.

## 3. 기능과 효과

| 기능 | 효과 | 검증 결과 |
| --- | --- | --- |
| 브라우저 회의 | 별도 클라이언트 설치 없이 회의 접속 | Chromium Playwright로 입장 확인 |
| 내부 인증 | 방 개설자를 등록 계정으로 제한 | 게스트는 호스트 전까지 대기 |
| 게스트 도메인 | 참여자는 계정 없이 입장 가능 | 호스트 입장 후 게스트 입장 확인 |
| JWT 인증 | 외부 서비스가 방/사용자 권한을 토큰으로 전달 | 유효 JWT 사용자가 방 생성 |
| JVB 미디어 라우팅 | 다자 회의에서 SFU 구조로 대역폭 제어 | JVB 동작 및 `10000/udp` 확인 |
| 로비 | 참여 승인 흐름 제공 | 기능은 감지되나 기본 자동 강제는 아님 |
| Jibri | 서버 측 녹화/스트리밍 기반 | health OK, 실제 녹화 시작은 추가 구성 필요 |

Jitsi Meet의 장점은 개방형 구조다. XMPP signaling, Jicofo 회의 제어, JVB 미디어 라우팅, Jibri 녹화 인프라가 분리되어 있어 보안 경계와 운영 책임을 나눠 분석하기 좋다. 반대로 이 분리 구조 때문에 운영자는 각 컴포넌트의 인증, 인증서, 포트, 로그, 저장소 정책을 모두 맞춰야 한다.

## 4. 보안 점검 결과

### 4.1 웹 헤더와 ZAP

`https://localhost:8443/` 응답에서 HSTS와 `X-Content-Type-Options: nosniff`는 확인되었다. 그러나 ZAP Baseline에서는 다음 경고가 남았다.

| ZAP 경고 | 의미 |
| --- | --- |
| Missing Anti-clickjacking Header | `X-Frame-Options` 또는 CSP `frame-ancestors` 필요 |
| CSP Header Not Set | 스크립트/리소스 로딩 정책 부재 |
| Strict-Transport-Security Header Not Set | 일부 정적 자산 응답에서 HSTS 누락 |
| X-Content-Type-Options Header Missing | 일부 정적 자산에서 MIME sniffing 방어 누락 |
| Permissions Policy Header Not Set | 브라우저 기능 사용 제한 정책 미흡 |
| Cross-Domain Misconfiguration | CORS/교차 도메인 정책 점검 필요 |
| COEP Header Missing or Invalid | cross-origin isolation 미흡 |

또한 `http://localhost:8000/`은 HTTPS로 리다이렉트되었지만 `Location: https://localhost/`로 내려와, 비표준 HTTPS 포트 `8443`을 쓰는 실험 환경에서는 잘못된 포트로 안내될 수 있었다. 실제 운영에서는 `PUBLIC_URL`, reverse proxy, `X-Forwarded-*` 헤더, 표준 443 사용 여부를 함께 맞춰야 한다.

### 4.2 포트와 노출면

Nmap 결과 `8000/tcp`, `8443/tcp`는 nginx 웹으로 열려 있었고 `10000/udp`는 JVB 미디어 포트로 `open|filtered` 상태였다. Jicofo `8888/tcp`와 JVB `8080/tcp`는 `127.0.0.1`에만 바인딩되어 외부 노출은 줄어 있었다.

운영 권장 사항은 다음과 같다.

| 항목 | 권장 |
| --- | --- |
| 웹 | 표준 443 뒤에 reverse proxy 배치, HTTP는 HTTPS 리다이렉트만 |
| JVB UDP | 필요한 IP 범위만 허용, DDoS/대역폭 모니터링 적용 |
| 관리 API | `127.0.0.1` 또는 내부망에만 바인딩 |
| 인증서 | 자체 서명 대신 공개/사설 CA 신뢰 체인 사용 |
| 헤더 | CSP, frame-ancestors, Referrer-Policy, COOP/COEP 검토 |

## 5. 인증, 로비, JWT

### 5.1 내부 인증

내부 인증 모드에서 등록된 호스트 계정이 없는 상태로 게스트가 방에 접근하면 "호스트를 기다리는 중" 상태가 표시되었다. 이는 공개 사용자가 임의로 방을 생성하는 것을 막는 데 효과가 있다.

하지만 호스트가 먼저 방을 만들면 게스트는 같은 방에 바로 들어갈 수 있었다. `ENABLE_LOBBY=1`만으로 모든 방이 자동 승인제 로비가 되는 것은 아니므로, 민감한 회의는 다음을 추가로 검토해야 한다.

| 목적 | 설정/운영 방향 |
| --- | --- |
| 모든 참석자 승인 | persistent lobby 또는 방 생성 시 로비 자동 활성화 |
| 게스트 완전 차단 | 게스트 도메인 비활성화 |
| 호스트만 방 생성 | secure domain 또는 JWT 방 생성 정책 유지 |
| 참여자 권한 제한 | moderator checks, JWT feature claims, Prosody 권한 검증 |

### 5.2 JWT

JWT 모드에서 유효 토큰 사용자는 방을 생성할 수 있었다. 토큰이 없는 사용자는 호스트가 오기 전에는 대기했지만, JWT 사용자가 방을 만든 뒤에는 게스트로 입장할 수 있었다. 이는 공식 토큰 인증 문서의 "유효 토큰으로 방을 만들고, 방 생성 후 anonymous domain 사용자가 입장 가능" 구조와 일치한다.

엄격한 보안 환경에서는 `ENABLE_GUESTS=1`을 유지할지 먼저 결정해야 한다. 내부 포털과 연동하는 경우에는 다음 정책이 필요하다.

| 요구사항 | 권장 정책 |
| --- | --- |
| 토큰 없는 입장 금지 | 게스트 도메인 비활성화 또는 empty token 불허 |
| 방별 접근 제한 | JWT `room` claim을 와일드카드 대신 특정 방으로 제한 |
| 기능별 권한 | `context.features.recording`, `livestreaming`, `transcription` 등 명시 |
| 관리자 권한 보장 | Jicofo 로그와 UI 권한을 함께 확인 |
| 토큰 탈취 대응 | 짧은 만료, issuer/audience 제한, HTTPS 강제 |

실험 중 JWT가 `token=true`로 인증되었음에도 한 방에서는 Jicofo 로그상 역할이 `PARTICIPANT`로 기록되었다. 따라서 "토큰 검증 성공"을 "관리자 권한 보장"으로 바로 해석하면 안 된다. 녹화, 로비, 강제 음소거, 회의 종료 같은 관리자 기능은 별도 테스트 케이스로 확인해야 한다.

## 6. ICE/TURN 및 개인정보

브라우저에서 `RTCPeerConnection` 후보를 수집한 결과, 관찰된 ICE candidate type은 `host`뿐이었다. `relay` 후보는 관찰되지 않았고, 로컬/사설 인터페이스 주소가 후보에 포함되었다.

이는 로컬 실험 환경의 자연스러운 결과지만, 실제 운영에서는 개인정보와 네트워크 정보 노출 이슈가 될 수 있다.

| 위험 | 설명 | 대응 |
| --- | --- | --- |
| 사설 IP 노출 | 브라우저 ICE 후보에 내부 주소가 포함될 수 있음 | TURN relay 강제, P2P 비활성화 검토 |
| NAT 실패 | UDP 10000 차단 환경에서 연결 품질 저하 | coturn/TURN 443 배치 |
| P2P 우회 | 2인 회의에서 JVB를 우회할 수 있음 | 민감 환경은 P2P 비활성화 |
| 로그 민감정보 | IP, 방 이름, 참가자 식별자가 로그에 남음 | 보존 기간/마스킹 정책 수립 |

## 7. Jibri 녹화 검증

Jibri 컨테이너는 정상 기동되었고 health API는 다음 상태를 반환했다.

```json
{
  "busyStatus": "IDLE",
  "healthStatus": "HEALTHY"
}
```

Jicofo 로그에서도 `jibribrewery@internal-muc.meet.jitsi`에 Jibri instance가 추가되고 available 상태로 감지되었다. 컨테이너 보안 관점에서는 다음 특성이 확인되었다.

| 항목 | 결과 | 의미 |
| --- | --- | --- |
| `cap_add` | `CAP_SYS_ADMIN` | Chrome/X11/녹화 구동 때문에 권한 상승 면이 큼 |
| `shm_size` | 2 GiB | 녹화 안정성을 위해 공유 메모리 필요 |
| 외부 포트 | 없음 | Jibri API는 외부 노출되지 않음 |
| idle 메모리 | 약 175 MiB | 실제 녹화 시 CPU/메모리/디스크 증가 예상 |
| 인증서 | trust-all 설정 사용 | 실험용이며 운영에서는 금지해야 함 |

다만 실제 파일 녹화 시작까지 완료되었다고 보기는 어렵다. 이유는 다음과 같다.

1. Prosody 로그에 `recorder.meet.jitsi` 등록 시 `No such host`가 남았다.
2. 웹 설정에는 `hiddenDomain = recorder.meet.jitsi`와 `recordingService.enabled = true`가 생성되었다.
3. Jicofo는 Jibri를 available로 감지했다.
4. Playwright UI에서는 녹화 메뉴가 노출되지 않았고 녹화 시작 요청도 Jibri 로그에 남지 않았다.

공식 Jibri 문서는 recorder virtual host, Jibri control 계정, recorder 계정, Jicofo brewery, Jitsi Meet web recording 설정이 모두 맞아야 한다고 설명한다. 따라서 다음 단계는 recorder VirtualHost가 실제 Prosody 설정에 생성되도록 구성 디렉터리를 재생성하거나 템플릿 변수를 재검토하고, JWT 사용자가 OWNER/Moderator로 확정되는 조건에서 녹화 버튼과 녹화 파일 생성까지 다시 검증하는 것이다.

## 8. 주요 문제점

| 우선순위 | 문제 | 근거 | 대응 |
| ---: | --- | --- | --- |
| 1 | 게스트 입장 정책이 느슨할 수 있음 | 호스트 입장 후 게스트 바로 입장 | 게스트 비활성화, persistent lobby |
| 2 | JWT와 관리자 권한이 혼동될 수 있음 | token=true지만 PARTICIPANT 로그 관찰 | 권한별 테스트와 moderator 정책 명시 |
| 3 | TURN relay 미사용 | host ICE 후보만 관찰 | coturn 구성, P2P 비활성화 검토 |
| 4 | 웹 보안 헤더 미흡 | ZAP 경고 14종 | CSP/frame/referrer/COOP/COEP 보강 |
| 5 | Jibri 운영 부담 | `CAP_SYS_ADMIN`, 2 GiB shm, Chrome/ffmpeg | 전용 노드, 최소 권한, 저장소 암호화 |
| 6 | recorder 도메인 불완전 | Prosody `No such host` | recorder VirtualHost와 계정 재검증 |
| 7 | HTTP 리다이렉트 포트 오류 | `https://localhost/`로 이동 | `PUBLIC_URL`/proxy 설정 정합성 확보 |

## 9. 추가 연구 과제

| 과제 | 목적 | 산출물 |
| --- | --- | --- |
| recorder VirtualHost 수정 후 녹화 end-to-end | Jibri 실제 녹화 파일 생성 확인 | 녹화 파일, Jibri/Jicofo 로그 |
| coturn 구성 및 relay 강제 | 사설 IP 노출과 NAT 실패 완화 | ICE candidate 비교표 |
| persistent lobby 자동화 | 승인제 회의 보안성 검증 | 게스트 대기/승인 시나리오 |
| CSP 정책 설계 | XSS/클릭재킹 방어 강화 | CSP 초안, ZAP 재스캔 |
| 부하 테스트 | 인원 증가 시 JVB/Jicofo 리소스 측정 | CPU/메모리/대역폭 그래프 |
| 로그/개인정보 정책 | 방 이름, IP, 참가자 정보 보호 | 로그 보존/마스킹 기준 |
| 모바일 클라이언트 검증 | 브라우저와 앱 차이 확인 | Android/iOS 접속 결과 |

## 10. 증적 파일

세부 실행 결과는 로컬 증적 폴더에 저장했다.

| 파일 | 내용 |
| --- | --- |
| `reports/jitsi-lab/jitsi-zap-report.md` | ZAP Baseline 요약 |
| `reports/jitsi-lab/jitsi-zap-report.json` | ZAP JSON 결과 |
| `reports/jitsi-lab/jitsi-auth-page.json` | 내부 인증 초기 화면 |
| `reports/jitsi-lab/jitsi-host-login-result.json` | 호스트 로그인 결과 |
| `reports/jitsi-lab/jitsi-two-party-result.json` | 호스트/게스트 동시 입장 결과 |
| `reports/jitsi-lab/jitsi-ice-candidates.json` | ICE 후보 수집 결과 |
| `reports/jitsi-lab/jitsi-jwt-result.json` | JWT/무토큰 입장 비교 |
| `reports/jitsi-lab/jitsi-jibri-recording-toolbar.json` | Jibri UI 녹화 제어 확인 |
| `reports/evidence/jitsi_meet_full_validation_2026-06-03.md` | 핵심 명령 결과 요약 |

## 11. 참고 자료

- [Jitsi Docker self-hosting guide](https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-docker/)
- [Jitsi token authentication guide](https://jitsi.github.io/handbook/docs/devops-guide/token-authentication/)
- [Jitsi configuration reference, recording](https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-configuration/#recording)
- [Jitsi architecture](https://jitsi.github.io/handbook/docs/architecture/)
- [Jibri project documentation](https://github.com/jitsi/jibri)
