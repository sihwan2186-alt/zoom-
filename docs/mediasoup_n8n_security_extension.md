# Mediasoup-n8n 보안 자동화 확장 검토

- 작성일: 2026-06-02
- 목적: 기존 STRIDE-ZAP 화상회의 보안 연구를 Mediasoup 기반 미디어 서버와 n8n 자동화 보안 관제 실험으로 확장할 수 있는지 확인한다.

## 1. 확인 결과

### Mediasoup

Mediasoup는 WebRTC 화상회의에 사용할 수 있는 SFU(Selective Forwarding Unit) 미디어 서버이다. 공식 문서와 GitHub 저장소 기준으로 다음 내용이 확인된다.

- SFU 구조로 동작하며, 단말이 미디어를 서버에 보내고 서버가 다른 참여자에게 전달한다.
- WebRTC와 plain RTP 입력/출력을 모두 지원한다.
- 서버 측은 Node.js 모듈 또는 Rust crate로 사용할 수 있고, 클라이언트 측 라이브러리를 제공한다.
- signaling protocol은 강제하지 않는다. 즉, 회의방 생성, 사용자 인증, 권한, 토큰 검증, 로깅은 애플리케이션이 직접 설계해야 한다.
- WebRtcTransport는 ICE와 DTLS 절차를 통해 네트워크 경로를 협상하며, DTLS 연결 후 SRTP 키가 추출되는 구조이다.
- GitHub 저장소에서 소스코드를 확인할 수 있고, 2026-06-02 확인 시점의 최신 릴리스는 3.20.1(2026-06-01)이다.

보안 관점에서 Mediasoup 자체는 미디어 계층을 낮은 수준에서 잘 다루는 도구에 가깝다. 다만 minimalist/signaling agnostic 설계 때문에 "보안이 자동으로 완성되는 제품"은 아니다. 회의방 접근제어, moderator 권한, JWT 검증, signaling TLS, audit log, abuse detection, TURN 정책, recording storage 보호는 애플리케이션에서 별도로 구현해야 한다.

### n8n

n8n은 Webhook, HTTP/API, 코드 실행 노드, 400개 이상 통합을 제공하는 workflow automation 플랫폼이다. Mediasoup 또는 Jitsi Meet 같은 화상회의 시스템에서 발생하는 보안 이벤트를 받아 다음 작업을 자동화하기에 적합하다.

- ZAP/STRIDE 결과 수집
- WebRTC transport 상태, ICE 실패, 비정상 producer/consumer 증가 이벤트 수집
- login/session anomaly 이벤트 수집
- 위험도 점수화
- Slack, email, GitHub Issue, SIEM, 로그 저장소 알림

그러나 n8n은 "보안 자동화 도구"인 동시에 공격 표면이 큰 실행 플랫폼이다. 특히 self-hosted n8n은 workflow editor 권한, Code node, Git node, HTTP Request node, XML/Form/Webhook 계열 노드가 공격 지점이 될 수 있다. 따라서 본 연구에서는 n8n을 외부 공개 서비스가 아니라 격리된 보안 자동화 게이트웨이로 두는 것이 적합하다.

## 2. 보안 수준 요약

| 대상 | 보안 수준 판단 | 근거 | 주의점 |
| --- | --- | --- | --- |
| Mediasoup | 미디어 전송 계층은 높음, 전체 서비스 보안은 구현 의존 | WebRTC transport가 ICE/DTLS/SRTP 계층을 사용하고, SFU로 확장성이 좋음 | signaling, 인증, 권한, logging, E2EE는 애플리케이션 책임 |
| n8n | 자동화 성숙도는 높음, self-hosted 보안 위험은 중상 | Webhook/API/코드 실행/통합 기능이 강력하고 운영 자동화에 적합 | 최근 High/Critical advisory가 많아 버전 고정, 접근 제한, 노드 제한이 필수 |

정리하면, Mediasoup는 연구 대상으로 적합하고 n8n 연동도 주제로 타당하다. 단, "Mediasoup 보안성 평가"보다는 "WebRTC 화상회의 서버 보안 이벤트를 자동 수집하고 대응하는 하이브리드 보안 관제 구조"로 잡는 것이 더 설득력 있다.

## 3. n8n 주요 취약점 경향

아래 항목은 2026-06-02에 공식 n8n/GitHub advisory 기준으로 확인한 대표 위험이다.

| 구분 | 영향 | 영향 버전/수정 버전 | 보안 해석 |
| --- | --- | --- | --- |
| Form 기반 workflow 파일 접근 | 일부 Form Submission + Form Ending binary 반환 구성에서 unauthenticated attacker가 파일 시스템 정보에 접근 가능 | 1.65-1.120.4 영향, 1.121.0 이상 수정 | 공개 Form/Webhook workflow는 별도 도메인과 접근 제한 필요 |
| Form Trigger stored XSS, CVE-2025-52478 | 인증 사용자가 악성 HTML을 삽입해 계정 탈취 가능 | >=1.77.0, <1.98.2 영향, 1.98.2 수정 | Form Trigger HTML 입력과 CSP가 중요 |
| Git Node RCE, CVE-2025-65964 | Git custom hook 경로로 host command execution 가능 | >=0.123.1, <1.119.2 영향, 1.119.2 수정 | Git node는 신뢰 사용자에게만 허용하거나 제외 |
| XML Node prototype pollution to RCE, CVE-2026-44791 | workflow 편집 권한 사용자가 XML node 조합으로 RCE 가능 | <1.123.43, <2.22.1, <2.20.7 영향, 해당 버전 이상 수정 | XML node 제외 또는 편집 권한 최소화 |
| HTTP Request Node prototype pollution to RCE | HTTP Request pagination parameter 검증 부족으로 RCE 가능 | <1.123.43, <2.22.1, <2.20.7 영향, 해당 버전 이상 수정 | HTTP Request node는 강력하지만 고위험 노드로 관리 |
| Git Node arbitrary file read | Git push option 조작으로 서버 파일 읽기 가능 | <1.123.43, <2.22.1, <2.20.7 영향, 해당 버전 이상 수정 | secrets, DB, 설정 파일 보호 필요 |
| Python sandbox escape | Python Code Node가 task runner container에서 sandbox escape 가능 | <1.123.48, <2.22.4, <2.21.8 영향, 해당 버전 이상 수정 | Python Task Runner 비활성화 또는 workflow editor 제한 |

## 4. 이번 프로젝트에 도입한 n8n 실험 산출물

다음 파일을 추가했다.

- `automation/n8n/docker-compose.yml`: 로컬에서 n8n을 올리는 hardened lab compose
- `automation/n8n/.env.example`: n8n encryption key 예시
- `automation/n8n/mediasoup-security-monitor.workflow.json`: n8n으로 import 가능한 보안 이벤트 webhook workflow
- `automation/n8n/sample-alert.json`: Mediasoup/ZAP 보안 이벤트 예시 payload
- `automation/n8n/README.md`: 실행, import, 테스트 절차
- `reports/extension/mediasoup_n8n_security_summary.json`: 보안 수준과 권장 조치 요약 데이터

workflow는 실제 Mediasoup 서버를 설치하지 않고도 실험 흐름을 보일 수 있도록 설계했다. Webhook으로 보안 이벤트를 받으면 severity, source, eventType, signals 값을 기준으로 risk score를 계산하고, 위험도가 높으면 containment action을 권고한다.

현재 workflow는 `X-Video-Security-Token` 헤더를 검사하고, 인증 실패 시 `401 rejected`로 응답한다. 또한 원본 요청 전체를 응답에 되돌려주지 않고 필요한 필드만 길이 제한을 적용해 반환하도록 보완했다.

## 5. 권장 n8n hardening

실험 또는 논문용 데모에서 n8n을 사용할 때는 다음 수준을 최소 기준으로 둔다.

- n8n은 `127.0.0.1:5678` 또는 내부망에만 바인딩한다.
- 외부 공개가 필요하면 reverse proxy에서 TLS를 종료하고 n8n editor와 webhook domain을 분리한다.
- 최신 패치 버전을 고정한다. 2026-06-02 기준으로는 2.22.6 이상 사용을 권장한다.
- `N8N_ENCRYPTION_KEY`를 명시하고 별도 secret으로 관리한다.
- community nodes는 비활성화한다.
- Code node의 외부 모듈 import는 기본 차단 상태로 둔다.
- Python Task Runner는 필요한 경우에만 켜고, workflow 편집자는 완전히 신뢰된 사용자로 제한한다.
- Execute Command, SSH, Local File Trigger, Git, XML, Form 관련 노드는 실험 목적이 아니라면 제외한다.
- execution data 보관 기간을 짧게 두고 민감 payload 저장을 피한다.
- workflow import/export 권한을 제한한다.
- n8n 자체도 ZAP/Dependency Scan/버전 감사 대상으로 둔다.
- 운영 환경에서는 단순 shared token을 넘어 timestamp와 body 기반 HMAC 서명, replay 방지 nonce 저장소, reverse proxy rate limit을 추가한다.

## 6. Mediasoup 기반 실시간 보안 시스템 구조

```text
Mediasoup app / Jitsi app / local video lab
  -> auth events, room events, WebRTC transport stats, ZAP results
  -> n8n Webhook
  -> risk scoring and alert normalization
  -> Slack/email/GitHub issue/SIEM/log archive
  -> periodic report for STRIDE-ZAP comparison
```

추천 이벤트 종류는 다음과 같다.

| 이벤트 | 예시 탐지 신호 | 관련 보안 범위 |
| --- | --- | --- |
| transport anomaly | ICE failed 증가, DTLS failed, packet loss 급증 | DoS, network abuse |
| room access anomaly | 단시간 room join 실패, guest escalation 시도 | Broken Access Control, Auth failure |
| media abuse | producer/consumer 수 급증, simulcast layer 요청 이상 | DoS, resource exhaustion |
| privacy signal | public IP candidate 노출, TURN relay 미사용 | Information Disclosure |
| scan result | ZAP A05 경고, CSP/캐시/헤더 문제 | Security Misconfiguration |
| dependency advisory | n8n/mediasoup/Jitsi package advisory | Vulnerable Components |

## 7. 다른 화상회의 프로그램에 적용할 만한 보안 기능

| 보안 기능 | 적용 대상 | 기대 효과 |
| --- | --- | --- |
| 회의방 role claim 검증 | Mediasoup, Jitsi, Janus, 자체 WebRTC 앱 | participant/moderator 권한 혼동 방지 |
| Lobby/prejoin approval | 공개 회의방, 교육용 회의 | 무단 입장과 회의 링크 유출 피해 감소 |
| TURN relay 우선 정책 | 고프라이버시 회의 | ICE candidate 기반 IP 노출 감소 |
| WebRTC transport 상태 모니터링 | SFU 기반 서비스 | DTLS/ICE 실패, DoS 징후 조기 감지 |
| E2EE 또는 SFrame/Insertable Streams 검토 | 민감 회의 | SFU compromise 시 미디어 노출 위험 감소 |
| Recording storage retention policy | 녹화 기능 있는 서비스 | 개인정보 잔류와 사후 유출 위험 감소 |
| 보안 헤더와 CSP | 웹 기반 회의 클라이언트 | XSS, clickjacking, 정보 노출 방어 |
| Webhook/API rate limit | n8n, signaling API, bot API | 자동화 엔드포인트 악용 완화 |
| 감사 로그와 부인 방지 | 관리자 기능, 회의 설정 변경 | 행위 추적성과 사고 분석 강화 |
| 자동 보안 리포트 | 운영/연구 환경 | 반복 검증과 증거 보존 자동화 |

## 8. 논문 반영용 문단

결론 또는 향후 연구에 다음 내용을 반영할 수 있다.

향후 연구에서는 Jitsi Meet뿐 아니라 Mediasoup와 같은 WebRTC SFU 미디어 서버를 대상으로 확장할 수 있다. Mediasoup는 미디어 계층을 낮은 수준의 API로 제공하고 signaling protocol을 강제하지 않기 때문에, 회의방 인증, 권한 검증, WebRTC transport 상태, TURN relay 정책, audit log를 연구자가 직접 모델링하기에 적합하다.

또한 n8n과 같은 workflow automation 도구를 보안 이벤트 수집 계층으로 도입하면 ZAP 재스캔 결과, WebRTC transport anomaly, 회의방 접근 이벤트, 취약 dependency advisory를 webhook으로 수집하고 위험도를 점수화할 수 있다. 다만 n8n 자체도 최근 원격 코드 실행, 파일 읽기, XSS 관련 보안 권고가 다수 공개된 실행 플랫폼이므로, self-hosted 환경에서는 최신 버전 고정, workflow 편집 권한 제한, 고위험 노드 제외, TLS reverse proxy, execution data 보관 제한을 함께 적용해야 한다.

## 9. 참고한 공개 자료

- Mediasoup overview: <https://mediasoup.org/documentation/overview/>
- Mediasoup GitHub repository: <https://github.com/versatica/mediasoup>
- Mediasoup API, WebRtcTransport: <https://mediasoup.org/documentation/v3/mediasoup/api/>
- Mediasoup SRTP parameters: <https://mediasoup.org/documentation/v3/mediasoup/srtp-parameters/>
- n8n GitHub repository: <https://github.com/n8n-io/n8n>
- n8n self-hosted security guidance: <https://docs.n8n.io/privacy-security/what-you-can-do/>
- n8n SSL/reverse proxy guidance: <https://docs.n8n.io/hosting/securing/set-up-ssl/>
- n8n node environment variables: <https://docs.n8n.io/hosting/configuration/environment-variables/nodes/>
- n8n deployment environment variables: <https://docs.n8n.io/hosting/configuration/environment-variables/deployment/>
- n8n isolation guidance: <https://docs.n8n.io/hosting/configuration/configuration-examples/isolation/>
- n8n security advisories: <https://github.com/n8n-io/n8n/security>
- n8n January 2026 security advisory: <https://blog.n8n.io/security-advisory-20260108/>
