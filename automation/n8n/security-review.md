# n8n 실행 기준 보안 리뷰

이 문서는 `automation/n8n` 구성을 실제 n8n에서 실행했을 때 기대되는 보안 요소와 남는 취약점을 정리한다.

## 실행 시 탐지하는 취약 징후

`mediasoup-security-monitor.workflow.json`은 다음 입력 신호를 위험도 점수로 변환한다.

| 신호 | 위험 해석 | 기본 판정 기준 |
| --- | --- | ---: |
| `iceFailed` | WebRTC ICE 연결 실패 증가, 네트워크 이상 또는 DoS 징후 | 3 이상 |
| `dtlsFailed` | DTLS handshake 실패, 암호화 협상 오류 또는 공격 시도 | 1 이상 |
| `producerCount` | 비정상 미디어 송출 증가, SFU 자원 고갈 가능성 | 10 이상 |
| `consumerCount` | 과도한 consumer fanout, 대규모 부하 또는 DoS 가능성 | 80 이상 |
| `zapAlerts` | ZAP이 관찰한 보안 설정 오류 | 4 이상 |
| `publicIpCandidateObserved` | ICE candidate 기반 IP 노출 가능성 | `true` |
| `unauthorizedJoinAttempts` | 회의방 무단 접근 또는 인증 실패 반복 | 2 이상 |
| `timestamp` | 이벤트 재전송 또는 지연 수집 가능성 | 10분 초과 |

샘플 payload는 high severity에 여러 위험 신호가 함께 있으므로 `action-required`로 분류된다.

Docker 없이 같은 판정 로직을 확인하려면 다음 명령을 실행한다.

```powershell
python .\automation\n8n\simulate_security_monitor.py
```

## 현재 들어간 보안 요소

| 영역 | 보안 요소 | 효과 |
| --- | --- | --- |
| 네트워크 노출 | `127.0.0.1:5678` 바인딩 | 로컬 실험 중 외부 직접 접근 차단 |
| Webhook 인증 | `X-Video-Security-Token` 헤더 검사 | 임의 사용자의 가짜 이벤트 제출 완화 |
| 인증 실패 응답 | `401 rejected` 응답 분기 | 잘못된 요청을 scoring 단계와 분리 |
| 입력 정규화 | 문자열 길이 제한, 숫자 범위 제한 | 과대 payload와 비정상 타입으로 인한 workflow 오작동 완화 |
| 응답 최소화 | 원본 요청 전체 반환 제거 | token/header/body 민감정보 반사 노출 완화 |
| n8n API | public API와 Swagger UI 비활성화 | 자동화 플랫폼 관리면 축소 |
| 노드 제한 | executeCommand, SSH, Git, XML, localFileTrigger 제외 | 고위험 노드를 통한 파일 접근/RCE 위험 축소 |
| 코드 실행 제한 | 외부 모듈 import 차단, task runner 비활성화 | Code node 공격면 축소 |
| 데이터 보관 | 성공 실행 데이터 미저장, 7일 prune | 민감 이벤트 장기 보관 위험 완화 |
| 공급망 | community nodes 비활성화 | 검증되지 않은 노드 설치 위험 축소 |

## 남아 있는 취약점

| 위험 | 심각도 | 설명 | 보완 방향 |
| --- | --- | --- | --- |
| 기본 토큰 사용 | 높음 | workflow import 직후 `change-me-before-demo`가 그대로 남아 있으면 누구나 추측 가능 | `Score Alert` 노드에서 개인 토큰으로 교체 |
| HMAC 서명 부재 | 중간 | 단순 shared token은 payload 변조 여부를 증명하지 못함 | timestamp + body 기반 HMAC 검증 추가 |
| replay 방지 미완성 | 중간 | timestamp freshness는 점수화만 하며 중복 이벤트 저장소가 없음 | Redis/Postgres 또는 n8n Data Store로 nonce 저장 |
| TLS 부재 | 중간 | compose는 localhost HTTP 실험용임 | 외부 공개 시 reverse proxy TLS와 webhook 전용 도메인 적용 |
| rate limit 부재 | 중간 | localhost를 벗어나면 반복 POST로 workflow 실행량을 늘릴 수 있음 | reverse proxy rate limit, IP allowlist |
| workflow 편집자 신뢰 문제 | 높음 | n8n 편집 권한자가 Code node 로직을 바꾸면 우회 가능 | owner/editor 권한 분리, workflow export 감사 |
| 실제 파일 분석 부재 | 낮음 | `zapAlerts` 숫자를 신뢰하고 실제 ZAP JSON을 파싱하지 않음 | HTTP/File/SIEM 연동으로 보고서 원본 검증 |

## 논문에 넣기 좋은 한 문장

현재 n8n 실험 구성은 Webhook 기반 실시간 보안 이벤트 수집과 위험도 자동 판정 가능성을 보이기 위한 로컬 데모이며, 기본적으로 localhost 바인딩, 고위험 노드 제외, 실행 데이터 최소 보관, header token 검사를 적용하였다. 다만 운영 환경 수준의 보안을 위해서는 HMAC 서명, replay 방지 저장소, TLS reverse proxy, rate limit, workflow 편집 권한 분리가 추가로 필요하다.
