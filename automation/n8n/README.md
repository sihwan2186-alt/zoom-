# n8n Mediasoup Security Monitor

이 폴더는 Mediasoup/Jitsi/자체 WebRTC 화상회의 보안 이벤트를 n8n으로 받아 위험도를 계산하는 간단한 실험 구성을 담고 있다.

## 포함 파일

- `docker-compose.yml`: 로컬 n8n 실행용 hardened compose
- `.env.example`: n8n encryption key 예시
- `mediasoup-security-monitor.workflow.json`: n8n import용 workflow
- `sample-alert.json`: 테스트용 보안 이벤트 payload

## 실행

1. `.env.example`을 `.env`로 복사하고 `N8N_ENCRYPTION_KEY`를 긴 랜덤 문자열로 바꾼다.
2. Docker가 설치된 환경에서 다음을 실행한다.

```powershell
cd .\automation\n8n
docker compose up -d
```

1. 브라우저에서 `http://127.0.0.1:5678`에 접속해 초기 계정을 만든다.
2. n8n UI에서 `mediasoup-security-monitor.workflow.json`을 import한다.
3. `Score Alert` 노드의 `WEBHOOK_SHARED_TOKEN` 값을 실험용 기본값에서 개인 토큰으로 바꾼다.
4. workflow를 활성화한다.

## 테스트

workflow가 활성화된 뒤 저장소 루트에서 다음 요청을 보낸다.

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:5678/webhook/mediasoup-security-alert" `
  -Headers @{ "X-Video-Security-Token" = "change-me-before-demo" } `
  -ContentType "application/json" `
  -InFile ".\automation\n8n\sample-alert.json"
```

예상 결과는 `action-required` 또는 `logged` JSON 응답이다. `sample-alert.json`은 high severity와 ICE/DTLS 실패, public IP candidate 관찰, 무단 참가 시도 신호를 포함하므로 `action-required`로 분류된다.

인증 헤더가 없거나 잘못되면 workflow는 이벤트를 분석하지 않고 `401 rejected`로 응답한다.

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:5678/webhook/mediasoup-security-alert" `
  -ContentType "application/json" `
  -InFile ".\automation\n8n\sample-alert.json"
```

Docker 없이 scoring 결과만 확인하려면 저장소 루트에서 다음을 실행한다.

```powershell
python .\automation\n8n\simulate_security_monitor.py
```

## 보안 주의

- 이 compose는 로컬 실험용으로 `127.0.0.1:5678`에만 노출한다.
- 외부 접속이 필요하면 nginx/caddy/traefik 같은 reverse proxy에서 TLS를 종료한다.
- workflow는 `X-Video-Security-Token` 헤더를 검사한다. 실험 후 기본값 `change-me-before-demo`를 반드시 바꾼다.
- n8n은 자동화 도구이지만 Code/Git/XML/Form/HTTP Request 계열 취약점 이력이 있으므로 workflow 편집 권한을 신뢰된 사용자로 제한한다.
- 응답에는 원본 요청 전체를 되돌려주지 않고, 길이 제한이 적용된 필드와 위험도 결과만 포함한다.
- 실제 운영에서는 Slack/email/SIEM 발송 노드를 추가할 수 있지만, credential 저장과 execution data 보관 기간을 별도로 검토해야 한다.
