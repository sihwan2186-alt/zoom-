# Jitsi Meet 전체 검증 증적

- 실행일: 2026-06-03
- 실험 릴리스: `jitsi/docker-jitsi-meet stable-10978`
- 실행 방식: Docker Compose, Playwright, ZAP Baseline, Nmap Docker image

## 컨테이너 상태

| 서비스 | 상태 | 포트 |
| --- | --- | --- |
| web | Up | `8000/tcp`, `8443/tcp` |
| prosody | Up | 내부 네트워크 |
| jicofo | Up | `127.0.0.1:8888` |
| jvb | Up | `10000/udp`, `127.0.0.1:8080` |
| jibri | Up | 외부 포트 없음 |

## 웹 헤더

`https://localhost:8443/`에서 확인한 주요 헤더:

```text
Server: nginx
Strict-Transport-Security: max-age=63072000
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Permissions-Policy: interest-cohort=()
```

미확인 또는 보강 필요 항목:

```text
Content-Security-Policy
X-Frame-Options 또는 frame-ancestors
Referrer-Policy
Cross-Origin-Opener-Policy
Cross-Origin-Embedder-Policy
```

HTTP 리다이렉트:

```text
http://localhost:8000/ -> 301 Location: https://localhost/
```

비표준 HTTPS 포트 `8443`을 사용하는 실험 환경에서는 리다이렉트 포트 정합성 보정이 필요하다.

## ZAP Baseline

- 대상: `https://host.docker.internal:8443/`
- 결과: `PASS: 53`, `WARN-NEW: 14`, 실패 없음
- 주요 경고:

```text
Missing Anti-clickjacking Header
CSP Header Not Set
Strict-Transport-Security Header Not Set
X-Content-Type-Options Header Missing
Permissions Policy Header Not Set
Cross-Domain Misconfiguration
COEP Header Missing or Invalid
Timestamp Disclosure - Unix
Dangerous JS Functions
```

## Nmap

TCP:

```text
8000/tcp open http nginx
8443/tcp open ssl/http nginx
```

UDP:

```text
10000/udp open|filtered
```

## 인증과 JWT

내부 인증:

```text
게스트 단독 입장: 호스트 대기 화면
호스트 로그인 후: 회의 생성 성공
호스트 존재 시 게스트: 같은 방 입장 성공
```

JWT:

```text
유효 JWT 사용자: 방 생성 성공
토큰 없는 사용자: 호스트 전 대기
호스트 생성 후 토큰 없는 사용자: 입장 가능
Jicofo 로그: token=true 요청 확인
일부 JWT 방에서 role=PARTICIPANT 관찰
```

## ICE 후보

브라우저 수집 결과:

```text
candidate type: host
relay candidate: 관찰되지 않음
private/local interface IP 후보 포함
```

해석:

```text
TURN relay가 강제되지 않는 구성에서는 사설 IP와 네트워크 인터페이스 정보가 노출될 수 있다.
```

## Jibri

Jibri health:

```json
{
  "status": {
    "busyStatus": "IDLE",
    "health": {
      "healthStatus": "HEALTHY",
      "details": {}
    }
  }
}
```

컨테이너 보안 속성:

```text
CapAdd=["CAP_SYS_ADMIN"]
ShmSize=2147483648
Privileged=false
PortBindings={}
```

Jicofo 감지:

```text
JibriDetector ... available = true
```

추가 확인 필요:

```text
Prosody recorder user registration output: Error: No such host: recorder.meet.jitsi
Playwright UI에서 녹화 시작 메뉴 미노출
Jibri 로그에 실제 recording session request 없음
```

## 로컬 증적

상세 원본은 `reports/jitsi-lab/`에 저장되어 있다. 해당 폴더는 도구 산출물로 `.gitignore` 대상이다.
