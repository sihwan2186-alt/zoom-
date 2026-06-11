# Jitsi Meet 모의공격 실습 절차 및 결과 문서

- 작성일: 2026-05-26
- 대상: 본인 PC 또는 본인이 소유/허가받은 로컬 Jitsi Meet 실습 환경
- 금지 대상: `meet.jit.si`, `alpha.jitsi.net`, 학교/회사/타인 서비스, 허가받지 않은 공인 IP

## 1. 실습 목적

이 실습은 Jitsi Meet 프로그램을 직접 실행한 뒤, 허가된 로컬 환경에서 웹 보안 진단과 화상회의 특화 위협 점검을 수행하는 절차를 정리한다. 목표는 실제 공격 행위를 외부 서비스에 수행하는 것이 아니라, 로컬 테스트베드에서 어떤 취약점이 발견되는지 확인하고 보고서에 재현 절차, 증거, 영향, 대응 방안을 남기는 것이다.

## 2. 실습 범위와 안전 기준

| 항목 | 기준 |
| --- | --- |
| 허용 범위 | `https://localhost:8443`, `https://127.0.0.1:8443`, 본인 VM의 사설 IP |
| 허용 도구 | 브라우저 개발자도구, OWASP ZAP, Nmap, curl/PowerShell 요청, `npm audit`, Docker 로그 |
| Active Scan | 외부 네트워크와 분리된 로컬 Jitsi 인스턴스에서만 수행 |
| 금지 | 공개 Jitsi 서버, 학교/회사 서비스, 타인 서버, 무차별 대입, 대량 트래픽, 서비스 중단 유발 |
| 증거 관리 | URL, 토큰, 회의방 이름, IP, 사용자명은 보고서에 마스킹 |

## 2.1 영문 용어 빠른 해설

Jitsi Meet과 보안 도구 문서에는 영어 용어가 많이 나온다. 아래 표를 먼저 보고 실습하면 각 단계가 무엇을 하는지 이해하기 쉽다.

| 영문 용어 | 한글 뜻 | 실습에서 보는 위치 |
| --- | --- | --- |
| Self-hosted | 직접 운영하는 서버 | Docker로 내 PC/VM에 Jitsi Meet을 띄우는 방식 |
| Web UI | 웹 화면 | 브라우저로 접속하는 Jitsi Meet 화면 |
| XMPP | 신호 전달 프로토콜 | 참가자 입장, 회의방 상태, 메시지 같은 제어 정보를 주고받는 통신 |
| Jicofo | 회의 제어 구성요소 | 누가 회의에 들어오고 어떤 미디어 경로를 쓸지 조율 |
| Jitsi Videobridge | 미디어 라우터 | 음성·영상 데이터를 참가자에게 전달하는 핵심 서버 |
| Baseline Scan | 기준선 진단 | ZAP이 비교적 안전하게 응답을 살펴보는 기본 점검 |
| Active Scan | 능동 진단 | 공격 페이로드를 보내 취약점을 확인하는 점검. 로컬 실습 대상에만 사용 |
| Header | 응답 헤더 | 서버가 브라우저에게 보내는 보안 정책 정보 |
| CSP | 콘텐츠 보안 정책 | 허용할 스크립트, 이미지, 프레임 출처를 제한하는 브라우저 보안 정책 |
| ICE Candidate | WebRTC 연결 후보 | 화상회의 연결을 위해 브라우저가 수집하는 IP/포트 후보 |
| TURN Relay | 미디어 중계 | 직접 연결 대신 중계 서버를 거쳐 IP 노출을 줄이는 방식 |
| Lobby | 대기실 | 게스트가 바로 들어오지 못하고 호스트 승인을 기다리는 기능 |

## 3. 현재 로컬 저장소 사전 점검 결과

현재 작업 폴더의 `jitsi-meet` 소스는 전체 배포 서버가 아니라 Jitsi Meet 웹 프론트엔드 소스다. 전체 회의 기능을 테스트하려면 웹 UI, XMPP 서버, Jicofo, Jitsi Videobridge가 함께 있는 self-hosted 구성이 필요하다.

| 확인 항목 | 결과 | 의미 |
| --- | --- | --- |
| `jitsi-meet/package.json` 엔진 | Node `>=24.0.0`, npm `>=11.0.0` | 현재 PC Node가 낮으면 `npm install` 또는 `make dev` 전에 Node 업그레이드 필요 |
| 현재 PC Node/npm | Node `v20.20.1`, npm `11.11.0` | npm은 충족하지만 Node는 부족 |
| `node_modules` | 없음 | `npm install` 전 상태 |
| 개발 서버 방식 | `npm start` -> `make dev` -> webpack dev server | 기본 실행 URL은 `https://localhost:8080/` |
| 개발 서버 기본 백엔드 | `alpha.jitsi.net` 프록시 | 모의공격 대상이 외부로 흘러갈 수 있으므로 Active Scan 대상 부적합 |

따라서 공격 실습에는 `make dev` 방식보다 Docker 기반 full self-hosted Jitsi Meet 인스턴스를 권장한다.

## 4. 실행 방식 선택

### 선택 1: Docker 기반 full Jitsi Meet 실행 권장

공식 Docker self-hosting 방식은 Jitsi Meet 구성요소를 컨테이너로 실행한다. 실습 대상이 독립적으로 구성되므로 ZAP/Nmap/권한 점검에 적합하다.

1. WSL2 Ubuntu 또는 Linux VM을 준비한다.
1. Docker와 Docker Compose를 설치하고 실행한다.
1. 공식 `docker-jitsi-meet` 최신 릴리스 zip을 내려받아 압축을 푼다.
1. `.env` 파일을 만든다.

```bash
cp env.example .env
```

1. 내부 계정 비밀번호를 생성한다.

```bash
./gen-passwords.sh
```

1. 설정 디렉터리를 만든다.

```bash
mkdir -p ~/.jitsi-meet-cfg/{web,transcripts,prosody/config,prosody/prosody-plugins-custom,jicofo,jvb,jigasi,jibri}
```

1. 로컬 실습용 `.env`에서 최소 항목을 확인한다.

```env
HTTP_PORT=8000
HTTPS_PORT=8443
PUBLIC_URL=https://localhost:8443
ENABLE_AUTH=1
AUTH_TYPE=internal
ENABLE_GUESTS=1
ENABLE_LOBBY=1
ENABLE_HTTP_REDIRECT=1
```

1. 컨테이너를 실행한다.

```bash
docker compose up -d
docker compose ps
```

1. 관리자/호스트 계정을 만든다.

```bash
docker compose exec prosody /bin/bash
prosodyctl --config /config/prosody.cfg.lua register hostuser meet.jitsi StrongLabPassword1!
exit
```

1. 브라우저에서 접속한다.

```text
https://localhost:8443/
```

브라우저가 자체 서명 인증서 경고를 보여도 로컬 실습에서는 계속 진행할 수 있다. 단, 운영 환경에서는 신뢰된 TLS 인증서를 사용해야 한다.

### 선택 2: 현재 저장소의 Jitsi Meet 프론트엔드 개발 서버 실행

이 방식은 UI 개발 확인에 적합하지만, 기본 프록시가 외부 백엔드(`alpha.jitsi.net`)를 향하므로 공격 실습의 주 대상이 되면 안 된다. 정적 리소스, 보안 헤더, 의존성, UI 흐름 점검에만 사용한다.

1. Node 24 이상을 설치한다.
1. Windows에서는 WSL2 또는 Linux 기반 환경을 사용한다.
1. `jitsi-meet` 폴더에서 의존성을 설치한다.

```bash
cd jitsi-meet
npm install
```

1. 개발 서버를 실행한다.

```bash
make dev
```

1. 접속한다.

```text
https://localhost:8080/
```

1. 외부 백엔드로 요청이 나가지 않게 하려면 full local Jitsi 서버를 먼저 띄운 뒤 아래처럼 프록시 대상을 로컬 서버로 바꾼다.

```bash
export WEBPACK_DEV_SERVER_PROXY_TARGET=https://localhost:8443
make dev
```

## 5. 모의공격 실습 절차

### 5.1 기준 상태 기록

```bash
docker compose ps
docker compose logs --tail=100 web
docker compose logs --tail=100 prosody
docker compose logs --tail=100 jicofo
docker compose logs --tail=100 jvb
```

보고서에는 실행 중인 컨테이너, 접속 URL, 실습 일시, 브라우저 종류, Docker 네트워크 범위를 기록한다.

### 5.2 포트 노출 점검

로컬 또는 사설 IP만 대상으로 실행한다.

```bash
nmap -sV -Pn -p 80,443,8000,8443 localhost
nmap -sU -Pn -p 10000 localhost
```

확인할 내용:

- HTTP/HTTPS 포트가 의도한 포트만 열려 있는가?
- UDP `10000` 포트가 Jitsi Videobridge 미디어 경로로 열려 있는가?
- 외부 인터페이스 `0.0.0.0`에 불필요하게 바인딩되어 있지 않은가?

### 5.3 HTTP 응답 헤더 점검

```bash
curl -k -I https://localhost:8443/
```

확인할 헤더:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options` 또는 CSP `frame-ancestors`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Resource-Policy`
- `Cache-Control`
- `Server`

보고서에는 누락 헤더와 실제 응답 값을 그대로 붙이되, 민감한 쿠키나 토큰은 제거한다.

### 5.4 OWASP ZAP Baseline Scan

Baseline Scan은 수동 진단 위주라 첫 번째 실습에 적합하다.

```bash
mkdir -p reports/jitsi-lab
docker run --rm \
  -v "$(pwd)/reports/jitsi-lab:/zap/wrk/:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t https://host.docker.internal:8443/ \
  -m 5 \
  -J jitsi-zap-report.json \
  -r jitsi-zap-report.html \
  -w jitsi-zap-report.md \
  -I
```

Linux에서 Docker 컨테이너가 `host.docker.internal`을 해석하지 못하면 대상 URL을 VM 사설 IP로 바꾼다.

### 5.5 OWASP ZAP Active Scan

Active Scan은 실제 공격 페이로드를 전송하므로 반드시 로컬 격리 환경에서만 수행한다. 서비스 중단 위험을 줄이기 위해 실습 전 스냅샷 또는 컨테이너 재생성 절차를 준비한다.

```bash
docker run --rm \
  -v "$(pwd)/reports/jitsi-lab:/zap/wrk/:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py \
  -t https://host.docker.internal:8443/ \
  -m 5 \
  -J jitsi-zap-active-report.json \
  -r jitsi-zap-active-report.html \
  -w jitsi-zap-active-report.md \
  -I
```

### 5.6 인증 및 회의방 접근통제 점검

1. 비로그인 브라우저에서 새 회의방 생성을 시도한다.
1. 로그인한 호스트가 회의방을 만든 뒤, 다른 비로그인 브라우저로 같은 회의방 URL에 접근한다.
1. `ENABLE_GUESTS=1`인 경우 게스트가 호스트 입장 전 대기 상태인지 확인한다.
1. `ENABLE_LOBBY=1`인 경우 호스트 승인 없이 입장 가능한지 확인한다.
1. 예측 가능한 회의방 이름으로 접근을 시도한다.

예시 회의방 이름:

```text
test
meeting
team1
classroom
security
```

취약 판단 기준:

- 인증 없이 회의방 생성 가능
- 호스트 승인 없이 게스트 즉시 입장 가능
- 짧고 예측 가능한 회의방 이름으로 기존 회의에 접근 가능
- 호스트 권한이 일반 참가자에게 노출됨

### 5.7 회의 링크와 Referrer 노출 점검

1. 회의방 URL을 복사한다.
1. 회의 화면에서 외부 링크, 아바타, 문서 공유, 화이트보드, 채팅 링크 클릭을 테스트한다.
1. 브라우저 개발자도구 Network 탭에서 외부 요청의 `Referer` 값을 확인한다.
1. 회의방 이름, JWT, 토큰, 사용자명이 URL이나 로그에 남는지 확인한다.

### 5.8 WebRTC IP 노출 점검

1. 두 개의 브라우저 또는 두 장치로 같은 회의에 접속한다.
1. Chrome/Edge에서 `chrome://webrtc-internals`를 연다.
1. ICE candidate 항목에서 `host`, `srflx`, `relay` 후보를 확인한다.
1. 사설 IP 또는 공인 IP가 직접 노출되는지 기록한다.

취약 판단 기준:

- 고프라이버시 환경인데 P2P가 켜져 직접 IP 후보가 노출됨
- TURN relay만 사용해야 하는 정책인데 `host` 또는 `srflx` 후보가 상대에게 보임

완화 방향:

- 고프라이버시 회의는 P2P 비활성화
- TURN relay 강제
- 회의방 생성 시 개인정보 보호 옵션 명시

### 5.9 의존성 취약점 점검

프론트엔드 소스 폴더에서 실행한다.

```bash
cd jitsi-meet
npm audit --omit=dev
npm audit
```

보고서에는 패키지명, 심각도, CVE/GHSA, 영향 범위, 업데이트 가능 여부를 기록한다. `npm audit fix --force`는 의존성 변경 폭이 크므로 실습 보고서 작성 단계에서는 실행하지 않는다.

### 5.10 설정 파일 점검

점검 대상:

- `.env`
- `~/.jitsi-meet-cfg/web/config.js`
- `~/.jitsi-meet-cfg/web/interface_config.js`
- `prosody` 사용자 계정
- Docker Compose 포트 매핑

확인할 내용:

- 기본 비밀번호 또는 약한 비밀번호 사용 여부
- `ENABLE_AUTH`, `ENABLE_GUESTS`, `ENABLE_LOBBY` 설정
- HTTP -> HTTPS 리다이렉트 여부
- Web UI 포트가 외부 전체 인터페이스에 노출되는지 여부
- 로깅에 회의방 이름, IP, 사용자명, 토큰이 남는지 여부

## 6. 실습 결과 문서 작성 양식

아래 양식을 그대로 사용해 최종 보고서를 작성한다.

```markdown
# Jitsi Meet 보안 모의공격 실습 결과

## 1. 실습 개요

- 일시:
- 실습자:
- 대상 URL:
- 대상 버전/이미지:
- 실행 방식: Docker self-hosted / webpack dev server
- 사용 도구: OWASP ZAP, Nmap, curl, 브라우저 개발자도구, npm audit
- 허가 범위: 로컬 PC 또는 본인 VM

## 2. 실행 환경

| 항목 | 값 |
| --- | --- |
| OS |  |
| Docker |  |
| Node/npm |  |
| Jitsi 접속 URL |  |
| 열려 있는 포트 |  |
| 인증 설정 |  |
| 로비 설정 |  |

## 3. 수행 절차

1. Docker 기반 Jitsi Meet 실행
1. 포트 노출 점검
1. HTTP 보안 헤더 점검
1. ZAP Baseline Scan
1. ZAP Active Scan
1. 인증/회의방 접근통제 점검
1. WebRTC IP 노출 점검
1. 의존성 취약점 점검
1. 설정 파일 검토

## 4. 발견 취약점 요약

| ID | 취약점 | 심각도 | 근거 | 영향 | 대응 방안 |
| --- | --- | --- | --- | --- | --- |
| F-01 |  |  |  |  |  |

## 5. 상세 발견 내용

### F-01. 취약점 제목

- 분류:
- 심각도:
- 발견 도구:
- 재현 절차:
- 증거:
- 영향:
- 대응 방안:
- 재검증 결과:

## 6. 결론

이번 실습에서 Jitsi Meet은 화상회의 특성상 회의방 링크, 인증/게스트 정책, WebRTC ICE 후보, HTTP 보안 헤더, 외부 연동 설정이 핵심 점검 지점으로 확인되었다. STRIDE 위협 모델링은 설계·운영 정책 위험을 정리하는 데 유용했고, ZAP/Nmap은 실제 실행 환경의 노출과 웹 보안 설정 문제를 확인하는 데 유용했다.
```

## 7. 보고서에 바로 넣을 수 있는 발견 항목 예시

아래 항목은 실습에서 확인되면 그대로 최종 보고서에 옮겨 적을 수 있는 문장이다. 실제 제출 전에는 각 항목의 증거 URL, 헤더, 스크린샷, 도구 로그를 붙여야 한다.

| ID | 발견 항목 | 심각도 | 보고서 서술 예시 |
| --- | --- | --- | --- |
| F-01 | 개발 서버가 외부 백엔드로 프록시됨 | 중간 | 현재 소스의 webpack dev server는 기본 백엔드가 `alpha.jitsi.net`으로 설정되어 있어, 로컬 개발 서버를 대상으로 Active Scan을 수행하면 요청이 외부 서비스로 전달될 가능성이 있다. 따라서 공격 실습에는 full local self-hosted 인스턴스를 사용해야 한다. |
| F-02 | 인증 없는 회의방 생성 가능 | 높음 | 인증이 비활성화된 기본 설정에서는 비로그인 사용자가 회의방을 생성하거나 기존 회의방 URL로 접근할 수 있다. 공개 환경에서는 무단 회의 참여와 회의 링크 유출 위험이 커지므로 `ENABLE_AUTH=1`, 강한 호스트 계정, 로비 기능을 적용해야 한다. |
| F-03 | 예측 가능한 회의방 이름 | 중간 | `test`, `meeting`, `team1`처럼 짧고 추측 가능한 회의방 이름은 외부 사용자가 우연히 접근할 가능성을 높인다. 회의방 이름은 충분히 긴 난수 또는 초대 토큰과 함께 사용하고, 로비/비밀번호를 적용해야 한다. |
| F-04 | 보안 헤더 누락 또는 약한 CSP | 중간 | ZAP 진단 결과 CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Cross-Origin 계열 헤더가 누락되거나 약하게 설정된 경우 브라우저 기반 공격면이 증가한다. 웹 컨테이너 또는 리버스 프록시에서 보안 헤더를 명시해야 한다. |
| F-05 | HTTP 또는 자체 서명 인증서 사용 | 중간 | 로컬 실습에서는 자체 서명 인증서를 허용할 수 있으나 운영 환경에서 신뢰되지 않은 인증서나 HTTP 접속을 허용하면 사용자 신뢰와 전송 보안에 문제가 생긴다. 운영 환경에서는 신뢰된 TLS 인증서와 HTTP -> HTTPS 리다이렉트를 적용해야 한다. |
| F-06 | Web UI 포트 전체 인터페이스 노출 | 중간 | Docker 포트가 기본값대로 전체 인터페이스에 바인딩되면 같은 네트워크의 다른 사용자가 실습 서버에 접근할 수 있다. 로컬 실습은 `127.0.0.1` 바인딩 또는 방화벽으로 제한해야 한다. |
| F-07 | WebRTC ICE 후보를 통한 IP 노출 | 중간 | WebRTC 연결 과정에서 `host` 또는 `srflx` ICE 후보가 노출되면 참가자의 사설/공인 IP와 네트워크 정보가 상대에게 보일 수 있다. 고프라이버시 회의에서는 P2P를 끄고 TURN relay 정책을 적용한다. |
| F-08 | 의존성 취약점 | 중간 | `npm audit`에서 취약한 패키지가 확인되면 프론트엔드 공급망 위험이 존재한다. 패키지명, 심각도, 패치 버전을 정리하고 Jitsi 프로젝트의 고정 의존성 정책을 고려해 신중하게 업데이트한다. |
| F-09 | 로그 내 민감정보 | 낮음 | Docker 로그 또는 웹 서버 로그에 회의방 이름, 사용자명, IP, 토큰이 남으면 보고서/운영 로그 유출 시 개인정보 노출로 이어질 수 있다. 로그 보존기간과 마스킹 정책을 적용해야 한다. |
| F-10 | E2EE 보호 범위 오해 | 중간 | 미디어 E2EE가 활성화되어도 채팅, 녹화, 자막, 파일 공유, 외부 연동이 동일하게 보호된다고 볼 수 없다. 보고서에는 기능별 보호 범위를 분리해 명시해야 한다. |

## 8. 최종 제출 전 체크리스트

| 확인 | 항목 |
| --- | --- |
| [ ] | 공격 대상 URL이 로컬 또는 본인 VM인지 확인 |
| [ ] | `meet.jit.si`, `alpha.jitsi.net` 등 외부 서비스에 Active Scan을 하지 않았는지 확인 |
| [ ] | ZAP HTML/Markdown/JSON 보고서 저장 |
| [ ] | Nmap 포트 결과 저장 |
| [ ] | HTTP 헤더 원문 저장 |
| [ ] | 인증/게스트/로비 테스트 스크린샷 저장 |
| [ ] | WebRTC ICE 후보 노출 여부 기록 |
| [ ] | `npm audit` 결과 저장 |
| [ ] | 발견 항목별 영향과 대응 방안 작성 |
| [ ] | 토큰, 회의방 이름, IP, 사용자명 마스킹 |

## 9. 참고 자료

- [Jitsi Meet Docker self-hosting guide](https://jitsi.github.io/handbook/docs/devops-guide/devops-guide-docker/)
- [Jitsi Meet web development guide](https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-web-jitsi-meet/)
- Jitsi Meet security reporting: `jitsi-meet/SECURITY.md`
- [OWASP ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [OWASP Top 10](https://owasp.org/Top10/)
