# 실행 증거: 보안 헤더 적용 서버 응답 및 포트 확인

- 캡처 일시: 2026-06-01 12:52 KST
- 대상: 로컬 실습용 화상회의 웹 클라이언트
- 서버: `화상회의/zoom-/client/secure_static_server.py`
- URL: `http://127.0.0.1:18112/`
- 비고: 현재 환경에서 `nmap` 명령은 발견되지 않아, HTTP 응답 헤더와 PowerShell TCP 연결 확인으로 실행 증거를 남겼다.

## 실행 명령

```powershell
python .\secure_static_server.py --host 127.0.0.1 --port 18112
Invoke-WebRequest -Uri "http://127.0.0.1:18112/" -Method Head -UseBasicParsing
Test-NetConnection -ComputerName 127.0.0.1 -Port 18112
Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 18112 -State Listen
```

## 응답 결과

```text
STATUS=200 OK

Cache-Control: no-store
Content-Length: 8965
Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; frame-src https://meet.jit.si; connect-src 'self' https://meet.jit.si wss://meet.jit.si; img-src 'self' data: https://meet.jit.si; style-src 'self'; script-src 'self'; form-action 'self'
Content-Type: text/html
Cross-Origin-Embedder-Policy: credentialless
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Date: Mon, 01 Jun 2026 03:52:21 GMT
Last-Modified: Thu, 21 May 2026 07:44:24 GMT
Permissions-Policy: camera=(self "https://meet.jit.si"), microphone=(self "https://meet.jit.si"), fullscreen=(self "https://meet.jit.si"), display-capture=(self "https://meet.jit.si"), geolocation=(), payment=(), usb=()
Pragma: no-cache
Referrer-Policy: no-referrer
Server: SecureMeetLab
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

## 포트 확인 결과

```text
ComputerName     : 127.0.0.1
RemoteAddress    : 127.0.0.1
RemotePort       : 18112
TcpTestSucceeded : True

LocalAddress  : 127.0.0.1
LocalPort     : 18112
State         : Listen
```

## 서버 접근 로그

```text
127.0.0.1 - - [01/Jun/2026 12:52:21] "HEAD / HTTP/1.1" 200 -
```

## 해석

보안 헤더 적용 서버는 CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin 계열 정책과 캐시 제어 헤더를 반환하였다. 포트 확인 결과 로컬 서버가 `127.0.0.1:18112`에서 정상적으로 수신 중이었고, HEAD 요청에 200 OK로 응답하였다. 이 증거는 ZAP 재스캔에서 헤더 누락 계열 경고가 감소한 실행 환경 근거로 사용할 수 있다.
