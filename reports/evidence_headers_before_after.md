# 보안 헤더 적용 전후 증거

이 문서는 로컬 실습용 화상회의 웹 클라이언트에 보안 헤더를 적용하기 전후의 HTTP 응답 헤더를 비교한 증거이다.

## 적용 전 응답 헤더

실행 명령:

```powershell
python -m http.server 18101 --bind 127.0.0.1
curl.exe -s -I http://127.0.0.1:18101/
```

결과 원문: [`evidence/response_headers_before.txt`](../evidence/response_headers_before.txt)

```text
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.3
Content-type: text/html
Content-Length: 8965
```

## 적용 후 응답 헤더

실행 명령:

```powershell
python .\secure_static_server.py --host 127.0.0.1 --port 18102
curl.exe -s -I http://127.0.0.1:18102/
```

결과 원문: [`evidence/response_headers_after.txt`](../evidence/response_headers_after.txt)

```text
HTTP/1.0 200 OK
Server: SecureMeetLab
Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(self "https://meet.jit.si"), microphone=(self "https://meet.jit.si"), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: credentialless
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
Pragma: no-cache
```

## 해석

Python 기본 정적 서버는 `Content-Type`, `Content-Length`, `Last-Modified` 중심의 기본 헤더만 반환했다. 보안 헤더 서버는 CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin 계열 헤더와 캐시 제어 헤더를 추가했다.

이 차이는 ZAP 경고 감소의 실행 증거로 사용할 수 있다. 보안 헤더 적용 전 `zap-report.json`에서는 경고 13건과 인스턴스 19건이 수집되었고, 적용 후 `zap-secure-report.json`에서는 경고 4건과 인스턴스 8건으로 감소하였다.
