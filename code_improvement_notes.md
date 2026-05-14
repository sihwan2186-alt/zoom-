# 코드 수정 및 보완 검토 결과

- 검토일: 2026-05-14
- 대상: `화상회의/zoom-/security` 보안 실습 코드와 현재 논문/선행연구 자료
- 연구 주제 연결: WebRTC 기반 화상회의의 무단 참가 및 미디어 유출 방지를 위한 종단 간 암호화, 인증, 세션 관리 통합 보안 강화

## 1. 직접 보완한 부분

### 1.1 인증 모듈 보완

수정 파일: `화상회의/zoom-/security/authentication/AuthModule.java`

기존에는 비밀번호를 salt + SHA-256 단일 해시로 저장하고 있었다. 단일 SHA-256은 빠르게 계산되므로 유출된 해시가 오프라인 대입 공격에 취약할 수 있다. 이를 `PBKDF2WithHmacSHA256` 기반으로 변경하고 반복 횟수 210,000회, 256비트 해시를 사용하도록 보완했다.

추가로 로그인 실패 횟수를 기록하여 5회 실패 시 5분 동안 비밀번호 검증을 잠그는 로직을 추가했다. 토큰 유효기간은 기존 2시간에서 30분으로 줄여 세션 탈취 시 피해 범위를 낮췄고, 토큰 생성 시 외부에서 전달된 username이 아니라 등록된 사용자 정보의 username을 사용하도록 수정했다.

보완 효과:

| 항목 | 기존 | 보완 후 |
|---|---|---|
| 비밀번호 저장 | SHA-256 단일 해시 | PBKDF2-HMAC-SHA256 |
| 대입 공격 방어 | 별도 제한 없음 | 5회 실패 시 5분 잠금 |
| 토큰 유효기간 | 2시간 | 30분 |
| 토큰 세션 사용자명 | 호출자가 전달한 값 사용 | 등록된 사용자 정보 사용 |

### 1.2 세션 관리 모듈 보완

수정 파일: `화상회의/zoom-/security/session_management/session_security.py`

기존 세션 검증은 전체 만료 시간은 확인했지만, 일정 시간 사용하지 않은 세션을 만료하는 idle timeout 개념이 약했다. 30분 유휴 만료를 추가하여 토큰이 남아 있어도 장시간 사용하지 않은 세션은 폐기되도록 했다.

또한 브라우저 기반 화상회의 서비스에서 필요한 보안 쿠키 설정을 검증 자료로 남길 수 있도록 `build_session_cookie_header()`를 추가했다. 이 메서드는 `HttpOnly`, `Secure`, `SameSite=Strict`, `Max-Age`, `Path=/` 속성이 포함된 세션 쿠키 헤더를 생성한다.

보완 효과:

| 항목 | 기존 | 보완 후 |
|---|---|---|
| 유휴 세션 만료 | 없음 | 30분 idle timeout |
| 세션 갱신 검증 | 세션 ID 서명 검증 약함 | refresh 전 서명/활성/만료 검증 |
| 쿠키 보안 설정 | 코드 없음 | Secure/HttpOnly/SameSite 쿠키 헤더 생성 |
| 세션 정보 | 절대 만료만 표시 | idle 만료 시각도 표시 |

## 2. 현재 코드에서 추가 보완 가능한 부분

### 2.1 암호화 모듈

`encryption.py`는 `cryptography` 패키지가 없을 때 HMAC 기반 데모 모드로 실행된다. 학습 환경에서는 장점이 있지만, 보고서에서는 운영 암호화가 아니라는 점을 명확히 해야 한다. 추가 보완으로는 `allow_demo_fallback=False` 옵션을 두어 운영 모드에서는 AES-GCM 사용 불가 시 예외가 발생하도록 만드는 방법이 좋다.

추가로 실제 WebRTC 미디어 암호화와 연결하려면 Jitsi Insertable Streams 또는 SFrame 적용 위치를 코드 레벨에서 명확히 조사해야 한다.

### 2.2 인증 모듈

현재 MFA 코드는 실습용 6자리 challenge 방식이다. 실제 서비스와 더 가깝게 만들려면 TOTP 표준(RFC 6238) 기반 secret 등록, 시간창 검증, 백업 코드, MFA 재시도 제한을 추가하는 것이 좋다.

또한 token blocklist, refresh token 회전, 회의별 권한 claim, host/participant role 검증이 추가되면 논문에서 말한 "회의별 접근통제"를 더 잘 증명할 수 있다.

### 2.3 세션 관리 모듈

현재 세션은 메모리에 저장된다. 실제 배포 환경에서는 서버 재시작, 다중 서버 구성, 세션 폐기 동기화가 필요하므로 Redis 같은 중앙 저장소 또는 서명된 short-lived token과 blocklist 조합을 검토할 수 있다.

### 2.4 데이터 유출 방지 모듈

`data_protection.py`는 이메일, 전화번호, JWT, URL query token 등을 마스킹한다. 추가로 녹화 파일, 채팅 로그, 회의 제목, 참가자 목록에 대한 보존기간 정책을 코드화하면 "데이터 최소 수집 및 보존기간 제한"을 증명하기 쉽다.

### 2.5 입력 검증 및 도구 실행 범위

`buffer_protection.py`에는 ZAP 스캔 대상 URL이 허용된 호스트인지 확인하는 `validate_scan_scope()`가 있다. 향후 Nmap, Hydra 실습을 추가할 경우에도 같은 방식으로 허용 대상 목록을 두어 무단 스캔을 방지해야 한다.

## 3. 추가 자료가 있으면 더 정확히 보완할 수 있는 부분

다음 자료가 있으면 코드 수정 범위를 더 구체화할 수 있다.

| 필요한 자료 | 있으면 좋은 이유 |
|---|---|
| 실제 실행할 Jitsi Meet 설정 파일(`config.js`, nginx/prosody 설정) | E2EE, JWT 인증, 대기실, 도메인 제한을 실제 설정에 반영 가능 |
| OWASP ZAP JSON 리포트 | 취약점 경고를 코드/설정 수정 항목으로 바로 연결 가능 |
| Wireshark 캡처 파일 또는 캡처 기준 | 평문 RTP 노출 여부, SRTP/DTLS 흐름 검증 가능 |
| Nmap 결과 | 불필요하게 열린 포트와 서비스 버전 노출 여부 확인 가능 |
| Hydra 실습 대상 로그인 폼/테스트 계정 | rate limit, lockout, MFA 우회 방어 검증 가능 |
| 배포 구조도 | 신뢰경계, SFU, TURN, 웹서버, 인증서버 간 위협 모델 구체화 가능 |

## 4. 검증 완료 항목

다음 명령으로 수정 후 기본 검증을 완료했다.

```bash
python -m compileall 화상회의/zoom-
javac -encoding UTF-8 -d .tmp_classes 화상회의/zoom-/security/authentication/AuthModule.java
java -cp .tmp_classes com.zoom.security.authentication.AuthModule
python 화상회의/zoom-/security/session_management/session_security.py
```

검증 결과:

- Python 보안 모듈 컴파일 성공
- Java 인증 모듈 컴파일 성공
- Java 인증 흐름 실행 성공: 사용자 등록, 비밀번호 검증, MFA 검증, 토큰 생성/검증, 토큰 폐기 후 무효 확인
- Python 세션 흐름 실행 성공: 세션 생성/검증, 보안 쿠키 헤더 생성, 세션 재생성, 만료 세션 정리
