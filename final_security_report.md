# 화상회의 STRIDE-ZAP 취약점 탐지 효과성 비교 최종본

- 최종 정리일: 2026-05-19
- 대상: WebRTC 기반 화상회의 보안 실습 코드
- 연구 주제: 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 동적 자동화 진단 도구(OWASP ZAP)의 취약점 탐지 효과성 비교 분석

## 1. 정리 범위

이 프로젝트는 화상회의 시스템에서 반복적으로 발생하는 인증 우회, 세션 탈취, 미디어 도청/변조, WebRTC IP 노출, 회의 링크 유출, 개인정보 재식별, ReDoS, 취약점 평가 누락을 대상으로 한다. 최종 연구의 중심은 보완 기능 자체의 우수성 입증이 아니라, STRIDE 위협 모델링과 OWASP ZAP 동적 진단이 같은 화상회의 보안 위협을 어떤 범위와 방식으로 탐지하는지 비교하는 것이다.

Zoom, Jitsi Meet 같은 제품명은 논문 제목, 참고 사례, 테스트용 WebRTC 임베드 도메인처럼 필요한 경우에만 사용한다. 프로젝트의 중심은 특정 제품 소개가 아니라 화상회의 아키텍처에서 발생 가능한 위협을 정의하고, 그 위협을 STRIDE와 ZAP가 어떻게 다르게 식별하는지 분석하는 것이다.

분석 대상은 WebRTC 기반 화상회의 보안 실습 코드와 STRIDE-ZAP 비교 스크립트다. `jitsi-meet` 하위 원본 소스는 화상회의 환경 이해를 위한 배경 자료로만 참고하고, 직접 분석과 검증은 `화상회의/zoom-` 하위 보안 모듈과 평가 스크립트를 중심으로 수행한다.

### 연구 구성 요약

| 구분 | 진행상황 |
|---|---|
| 연구 방향 | STRIDE 위협 모델링과 OWASP ZAP 동적 진단의 취약점 탐지 효과성 비교로 확정 |
| 실험 A | 화상회의 아키텍처 기반 STRIDE 샘플 위협 항목과 DREAD 점수 체계 구성 |
| 실험 B | OWASP ZAP JSON 결과를 읽어 OWASP Top 10 기준으로 매핑하는 비교 유틸리티 구성 |
| 비교 분석 | 탐지 건수, 커버리지, 중복/단독 탐지, 오탐률, 위험도 가중 점수, 우선순위 항목 산출 |
| 시각화 | Markdown 표와 Mermaid 기반 커버리지/탐지범위 그래프 출력 추가 |
| 실험 대상 코드 | 인증, 세션, 암호화, 개인정보 보호, 입력 검증, 평가 모듈에 화상회의 특화 보안 요소 반영 |
| 검증 | Python/Java 컴파일, 주요 보안 모듈 실행, STRIDE-ZAP 비교 스크립트 실행 검증 완료 |

## 2. 연구 설계와 검증방법

### 연구 질문

본 연구는 다음 질문에 답하는 것을 목표로 한다.

| 연구 질문 | 확인하려는 내용 |
|---|---|
| RQ1 | STRIDE 위협 모델링과 OWASP ZAP는 화상회의 아키텍처의 취약점 범위를 동일하게 탐지하는가? |
| RQ2 | STRIDE는 ZAP가 탐지하기 어려운 설계·구조적 위협을 식별할 수 있는가? |
| RQ3 | ZAP는 STRIDE 분석만으로 확인하기 어려운 실행 환경의 웹 취약점과 설정 문제를 탐지할 수 있는가? |
| RQ4 | 두 방법을 함께 사용할 때 단일 방법보다 탐지 범위와 우선순위 판단이 개선되는가? |

| 구분 | 내용 |
|---|---|
| 연구 주제 | 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP의 취약점 탐지 효과성 비교 분석 |
| 실험 A | 화상회의 아키텍처, 데이터 흐름, 신뢰 경계, 사용자/회의방/미디어 서버/브라우저 구성요소를 기준으로 STRIDE 위협 모델링 수행 |
| 실험 B | 동일 대상에 대해 OWASP ZAP 동적 자동화 진단을 수행하고 JSON/HTML/Markdown 결과 확보 |
| 공통 비교 축 | 실험 A와 실험 B 결과를 OWASP Top 10 카테고리 기준으로 매핑 |
| 분석 지표 | 탐지 건수, OWASP 카테고리 커버리지, 중복 탐지, STRIDE 단독 탐지, ZAP 단독 탐지, 오탐률, 위험도 가중 점수 |
| 시각화 자료 | 탐지 범위 매트릭스 표, OWASP Top 10 커버리지 막대 그래프, 탐지 범위 분포 그래프 |

### 연구가설

본 연구는 화상회의 프로그램 자체의 우수성을 입증하는 것이 아니라, 같은 화상회의 아키텍처를 대상으로 두 보안 분석 방법론의 탐지 특성이 어떻게 다른지를 비교한다.

따라서 본 연구의 주 가설은 다음과 같다.

> 동일한 화상회의 아키텍처를 대상으로 분석했을 때, STRIDE 위협 모델링은 설계·구조적 위협을 더 폭넓게 식별하고, OWASP ZAP는 실제 실행 환경에서 노출되는 웹 취약점과 설정 문제를 더 구체적으로 탐지할 것이다.

보조 가설은 다음과 같다.

> STRIDE와 ZAP의 탐지 결과를 OWASP Top 10 기준으로 함께 매핑하면, 단일 방법만 사용할 때보다 화상회의 시스템의 취약점 탐지 범위와 보완 우선순위를 더 명확하게 도출할 수 있을 것이다.

### 검증 방법

가설을 검증하기 위해 동일한 화상회의 아키텍처와 보안 실습 코드를 대상으로 STRIDE 기반 수동 위협 모델링과 OWASP ZAP 기반 동적 자동화 진단을 각각 수행한다. 두 결과는 OWASP Top 10 카테고리로 매핑하여 같은 기준에서 비교한다.

첫째, STRIDE 분석에서는 사용자, 회의방, 인증 서버, 미디어 서버, 브라우저 클라이언트, 외부 API 사이의 데이터 흐름과 신뢰 경계를 정의한다. 이후 Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege 관점에서 가능한 위협을 식별하고 DREAD 기준으로 위험도를 산정한다.

둘째, ZAP 분석에서는 동일 대상에 대해 동적 자동화 진단을 수행하고, 탐지된 경고를 OWASP Top 10 카테고리와 연결한다. 실제 ZAP JSON 결과가 있을 때는 이를 입력값으로 사용하고, 실험 환경에서 ZAP 실행이 어려운 경우에는 샘플 경고 데이터를 사용해 비교 절차와 산출물 형식을 검증한다.

셋째, 두 결과를 탐지 건수, OWASP 카테고리 커버리지, 중복 탐지, STRIDE 단독 탐지, ZAP 단독 탐지, 오탐 가능성, 위험도 가중 점수로 비교한다. 이를 통해 두 방법이 서로 대체 관계인지, 보완 관계인지 판단한다.

넷째, 실험 및 자동 진단만으로 확인하기 어려운 WebRTC IP 노출, 회의 화면 재식별, 그룹 키 갱신, P2P 미디어 경로 위험 등 화상회의 특화 위협은 관련 논문과 보안 가이드라인을 근거로 보완 분석한다.

### 평가 기준

| 평가 기준 | 비교 의미 |
|---|---|
| 탐지 범위 | STRIDE와 ZAP가 탐지한 위협이 OWASP Top 10 중 어느 범위를 포함하는지 확인 |
| 탐지 깊이 | 단순 경고 수준인지, 원인·영향·완화책까지 설명 가능한지 비교 |
| 자동화 가능성 | 사람이 직접 분석해야 하는 항목과 도구로 반복 실행 가능한 항목을 구분 |
| 설계 위협 탐지 | 신뢰 경계, 권한 모델, 회의방 역할, 그룹 키 갱신처럼 실행 전 설계 단계에서 드러나는 위협 확인 |
| 실행 환경 취약점 탐지 | 보안 헤더, 쿠키 설정, XSS, 노출된 엔드포인트처럼 실제 구동 환경에서 드러나는 취약점 확인 |
| 보완 우선순위 | 위험도 가중 점수와 중복 탐지 여부를 기준으로 우선 대응 항목 산출 |

검증 스크립트는 `화상회의/zoom-/security/assessment/threat_zap_comparison.py`이다. ZAP 리포트가 없을 때는 내장 샘플 경고로 비교 형식을 확인하고, 실제 실험에서는 `--zap-json` 옵션으로 OWASP ZAP JSON 결과를 입력한다.

## 3. 논문 기반 반영 근거

| 논문 파일 | 논문 제목 | 보완에 활용한 내용 | 반영 위치 |
|---|---|---|---|
| `1601.00184v1.pdf` | The Security of WebRTC | WebRTC의 중단, 변조, 도청 위협 | STRIDE 항목, 미디어 AAD, replay 탐지 |
| `1709.05395v1.pdf` | One Leak Will Sink A Ship: WebRTC IP Address Leaks | WebRTC IP 주소 노출과 네트워크 식별 위험 | ICE 후보 마스킹, P2P 제한, TURN relay 권장 설정 |
| `1908.05901v1.pdf` | Evaluating User Perception of Multi-Factor Authentication | MFA의 보안 효과와 사용성 한계 | TOTP, MFA 실패 잠금, 코드 재사용 방지 |
| `2007.01059v1.pdf` | Zooming Into Video Conferencing Privacy and Security Threats | 공개 회의 캡처의 얼굴/이름/사용자명 재식별 위험 | 표시명/회의 링크/이미지 URL 마스킹, CSP/referrer/sandbox |
| `2212.02740v2.pdf` | Stealthy Peers | WebRTC P2P/peer-assisted 구조의 노출과 오염 위험 | P2P 비활성화 권장, privacy advisor 설정 |
| `2406.11618v4.pdf` | SoK: Regular Expression Denial of Service | ReDoS 취약 정규식 패턴 | 정규식 길이/구조 검증, 안전 검색 API |
| `000000100869_20260512170757.pdf` | 화상회의 시스템에서 타원곡선암호를 이용한 사용자 인증 및 그룹 키 합의 방식 | 화상회의 사용자 인증과 그룹 키 합의 필요성 | 회의 epoch 키 갱신 모델 |
| `3498335.pdf` | Security and Privacy in Unified Communication | Unified Communication 보안/프라이버시 위협 분류 | STRIDE 샘플 항목 확장 |
| `electronics-12-01247-v2.pdf` | Exploring Personal Data Processing in Video Conferencing Apps | 화상회의 앱의 제3자 데이터 전송과 개인정보 처리 문제 | 제3자 요청 차단, 보존기간 정책 |
| `팀6 - vuln-jwt-lab.pdf` | Towards a Threat Model and Security Analysis of Video Conferencing Systems | 화상회의 시스템 위협 모델과 JWT 위험 | 회의방/역할 바인딩 토큰, STRIDE-ZAP 비교 |
| `08887256.pdf` | 제목 확인 필요 | 자동 텍스트 추출 실패 | OCR 또는 수동 확인 전까지 코드 근거로 사용하지 않음 |

## 4. 실험 대상 보안 요소

본 비교 실험은 보안 기능 자체의 성능을 주장하기보다, 화상회의 환경에서 실제로 고려해야 할 보안 요소를 분석 대상으로 정의한다. 아래 항목은 STRIDE와 ZAP가 각각 어떤 범위까지 탐지할 수 있는지 비교하기 위한 기준이다.

| 영역 | 실험 대상 보안 요소 | STRIDE-ZAP 비교 관점 |
|---|---|---|
| 인증 | PBKDF2-HMAC-SHA256, TOTP, MFA 실패 잠금, TOTP 재사용 방지, 회의방/역할 claim, 토큰 폐기 | STRIDE는 인증 우회와 권한 상승 시나리오를 식별하고, ZAP는 로그인 흐름과 세션 처리의 노출 취약점을 탐지 |
| 세션 | idle/absolute timeout, CSRF 토큰, refresh 시 CSRF 회전, `__Host-vc_session` | STRIDE는 세션 탈취·고정 위협을 모델링하고, ZAP는 쿠키 속성·CSRF 관련 구현 문제를 확인 |
| 암호화 | AES-GCM 우선, 운영 모드 fallback 차단, 회의/참가자/epoch/sequence AAD, replay 탐지 | STRIDE는 미디어 도청·변조·재전송 위협을 식별하고, ZAP는 웹 계층에서 노출되는 전송 보안 문제를 확인 |
| 그룹 키 | 참가자 변경 시 epoch 키 갱신 모델 | STRIDE는 참가자 변경 후 키 노출과 권한 잔존 문제를 다루고, ZAP는 해당 설계 위협을 직접 탐지하기 어려움 |
| 개인정보 보호 | 회의 링크, 표시명, 얼굴/아바타 URL, ICE 후보 마스킹, 보존기간 정책 | STRIDE는 정보 노출과 재식별 위험을 폭넓게 식별하고, ZAP는 응답 본문·헤더·URL에 노출된 정보 탐지에 강점 |
| 입력 검증 | 회의 ID/표시명 allow-list, ReDoS 정규식 검증, 안전 검색 API | STRIDE는 서비스 거부와 입력 변조 시나리오를 정리하고, ZAP는 XSS·주입·경로 노출 같은 웹 취약점을 탐지 |
| 브라우저 보안 | CSP, referrer 차단, iframe sandbox, 암호학적 난수 회의 ID, privacy 설정 파라미터 | STRIDE는 제3자 임베드와 링크 유출 위협을 식별하고, ZAP는 보안 헤더 누락과 브라우저 정책 설정 문제를 확인 |
| 평가 | 화상회의 특화 STRIDE 항목, ZAP 경고와 OWASP Top 10 매핑 | 두 결과를 동일 기준으로 비교해 중복 탐지, 단독 탐지, 우선 대응 항목을 산출 |

## 5. 실험 대상 코드 구성

| 파일 | 추가/수정 내용 | 기대 효과 |
|---|---|---|
| `화상회의/zoom-/security/authentication/AuthModule.java` | PBKDF2-HMAC-SHA256, TOTP, MFA 실패 잠금, TOTP 재사용 방지, 회의방/역할 바인딩 토큰, token revocation | 계정 탈취와 토큰 재사용 위험 감소 |
| `화상회의/zoom-/security/session_management/session_security.py` | idle/absolute timeout, CSRF 토큰 생성/검증, refresh 시 CSRF 회전, `__Host-` 쿠키 헤더 | 세션 고정, 장기 세션 악용, 요청 위조 방지 |
| `화상회의/zoom-/security/encryption/encryption.py` | AES-GCM 우선 사용, 데모 fallback 제한 옵션, 회의별 AAD, replay 탐지, epoch 키 스케줄 | 미디어 변조/재전송/참가자 변경 후 키 노출 위험 감소 |
| `화상회의/zoom-/security/data_leak_prevention/data_protection.py` | 회의 링크/표시명/ICE 후보/이미지 URL 마스킹, 보존기간 정책, 개인정보 보호 설정 생성기 | 회의 메타데이터와 개인정보 유출 감소 |
| `화상회의/zoom-/security/buffer_overflow/buffer_protection.py` | 회의 ID/표시명 검증, ReDoS 위험 정규식 검증, 안전 검색 API, 스캔 범위 검증 | 입력 기반 공격과 무단 스캔 오용 방지 |
| `화상회의/zoom-/security/assessment/threat_zap_comparison.py` | `PAPER_EVIDENCE`, 화상회의 특화 STRIDE 항목, ZAP 경고와 OWASP Top 10 비교 | 설계 위협과 자동 진단 결과를 함께 설명 가능 |
| `화상회의/zoom-/client/index.html` | CSP, referrer 차단, sandbox iframe, 난수 기반 회의 ID, 회의 ID allow-list, privacy URL 옵션 | 브라우저 측 회의 링크/제3자 요청/임베드 위험 완화 |
| `.gitignore` | `.tmp_pdf/`, `.tmp_pdf_text/`, `reports/` 제외 | 논문 텍스트 추출 임시 산출물과 실습 보고서 산출물 관리 |

## 6. 실제 실험 결과 입력 위치

실제 ZAP 스캔이나 직접 작성한 STRIDE 분석 결과가 준비되면 다음 위치를 갱신한다.

| 실험 산출물 | 입력/반영 위치 | 갱신 내용 |
|---|---|---|
| ZAP JSON 보고서 | `README.md`의 ZAP 실습 절차와 `threat_zap_comparison.py --zap-json` 옵션 | 실제 ZAP 경고 건수, 위험도, OWASP Top 10 매핑 |
| 직접 작성한 STRIDE CSV/JSON | `threat_zap_comparison.py --stride-csv` 또는 `--stride-json` 옵션 | 팀이 직접 식별한 STRIDE 위협, DREAD 점수, 대응 우선순위 |
| STRIDE-ZAP 비교 보고서 | `reports/stride_zap_comparison.md` | 중복 탐지, STRIDE 단독 탐지, ZAP 단독 탐지, 결합 커버리지 |
| 최종 해석 | 이 문서의 `검증 결과`와 `최종 결론` | 샘플 기반 해석을 실제 실험 결과 기반 해석으로 교체 |

## 7. 남은 한계와 보완 과제

현재 코드는 보안 설계를 설명하고 검증하기 위한 실습 코드다. 실제 운영 환경에 적용하려면 다음 항목을 추가 검증해야 한다.

| 항목 | 이유 |
|---|---|
| 실제 WebRTC Insertable Streams 또는 SFrame 연동 | 현재는 화상회의 미디어 AAD와 epoch 모델을 코드로 표현한 단계 |
| 중앙 세션 저장소 또는 토큰 폐기 동기화 | 다중 서버 환경에서는 메모리 기반 세션/폐기 목록만으로 부족 |
| OCR 기반 `08887256.pdf` 재검토 | 자동 추출 실패로 논문 내용을 근거에 반영하지 못함 |
| 실제 ZAP JSON, Nmap 결과, 배포 설정 파일 반영 | 실측 취약점과 설정 보완을 연결하려면 실행 결과가 필요 |
| 녹화/채팅/자막/파일 공유의 E2EE 범위 구분 | 미디어 E2EE만으로 모든 부가기능이 보호되지는 않음 |

## 8. 검증 결과

다음 명령으로 코드 실행 가능성과 STRIDE-ZAP 비교 스크립트의 산출물 생성을 확인했다.

```powershell
python -m compileall "화상회의\zoom-"
javac -encoding UTF-8 -d .tmp_classes "화상회의\zoom-\security\authentication\AuthModule.java"
java -cp .tmp_classes com.videoconference.security.authentication.AuthModule
python "화상회의\zoom-\security\encryption\encryption.py"
python "화상회의\zoom-\security\session_management\session_security.py"
python "화상회의\zoom-\security\data_leak_prevention\data_protection.py"
python "화상회의\zoom-\security\buffer_overflow\buffer_protection.py"
python "화상회의\zoom-\security\assessment\threat_zap_comparison.py"
```

모든 명령은 성공했다. 현재 환경에는 `cryptography` 패키지가 없어 RSA 전자봉투 데모는 건너뛰었지만, 암호화 모듈의 기본 실행과 미디어 패킷 암복호화 검증은 통과했다.

비교 스크립트는 Markdown 보고서 안에 다음 산출물을 포함하도록 구성했다.

- 실험 A/B 정의와 OWASP Top 10 매핑 기준
- 탐지 범위 매트릭스 표
- OWASP Top 10 커버리지 막대 그래프
- 탐지 범위 분포 그래프
- 오탐률, 위험도 가중 점수, 우선 검토 STRIDE 항목

현재 구현된 평가 항목과 샘플 ZAP 경고 기준의 예비 해석은 다음과 같다. 실제 ZAP JSON과 직접 작성한 STRIDE 결과가 입력되면 이 표는 실측 결과에 맞춰 갱신해야 한다.

| 비교 항목 | 확인 결과 |
|---|---|
| STRIDE 강점 | WebRTC IP 노출, 회의 링크 유출, 회의방 권한 혼동, 그룹 키 갱신, 미디어 도청/변조처럼 설계·구조 단계에서 드러나는 위협을 폭넓게 식별 |
| ZAP 강점 | 보안 헤더 누락, 쿠키 속성 문제, XSS·주입 가능성, 노출된 엔드포인트처럼 실행 중인 웹 애플리케이션에서 관찰 가능한 취약점 탐지에 적합 |
| 중복 탐지 영역 | 인증, 세션, 입력 검증, 정보 노출처럼 설계 위협과 실제 구현 취약점이 함께 나타나는 영역 |
| 단독 탐지 영역 | STRIDE는 미디어 경로·신뢰 경계·권한 모델 위협을 더 잘 다루고, ZAP는 실제 응답·헤더·쿠키·URL 기반 취약점을 더 구체적으로 확인 |
| 종합 판단 | 두 방법은 대체 관계보다 보완 관계에 가깝다. STRIDE로 설계 위협을 선제적으로 정리하고 ZAP로 실행 환경의 취약점을 반복 검증하는 방식이 화상회의 보안 평가에 더 적합하다. |

## 9. 최종 결론

최종본은 특정 화상회의 제품 설명이나 보안 강화 프로그램 자체의 우수성 검증이 아니라, 화상회의 아키텍처에서 STRIDE와 OWASP ZAP의 취약점 탐지 효과성을 비교하기 위한 산출물이다.

연구가설에 따라 STRIDE는 신뢰 경계, 권한 모델, WebRTC 미디어 경로, 회의 링크 유출, 그룹 키 갱신처럼 설계 단계에서 드러나는 위협을 폭넓게 식별하는 데 강점이 있다. 반면 OWASP ZAP는 보안 헤더, 쿠키 설정, XSS, 주입 가능성, 노출된 엔드포인트처럼 실행 중인 웹 애플리케이션에서 관찰 가능한 취약점을 구체적으로 탐지하는 데 강점이 있다.

따라서 화상회의 시스템 보안 평가는 STRIDE와 ZAP 중 하나만 선택하기보다, STRIDE로 위협 범위를 먼저 정의하고 ZAP로 실제 구현 취약점을 검증한 뒤, 두 결과를 OWASP Top 10 기준으로 매핑하여 보완 우선순위를 정하는 방식이 가장 적절하다.
