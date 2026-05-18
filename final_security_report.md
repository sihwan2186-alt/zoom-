# 화상회의 STRIDE-ZAP 취약점 탐지 효과성 비교 최종본

- 최종 정리일: 2026-05-18
- 비교 기준일: 2026-05-14
- 대상: WebRTC 기반 화상회의 보안 실습 코드
- 연구 주제: 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 동적 자동화 진단 도구(OWASP ZAP)의 취약점 탐지 효과성 비교 분석
- 산출 문서 정책: `README.md`와 이 문서만 유지

## 1. 정리 범위

이 프로젝트는 화상회의 시스템에서 반복적으로 발생하는 인증 우회, 세션 탈취, 미디어 도청/변조, WebRTC IP 노출, 회의 링크 유출, 개인정보 재식별, ReDoS, 취약점 평가 누락을 대상으로 한다. 최종 연구의 중심은 보완 기능 자체가 아니라 STRIDE와 OWASP ZAP가 이 취약점 범위를 얼마나 다르게 탐지하는지 비교하는 것이다.

Zoom, Jitsi Meet 같은 제품명은 논문 제목, 참고 사례, 테스트용 WebRTC 임베드 도메인처럼 필요한 경우에만 남겼다. 프로젝트의 중심은 특정 제품 소개가 아니라 화상회의 보안 설계와 보완 코드다.

`jitsi-meet` 하위 문서는 외부 원본 소스 문서에 가까워 이번 산출물 정리 대상에서 제외했다. 루트와 `화상회의/zoom-` 하위에 흩어져 있던 중복 README와 중간 보고서는 이 최종본으로 통합했다.

### 현재까지 진행상황 요약

| 구분 | 진행상황 |
|---|---|
| 연구 방향 | STRIDE 위협 모델링과 OWASP ZAP 동적 진단의 취약점 탐지 효과성 비교로 확정 |
| 문서 정리 | 중복 문서와 기존 `docx` 산출물을 제거하고 `README.md`, `final_security_report.md` 두 개로 통합 |
| 실험 A | 화상회의 아키텍처 기반 STRIDE 샘플 위협 항목과 DREAD 점수 체계 구성 |
| 실험 B | OWASP ZAP JSON 결과를 읽어 OWASP Top 10 기준으로 매핑하는 비교 유틸리티 구성 |
| 비교 분석 | 탐지 건수, 커버리지, 중복/단독 탐지, 오탐률, 위험도 가중 점수, 우선순위 항목 산출 |
| 시각화 | Markdown 표와 Mermaid 기반 커버리지/탐지범위 그래프 출력 추가 |
| 보완 코드 | 인증, 세션, 암호화, 개인정보 보호, 입력 검증, 평가 모듈의 화상회의 특화 보완 적용 |
| 검증 | Python/Java 컴파일과 주요 보안 모듈 실행 검증 완료 |

## 2. 연구 설계와 검증방법

| 구분 | 내용 |
|---|---|
| 연구 주제 | 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP의 취약점 탐지 효과성 비교 분석 |
| 실험 A | 화상회의 아키텍처, 데이터 흐름, 신뢰 경계, 사용자/회의방/미디어 서버/브라우저 구성요소를 기준으로 STRIDE 위협 모델링 수행 |
| 실험 B | 동일 대상에 대해 OWASP ZAP 동적 자동화 진단을 수행하고 JSON/HTML/Markdown 결과 확보 |
| 공통 비교 축 | 실험 A와 실험 B 결과를 OWASP Top 10 카테고리 기준으로 매핑 |
| 분석 지표 | 탐지 건수, OWASP 카테고리 커버리지, 중복 탐지, STRIDE 단독 탐지, ZAP 단독 탐지, 오탐률, 위험도 가중 점수 |
| 시각화 자료 | 탐지 범위 매트릭스 표, OWASP Top 10 커버리지 막대 그래프, 탐지 범위 분포 그래프 |

검증 스크립트는 `화상회의/zoom-/security/assessment/threat_zap_comparison.py`이다. ZAP 리포트가 없을 때는 내장 샘플 경고로 비교 형식을 확인하고, 실제 실험에서는 `--zap-json` 옵션으로 OWASP ZAP JSON 결과를 입력한다.

## 3. 논문 기반 반영 근거

| 논문 파일 | 보완에 활용한 내용 | 반영 위치 |
|---|---|---|
| `1601.00184v1.pdf` | WebRTC의 중단, 변조, 도청 위협 | STRIDE 항목, 미디어 AAD, replay 탐지 |
| `1709.05395v1.pdf` | WebRTC IP 주소 노출과 네트워크 식별 위험 | ICE 후보 마스킹, P2P 제한, TURN relay 권장 설정 |
| `1908.05901v1.pdf` | MFA의 보안 효과와 사용성 한계 | TOTP, MFA 실패 잠금, 코드 재사용 방지 |
| `2007.01059v1.pdf` | 공개 회의 캡처의 얼굴/이름/사용자명 재식별 위험 | 표시명/회의 링크/이미지 URL 마스킹, CSP/referrer/sandbox |
| `2212.02740v2.pdf` | WebRTC P2P/peer-assisted 구조의 노출과 오염 위험 | P2P 비활성화 권장, privacy advisor 설정 |
| `2406.11618v4.pdf` | ReDoS 취약 정규식 패턴 | 정규식 길이/구조 검증, 안전 검색 API |
| `000000100869_20260512170757.pdf` | 화상회의 사용자 인증과 그룹 키 합의 필요성 | 회의 epoch 키 갱신 모델 |
| `3498335.pdf` | Unified Communication 보안/프라이버시 위협 분류 | STRIDE 샘플 항목 확장 |
| `electronics-12-01247-v2.pdf` | 화상회의 앱의 제3자 데이터 전송과 개인정보 처리 문제 | 제3자 요청 차단, 보존기간 정책 |
| `팀6 - vuln-jwt-lab.pdf` | 화상회의 시스템 위협 모델과 JWT 위험 | 회의방/역할 바인딩 토큰, STRIDE-ZAP 비교 |
| `08887256.pdf` | 자동 텍스트 추출 실패 | OCR 또는 수동 확인 전까지 코드 근거로 사용하지 않음 |

## 4. 2026-05-14 대비 변경점

2026-05-14 기준 보완은 기본 보안 기능을 갖추는 단계였다. 비밀번호 저장 방식 개선, 로그인 실패 잠금, 토큰 만료 단축, idle timeout, 보안 쿠키, 기본 개인정보 마스킹, STRIDE/ZAP 비교 틀이 중심이었다.

2026-05-18 현재 최종본은 수집 논문을 근거로 화상회의 특화 위험을 추가했다. WebRTC IP leak, 공개 회의 화면 재식별, P2P 미디어 경로 위험, MFA 재사용/피로 공격, 그룹 키 갱신, ReDoS, 제3자 데이터 전송, JWT 권한 혼동을 코드와 평가 항목에 연결했다.

| 영역 | 2026-05-14 기준 | 현재 최종본 |
|---|---|---|
| 인증 | PBKDF2, 로그인 실패 잠금, 30분 토큰 | TOTP, MFA 실패 잠금, TOTP 재사용 방지, 회의방/역할 claim, 토큰 폐기 |
| 세션 | idle timeout, 보안 쿠키 | 절대 만료, CSRF 토큰, refresh 시 CSRF 회전, `__Host-vc_session` |
| 암호화 | AES-256 실습 코드 | AES-GCM 우선, 운영 모드 fallback 차단, 회의/참가자/epoch/sequence AAD, replay 탐지 |
| 그룹 키 | 단일 세션 키 중심 | 참가자 변경 시 epoch 키 갱신 모델 |
| 개인정보 보호 | 이메일, 전화번호, JWT, URL 토큰 마스킹 | 회의 링크, 표시명, 얼굴/아바타 URL, ICE 후보 마스킹, 보존기간 정책 |
| 입력 검증 | XSS/명령 주입/경로 탐색 차단 | 회의 ID/표시명 allow-list, ReDoS 정규식 검증, 안전 검색 API |
| 프론트 | 기본 로그인/회의 화면 | CSP, referrer 차단, iframe sandbox, 암호학적 난수 회의 ID, privacy 설정 파라미터 |
| 평가 | STRIDE와 ZAP 비교 구조 | 논문 근거 목록, 화상회의 특화 STRIDE 항목, OWASP 2021/2025 매핑 |
| 문서 | 여러 중간 보고서와 README가 중복 | `README.md` + `final_security_report.md`로 통합 |

## 5. 코드 보완 내역

| 파일 | 추가/수정 내용 | 기대 효과 |
|---|---|---|
| `화상회의/zoom-/security/authentication/AuthModule.java` | PBKDF2-HMAC-SHA256, TOTP, MFA 실패 잠금, TOTP 재사용 방지, 회의방/역할 바인딩 토큰, token revocation | 계정 탈취와 토큰 재사용 위험 감소 |
| `화상회의/zoom-/security/session_management/session_security.py` | idle/absolute timeout, CSRF 토큰 생성/검증, refresh 시 CSRF 회전, `__Host-` 쿠키 헤더 | 세션 고정, 장기 세션 악용, 요청 위조 방지 |
| `화상회의/zoom-/security/encryption/encryption.py` | AES-GCM 우선 사용, 데모 fallback 제한 옵션, 회의별 AAD, replay 탐지, epoch 키 스케줄 | 미디어 변조/재전송/참가자 변경 후 키 노출 위험 감소 |
| `화상회의/zoom-/security/data_leak_prevention/data_protection.py` | 회의 링크/표시명/ICE 후보/이미지 URL 마스킹, 보존기간 정책, 개인정보 보호 설정 생성기 | 회의 메타데이터와 개인정보 유출 감소 |
| `화상회의/zoom-/security/buffer_overflow/buffer_protection.py` | 회의 ID/표시명 검증, ReDoS 위험 정규식 검증, 안전 검색 API, 스캔 범위 검증 | 입력 기반 공격과 무단 스캔 오용 방지 |
| `화상회의/zoom-/security/assessment/threat_zap_comparison.py` | `PAPER_EVIDENCE`, 화상회의 특화 STRIDE 항목, ZAP 경고와 OWASP Top 10 비교 | 설계 위협과 자동 진단 결과를 함께 설명 가능 |
| `화상회의/zoom-/client/index.html` | CSP, referrer 차단, sandbox iframe, 난수 기반 회의 ID, 회의 ID allow-list, privacy URL 옵션 | 브라우저 측 회의 링크/제3자 요청/임베드 위험 완화 |
| `.gitignore` | `.tmp_pdf/`, `.tmp_pdf_text/` 제외 | 논문 텍스트 추출 임시 산출물 관리 |

## 6. 삭제 및 통합한 문서

다음 문서는 내용이 중복되어 이 최종본으로 통합하고 삭제했다.

| 삭제 문서 | 통합 위치 |
|---|---|
| `code_improvement_notes.md` | 4장, 5장 |
| `research_video_conference_security.md` | 3장, 8장 |
| `paper_based_improvements.md` | 3장, 5장 |
| `changes_since_2026-05-14.md` | 4장 |
| `화상회의/zoom-/README.md` | 5장, README 안내 |
| `화상회의/zoom-/security/*/README.md` | 5장 |
| `화상회의_보안강화_논문.docx` | Markdown 최종본으로 대체 |

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

다음 명령으로 최종 문서 정리 후 기본 검증을 완료했다.

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

비교 스크립트는 Markdown 보고서 안에 다음 산출물을 포함하도록 수정했다.

- 실험 A/B 정의와 OWASP Top 10 매핑 기준
- 탐지 범위 매트릭스 표
- OWASP Top 10 커버리지 막대 그래프
- 탐지 범위 분포 그래프
- 오탐률, 위험도 가중 점수, 우선 검토 STRIDE 항목

## 9. 최종 결론

최종본은 특정 화상회의 제품 설명이 아니라, 화상회의 아키텍처에서 STRIDE와 OWASP ZAP의 취약점 탐지 효과성을 비교하기 위한 산출물이다. 중복 문서는 제거했고, 결과적으로 사용자가 확인해야 할 문서는 `README.md`와 `final_security_report.md` 두 개로 정리했다.
