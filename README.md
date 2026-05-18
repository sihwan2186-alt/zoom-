# 화상회의 STRIDE-ZAP 탐지 효과성 비교 프로젝트

이 저장소는 "화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 동적 자동화 진단 도구(OWASP ZAP)의 취약점 탐지 효과성 비교 분석"을 위한 최종 산출물이다. 특정 상용 서비스나 오픈소스 제품 소개가 아니라, 화상회의 아키텍처에서 두 보안 방법론이 어떤 취약점 범위를 탐지하는지 비교하는 데 초점을 둔다.

## 최종 문서

문서는 중복을 줄이기 위해 다음 두 개만 유지한다.

- `README.md`: 프로젝트 실행과 문서 위치 안내
- `final_security_report.md`: 연구 주제, 실험 A/B 설계, OWASP Top 10 매핑, 논문 근거, 코드 보완 내역, 검증 결과를 합친 최종본

`jitsi-meet` 하위 문서는 외부 원본 소스 문서이므로 이번 산출물 정리 대상에서 제외했다.

## 연구 및 검증 방법

- 실험 A: 화상회의 아키텍처를 기준으로 STRIDE 위협 모델링 수행
- 실험 B: 동일 대상에 대해 OWASP ZAP 동적 자동화 진단 수행
- 비교 기준: 실험 A/B 결과를 OWASP Top 10 카테고리로 매핑
- 분석 항목: 탐지 스펙트럼, 중복/단독 탐지 카테고리, 오탐률, 위험도 가중 점수
- 산출물: 탐지 범위 표, OWASP 커버리지 그래프, 탐지 범위 분포 그래프

## 보완 코드 축

- 인증: PBKDF2, TOTP, MFA 실패 잠금, 회의방/역할 바인딩 토큰, 토큰 폐기 목록
- 세션: idle timeout, 절대 만료, CSRF 토큰, `__Host-` 보안 쿠키
- 암호화: AES-GCM 우선 사용, 데모 fallback 제한, 미디어 AAD, replay 탐지, epoch 키 갱신 모델
- 개인정보 보호: 회의 링크, 표시명, ICE 후보, 얼굴/아바타 URL 마스킹, 보존기간 정책
- 입력 검증: 회의 ID/표시명 allow-list, ReDoS 위험 정규식 차단, 안전한 스캔 범위 검증
- 평가: 화상회의 특화 STRIDE 항목과 OWASP ZAP 결과 비교

## 검증 명령

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

비교 보고서만 생성하려면 마지막 명령을 실행하면 된다. 실제 ZAP JSON 결과가 있으면 `--zap-json` 옵션으로 입력해 같은 기준으로 비교할 수 있다.
