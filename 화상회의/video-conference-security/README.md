# 화상회의 보안 분석 및 오픈소스 WebRTC 기반 보완 프로젝트

## 프로젝트 개요
- **프로젝트명**: video-conference-security (화상회의 보안 강화)
- **목적**: 특정 제품이 아닌 화상회의 아키텍처 전반의 보안 취약점 분석 및 오픈소스 WebRTC 기반 보완 구현
- **기술 스택**: Python, Java

## 보안 취약점 분석 분야

### 1. 암호화 보안 (Encryption)
- 화상회의 서비스의 종단 간 암호화(E2EE) 적용 범위 및 키 관리 위험
- AES-256, RSA-4096 기반 보완 구현

### 2. 인증 보안 (Authentication)
- 회의 참여자 검증 부족
- 다단계 인증(MFA), 토큰 기반 인증 구현

### 3. 데이터 유출 방지 (Data Leak Prevention)
- 메타데이터 노출 위험
- 데이터 마스킹, 익명화 처리

### 4. 버퍼 오버플로우 탐지 (Buffer Overflow Detection)
- 입력 검증 부재로 인한 취약점
- 입력 길이 제한, 샌드박싱

### 5. 세션 관리 보안 (Session Management)
- 세션 하이재킹 위험
- 안전한 세션 생성, 갱신, 폐기

### 6. STRIDE/ZAP 비교 분석 (Assessment)
- STRIDE 위협 모델링 결과와 OWASP ZAP JSON 리포트를 OWASP Top 10 기준으로 매핑
- 탐지 건수, 커버리지, 오탐률, 소요시간, 중복 탐지 카테고리, 상호 보완 탐지 영역 산출
- OWASP Top 10:2021 기준을 기본값으로 유지하되, 공식 사이트의 2025 버전도 `--taxonomy 2025`로 비교 가능
- 학부 논문 주제인 “STRIDE 위협 모델링과 OWASP ZAP 동적 자동화 진단의 취약점 탐지 효과성 비교 분석” 실험 데이터 정리 지원

## 연구 참고자료 반영 보완점

- Microsoft Threat Modeling Tool 문서는 STRIDE를 설계 초기에 보안 이슈를 식별하는 SDL 활동으로 설명한다. 따라서 본 프로젝트는 STRIDE 결과를 단순 취약점 목록이 아니라 DFD/신뢰경계 기반 설계 위협으로 기록한다.
- OWASP ZAP Baseline Scan은 기본적으로 짧은 스파이더링 후 수동 진단 결과를 보고하며, 실제 공격을 수행하지 않는 CI 친화적 진단으로 안내된다. 6주 학부 연구에서는 baseline JSON을 1차 자료로 사용하고, 필요 시 별도 허가된 테스트베드에서만 active scan을 추가한다.
- OWASP ZAP Automation Framework는 YAML 기반 반복 실험과 exit status 기준을 제공한다. 동일 대상 URL, 동일 spider 시간, 동일 alert filter를 고정해 반복 측정 가능성을 확보한다.
- OWASP Top 10은 2021판과 2025판의 분류가 다르므로, 논문 본문에는 사용한 버전을 명시한다. 기존 연구 비교는 2021, 최신성 검토는 2025 기준 표를 함께 제시할 수 있다.
- WebRTC 보안 선행연구는 통신 중단, 변조, 도청 시나리오를 다루므로, STRIDE 샘플에는 미디어 경로의 Information Disclosure와 스트리밍 서버의 Denial of Service 항목을 포함한다.

## 디렉토리 구조
```
video-conference-security/
├── security/
│   ├── encryption/      # 암호화 보안 모듈
│   ├── authentication/  # 인증 보안 모듈
│   ├── data_leak_prevention/  # 데이터 유출 방지
│   ├── buffer_overflow/      # 버퍼 오버플로우 탐지
│   ├── session_management/   # 세션 관리 보안
│   └── assessment/      # STRIDE/ZAP 비교 분석
└── README.md
```

## 실행 검증 예시
```bash
python -m compileall 화상회의/video-conference-security
python 화상회의/video-conference-security/security/encryption/encryption.py
python 화상회의/video-conference-security/security/assessment/threat_zap_comparison.py
python 화상회의/video-conference-security/security/assessment/threat_zap_comparison.py --taxonomy 2025
javac -encoding UTF-8 -d .tmp_classes 화상회의/video-conference-security/security/authentication/AuthModule.java
java -cp .tmp_classes com.videoconference.security.authentication.AuthModule
```

## ZAP 실험 데이터 정리 예시

ZAP JSON 리포트가 있을 때는 다음처럼 논문용 비교표와 원자료 JSON을 생성한다.

```bash
python 화상회의/video-conference-security/security/assessment/threat_zap_comparison.py ^
  --zap-json zap-report.json ^
  --taxonomy 2021 ^
  --stride-minutes 180 ^
  --zap-minutes 35 ^
  --zap-false-positive-plugin-ids 10020 ^
  --output-md stride-zap-summary.md ^
  --output-json stride-zap-summary.json
```

공식 ZAP Docker baseline scan 형식에 맞춘 실행 예시는 다음 명령으로 출력할 수 있다.

```bash
python 화상회의/video-conference-security/security/assessment/threat_zap_comparison.py --target-url https://meet.local
```

정량 비교 지표는 다음을 기준으로 해석한다.

- `combined_coverage_ratio`: STRIDE와 ZAP을 결합했을 때 OWASP Top 10 중 몇 개 범주를 설명하는지
- `coverage_gain_vs_stride`: ZAP을 추가했을 때 STRIDE 단독 대비 늘어난 OWASP 범주 수
- `coverage_gain_vs_zap`: STRIDE를 추가했을 때 ZAP 단독 대비 늘어난 OWASP 범주 수
- `zap_false_positive_rate`: ZAP 원시 경고 중 수동 검토 후 오탐으로 제외한 비율
- `findings_per_minute`: 제한된 6주 일정에서 방법론별 분석 효율을 비교하기 위한 보조 지표

## 참고 링크

- Microsoft Threat Modeling Tool / STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP ZAP Baseline Scan: https://www.zaproxy.org/docs/docker/baseline-scan/
- OWASP ZAP Automation Framework: https://www.zaproxy.org/docs/automate/automation-framework/
- OWASP Top 10:2021: https://owasp.org/Top10/2021/
- OWASP Top 10:2025: https://owasp.org/Top10/2025/
- The Security of WebRTC: https://arxiv.org/abs/1601.00184

`encryption.py`는 `cryptography` 패키지가 설치된 환경에서는 AES-256-GCM/RSA-OAEP를 사용하고,
패키지가 없는 학습 환경에서는 HMAC 기반 데모 모드로 실행된다. 데모 모드는 연구 흐름 검증용이며
운영 암호화로 사용하지 않는다.
