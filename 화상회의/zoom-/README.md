# Zoom 보안 분석 및 Jitsi Meet 기반 보완 프로젝트

## 프로젝트 개요
- **프로젝트명**: zoom- (화상회의 보안 강화)
- **목적**: Zoom 취약점 분석 및 Jitsi Meet 기반 보완方案 구현
- **기술 스택**: Python, Java

## 보안 취약점 분석 분야

### 1. 암호화 보안 (Encryption)
- Zoom 종단 간 암호화(E2EE) 미흡 문제
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
- 탐지 건수, 커버리지, 중복 탐지 카테고리, 상호 보완 탐지 영역 산출
- 학부 논문 주제인 “STRIDE 위협 모델링과 OWASP ZAP 동적 자동화 진단의 취약점 탐지 효과성 비교 분석” 실험 데이터 정리 지원

## 디렉토리 구조
```
zoom-/
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
python -m compileall 화상회의/zoom-
python 화상회의/zoom-/security/encryption/encryption.py
python 화상회의/zoom-/security/assessment/threat_zap_comparison.py
javac -encoding UTF-8 -d .tmp_classes 화상회의/zoom-/security/authentication/AuthModule.java
java -cp .tmp_classes com.zoom.security.authentication.AuthModule
```

`encryption.py`는 `cryptography` 패키지가 설치된 환경에서는 AES-256-GCM/RSA-OAEP를 사용하고,
패키지가 없는 학습 환경에서는 HMAC 기반 데모 모드로 실행된다. 데모 모드는 연구 흐름 검증용이며
운영 암호화로 사용하지 않는다.
