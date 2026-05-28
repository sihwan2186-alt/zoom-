# 연구 진행 현황 체크리스트

- 연구 제목: 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 동적 자동화 진단 도구(OWASP ZAP)의 취약점 탐지 효과성 비교 분석
- 점검일: 2026-05-27
- 기준 산출물: `final_security_report.md`, `reports/stride_zap_comparison.md`, `reports/stride_zap_summary.json`, `reports/stride_findings.json`, `reports/zap-secure-report.json`

## 1. 전체 진행 요약

| 구분 | 현재 상태 | 산출물 | 남은 작업 |
| --- | --- | --- | --- |
| 연구 주제 확정 | 완료 | `final_security_report.md` | 제목/초록 문장만 최종 다듬기 |
| 선행연구 정리 | 완료 | `paper_korean_summary.md` | `08887256.pdf`는 OCR 또는 수동 확인 전까지 제외 |
| 실험 A: STRIDE | 완료 | `Microsoft Threat Modeling Tool 기반 STRIDE.pdf`, `reports/stride_findings.json` | 지도교수 피드백에 따라 위협 항목 추가 가능 |
| 실험 B: OWASP ZAP | 완료 | `reports/zap-report.*`, `reports/zap-secure-report.*` | 보안 헤더 적용 전후 차이는 본문 해석에 반영 완료 |
| OWASP Top 10 매핑 | 완료 | `reports/stride_zap_comparison.md`, `reports/stride_zap_summary.json`, `reports/stride_zap_secure_comparison.md` | 추가 실험 시 수치 갱신 |
| 오탐 분석 | 완료 | `reports/stride_zap_comparison.md`의 ZAP 경고별 오탐 검토 | 실제 응답 헤더 캡처를 증거로 추가하면 더 탄탄함 |
| 시각화 자료 | 완료 | Mermaid 그래프, 탐지 범위 매트릭스 | 논문 제출 양식에서는 이미지 또는 표로 변환 필요 |
| 논문 초안 | 완료 | `paper_draft.md`, `논문 진짜 작성하는 곳.docx`, `논문_작성본_STRIDE_ZAP.docx` | 저자명/소속만 실제 정보로 교체 필요 |

## 2. 6주 계획 대비 진행률

| 주차 | 계획 | 진행 상태 | 근거 파일 |
| --- | --- | --- | --- |
| 1주차 | 선행 연구 조사 및 환경 준비 | 대부분 완료 | `paper_korean_summary.md`, `jitsi_meet_security_lab.md`, `README.md` |
| 2주차 | STRIDE 위협 모델링 및 DREAD 점수화 | 완료 | `reports/stride_findings.json` |
| 3주차 | OWASP ZAP 동적 진단 | 완료 | `reports/zap-report.*`, `reports/zap-secure-report.*` |
| 4주차 | OWASP Top 10 매핑, 오탐 분석, 시각화 | 완료 | `reports/stride_zap_comparison.md`, `reports/stride_zap_secure_comparison.md` |
| 5주차 | 논문 초안 작성 | 완료 | `paper_draft.md` |
| 6주차 | 수정 및 제출 준비 | 대부분 완료 | `논문 진짜 작성하는 곳.docx` 양식 반영 완료, 저자 정보 최종 입력 필요 |

## 3. 현재 정량 결과

| 지표 | STRIDE | OWASP ZAP | 해석 |
| --- | ---: | ---: | --- |
| 유효 탐지/경고 수 | 9건 | 4건 | ZAP은 인스턴스 기준 8건 |
| OWASP Top 10 커버리지 | 8/10, 80.0% | 1/10, 10.0% | 두 방법 모두 A05에서 겹침 |
| 단독 탐지 영역 | A01, A02, A03, A04, A07, A08, A09 | 없음 | ZAP의 단독 경고는 OWASP 미매핑 정보성 1건 |
| 미탐지 영역 | A06, A10 | A01, A02, A03, A04, A06, A07, A08, A09, A10 | 현재 정적 페이지 중심 실험의 한계 |
| 오탐 후보 | 0건 | 1건 | `10109 Modern Web Application` |
| 위험도 점수 | DREAD 합계 347 | 가중 위험 점수 10 | STRIDE는 설계 위험 우선순위 산출에 유리 |

## 4. 지금 더 하면 좋은 작업 우선순위

| 우선순위 | 작업 | 이유 |
| ---: | --- | --- |
| 1 | 저자명, 소속, 이메일 실제 정보 입력 | 현재 작성본은 양식용 placeholder를 유지함 |
| 2 | Mermaid 그래프를 이미지로 캡처 | 학회 docx 양식에 그림으로 넣기 쉬움 |
| 3 | Nmap 또는 응답 헤더 원문 1회 저장 | ZAP 결과 외의 실행 환경 증거 보강 |
| 4 | STRIDE 분석 시간 입력 | 탐지 소요 시간 비교 지표 완성 |

## 5. 현재 한계 문장

본 연구는 로컬 실습용 화상회의 웹 클라이언트와 ZAP Baseline Scan 재스캔 결과를 중심으로 수행되었기 때문에, 실제 운영형 Jitsi Meet 전체 구성요소의 TURN, XMPP, Jicofo, Videobridge, 녹화 저장소까지 검증한 결과로 일반화하기에는 제한이 있다. 다만 6주 내 학부 수준 연구라는 조건에서는 STRIDE 기반 설계 위협과 ZAP 기반 실행 환경 경고를 동일한 OWASP Top 10 기준으로 매핑하고, 보안 헤더 적용 전후 경고 감소까지 확인했다는 점에서 실증적 의미가 있다.
