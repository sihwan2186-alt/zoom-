# 연구 진행 현황 체크리스트

- 연구 제목: 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 동적 자동화 진단 도구(OWASP ZAP)의 취약점 탐지 효과성 비교 분석
- 점검일: 2026-06-04
- 기준 산출물: `docs/final_security_report.md`, `reports/comparison/stride_zap_comparison.md`, `reports/comparison/stride_zap_summary.json`, `reports/stride/stride_findings.json`, `reports/zap/secure/zap-secure-report.json`

## 1. 전체 진행 요약

| 구분 | 현재 상태 | 산출물 | 남은 작업 |
| --- | --- | --- | --- |
| 연구 주제 확정 | 완료 | `docs/final_security_report.md` | 제목/초록 문장만 최종 다듬기 |
| 선행연구 정리 | 완료 | `docs/literature_korean_summary.md` | `08887256.pdf`는 OCR 또는 수동 확인 전까지 제외 |
| 실험 A: STRIDE | 완료 | `references/stride/stride_threat_model.pdf`, `reports/stride/stride_findings.json` | 지도교수 피드백에 따라 위협 항목 추가 가능 |
| 실험 B: OWASP ZAP | 완료 | `reports/zap/baseline/zap-report.*`, `reports/zap/secure/zap-secure-report.*` | 보안 헤더 적용 전후 차이는 본문 해석에 반영 완료 |
| OWASP Top 10 매핑 | 완료 | `reports/comparison/stride_zap_comparison.md`, `reports/comparison/stride_zap_summary.json`, `reports/figures/*.png` | 추가 실험 시 수치 갱신 |
| 오탐 분석 | 완료 | `reports/comparison/stride_zap_comparison.md`의 ZAP 경고별 오탐 검토, `reports/evidence/execution_evidence_2026-06-01.md` | 응답 헤더와 포트 확인 증거 추가 완료 |
| 시각화 자료 | 완료 | `reports/figures/*.png`, 탐지 범위 매트릭스 | 제출용 PNG 이미지와 표 형태로 정리 완료 |
| 논문 초안 | 수정 반영 | `paper/paper_draft.md`, `paper/paper_submission_STRIDE_ZAP.docx` | 저자명/소속/이메일과 Jitsi Meet 보조 검증 문장 반영, 최종 오탈자 확인 필요 |
| Jitsi Meet 심층 조사 | 추가 완료 | `docs/jitsi_meet_deep_research.md` | Jitsi Meet 기능, 효과, 문제점을 중심으로 정리 |
| Jitsi Meet 실제 검증 | 추가 완료 | `docs/jitsi_meet_full_validation_report.md`, `reports/evidence/jitsi_meet_full_validation_2026-06-03.md` | Docker lab에서 인증/JWT/ICE/Jibri/ZAP/Nmap 결과 정리 |

## 2. 단계별 진행률

| 주차 | 계획 | 진행 상태 | 근거 파일 |
| --- | --- | --- | --- |
| 1주차 | 선행 연구 조사 및 환경 준비 | 대부분 완료 | `docs/literature_korean_summary.md`, `docs/jitsi_meet_security_lab.md`, `README.md` |
| 2주차 | STRIDE 위협 모델링 및 DREAD 점수화 | 완료 | `reports/stride/stride_findings.json` |
| 3주차 | OWASP ZAP 동적 진단 | 완료 | `reports/zap/baseline/zap-report.*`, `reports/zap/secure/zap-secure-report.*` |
| 4주차 | OWASP Top 10 매핑, 오탐 분석, 시각화 | 완료 | `reports/comparison/stride_zap_comparison.md`, `reports/figures/*.png` |
| 5주차 | 논문 초안 작성 | 완료 | `paper/paper_draft.md` |
| 최종 정리 | 수정 및 제출 준비 | 대부분 완료 | `paper/paper_submission_STRIDE_ZAP.docx` 양식 반영, 저자 정보와 Jitsi Meet 보조 검증 내용 반영 |

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
| 1 | 최종 제출 전 저자명, 소속, 이메일 오탈자 확인 | 원고 소스에는 실제 정보가 반영되었으나 제출 전 팀 확인 필요 |
| 2 | DOCX 양식과 그림/표 렌더링 최종 확인 | 원고를 다시 생성한 뒤 Word에서 표 폭, 그림 표시, 쪽 나눔 확인 필요 |
| 3 | Jibri recorder VirtualHost 수정 후 실제 녹화 파일 생성 검증 | 현재는 Jibri health와 Jicofo available까지 확인, end-to-end 녹화는 미완 |
| 4 | TURN relay 강제, persistent lobby, 모바일/부하 테스트 확장 | 운영망 일반화를 위해 남은 추가 실험 |

## 5. 현재 한계 문장

본 연구의 STRIDE-ZAP 정량 비교는 로컬 실습용 화상회의 웹 클라이언트와 ZAP Baseline Scan 재스캔 결과를 중심으로 수행되었다. 추가로 Jitsi Meet Docker lab에서 인증, JWT, ICE 후보, JVB, Jicofo, Jibri 기동까지 검증했지만, 실제 운영망의 장기 부하, TURN relay 강제, 녹화 파일 생성, 모바일 앱까지 일반화하려면 별도 운영 환경 검증이 필요하다. 다만 제한된 실습 환경 안에서 STRIDE 기반 설계 위협과 ZAP 기반 실행 환경 경고를 동일한 OWASP Top 10 기준으로 매핑하고, 보안 헤더 적용 전후 경고 감소와 Jitsi Meet 구성요소별 실제 점검 결과까지 확인했다는 점에서 실증적 의미가 있다.
