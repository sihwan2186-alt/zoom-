# 파일 안내

이 문서는 외부 확인자가 산출물의 위치와 역할을 빠르게 확인할 수 있도록 정리한 파일 지도이다.

## 논문

| 파일 | 역할 |
| --- | --- |
| `paper/paper_submission_STRIDE_ZAP.docx` | 제출용 논문 작성본 |
| `paper/paper_draft.md` | 논문 본문 원본 |
| `paper/paper_preview.html` | 브라우저 확인용 미리보기 |
| `paper/paper_preview.md` | Markdown 미리보기 |
| `paper/paper_template_original.docx` | 논문 양식 원본 백업 |

## 연구 설명

| 파일 | 역할 |
| --- | --- |
| `docs/final_security_report.md` | 전체 연구 설계, 반영 근거, 최종 결론 |
| `docs/research_progress_status.md` | 6주 일정 대비 진행 현황 |
| `docs/literature_korean_summary.md` | 참고 논문과 보안 용어 한글 해설 |
| `docs/limitations.md` | 연구 한계 |
| `docs/jitsi_meet_security_lab.md` | Jitsi Meet 실습 확장 가이드 |
| `docs/jitsi_meet_deep_research.md` | Jitsi Meet 기능, 효과, 문제점 심층 조사 |
| `docs/jitsi_meet_full_validation_report.md` | Jitsi Meet Docker lab, 인증/JWT/ICE/Jibri 실제 검증 보고서 |

## 실험 결과

| 폴더 | 역할 |
| --- | --- |
| `reports/stride/` | STRIDE 위협 9건과 DREAD 점수 입력 데이터 |
| `reports/zap/baseline/` | 보안 헤더 적용 전 ZAP 결과 |
| `reports/zap/secure/` | 보안 헤더 적용 후 ZAP 재스캔 결과 |
| `reports/comparison/` | STRIDE-ZAP 비교 보고서와 JSON 요약 |
| `reports/figures/` | 논문 삽입용 그래프 이미지 |
| `reports/evidence/` | 응답 헤더, 포트 확인, ZAP 요약 증거 |

## 참고 자료와 코드

| 폴더 | 역할 |
| --- | --- |
| `references/stride/` | STRIDE 분석 원본 발표/PDF 자료 |
| `화상회의/zoom-/` | 로컬 보안 실습 코드 |
| `jitsi-meet/` | 화상회의 구조 참고용 오픈소스 코드 |
| `tools/` | 검증, 그래프 생성, 논문 DOCX/HTML 생성 스크립트 |
