# 화상회의 STRIDE-ZAP 탐지 효과성 비교 연구

이 저장소는 화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP 동적 진단의 취약점 탐지 효과성을 비교한 학부 연구 산출물이다. 특정 제품을 평가하기보다, 설계 기반 분석과 실행 환경 스캔이 어떤 취약점 범위를 다르게 탐지하는지 OWASP Top 10 기준으로 정리한다.

## 먼저 볼 파일

| 목적 | 파일 |
| --- | --- |
| 제출용 논문 | `paper/paper_submission_STRIDE_ZAP.docx` |
| 논문 초안 원본 | `paper/paper_draft.md` |
| 브라우저 미리보기 | `paper/paper_preview.html` |
| 최종 연구 요약 | `docs/final_security_report.md` |
| Jitsi Meet 심층 조사 | `docs/jitsi_meet_deep_research.md` |
| Jitsi Meet 실제 검증 보고서 | `docs/jitsi_meet_full_validation_report.md` |
| 진행 현황 | `docs/research_progress_status.md` |
| 비교 결과 보고서 | `reports/comparison/stride_zap_comparison.md` |
| 실행 증거 | `reports/evidence/execution_evidence_2026-06-01.md` |

## 폴더 구조

```text
.
├─ README.md
├─ paper/                 # 논문 원본, 미리보기, 제출용 DOCX
├─ docs/                  # 연구 설명, 진행 현황, 한계, 실습 가이드
├─ reports/
│  ├─ comparison/         # STRIDE-ZAP 정량 비교 결과
│  ├─ figures/            # 논문 삽입용 그래프 PNG
│  ├─ stride/             # STRIDE 입력 데이터
│  ├─ zap/                # ZAP 기준선/보안헤더 적용 후 보고서
│  └─ evidence/           # 응답 헤더와 실행 증거
├─ references/stride/     # STRIDE 원본 발표/PDF 자료
├─ tools/                 # 보고서·논문 재생성 및 검증 스크립트
├─ 화상회의/zoom-/        # 로컬 보안 실습 코드
└─ jitsi-meet/            # 화상회의 구조 참고용 오픈소스 코드
```

## 핵심 결과

| 지표 | STRIDE | OWASP ZAP | 해석 |
| --- | ---: | ---: | --- |
| 유효 탐지/경고 수 | 9건 | 4건 | ZAP은 인스턴스 기준 8건 |
| OWASP Top 10 커버리지 | 8/10, 80.0% | 1/10, 10.0% | 공통 영역은 A05 |
| 단독 탐지 영역 | A01, A02, A03, A04, A07, A08, A09 | 없음 | ZAP의 단독 경고는 OWASP 미매핑 정보성 1건 |
| 위험도 점수 | DREAD 합계 347 | 가중 위험 점수 10 | STRIDE는 설계 위험 우선순위화에 유리 |
| 소요시간 지표 | 75분, 0.12건/분 | 5분, 0.80건/분 | ZAP은 보완 후 반복 검증에 유리 |

보안 헤더 적용 전 ZAP Baseline Scan에서는 경고 13건과 인스턴스 19건이 수집되었고, 보안 헤더 적용 후에는 경고 4건과 인스턴스 8건으로 감소하였다.

## 산출물 위치

| 구분 | 위치 |
| --- | --- |
| STRIDE 원본 자료 | `references/stride/stride_threat_model.pdf`, `references/stride/stride_threat_model.pptx` |
| STRIDE 정리 데이터 | `reports/stride/stride_findings.json` |
| ZAP 기준선 보고서 | `reports/zap/baseline/zap-report.*` |
| ZAP 보안 헤더 적용 후 보고서 | `reports/zap/secure/zap-secure-report.*` |
| 비교 보고서 | `reports/comparison/stride_zap_comparison.md` |
| 비교 원본 데이터 | `reports/comparison/stride_zap_summary.json` |
| Jitsi Meet 심층 조사 | `docs/jitsi_meet_deep_research.md` |
| Jitsi Meet 실제 검증 보고서 | `docs/jitsi_meet_full_validation_report.md` |
| 논문 그래프 | `reports/figures/*.png` |
| 응답 헤더 증거 | `reports/evidence/*.txt`, `reports/evidence/*.md` |

## 재생성 방법

전체 검증과 산출물 갱신을 한 번에 수행한다.

```powershell
.\tools\validate.ps1
```

논문 생성은 건너뛰고 코드와 비교 결과만 확인하려면 다음을 실행한다.

```powershell
.\tools\validate.ps1 -SkipPaperBuild
```

수동으로 비교 보고서만 다시 만들 때는 다음 명령을 사용한다.

```powershell
python ".\화상회의\zoom-\security\assessment\threat_zap_comparison.py" `
  --stride-json ".\reports\stride\stride_findings.json" `
  --zap-json ".\reports\zap\secure\zap-secure-report.json" `
  --stride-minutes 75 `
  --zap-minutes 5 `
  --output-md ".\reports\comparison\stride_zap_comparison.md" `
  --output-json ".\reports\comparison\stride_zap_summary.json"

python .\tools\build_figures.py
python .\tools\build_vsc_paper.py
python .\tools\build_paper_docx.py
```

## 로컬 ZAP 실험 흐름

- 보안 헤더가 적용된 로컬 서버를 실행한다.

```powershell
cd ".\화상회의\zoom-\client"
python .\secure_static_server.py --port 8000
```

- 다른 PowerShell 창에서 ZAP Baseline Scan을 실행한다.

```powershell
$reportDir = (Resolve-Path ".\reports\zap\secure").Path
docker run --rm -v "${reportDir}:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8000/ -m 5 -J zap-secure-report.json -r zap-secure-report.html -w zap-secure-report.md -I
```

- 비교 보고서와 그래프를 다시 생성한다.

```powershell
.\tools\validate.ps1
```

## 문서 수정 규칙

- 논문 본문은 `paper/paper_draft.md`를 수정한다.
- `paper/paper_preview.md`, `paper/paper_preview.html`, `paper/paper_submission_STRIDE_ZAP.docx`는 스크립트로 다시 생성되는 결과물이다.
- 연구 설명 문서는 `docs/`에, 실험 원자료는 `reports/`에, 참고 발표 자료는 `references/`에 둔다.

## 한계

본 연구의 STRIDE-ZAP 정량 비교는 로컬 실습용 화상회의 웹 클라이언트와 OWASP ZAP Baseline Scan 결과를 중심으로 수행되었다. 추가로 Jitsi Meet Docker lab에서 인증, JWT, ICE 후보, JVB, Jicofo, Jibri 기동까지 검증했지만, 실제 운영망의 장기 부하, TURN relay 강제, 녹화 파일 생성, 모바일 앱까지 일반화하려면 별도 운영 환경 검증이 필요하다.
