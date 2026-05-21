# 화상회의 STRIDE-ZAP 탐지 효과성 비교 프로젝트

이 저장소는 "화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 동적 자동화 진단 도구(OWASP ZAP)의 취약점 탐지 효과성 비교 분석"을 위한 최종 산출물이다. 특정 상용 서비스나 오픈소스 제품 소개가 아니라, 화상회의 아키텍처에서 두 보안 방법론이 어떤 취약점 범위를 탐지하는지 비교하는 데 초점을 둔다.

처음 실습하는 사람은 아래 순서대로 진행하면 된다.

1. 보안 헤더가 적용된 로컬 웹 페이지를 실행한다.
2. ZAP Baseline Scan으로 `zap-report.json`을 만든다.
3. STRIDE-ZAP 비교 스크립트로 `stride_zap_comparison.md`를 생성한다.

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

아래 명령은 개발자용 기본 검증이다. 코드가 실행 가능한지 확인하는 용도이며, 실제 ZAP/STRIDE 실습 절차는 뒤쪽의 `OWASP ZAP 실습 순서`와 `STRIDE 실습 순서`를 따르면 된다.

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

## 결과 파일 요약

실습 과정에서 생성되는 주요 파일은 `reports` 폴더에 모은다.

| 파일 | 생성 단계 | 용도 |
| --- | --- | --- |
| `zap-report.html` | ZAP Baseline Scan | 브라우저로 확인하는 ZAP 보고서 |
| `zap-report.md` | ZAP Baseline Scan | Markdown 형식 ZAP 보고서 |
| `zap-report.json` | ZAP Baseline Scan | STRIDE-ZAP 비교 스크립트 입력값 |
| `stride_zap_comparison.md` | 비교 스크립트 | STRIDE와 ZAP 탐지 효과성 비교 보고서 |
| `stride_zap_summary.json` | 비교 스크립트 | 비교 결과 원본 데이터 |
| `stride_sample_report.md` | STRIDE 샘플 실행 | 내장 STRIDE 샘플 기반 예비 보고서 |
| `stride_findings.csv` 또는 `stride_findings.json` | 사용자가 직접 작성 | 팀이 직접 수행한 STRIDE 분석 결과 |

## OWASP ZAP 실습 순서

이 절차는 ZAP을 처음 사용하는 사람을 기준으로 작성했다. ZAP은 웹 애플리케이션을 대상으로 취약점 진단을 수행하는 도구이며, 허가받지 않은 사이트에 실행하면 실제 공격으로 간주될 수 있다. 이 프로젝트에서는 반드시 본인 PC에서 실행한 로컬 실습 대상만 스캔한다.

### 1. 실습 전에 알아둘 용어

| 용어 | 뜻 |
| --- | --- |
| Target | ZAP이 검사할 웹 사이트 주소 |
| Spider | 웹 사이트 안의 링크와 페이지를 자동으로 찾아가는 과정 |
| Passive Scan | 요청과 응답을 관찰하면서 위험한 설정이나 노출 정보를 찾는 검사 |
| Active Scan | 실제 공격 패턴을 보내 취약점을 확인하는 검사 |
| Alert | ZAP이 발견한 의심 취약점 또는 보안 경고 |
| False Positive | 실제 취약점이 아닌데 취약점처럼 탐지된 오탐 |

초보자는 먼저 Docker 기반 Baseline Scan으로 실습한다. Baseline Scan은 Spider를 실행한 뒤 Passive Scan 결과를 보고하므로, Active Scan보다 부담이 작다.

### 2. 준비물 확인

PowerShell에서 아래 명령을 실행해 Python과 Docker가 준비되어 있는지 확인한다.

```powershell
python --version
docker --version
```

`python --version`이 실패하면 Python을 먼저 설치한다. `docker --version`이 실패하면 Docker Desktop을 설치하고 실행한 뒤 다시 확인한다.

ZAP Desktop으로 실습하려면 OWASP ZAP 설치 파일도 필요하다. Windows에서는 ZAP 실행을 위해 Java 17 이상이 필요할 수 있다.

### 3. 실습 대상 웹 페이지 실행

첫 번째 PowerShell 창에서 본인 PC의 프로젝트 폴더를 기준으로 웹 클라이언트 폴더로 이동한 뒤 보안 헤더가 포함된 로컬 웹 서버를 실행한다. 프로젝트 경로와 포트 번호는 사람마다 다를 수 있으므로, 아래 명령의 `$PROJECT_ROOT`와 `$PORT` 값을 본인 환경에 맞게 바꿔 실행한다.

```powershell
$PROJECT_ROOT = "본인 프로젝트 폴더 경로"
$PORT = "사용할 포트 번호"

Set-Location "$PROJECT_ROOT\화상회의\zoom-\client"
python .\secure_static_server.py --port $PORT
```

`$PORT`에는 현재 PC에서 비어 있는 포트 번호를 넣는다. 서버가 실행되면 이 PowerShell 창은 닫지 않는다. 아래 명령으로 브라우저 접속 주소를 만든 뒤, 출력된 주소를 브라우저에 열어 페이지가 보이면 준비가 끝난 것이다.

```powershell
$browserUrl = "http" + "://127.0.0.1:" + $PORT + "/"
$browserUrl
```

이 실습 대상은 정적 HTML 페이지지만, `secure_static_server.py`가 CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Cross-Origin 계열 헤더를 추가한다. 따라서 ZAP 결과는 실제 운영용 화상회의 서버 전체에 대한 진단 결과가 아니라, 실습용 페이지와 로컬 보안 헤더 구성을 대상으로 한 예비 진단 결과로 해석한다.

현재 `reports/zap-report.*` 파일은 기존 기준선 진단 산출물이다. 보안 헤더 서버를 적용한 뒤 ZAP을 다시 실행하면 CSP/브라우저 보안 헤더 관련 경고 변화까지 비교할 수 있다.

비교를 위해 Python 기본 서버를 써야 한다면 아래처럼 실행할 수 있다. 다만 이 경우 ZAP에서 보안 헤더 누락 경고가 더 많이 나오는 것이 정상이다.

```powershell
python -m http.server $PORT
```

### 4. Docker로 ZAP Baseline Scan 실행

두 번째 PowerShell 창을 열고 프로젝트 루트 폴더로 이동한다. 여기서도 `$PROJECT_ROOT`는 README 파일이 있는 본인 PC의 프로젝트 위치로 바꿔 사용한다.

```powershell
$PROJECT_ROOT = "본인 프로젝트 폴더 경로"
$PORT = "3번에서 사용한 포트 번호"

Set-Location $PROJECT_ROOT
```

ZAP 보고서를 저장할 폴더를 만든다.

```powershell
New-Item -ItemType Directory -Force reports
```

다음 명령으로 Baseline Scan을 실행한다.

```powershell
$reportDir = (Resolve-Path .\reports).Path
$targetUrl = "http" + "://host.docker.internal:" + $PORT + "/"
docker run --rm -v "${reportDir}:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t $targetUrl -m 5 -J zap-report.json -r zap-report.html -w zap-report.md -I
```

여기서 `$PORT`는 3번에서 Python 웹 서버를 실행할 때 사용한 포트와 같은 번호로 맞춘다. Docker 컨테이너는 내 PC의 로컬 서버에 직접 `127.0.0.1`로 접근하지 못할 수 있으므로, Docker 명령에서는 `host.docker.internal` 주소를 사용한다. 브라우저나 ZAP Desktop에서는 `127.0.0.1`과 `$PORT`를 조합한 주소로 접속하고, Docker 명령에서는 `host.docker.internal`과 `$PORT`를 조합한 주소로 접속한다고 이해하면 된다.

명령이 끝나면 `reports` 폴더에 다음 파일이 생성된다.

| 파일 | 용도 |
| --- | --- |
| `zap-report.html` | 사람이 읽기 좋은 ZAP HTML 보고서 |
| `zap-report.md` | Markdown 형식 보고서 |
| `zap-report.json` | 이 프로젝트의 STRIDE-ZAP 비교 스크립트에 넣을 ZAP 결과 |

HTML 보고서는 다음 명령으로 열 수 있다.

```powershell
Start-Process ".\reports\zap-report.html"
```

### 5. ZAP 결과를 STRIDE 비교 스크립트에 연결

ZAP이 만든 JSON 보고서를 이 프로젝트의 비교 스크립트에 입력한다.

```powershell
python "화상회의\zoom-\security\assessment\threat_zap_comparison.py" --zap-json ".\reports\zap-report.json" --zap-minutes 5 --output-md ".\reports\stride_zap_comparison.md" --output-json ".\reports\stride_zap_summary.json"
```

실행이 끝나면 `reports` 폴더에 비교 결과가 추가된다.

| 파일 | 용도 |
| --- | --- |
| `stride_zap_comparison.md` | STRIDE와 ZAP 탐지 결과를 비교한 Markdown 보고서 |
| `stride_zap_summary.json` | 비교 결과 원본 데이터 |

`stride_zap_comparison.md`에서 확인할 핵심은 다음이다.

- STRIDE와 ZAP가 공통으로 탐지한 영역
- STRIDE만 탐지한 설계·구조적 위협
- ZAP만 탐지한 실행 환경 취약점
- OWASP Top 10 기준 커버리지
- 우선적으로 보완해야 할 항목

### 6. ZAP Desktop으로 직접 눌러보는 방법

Docker 명령이 어렵다면 ZAP Desktop으로도 실습할 수 있다.

1. OWASP ZAP을 설치하고 실행한다.
2. 처음 실행할 때 세션 저장 여부를 물으면 실습용이므로 저장하지 않아도 된다.
3. 상단 또는 왼쪽의 `Quick Start` 탭을 연다.
4. `Automated Scan`을 선택한다.
5. URL 입력 칸에 3번에서 만든 브라우저 접속 주소를 입력한다.
6. `Attack` 버튼을 누른다.
7. 하단의 `Alerts` 탭에서 탐지 결과를 확인한다.

`Automated Scan`은 Active Scan을 포함할 수 있으므로 반드시 본인 로컬 실습 대상에만 사용한다. 외부 사이트, 학교 사이트, 회사 사이트, 실제 서비스에는 허가 없이 실행하지 않는다.

### 7. 결과 해석 방법

ZAP 결과는 높음, 중간, 낮음, 정보성 같은 위험도 등급으로 표시된다. 처음 볼 때는 모든 Alert를 취약점으로 확정하지 말고 다음 순서로 확인한다.

1. Alert 이름을 확인한다.
2. 어떤 URL에서 발생했는지 확인한다.
3. Response Header 또는 Response Body에서 근거가 있는지 확인한다.
4. 실제 프로젝트 코드에서 수정 가능한 항목인지 확인한다.
5. 오탐이면 비교 스크립트 실행 시 `--zap-false-positive-plugin-ids` 옵션으로 제외한다.

예를 들어 plugin ID `10020`을 오탐으로 제외하려면 다음처럼 실행한다.

```powershell
python "화상회의\zoom-\security\assessment\threat_zap_comparison.py" --zap-json ".\reports\zap-report.json" --zap-false-positive-plugin-ids "10020" --output-md ".\reports\stride_zap_comparison.md"
```

### 8. 자주 막히는 부분

| 증상 | 해결 방법 |
| --- | --- |
| 브라우저에서 로컬 주소가 열리지 않음 | 첫 번째 PowerShell에서 `python -m http.server $PORT`가 계속 실행 중인지 확인 |
| Docker에서 대상에 접속하지 못함 | Docker 명령의 `$targetUrl`이 3번에서 사용한 포트 번호와 같은지 확인 |
| ZAP 결과가 너무 적음 | 정적 HTML만 실행하면 탐지할 표면이 적을 수 있다. 이 경우 실습 목적상 정상이다. |
| WARN 때문에 실패처럼 보임 | Baseline Scan은 경고가 있으면 종료 코드가 경고로 나올 수 있다. 이 README 명령은 `-I` 옵션으로 경고를 실패 처리하지 않도록 했다. |
| JSON 파일이 없음 | Docker 명령에 `-J zap-report.json` 옵션이 포함되어 있는지 확인 |

참고 문서:

- [OWASP ZAP Getting Started](https://www.zaproxy.org/getting-started/)
- [OWASP ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [OWASP ZAP Docker User Guide](https://www.zaproxy.org/docs/docker/about/)

## STRIDE 실습 순서

이 절차는 STRIDE를 처음 접하는 사람을 기준으로 작성했다. ZAP은 도구를 실행해 결과를 얻는 방식이지만, STRIDE는 시스템 구조를 보고 가능한 위협을 빠뜨리지 않도록 분류하는 수동 분석 방법이다. 따라서 먼저 화상회의 시스템의 구성요소와 데이터 흐름을 적고, 각 지점에서 어떤 위협이 생길 수 있는지 질문하는 방식으로 진행한다.

### 1. STRIDE 용어 이해

STRIDE는 여섯 가지 위협 유형의 앞 글자를 모은 것이다.

| 분류 | 의미 | 화상회의 예시 |
| --- | --- | --- |
| S: Spoofing | 다른 사용자나 시스템인 척함 | 공격자가 다른 사용자 계정으로 로그인하거나 회의 호스트인 척함 |
| T: Tampering | 데이터나 요청을 변조함 | 회의 ID, 권한 토큰, 미디어 패킷을 바꿔서 전송함 |
| R: Repudiation | 행위 부인 | 사용자가 회의방 설정 변경이나 강제 퇴장 행위를 부인함 |
| I: Information Disclosure | 정보 노출 | 회의 링크, 참가자 이름, WebRTC IP, 토큰이 외부로 노출됨 |
| D: Denial of Service | 서비스 거부 | 과도한 요청이나 ReDoS 입력으로 회의 참여가 불가능해짐 |
| E: Elevation of Privilege | 권한 상승 | 일반 참가자가 호스트 권한을 얻거나 관리자 기능을 실행함 |

### 2. 분석 범위 정하기

처음부터 전체 시스템을 보려고 하면 어렵다. 이 프로젝트에서는 아래 범위만 대상으로 잡는다.

| 분석 범위 | 포함 내용 |
| --- | --- |
| 사용자 | 회의 생성자, 일반 참가자, 비로그인 접근자 |
| 클라이언트 | `화상회의/zoom-/client/index.html` |
| 인증 | 로그인, MFA, 회의방/역할 바인딩 토큰 |
| 세션 | 쿠키, CSRF 토큰, 세션 만료 |
| 회의방 | 회의 ID, 초대 링크, 참가자 권한 |
| 미디어 | 영상·음성 패킷, 암호화, replay 탐지 |
| 개인정보 | 표시명, 회의 링크, ICE 후보, 아바타 URL |

### 3. 데이터 흐름 간단히 그리기

종이에 그리거나 Markdown에 아래처럼 적으면 된다. 중요한 것은 “누가 누구에게 어떤 데이터를 보내는지”를 보이게 만드는 것이다.

```text
[사용자]
  -> 로그인 정보 입력
[브라우저 클라이언트]
  -> 인증 요청
[인증 모듈]
  -> 토큰 발급
[브라우저 클라이언트]
  -> 회의 ID와 토큰으로 회의방 참여
[회의방/세션 관리]
  -> 미디어 송수신
[미디어 암호화 모듈]
```

그 다음 신뢰 경계를 표시한다. 신뢰 경계는 “여기부터는 다른 권한 또는 다른 보안 수준의 영역”이라고 보면 된다.

| 신뢰 경계 | 설명 |
| --- | --- |
| 사용자 입력 경계 | 사용자가 입력한 회의 ID, 표시명, 로그인 정보는 신뢰할 수 없음 |
| 브라우저-서버 경계 | 요청이 네트워크를 통해 이동하므로 탈취·변조 가능성이 있음 |
| 인증-회의방 경계 | 로그인한 사용자라도 특정 회의방 권한이 있는지는 별도 확인 필요 |
| 미디어 경계 | 영상·음성 데이터는 도청, 변조, 재전송 위험이 있음 |
| 외부 서비스 경계 | 아바타 URL, 외부 iframe, 제3자 요청은 정보 노출 위험이 있음 |

### 4. STRIDE 질문하기

각 구성요소마다 아래 질문을 던진다. 답이 “그럴 수 있다”이면 위협 후보로 기록한다.

| STRIDE | 질문 |
| --- | --- |
| Spoofing | 공격자가 다른 사용자, 호스트, 서버인 척할 수 있는가? |
| Tampering | 회의 ID, 토큰, 요청 파라미터, 미디어 데이터가 변조될 수 있는가? |
| Repudiation | 누가 어떤 행동을 했는지 나중에 확인할 로그가 부족한가? |
| Information Disclosure | 회의 링크, 참가자 정보, IP, 토큰, 미디어가 노출될 수 있는가? |
| Denial of Service | 많은 요청, 긴 입력, 악성 정규식, 반복 접속으로 서비스가 멈출 수 있는가? |
| Elevation of Privilege | 일반 참가자가 호스트나 관리자 권한을 얻을 수 있는가? |

### 5. 위협 목록 작성하기

아래 표를 복사해서 실습용 STRIDE 분석표로 사용한다.

| ID | 구성요소 | STRIDE 분류 | 위협 설명 | 영향 | 기존 방어책 | 추가 보완책 |
| --- | --- | --- | --- | --- | --- | --- |
| S-01 | 인증 | Spoofing | 공격자가 탈취한 토큰으로 다른 사용자처럼 회의에 참여할 수 있음 | 무단 회의 참여 | 토큰 만료 | 회의방/역할 claim 검증, 토큰 폐기 목록 |
| I-01 | 회의 링크 | Information Disclosure | 회의 초대 링크가 로그나 화면 공유로 노출될 수 있음 | 외부인 접속 | 회의 ID 난수화 | 링크 마스킹, 대기실, 호스트 승인 |
| D-01 | 입력 검증 | Denial of Service | 매우 긴 표시명이나 위험한 정규식 입력으로 처리 지연 가능 | 회의 참여 장애 | 길이 제한 | ReDoS 위험 패턴 차단 |

새 위협을 추가할 때는 ID를 `S-02`, `T-01`, `I-02`처럼 분류별로 붙이면 나중에 정리하기 쉽다.

### 6. DREAD로 위험도 점수 매기기

이 프로젝트에서는 STRIDE로 찾은 위협의 우선순위를 정하기 위해 DREAD 점수를 함께 사용할 수 있다. 각 항목은 1점에서 5점으로 평가한다.

| 항목 | 의미 | 점수 기준 |
| --- | --- | --- |
| Damage | 피해 규모 | 1점은 영향 작음, 5점은 계정 탈취·회의 도청처럼 영향 큼 |
| Reproducibility | 재현 가능성 | 1점은 조건이 까다로움, 5점은 누구나 반복 가능 |
| Exploitability | 공격 난이도 | 1점은 어렵고, 5점은 간단한 URL·요청 조작으로 가능 |
| Affected Users | 영향 사용자 범위 | 1점은 일부 사용자, 5점은 전체 회의 또는 전체 사용자 |
| Discoverability | 발견 쉬움 | 1점은 내부 지식 필요, 5점은 화면·URL·응답만 봐도 알 수 있음 |

예시는 다음과 같다.

| ID | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | 평균 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| S-01 | 5 | 4 | 3 | 4 | 3 | 3.8 |
| I-01 | 4 | 5 | 4 | 3 | 5 | 4.2 |
| D-01 | 3 | 3 | 3 | 4 | 2 | 3.0 |

평균 점수가 높은 항목부터 먼저 보완 대상으로 잡는다.

### 7. 이 프로젝트의 STRIDE 샘플 보고서 실행

이 프로젝트에는 화상회의 환경을 기준으로 작성된 STRIDE 샘플 항목이 비교 스크립트 안에 들어 있다. PowerShell에서 본인 PC의 프로젝트 루트로 이동한 뒤 실행한다.

```powershell
$PROJECT_ROOT = "본인 프로젝트 폴더 경로"

Set-Location $PROJECT_ROOT
New-Item -ItemType Directory -Force reports
python "화상회의\zoom-\security\assessment\threat_zap_comparison.py" --output-md ".\reports\stride_sample_report.md" --output-json ".\reports\stride_sample_summary.json"
```

이 명령은 실제 ZAP JSON을 넣지 않았으므로 내장 샘플 ZAP 경고와 내장 STRIDE 항목을 사용한다. 결과 파일에서 STRIDE 항목이 OWASP Top 10 기준으로 어떻게 매핑되는지 확인할 수 있다.

### 8. 직접 작성한 STRIDE 결과 입력하기

직접 작성한 STRIDE 분석표는 CSV 또는 JSON으로 저장한 뒤 비교 스크립트에 입력할 수 있다.

CSV 파일은 아래 헤더를 사용한다.

```csv
id,component,threat,description,damage,reproducibility,exploitability,affected_users,discoverability,owasp_categories
I-01,회의 링크,Information Disclosure,회의 링크 노출로 외부인이 접근할 수 있음,4,5,4,3,5,A01
E-01,회의방 권한,Elevation of Privilege,일반 참가자가 호스트 권한을 획득할 수 있음,5,4,4,4,4,A01
```

예를 들어 `reports/stride_findings.csv`로 저장했다면 다음처럼 실행한다.

```powershell
python "화상회의\zoom-\security\assessment\threat_zap_comparison.py" --stride-csv ".\reports\stride_findings.csv" --zap-json ".\reports\zap-report.json" --output-md ".\reports\stride_zap_comparison.md"
```

JSON 파일은 아래 형식을 사용한다.

```json
{
  "findings": [
    {
      "id": "I-01",
      "component": "회의 링크",
      "threat": "Information Disclosure",
      "description": "회의 링크 노출로 외부인이 접근할 수 있음",
      "damage": 4,
      "reproducibility": 5,
      "exploitability": 4,
      "affected_users": 3,
      "discoverability": 5,
      "owasp_categories": ["A01"]
    }
  ]
}
```

JSON으로 저장했다면 다음처럼 실행한다.

```powershell
python "화상회의\zoom-\security\assessment\threat_zap_comparison.py" --stride-json ".\reports\stride_findings.json" --zap-json ".\reports\zap-report.json" --output-md ".\reports\stride_zap_comparison.md"
```

### 9. 직접 작성한 STRIDE 결과 검토하기

직접 작성한 STRIDE 표를 보고 다음을 확인한다.

| 확인 항목 | 질문 |
| --- | --- |
| 누락 확인 | 인증, 세션, 회의방, 미디어, 개인정보, 입력 검증을 모두 봤는가? |
| 분류 확인 | 각 위협이 S/T/R/I/D/E 중 어디에 해당하는지 설명할 수 있는가? |
| 근거 확인 | 해당 위협이 실제 코드나 데이터 흐름에서 발생 가능한 이유가 있는가? |
| 보완책 확인 | 단순히 위험하다고 쓰는 데서 끝나지 않고 완화책을 제시했는가? |
| ZAP 비교 | ZAP이 탐지할 수 있는 실행 환경 취약점인지, STRIDE로만 보이는 설계 위협인지 구분했는가? |

예를 들어 “참가자 변경 후 이전 참가자가 미디어 키를 계속 알 수 있음”은 STRIDE의 Information Disclosure 또는 Elevation of Privilege에 해당할 수 있다. 그러나 이런 그룹 키 갱신 문제는 일반적인 ZAP 웹 스캔만으로는 직접 탐지하기 어렵다. 반대로 “X-Frame-Options 헤더 누락”은 ZAP이 잘 탐지하지만, STRIDE 분석에서는 브라우저 보안 정책 검토를 하지 않으면 빠뜨리기 쉽다.

### 10. STRIDE 결과를 보고서에 반영하는 방법

최종 보고서에는 아래 형식으로 정리하면 된다.

```markdown
| ID | 구성요소 | STRIDE | 위협 | OWASP Top 10 매핑 | DREAD 평균 | 대응 우선순위 |
| --- | --- | --- | --- | --- | ---: | --- |
| I-01 | 회의 링크 | Information Disclosure | 회의 링크 노출로 외부인이 접근할 수 있음 | A01 Broken Access Control | 4.2 | 높음 |
| E-01 | 회의방 권한 | Elevation of Privilege | 일반 참가자가 호스트 권한을 획득할 수 있음 | A01 Broken Access Control | 4.4 | 높음 |
| D-01 | 입력 검증 | Denial of Service | ReDoS 입력으로 회의 참여가 지연될 수 있음 | A03 Injection | 3.0 | 중간 |
```

보고서 문장으로는 다음처럼 정리한다.

```text
STRIDE 분석 결과, 화상회의 시스템에서는 회의방 권한 검증, 회의 링크 노출, WebRTC 미디어 경로, 그룹 키 갱신과 같은 설계·구조적 위협이 주요하게 식별되었다. 이 중 일부는 ZAP이 탐지하는 웹 취약점과 겹치지만, 미디어 암호화와 권한 모델처럼 실행 환경 스캔만으로 확인하기 어려운 항목은 STRIDE 분석을 통해 보완적으로 도출되었다.
```

### 11. STRIDE 실습 시 주의할 점

| 주의점 | 설명 |
| --- | --- |
| 취약점 이름만 나열하지 않기 | 반드시 어떤 구성요소에서 왜 발생하는지 적어야 한다. |
| 코드만 보지 않기 | STRIDE는 코드 취약점뿐 아니라 설계·권한·데이터 흐름 위협도 본다. |
| ZAP 결과와 혼동하지 않기 | ZAP은 실행 중인 웹 앱을 검사하고, STRIDE는 구조와 설계를 분석한다. |
| 모든 항목을 높음으로 주지 않기 | DREAD 점수로 우선순위를 구분해야 한다. |
| 완화책까지 적기 | 위협 설명만 쓰면 분석이 끝나지 않는다. 대응 방안까지 연결한다. |
