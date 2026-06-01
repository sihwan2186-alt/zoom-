"""
STRIDE 위협 모델링과 OWASP ZAP 동적 진단 결과 비교 유틸리티.

연구 주제:
화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP의
취약점 탐지 효과성 비교 분석
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set


DEFAULT_TAXONOMY_VERSION = "2021"

# OWASP Top 10의 영문 카테고리명은 공식 명칭이라 그대로 보존한다.
# 대신 KOREAN_OWASP_HELP와 KOREAN_SECURITY_GLOSSARY를 보고서에 함께 출력해,
# 영어를 모르는 실습자도 각 항목이 무엇을 뜻하는지 바로 확인할 수 있게 한다.
OWASP_TAXONOMIES = {
    "2021": {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery",
    },
    "2025": {
        "A01": "Broken Access Control",
        "A02": "Security Misconfiguration",
        "A03": "Software Supply Chain Failures",
        "A04": "Cryptographic Failures",
        "A05": "Injection",
        "A06": "Insecure Design",
        "A07": "Authentication Failures",
        "A08": "Software or Data Integrity Failures",
        "A09": "Security Logging and Alerting Failures",
        "A10": "Mishandling of Exceptional Conditions",
    },
}

STRIDE_TO_OWASP = {
    "2021": {
        "Spoofing": {"A01", "A07"},
        "Tampering": {"A03", "A08"},
        "Repudiation": {"A09"},
        "Information Disclosure": {"A02", "A05"},
        "Denial of Service": {"A05"},
        "Elevation of Privilege": {"A01", "A04"},
    },
    "2025": {
        "Spoofing": {"A01", "A07"},
        "Tampering": {"A05", "A08"},
        "Repudiation": {"A09"},
        "Information Disclosure": {"A02", "A04"},
        "Denial of Service": {"A02", "A10"},
        "Elevation of Privilege": {"A01", "A06"},
    },
}

ZAP_PLUGIN_TO_OWASP = {
    "2021": {
        "2": "A05",       # Private IP Disclosure
        "3": "A05",       # Session ID in URL Rewrite
        "10010": "A05",   # Cookie No HttpOnly Flag
        "10011": "A02",   # Cookie Without Secure Flag
        "10015": "A05",   # Cache-control and Pragma Header
        "10016": "A05",   # Web Browser XSS Protection
        "10017": "A05",   # Cross-Domain JavaScript Inclusion
        "10019": "A05",   # Content-Type Header Missing
        "10020": "A05",   # X-Frame-Options Header
        "10021": "A05",   # X-Content-Type-Options Header
        "10023": "A05",   # Debug Error Messages
        "10024": "A05",   # Sensitive Information in URL
        "10025": "A05",   # Sensitive Information in Referrer
        "10027": "A05",   # Suspicious Comments
        "10035": "A05",   # Strict-Transport-Security Header
        "10036": "A05",   # Server Leaks Version Information
        "10038": "A05",   # Content Security Policy Header
        "10049": "A05",   # Storable and Cacheable Content
        "10054": "A05",   # Cookie Without SameSite Attribute
        "10055": "A05",   # CSP Scanner Findings
        "10063": "A05",   # Permissions Policy Header
        "10096": "A06",   # Vulnerable JS Library
        "40012": "A03",   # Cross Site Scripting
        "40014": "A01",   # Absence of Anti-CSRF Tokens
        "40018": "A03",   # SQL Injection
        "40035": "A03",   # Server Side Code Injection
        "40045": "A01",   # Spring Actuator Information Leak
        "90004": "A05",   # Cross-Origin Policy Headers
        "90022": "A05",   # Application Error Disclosure
        "90033": "A05",   # Loosely Scoped Cookie
    },
    "2025": {
        "2": "A02",
        "3": "A02",
        "10010": "A02",
        "10011": "A04",
        "10015": "A02",
        "10016": "A02",
        "10017": "A02",
        "10019": "A02",
        "10020": "A02",
        "10021": "A02",
        "10023": "A02",
        "10024": "A02",
        "10025": "A02",
        "10027": "A02",
        "10035": "A04",
        "10036": "A02",
        "10038": "A02",
        "10049": "A02",
        "10054": "A02",
        "10055": "A02",
        "10063": "A02",
        "10096": "A03",
        "40012": "A05",
        "40014": "A01",
        "40018": "A05",
        "40035": "A05",
        "40045": "A01",
        "90004": "A02",
        "90022": "A10",
        "90033": "A02",
    },
}

ZAP_KEYWORD_TO_OWASP = {
    "2021": (
        ("strict-transport-security", "A02"),
        ("secure flag", "A02"),
        ("vulnerable js", "A06"),
        ("outdated", "A06"),
        ("x-frame-options", "A05"),
        ("content security policy", "A05"),
        ("content-type", "A05"),
        ("cache-control", "A05"),
        ("pragma", "A05"),
        ("cookie", "A05"),
        ("httponly", "A05"),
        ("server leaks", "A05"),
        ("error disclosure", "A05"),
        ("cross-domain", "A05"),
        ("xss", "A03"),
        ("cross site scripting", "A03"),
        ("sql injection", "A03"),
        ("path traversal", "A01"),
        ("authentication", "A07"),
        ("csrf", "A01"),
        ("ssrf", "A10"),
    ),
    "2025": (
        ("strict-transport-security", "A04"),
        ("secure flag", "A04"),
        ("vulnerable js", "A03"),
        ("outdated", "A03"),
        ("supply chain", "A03"),
        ("x-frame-options", "A02"),
        ("content security policy", "A02"),
        ("content-type", "A02"),
        ("cache-control", "A02"),
        ("pragma", "A02"),
        ("cookie", "A02"),
        ("httponly", "A02"),
        ("server leaks", "A02"),
        ("error disclosure", "A10"),
        ("exception", "A10"),
        ("cross-domain", "A02"),
        ("xss", "A05"),
        ("cross site scripting", "A05"),
        ("sql injection", "A05"),
        ("path traversal", "A01"),
        ("authentication", "A07"),
        ("csrf", "A01"),
        ("ssrf", "A06"),
    ),
}

RISK_WEIGHT = {
    "Informational": 1,
    "Info": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}

ZAP_REVIEW_NOTES = {
    "10020": {
        "triage": "유효 경고",
        "false_positive_likelihood": "낮음",
        "analysis": "frame-ancestors 또는 X-Frame-Options가 없으면 회의 화면 clickjacking 위험이 남는다.",
    },
    "10021": {
        "triage": "유효 경고",
        "false_positive_likelihood": "낮음",
        "analysis": "X-Content-Type-Options 누락은 브라우저 MIME sniffing 완화책이 빠진 상태다.",
    },
    "10036": {
        "triage": "환경 의존",
        "false_positive_likelihood": "중간",
        "analysis": "Server 헤더의 상세 버전이 실제 공격 단서가 되는지 배포 서버 기준으로 확인해야 한다.",
    },
    "10038": {
        "triage": "유효 경고",
        "false_positive_likelihood": "낮음",
        "analysis": "CSP 미설정은 XSS와 외부 리소스 삽입의 피해 범위를 키울 수 있다.",
    },
    "10049": {
        "triage": "환경 의존",
        "false_positive_likelihood": "중간",
        "analysis": "정적 파일만 캐시되면 영향이 낮지만 회의 링크, 토큰, 사용자 정보가 포함되면 유효 취약점이다.",
    },
    "10055": {
        "triage": "유효 경고",
        "false_positive_likelihood": "낮음",
        "analysis": "CSP fallback 지시어 누락 또는 unsafe-inline은 브라우저 정책 우회면을 넓힌다.",
    },
    "10063": {
        "triage": "유효 경고",
        "false_positive_likelihood": "낮음",
        "analysis": "Permissions-Policy가 없으면 카메라, 마이크, 위치 같은 브라우저 기능 제한 의도가 불명확하다.",
    },
    "10109": {
        "triage": "오탐 후보",
        "false_positive_likelihood": "높음",
        "analysis": "Modern Web Application은 앱 구조 식별 신호에 가까워 직접 취약점으로 보기는 어렵다.",
    },
    "90004": {
        "triage": "유효 경고",
        "false_positive_likelihood": "낮음",
        "analysis": "COOP/CORP/COEP 누락은 교차 출처 격리와 리소스 경계 정책 미흡으로 해석할 수 있다.",
    },
}

KOREAN_OWASP_HELP = {
    "A01": "접근통제 실패: 권한 없는 사용자가 회의방, 관리자 기능, 참가자 제어 기능에 접근하는 문제",
    "A02": "암호화 실패: 토큰, 미디어, 개인정보가 안전하게 암호화되지 않거나 키 관리가 약한 문제",
    "A03": "주입 공격: XSS, SQL Injection, 명령 주입처럼 입력값이 코드나 명령으로 실행되는 문제",
    "A04": "불안전한 설계: 구현 버그 이전에 구조, 권한 모델, 신뢰 경계 자체가 약한 문제",
    "A05": "보안 설정 오류: CSP, X-Frame-Options, 쿠키 속성, 서버 헤더 같은 설정이 빠진 문제",
    "A06": "취약하거나 오래된 구성요소: 오래된 라이브러리나 알려진 취약점이 있는 패키지 사용 문제",
    "A07": "식별·인증 실패: 로그인, MFA, 토큰 검증, 세션 인증이 충분하지 않은 문제",
    "A08": "소프트웨어·데이터 무결성 실패: 업데이트, 의존성, 미디어 데이터가 변조될 수 있는 문제",
    "A09": "로깅·모니터링 실패: 누가 무엇을 했는지 기록하거나 탐지하지 못하는 문제",
    "A10": "서버 측 요청 위조: 서버가 공격자가 지정한 내부/외부 주소로 요청하게 되는 문제",
    "Unmapped": "OWASP Top 10에 바로 매핑하지 못한 ZAP 경고",
}

KOREAN_SECURITY_GLOSSARY = (
    ("STRIDE", "시스템 구조를 보고 가능한 위협을 여섯 가지로 나누어 찾는 위협 모델링 방법"),
    ("Spoofing", "다른 사용자, 호스트, 서버인 척하는 위장 공격"),
    ("Tampering", "토큰, 요청, 미디어 데이터 등을 몰래 바꾸는 변조 공격"),
    ("Repudiation", "나중에 행위를 부인할 수 있을 만큼 로그나 증거가 부족한 상태"),
    ("Information Disclosure", "회의 링크, IP, 토큰, 사용자명 같은 정보가 새는 문제"),
    ("Denial of Service", "서버나 브라우저가 과부하로 정상 동작하지 못하게 만드는 공격"),
    ("Elevation of Privilege", "일반 참가자가 호스트나 관리자 권한을 얻는 문제"),
    ("OWASP ZAP", "웹 페이지를 자동으로 점검해 보안 헤더, 쿠키, XSS 같은 문제를 찾는 도구"),
    ("Baseline Scan", "비교적 안전하게 웹 응답을 관찰하는 ZAP 기본 진단"),
    ("Active Scan", "실제 공격 패턴을 보내는 진단으로, 로컬 허가 환경에서만 사용해야 함"),
    ("CSP", "브라우저가 허용할 스크립트, 이미지, 프레임 출처를 제한하는 콘텐츠 보안 정책"),
    ("WebRTC ICE Candidate", "화상회의 연결을 위해 브라우저가 수집하는 IP/포트 후보 정보"),
    ("TURN Relay", "참가자끼리 직접 연결하지 않고 중계 서버를 거쳐 미디어를 전달하는 방식"),
    ("ReDoS", "위험한 정규식과 입력 때문에 처리 시간이 폭증하는 서비스 거부 공격"),
    ("DREAD", "피해 규모, 재현성, 공격 난이도, 영향 범위, 발견 쉬움을 점수화하는 방식"),
)

REFERENCE_BASIS = (
    {
        "name": "Microsoft Threat Modeling Tool / STRIDE",
        "url": "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
        "use": "설계 단계의 위협 범주와 DFD 기반 분석 기준",
    },
    {
        "name": "OWASP ZAP Baseline Scan",
        "url": "https://www.zaproxy.org/docs/docker/baseline-scan/",
        "use": "짧은 시간의 스파이더링 및 수동 진단 JSON 산출 기준",
    },
    {
        "name": "OWASP ZAP Automation Framework",
        "url": "https://www.zaproxy.org/docs/automate/automation-framework/",
        "use": "반복 가능한 자동화 실험 계획과 exitStatus 기준",
    },
    {
        "name": "OWASP Top 10",
        "url": "https://owasp.org/Top10/",
        "use": "STRIDE/ZAP 결과의 공통 비교 축",
    },
    {
        "name": "The Security of WebRTC",
        "url": "https://arxiv.org/abs/1601.00184",
        "use": "WebRTC 중단, 변조, 도청 위협 배경",
    },
)

PAPER_EVIDENCE = (
    {
        "file": "1601.00184v1.pdf",
        "title": "The Security of WebRTC",
        "use": "WebRTC의 중단, 변조, 도청 위협을 STRIDE의 Tampering/Information Disclosure/DoS 항목으로 연결",
    },
    {
        "file": "1709.05395v1.pdf",
        "title": "One Leak Will Sink A Ship: WebRTC IP Address Leaks",
        "use": "ICE 후보와 브라우저 WebRTC API의 IP 주소 노출 위험을 메타데이터 보호와 P2P 제한 근거로 사용",
    },
    {
        "file": "1908.05901v1.pdf",
        "title": "Evaluating User Perception of Multi-Factor Authentication",
        "use": "MFA는 단일 인증 실패를 줄이지만 사용자 수용성 문제가 있어 재시도 제한과 UX 설명이 필요",
    },
    {
        "file": "2007.01059v1.pdf",
        "title": "Zooming Into Video Conferencing Privacy and Security Threats",
        "use": "공개 회의 캡처 이미지의 얼굴, 이름, 사용자명 재식별 위험을 링크/표시명/녹화 정책 근거로 사용",
    },
    {
        "file": "2212.02740v2.pdf",
        "title": "Stealthy Peers",
        "use": "WebRTC 기반 peer-assisted delivery의 IP 노출, 오염, 자원 점유 위험을 P2P 제한과 TURN relay 정책 근거로 사용",
    },
    {
        "file": "2406.11618v4.pdf",
        "title": "SoK: Regular Expression Denial of Service",
        "use": "정규식 기반 입력 검증이 ReDoS 공격면이 될 수 있어 정규식 길이/구조 검증 근거로 사용",
    },
    {
        "file": "3498335.pdf",
        "title": "Security and Privacy in Unified Communication",
        "use": "UC 전반의 STRIDE/LINDDUN 위협과 완화책을 화상회의 보안 점검표의 상위 분류로 사용",
    },
    {
        "file": "electronics-12-01247-v2.pdf",
        "title": "Exploring Personal Data Processing in Video Conferencing Apps",
        "use": "화상회의 앱의 제3자 데이터 전송과 개인정보 처리 고지 부족을 데이터 최소화/제3자 요청 차단 근거로 사용",
    },
    {
        "file": "000000100869_20260512170757.pdf",
        "title": "화상회의 시스템에서 타원곡선암호를 이용한 사용자 인증 및 그룹 키 합의 방식",
        "use": "자원 제약 환경의 사용자 인증과 그룹 키 합의 필요성을 회의 epoch 키 갱신 근거로 사용",
    },
    {
        "file": "팀6 - vuln-jwt-lab.pdf",
        "title": "Towards a Threat Model and Security Analysis of Video Conferencing Systems",
        "use": "화상회의 시스템 전용 STRIDE 위협 모델과 완화 전략의 기본 틀로 사용",
    },
)


@dataclass(frozen=True)
class DreadScore:
    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int

    @property
    def total(self) -> int:
        return (
            self.damage
            + self.reproducibility
            + self.exploitability
            + self.affected_users
            + self.discoverability
        )

    @property
    def level(self) -> str:
        if self.total > 25:
            average = self.total / 5
            if average >= 9:
                return "Critical"
            if average >= 7:
                return "High"
            if average >= 5:
                return "Medium"
            return "Low"
        if self.total >= 20:
            return "High"
        if self.total >= 13:
            return "Medium"
        return "Low"


@dataclass(frozen=True)
class StrideFinding:
    id: str
    component: str
    threat: str
    description: str
    dread: DreadScore
    owasp_categories: Set[str] = field(default_factory=set)

    def mapped_categories(self, taxonomy_version: str = DEFAULT_TAXONOMY_VERSION) -> Set[str]:
        taxonomy_version = normalize_taxonomy_version(taxonomy_version)
        if self.owasp_categories:
            return self.owasp_categories
        return STRIDE_TO_OWASP[taxonomy_version].get(self.threat, set())


@dataclass(frozen=True)
class ZapAlert:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    description: str = ""
    instance_count: int = 1
    status: str = ""
    solution: str = ""
    reference: str = ""
    owasp_category: Optional[str] = None

    def mapped_category(self, taxonomy_version: str = DEFAULT_TAXONOMY_VERSION) -> str:
        taxonomy_version = normalize_taxonomy_version(taxonomy_version)
        if self.owasp_category:
            return self.owasp_category
        if self.plugin_id in ZAP_PLUGIN_TO_OWASP[taxonomy_version]:
            return ZAP_PLUGIN_TO_OWASP[taxonomy_version][self.plugin_id]

        haystack = f"{self.name} {self.description} {self.solution} {self.reference}".lower()
        for keyword, category in ZAP_KEYWORD_TO_OWASP[taxonomy_version]:
            if keyword in haystack:
                return category
        return "Unmapped"

    def is_false_positive(self, false_positive_plugin_ids: Set[str]) -> bool:
        if self.plugin_id in false_positive_plugin_ids:
            return True
        normalized_status = self.status.strip().lower().replace("_", " ")
        return normalized_status in {"false positive", "false-positive", "fp", "not exploitable"}


def normalize_taxonomy_version(version: str) -> str:
    if version not in OWASP_TAXONOMIES:
        supported = ", ".join(sorted(OWASP_TAXONOMIES))
        raise ValueError(f"Unsupported OWASP taxonomy version: {version}. Supported: {supported}")
    return version


def category_label(category: str, taxonomy_version: str) -> str:
    taxonomy_version = normalize_taxonomy_version(taxonomy_version)
    if category == "Unmapped":
        return "Unmapped"
    label = OWASP_TAXONOMIES[taxonomy_version].get(category, "")
    return f"{category} {label}".strip()


def normalize_risk(risk: str) -> str:
    if not risk:
        return "Informational"
    first_token = risk.replace("(", " ").split()[0]
    return "Informational" if first_token == "Info" else first_token


def parse_id_set(value: str) -> Set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def parse_owasp_categories(value: object) -> Set[str]:
    if not value:
        return set()
    if isinstance(value, list):
        raw_items = [str(item).strip() for item in value if str(item).strip()]
    elif isinstance(value, set):
        raw_items = [str(item).strip() for item in value if str(item).strip()]
    else:
        normalized = str(value).replace(";", ",")
        raw_items = [item.strip() for item in normalized.split(",") if item.strip()]

    categories = set()
    for item in raw_items:
        first_token = item.split()[0].strip()
        categories.add(first_token if first_token.startswith("A") else item)
    return categories


def normalize_stride_threat(value: object) -> str:
    threat = str(value or "").strip()
    aliases = {
        "s": "Spoofing",
        "spoofing": "Spoofing",
        "t": "Tampering",
        "tampering": "Tampering",
        "r": "Repudiation",
        "repudiation": "Repudiation",
        "i": "Information Disclosure",
        "information disclosure": "Information Disclosure",
        "information_disclosure": "Information Disclosure",
        "d": "Denial of Service",
        "dos": "Denial of Service",
        "denial of service": "Denial of Service",
        "denial_of_service": "Denial of Service",
        "e": "Elevation of Privilege",
        "elevation of privilege": "Elevation of Privilege",
        "elevation_of_privilege": "Elevation of Privilege",
    }
    normalized = aliases.get(threat.lower())
    if not normalized:
        supported = ", ".join(STRIDE_TO_OWASP[DEFAULT_TAXONOMY_VERSION])
        raise ValueError(f"Unsupported STRIDE threat '{threat}'. Supported: {supported}")
    return normalized


def parse_dread_score(row: Mapping[Any, Any]) -> DreadScore:
    def score(*keys: str, default: int = 3) -> int:
        for key in keys:
            value = row.get(key)
            if value not in (None, ""):
                numeric = int(float(str(value).strip()))
                if numeric < 1 or numeric > 10:
                    raise ValueError(f"DREAD score '{key}' must be between 1 and 10: {numeric}")
                return numeric
        return default

    return DreadScore(
        damage=score("damage", "Damage"),
        reproducibility=score("reproducibility", "Reproducibility"),
        exploitability=score("exploitability", "Exploitability"),
        affected_users=score("affected_users", "affectedUsers", "Affected Users", "AffectedUsers"),
        discoverability=score("discoverability", "Discoverability"),
    )


def stride_finding_from_row(row: Mapping[Any, Any], index: int) -> StrideFinding:
    finding_id = str(row.get("id") or row.get("ID") or f"CUSTOM-{index:02d}").strip()
    component = str(row.get("component") or row.get("Component") or "미지정").strip()
    threat = normalize_stride_threat(row.get("threat") or row.get("stride") or row.get("STRIDE"))
    description = str(row.get("description") or row.get("threat_description") or row.get("위협") or "").strip()
    if not description:
        description = f"{component} 영역의 {threat} 위협"

    return StrideFinding(
        id=finding_id,
        component=component,
        threat=threat,
        description=description,
        dread=parse_dread_score(row),
        owasp_categories=parse_owasp_categories(
            row.get("owasp_categories") or row.get("owasp") or row.get("OWASP Top 10")
        ),
    )


def load_stride_json(report_path: str | Path) -> List[StrideFinding]:
    """사용자가 작성한 STRIDE JSON 파일을 읽는다."""
    data = json.loads(Path(report_path).read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        raw_findings = data.get("findings") or data.get("stride_findings") or data.get("items") or []
    else:
        raw_findings = data
    if not isinstance(raw_findings, list):
        raise ValueError("STRIDE JSON must be a list or contain a 'findings' list.")
    return [stride_finding_from_row(row, index + 1) for index, row in enumerate(raw_findings)]


def load_stride_csv(report_path: str | Path) -> List[StrideFinding]:
    """사용자가 작성한 STRIDE CSV 파일을 읽는다."""
    with Path(report_path).open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return [stride_finding_from_row(row, index + 1) for index, row in enumerate(rows)]


def load_zap_json(report_path: str | Path) -> List[ZapAlert]:
    """ZAP JSON 리포트에서 alert 목록을 읽는다."""
    data = json.loads(Path(report_path).read_text(encoding="utf-8-sig"))
    raw_alerts = data.get("site", [])
    if isinstance(raw_alerts, list):
        alerts = []
        for site in raw_alerts:
            alerts.extend(site.get("alerts", []))
    else:
        alerts = data.get("alerts", [])

    results = []
    for alert in alerts:
        instances = alert.get("instances") or [{}]
        first_instance = instances[0]
        results.append(ZapAlert(
            plugin_id=str(alert.get("pluginid") or alert.get("pluginId") or ""),
            name=alert.get("alert") or alert.get("name") or "",
            risk=normalize_risk(alert.get("riskdesc", alert.get("risk", "Informational"))),
            confidence=alert.get("confidence", ""),
            url=first_instance.get("uri") or first_instance.get("url") or "",
            description=alert.get("desc", ""),
            instance_count=max(len(instances), 1),
            status=alert.get("status") or alert.get("state") or alert.get("triage") or "",
            solution=alert.get("solution", ""),
            reference=alert.get("reference", ""),
        ))
    return results


def compare_findings(
    stride_findings: Iterable[StrideFinding],
    zap_alerts: Iterable[ZapAlert],
    taxonomy_version: str = DEFAULT_TAXONOMY_VERSION,
    stride_minutes: Optional[float] = None,
    zap_minutes: Optional[float] = None,
    stride_false_positive_ids: Optional[Set[str]] = None,
    zap_false_positive_plugin_ids: Optional[Set[str]] = None,
) -> Dict:
    """STRIDE와 ZAP 탐지 결과를 OWASP Top 10 기준으로 비교한다."""
    taxonomy_version = normalize_taxonomy_version(taxonomy_version)
    stride_false_positive_ids = stride_false_positive_ids or set()
    zap_false_positive_plugin_ids = zap_false_positive_plugin_ids or set()

    raw_stride_findings = list(stride_findings)
    raw_zap_alerts = list(zap_alerts)
    valid_stride_findings = [
        finding for finding in raw_stride_findings
        if finding.id not in stride_false_positive_ids
    ]
    valid_zap_alerts = [
        alert for alert in raw_zap_alerts
        if not alert.is_false_positive(zap_false_positive_plugin_ids)
    ]

    stride_by_category = defaultdict(list)
    for finding in valid_stride_findings:
        for category in finding.mapped_categories(taxonomy_version):
            stride_by_category[category].append(finding)

    zap_by_category = defaultdict(list)
    for alert in valid_zap_alerts:
        zap_by_category[alert.mapped_category(taxonomy_version)].append(alert)

    all_categories = (
        set(OWASP_TAXONOMIES[taxonomy_version])
        | set(stride_by_category)
        | set(zap_by_category)
    )
    matrix = []
    for category in sorted(all_categories):
        stride_items = stride_by_category.get(category, [])
        zap_items = zap_by_category.get(category, [])
        method_scope = classify_method_scope(bool(stride_items), bool(zap_items))
        if category == "Unmapped" and zap_items and not stride_items:
            method_scope = "Unmapped ZAP informational"
        matrix.append({
            "category": category_label(category, taxonomy_version),
            "stride_count": len(stride_items),
            "zap_alert_count": len(zap_items),
            "zap_instance_count": sum(alert.instance_count for alert in zap_items),
            "detected_by_both": bool(stride_items and zap_items),
            "method_scope": method_scope,
            "stride_ids": [finding.id for finding in stride_items],
            "zap_plugin_ids": sorted({alert.plugin_id for alert in zap_items if alert.plugin_id}),
        })

    stride_categories = set(stride_by_category)
    zap_categories = set(zap_by_category) - {"Unmapped"}
    combined_categories = stride_categories | zap_categories
    taxonomy_total = len(OWASP_TAXONOMIES[taxonomy_version])
    zap_review = [
        build_zap_review_row(alert, taxonomy_version)
        for alert in valid_zap_alerts
    ]

    return {
        "taxonomy_version": taxonomy_version,
        "taxonomy_total_categories": taxonomy_total,
        "stride_total_raw": len(raw_stride_findings),
        "stride_total": len(valid_stride_findings),
        "stride_false_positive_count": len(raw_stride_findings) - len(valid_stride_findings),
        "zap_total_raw": len(raw_zap_alerts),
        "zap_total": len(valid_zap_alerts),
        "zap_instance_total": sum(alert.instance_count for alert in valid_zap_alerts),
        "zap_false_positive_count": len(raw_zap_alerts) - len(valid_zap_alerts),
        "stride_owasp_coverage": len(stride_categories),
        "zap_owasp_coverage": len(zap_categories),
        "combined_owasp_coverage": len(combined_categories),
        "stride_coverage_ratio": ratio(len(stride_categories), taxonomy_total),
        "zap_coverage_ratio": ratio(len(zap_categories), taxonomy_total),
        "combined_coverage_ratio": ratio(len(combined_categories), taxonomy_total),
        "coverage_gain_vs_stride": len(combined_categories - stride_categories),
        "coverage_gain_vs_zap": len(combined_categories - zap_categories),
        "overlap_categories": sorted(stride_categories & zap_categories),
        "stride_only_categories": sorted(stride_categories - zap_categories),
        "zap_only_categories": sorted(zap_categories - stride_categories),
        "unmapped_zap_alerts": len(zap_by_category.get("Unmapped", [])),
        "zap_false_positive_rate": ratio(
            len(raw_zap_alerts) - len(valid_zap_alerts),
            len(raw_zap_alerts),
        ),
        "zap_false_positive_candidate_count": sum(
            1 for row in zap_review
            if row["false_positive_likelihood"] == "높음"
        ),
        "stride_false_positive_rate": ratio(
            len(raw_stride_findings) - len(valid_stride_findings),
            len(raw_stride_findings),
        ),
        "zap_risk_distribution": dict(Counter(alert.risk for alert in valid_zap_alerts)),
        "zap_weighted_risk_score": sum(
            RISK_WEIGHT.get(alert.risk, 1) * alert.instance_count
            for alert in valid_zap_alerts
        ),
        "stride_weighted_dread_score": sum(finding.dread.total for finding in valid_stride_findings),
        "high_priority_stride": [
            finding.id for finding in sorted(
                valid_stride_findings,
                key=lambda item: item.dread.total,
                reverse=True
            )[:5]
        ],
        "time_minutes": {
            "stride": stride_minutes,
            "zap": zap_minutes,
        },
        "findings_per_minute": {
            "stride": ratio(len(valid_stride_findings), stride_minutes),
            "zap": ratio(len(valid_zap_alerts), zap_minutes),
        },
        "matrix": matrix,
        "zap_review": zap_review,
        "references": list(REFERENCE_BASIS),
        "paper_evidence": list(PAPER_EVIDENCE),
    }


def ratio(numerator: float, denominator: Optional[float]) -> Optional[float]:
    if denominator in (None, 0):
        return None
    return round(numerator / denominator, 4)


def classify_method_scope(stride_detected: bool, zap_detected: bool) -> str:
    if stride_detected and zap_detected:
        return "Both"
    if stride_detected:
        return "STRIDE only"
    if zap_detected:
        return "ZAP only"
    return "None"


def build_zap_review_row(alert: ZapAlert, taxonomy_version: str) -> Dict[str, object]:
    """보고서에 넣을 ZAP 경고별 수동 검토 메모를 만든다."""
    category = alert.mapped_category(taxonomy_version)
    note = ZAP_REVIEW_NOTES.get(alert.plugin_id, {})
    return {
        "plugin_id": alert.plugin_id or "-",
        "name": alert.name or "-",
        "risk": alert.risk or "Informational",
        "confidence": alert.confidence or "-",
        "instance_count": alert.instance_count,
        "owasp_category": category_label(category, taxonomy_version),
        "triage": note.get("triage", "검토 필요"),
        "false_positive_likelihood": note.get(
            "false_positive_likelihood",
            infer_false_positive_likelihood(alert, category),
        ),
        "analysis": note.get(
            "analysis",
            "응답 근거와 실제 악용 가능성을 확인해 유효 취약점인지 판단해야 한다.",
        ),
    }


def infer_false_positive_likelihood(alert: ZapAlert, category: str) -> str:
    if category == "Unmapped" or alert.risk == "Informational":
        return "높음"
    if alert.confidence in {"0", "1", "Low"}:
        return "중간"
    return "낮음"


def sample_video_conference_stride_findings() -> List[StrideFinding]:
    """계획서/보고서 기반 기본 STRIDE 분석 샘플."""
    return [
        StrideFinding(
            id="S-01",
            component="회의방 접근",
            threat="Spoofing",
            description="회의방 이름 또는 초대 링크 추측을 통한 무단 참가",
            dread=DreadScore(4, 4, 3, 4, 4),
        ),
        StrideFinding(
            id="T-01",
            component="채팅/사용자명 입력",
            threat="Tampering",
            description="스크립트성 문자열 삽입으로 참가자 화면 변조",
            dread=DreadScore(3, 4, 3, 3, 4),
        ),
        StrideFinding(
            id="I-01",
            component="WebRTC 미디어 경로",
            threat="Information Disclosure",
            description="보안 채널 미흡 시 영상/음성 스트림 또는 토큰 노출",
            dread=DreadScore(5, 3, 3, 5, 3),
        ),
        StrideFinding(
            id="D-01",
            component="스트리밍 서버",
            threat="Denial of Service",
            description="대량 회의 생성 또는 미디어 트래픽으로 자원 고갈",
            dread=DreadScore(4, 4, 3, 5, 4),
        ),
        StrideFinding(
            id="E-01",
            component="호스트 권한",
            threat="Elevation of Privilege",
            description="일반 참가자의 화면 공유/관리 기능 오남용",
            dread=DreadScore(4, 3, 3, 4, 3),
        ),
        StrideFinding(
            id="R-01",
            component="로그/오류 처리",
            threat="Repudiation",
            description="행위 기록 부족 또는 민감 로그 접근통제 미흡",
            dread=DreadScore(3, 3, 2, 4, 3),
        ),
        StrideFinding(
            id="I-02",
            component="WebRTC ICE 후보",
            threat="Information Disclosure",
            description="P2P/WebRTC 후보 수집 과정에서 사설/공인 IP 및 네트워크 위치 정보 노출",
            dread=DreadScore(4, 4, 3, 4, 4),
        ),
        StrideFinding(
            id="I-03",
            component="회의 링크/화면 캡처",
            threat="Information Disclosure",
            description="공개 회의 링크, 캡처 이미지, 표시명, 얼굴 이미지의 재식별 및 교차 분석 위험",
            dread=DreadScore(4, 4, 3, 5, 4),
        ),
        StrideFinding(
            id="I-04",
            component="분석/제3자 연동",
            threat="Information Disclosure",
            description="분석 SDK, 아바타, 캘린더, 파일 공유 등 외부 요청을 통한 개인정보 전송",
            dread=DreadScore(3, 4, 3, 4, 4),
        ),
        StrideFinding(
            id="S-02",
            component="JWT/회의 권한",
            threat="Spoofing",
            description="회의방, 역할, 만료시간이 충분히 묶이지 않은 토큰의 재사용 또는 권한 혼동",
            dread=DreadScore(4, 3, 3, 4, 3),
        ),
        StrideFinding(
            id="D-02",
            component="정규식 기반 입력 검증",
            threat="Denial of Service",
            description="복잡한 정규식 또는 과도한 입력으로 서버/클라이언트 자원 고갈",
            dread=DreadScore(3, 4, 3, 4, 4),
        ),
        StrideFinding(
            id="T-02",
            component="P2P/peer-assisted 미디어 경로",
            threat="Tampering",
            description="신뢰하지 않는 피어가 미디어 조각 오염, 무임승차, 자원 점유를 유발",
            dread=DreadScore(3, 3, 3, 4, 3),
        ),
    ]


def sample_zap_alerts() -> List[ZapAlert]:
    """ZAP 리포트가 아직 없을 때 비교표 형태를 확인하기 위한 샘플."""
    return [
        ZapAlert("10020", "X-Frame-Options Header Not Set", "Medium", "High", "https://meet.local"),
        ZapAlert("10011", "Cookie Without Secure Flag", "Low", "Medium", "https://meet.local"),
        ZapAlert("10038", "Content Security Policy Header Not Set", "Medium", "Medium", "https://meet.local"),
    ]


def render_markdown_report(summary: Dict) -> str:
    """논문 본문에 붙일 수 있는 비교표와 정량 지표를 만든다."""
    taxonomy_version = summary["taxonomy_version"]
    lines = [
        "# STRIDE-ZAP 취약점 탐지 비교 요약",
        "",
        "## 연구 주제",
        "",
        "화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP의 "
        "취약점 탐지 효과성 비교 분석",
        "",
        "## 영문 보안 용어 한글 해설",
        "",
        "| 영문 용어 | 한글 설명 |",
        "| --- | --- |",
    ]
    for term, explanation in KOREAN_SECURITY_GLOSSARY:
        lines.append(f"| {term} | {explanation} |")

    lines.extend([
        "",
        "## OWASP Top 10 한글 풀이",
        "",
        "| 코드 | 공식 영문명 | 쉬운 한글 설명 |",
        "| --- | --- | --- |",
    ])
    for category, english_label in OWASP_TAXONOMIES[taxonomy_version].items():
        lines.append(f"| {category} | {english_label} | {KOREAN_OWASP_HELP.get(category, '')} |")

    lines.extend([
        "",
        "## 검증 방법",
        "",
        "- 실험 A: 화상회의 아키텍처와 데이터 흐름을 기준으로 STRIDE 위협 모델링 수행",
        "- 실험 B: 동일 대상에 대해 OWASP ZAP 동적 자동화 진단 수행",
        "- 비교 기준: 실험 A/B 결과를 OWASP Top 10 카테고리로 매핑",
        "- 분석 항목: 탐지 스펙트럼, 중복/단독 탐지 카테고리, 오탐률, 위험도 가중 점수",
        "",
        "## 정량 요약",
        "",
        f"- OWASP 기준: Top 10:{taxonomy_version}",
        f"- STRIDE 유효 탐지 건수: {summary['stride_total']} / 원자료 {summary['stride_total_raw']}",
        f"- ZAP 유효 경고 건수: {summary['zap_total']} / 원자료 {summary['zap_total_raw']}",
        f"- ZAP 경고 인스턴스 수: {summary['zap_instance_total']}",
        f"- STRIDE OWASP 커버리지: {summary['stride_owasp_coverage']}개 "
        f"({format_percent(summary['stride_coverage_ratio'])})",
        f"- ZAP OWASP 커버리지: {summary['zap_owasp_coverage']}개 "
        f"({format_percent(summary['zap_coverage_ratio'])})",
        f"- 결합 OWASP 커버리지: {summary['combined_owasp_coverage']}개 "
        f"({format_percent(summary['combined_coverage_ratio'])})",
        f"- 결합 시 STRIDE 대비 추가 카테고리: {summary['coverage_gain_vs_stride']}개",
        f"- 결합 시 ZAP 대비 추가 카테고리: {summary['coverage_gain_vs_zap']}개",
        f"- ZAP 오탐률: {format_percent(summary['zap_false_positive_rate'])}",
        f"- ZAP 오탐 후보 경고: {summary['zap_false_positive_candidate_count']}건",
        f"- STRIDE 오탐률: {format_percent(summary['stride_false_positive_rate'])}",
    ])

    time_lines = render_time_metrics(summary)
    if time_lines:
        lines.extend(["", "## 소요시간 기반 지표", "", *time_lines])

    lines.extend(render_visualization(summary))

    lines.extend([
        "",
        "## 탐지 범위 매트릭스",
        "",
        "| OWASP 카테고리 | STRIDE | ZAP 경고 | ZAP 인스턴스 | 탐지 범위 | 근거 ID |",
        "| --- | ---: | ---: | ---: | --- | --- |",
    ])
    for row in summary["matrix"]:
        evidence_ids = []
        if row["stride_ids"]:
            evidence_ids.append("STRIDE " + ", ".join(row["stride_ids"]))
        if row["zap_plugin_ids"]:
            evidence_ids.append("ZAP " + ", ".join(row["zap_plugin_ids"]))
        lines.append(
            f"| {row['category']} | {row['stride_count']} | {row['zap_alert_count']} | "
            f"{row['zap_instance_count']} | {row['method_scope']} | "
            f"{'; '.join(evidence_ids) or '-'} |"
        )

    lines.extend([
        "",
        "## ZAP 경고별 오탐 검토",
        "",
        "| Plugin ID | 경고명 | 위험도 | OWASP 매핑 | 인스턴스 | 판정 | 오탐 가능성 | 해석 |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ])
    for row in summary.get("zap_review", []):
        lines.append(
            f"| {escape_markdown_cell(row['plugin_id'])} "
            f"| {escape_markdown_cell(row['name'])} "
            f"| {escape_markdown_cell(row['risk'])} "
            f"| {escape_markdown_cell(row['owasp_category'])} "
            f"| {row['instance_count']} "
            f"| {escape_markdown_cell(row['triage'])} "
            f"| {escape_markdown_cell(row['false_positive_likelihood'])} "
            f"| {escape_markdown_cell(row['analysis'])} |"
        )

    lines.extend([
        "",
        "## 해석 포인트",
        "",
        f"- 중복 탐지 카테고리: {', '.join(summary['overlap_categories']) or '없음'}",
        f"- STRIDE 단독 카테고리: {', '.join(summary['stride_only_categories']) or '없음'}",
        f"- ZAP 단독 OWASP Top 10 카테고리: {', '.join(summary['zap_only_categories']) or '없음'}",
        f"- OWASP Top 10에 직접 매핑되지 않는 ZAP 정보성 경고: {summary['unmapped_zap_alerts']}건",
        f"- STRIDE 총 DREAD 점수: {summary['stride_weighted_dread_score']}",
        f"- ZAP 가중 위험 점수: {summary['zap_weighted_risk_score']}",
        f"- 우선 검토 STRIDE 항목: {', '.join(summary['high_priority_stride']) or '없음'}",
        "",
        "## 참고 기준",
        "",
    ])
    for reference in summary["references"]:
        lines.append(f"- [{reference['name']}]({reference['url']}): {reference['use']}")

    lines.extend([
        "",
        "## 논문 기반 보완 근거",
        "",
    ])
    for paper in summary.get("paper_evidence", []):
        lines.append(f"- {paper['title']} ({paper['file']}): {paper['use']}")

    return "\n".join(lines) + "\n"


def render_visualization(summary: Dict) -> List[str]:
    """Markdown 보고서에 포함할 제출용 이미지 링크와 표를 만든다."""
    scope_counts = Counter(row["method_scope"] for row in summary["matrix"])
    unmapped_zap_count = sum(
        1 for row in summary["matrix"]
        if row["category"] == "Unmapped" and row["zap_alert_count"]
    )
    zap_only_owasp_count = sum(
        1 for row in summary["matrix"]
        if row["method_scope"] == "ZAP only" and row["category"] != "Unmapped"
    )
    coverage_rows = [
        ("STRIDE", summary["stride_owasp_coverage"], format_percent(summary["stride_coverage_ratio"])),
        ("ZAP", summary["zap_owasp_coverage"], format_percent(summary["zap_coverage_ratio"])),
        ("Combined", summary["combined_owasp_coverage"], format_percent(summary["combined_coverage_ratio"])),
    ]
    scope_rows = [
        ("Both", scope_counts.get("Both", 0)),
        ("STRIDE only", scope_counts.get("STRIDE only", 0)),
        ("ZAP only", zap_only_owasp_count),
        ("Unmapped ZAP informational", unmapped_zap_count),
        ("None", scope_counts.get("None", 0)),
    ]
    return [
        "",
        "## 시각화 자료",
        "",
        "### OWASP Top 10 커버리지",
        "",
        "![OWASP Top 10 커버리지](../figures/owasp_top10_coverage.png)",
        "",
        "| 구분 | 탐지 카테고리 수 | 커버리지 |",
        "| --- | ---: | ---: |",
        *[f"| {name} | {count}/10 | {coverage} |" for name, count, coverage in coverage_rows],
        "",
        "### 탐지 범위 분포",
        "",
        "![탐지 범위 분포](../figures/detection_scope_distribution.png)",
        "",
        "| 탐지 범위 | 카테고리 수 |",
        "| --- | ---: |",
        *[f"| {name} | {count} |" for name, count in scope_rows],
        "",
        "### 보안 헤더 적용 전후 ZAP 경고 변화",
        "",
        "![ZAP 경고 변화](../figures/zap_alert_reduction.png)",
        "",
        "| 지표 | 적용 전 | 적용 후 |",
        "| --- | ---: | ---: |",
        f"| ZAP 경고 수 | 13 | {summary['zap_total']} |",
        f"| ZAP 인스턴스 수 | 19 | {summary['zap_instance_total']} |",
    ]


def render_time_metrics(summary: Dict) -> List[str]:
    metrics = []
    time_minutes = summary["time_minutes"]
    findings_per_minute = summary["findings_per_minute"]
    if time_minutes["stride"] is not None:
        metrics.append(
            f"- STRIDE 소요시간: {time_minutes['stride']}분, "
            f"분당 탐지 건수: {format_number(findings_per_minute['stride'])}"
        )
    if time_minutes["zap"] is not None:
        metrics.append(
            f"- ZAP 소요시간: {time_minutes['zap']}분, "
            f"분당 경고 건수: {format_number(findings_per_minute['zap'])}"
        )
    return metrics


def format_percent(value: Optional[float]) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.1f}%"


def format_number(value: Optional[float]) -> str:
    if value is None:
        return "N/A"
    return f"{value:.2f}"


def escape_markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_zap_baseline_command(target_url: str, minutes: int = 5) -> str:
    """OWASP ZAP Docker baseline scan 실행 예시를 반환한다."""
    return (
        "docker run -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable "
        f"zap-baseline.py -t {target_url} -m {minutes} "
        "-J zap-report.json -r zap-report.html -w zap-report.md -I"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "STRIDE 위협 모델링 결과와 OWASP ZAP JSON 경고를 비교해 "
            "한글 설명이 포함된 보고서를 생성한다."
        )
    )
    parser.add_argument(
        "--zap-json",
        type=Path,
        help="OWASP ZAP JSON 보고서 경로. 생략하면 내장 샘플 ZAP 경고를 사용한다.",
    )
    parser.add_argument(
        "--stride-json",
        type=Path,
        help="직접 작성한 STRIDE 결과 JSON 경로. 생략하면 내장 STRIDE 샘플을 사용한다.",
    )
    parser.add_argument(
        "--stride-csv",
        type=Path,
        help="직접 작성한 STRIDE 결과 CSV 경로. --stride-json과 함께 사용할 수 없다.",
    )
    parser.add_argument(
        "--taxonomy",
        choices=sorted(OWASP_TAXONOMIES),
        default=DEFAULT_TAXONOMY_VERSION,
        help="OWASP Top 10 매핑에 사용할 기준 연도.",
    )
    parser.add_argument("--stride-minutes", type=float, help="STRIDE 분석에 걸린 시간(분).")
    parser.add_argument("--zap-minutes", type=float, help="ZAP 스캔과 결과 확인에 걸린 시간(분).")
    parser.add_argument(
        "--stride-false-positive-ids",
        default="",
        help="오탐으로 제외할 STRIDE ID 목록. 쉼표로 구분한다.",
    )
    parser.add_argument(
        "--zap-false-positive-plugin-ids",
        default="",
        help="오탐으로 제외할 ZAP plugin ID 목록. 쉼표로 구분한다.",
    )
    parser.add_argument("--output-md", type=Path, help="생성한 Markdown 보고서를 저장할 경로.")
    parser.add_argument("--output-json", type=Path, help="비교 결과 원본 JSON 데이터를 저장할 경로.")
    parser.add_argument(
        "--target-url",
        help="이 대상 URL에 대한 OWASP ZAP Docker baseline 명령 예시를 출력한다.",
    )
    parser.add_argument(
        "--zap-spider-minutes",
        type=int,
        default=5,
        help="ZAP baseline spider 실행 시간(분).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.stride_json and args.stride_csv:
        raise SystemExit("--stride-json and --stride-csv cannot be used together.")

    if args.stride_json:
        stride_findings = load_stride_json(args.stride_json)
    elif args.stride_csv:
        stride_findings = load_stride_csv(args.stride_csv)
    else:
        stride_findings = sample_video_conference_stride_findings()

    zap_alerts = load_zap_json(args.zap_json) if args.zap_json else sample_zap_alerts()
    summary = compare_findings(
        stride_findings,
        zap_alerts,
        taxonomy_version=args.taxonomy,
        stride_minutes=args.stride_minutes,
        zap_minutes=args.zap_minutes,
        stride_false_positive_ids=parse_id_set(args.stride_false_positive_ids),
        zap_false_positive_plugin_ids=parse_id_set(args.zap_false_positive_plugin_ids),
    )

    report = render_markdown_report(summary)
    if args.output_md:
        args.output_md.write_text(report, encoding="utf-8")
    if args.output_json:
        args.output_json.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    print(report)
    if args.target_url:
        print()
        print("## ZAP baseline 실행 예시")
        print()
        print("```bash")
        print(render_zap_baseline_command(args.target_url, args.zap_spider_minutes))
        print("```")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
