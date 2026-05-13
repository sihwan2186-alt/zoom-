"""
STRIDE 위협 모델링과 OWASP ZAP 동적 진단 결과 비교 유틸리티.

연구 주제:
화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP의
취약점 탐지 효과성 비교 분석
"""
import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set


DEFAULT_TAXONOMY_VERSION = "2021"

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
        "10038": "A05",   # Content Security Policy Header
        "10054": "A05",   # Cookie Without SameSite Attribute
        "10096": "A06",   # Vulnerable JS Library
        "40012": "A03",   # Cross Site Scripting
        "40014": "A01",   # Absence of Anti-CSRF Tokens
        "40018": "A03",   # SQL Injection
        "40035": "A03",   # Server Side Code Injection
        "40045": "A01",   # Spring Actuator Information Leak
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
        "10038": "A02",
        "10054": "A02",
        "10096": "A03",
        "40012": "A05",
        "40014": "A01",
        "40018": "A05",
        "40035": "A05",
        "40045": "A01",
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


def load_zap_json(report_path: str | Path) -> List[ZapAlert]:
    """ZAP JSON 리포트에서 alert 목록을 읽는다."""
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
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
        matrix.append({
            "category": category_label(category, taxonomy_version),
            "stride_count": len(stride_items),
            "zap_alert_count": len(zap_items),
            "zap_instance_count": sum(alert.instance_count for alert in zap_items),
            "detected_by_both": bool(stride_items and zap_items),
            "method_scope": classify_method_scope(bool(stride_items), bool(zap_items)),
            "stride_ids": [finding.id for finding in stride_items],
            "zap_plugin_ids": sorted({alert.plugin_id for alert in zap_items if alert.plugin_id}),
        })

    stride_categories = set(stride_by_category)
    zap_categories = set(zap_by_category) - {"Unmapped"}
    combined_categories = stride_categories | zap_categories
    taxonomy_total = len(OWASP_TAXONOMIES[taxonomy_version])

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
        "references": list(REFERENCE_BASIS),
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
        f"- STRIDE 오탐률: {format_percent(summary['stride_false_positive_rate'])}",
    ]

    time_lines = render_time_metrics(summary)
    if time_lines:
        lines.extend(["", "## 소요시간 기반 지표", *time_lines])

    lines.extend([
        "",
        "## 탐지 범위 매트릭스",
        "",
        "| OWASP 카테고리 | STRIDE | ZAP 경고 | ZAP 인스턴스 | 탐지 범위 | 근거 ID |",
        "|---|---:|---:|---:|---|---|",
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
        "## 해석 포인트",
        "",
        f"- 중복 탐지 카테고리: {', '.join(summary['overlap_categories']) or '없음'}",
        f"- STRIDE 단독 카테고리: {', '.join(summary['stride_only_categories']) or '없음'}",
        f"- ZAP 단독 카테고리: {', '.join(summary['zap_only_categories']) or '없음'}",
        f"- OWASP 미매핑 ZAP 경고: {summary['unmapped_zap_alerts']}건",
        f"- STRIDE 총 DREAD 점수: {summary['stride_weighted_dread_score']}",
        f"- ZAP 가중 위험 점수: {summary['zap_weighted_risk_score']}",
        f"- 우선 검토 STRIDE 항목: {', '.join(summary['high_priority_stride']) or '없음'}",
        "",
        "## 참고 기준",
        "",
    ])
    for reference in summary["references"]:
        lines.append(f"- {reference['name']}: {reference['use']} ({reference['url']})")

    return "\n".join(lines)


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


def render_zap_baseline_command(target_url: str, minutes: int = 5) -> str:
    """OWASP ZAP Docker baseline scan 실행 예시를 반환한다."""
    return (
        "docker run -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable "
        f"zap-baseline.py -t {target_url} -m {minutes} "
        "-J zap-report.json -r zap-report.html -w zap-report.md -I"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare STRIDE threat modeling findings with OWASP ZAP JSON alerts."
    )
    parser.add_argument(
        "--zap-json",
        type=Path,
        help="OWASP ZAP JSON report path. If omitted, built-in sample alerts are used.",
    )
    parser.add_argument(
        "--taxonomy",
        choices=sorted(OWASP_TAXONOMIES),
        default=DEFAULT_TAXONOMY_VERSION,
        help="OWASP Top 10 taxonomy version used for mapping.",
    )
    parser.add_argument("--stride-minutes", type=float, help="Elapsed STRIDE analysis time in minutes.")
    parser.add_argument("--zap-minutes", type=float, help="Elapsed ZAP scan and triage time in minutes.")
    parser.add_argument(
        "--stride-false-positive-ids",
        default="",
        help="Comma-separated STRIDE finding IDs to exclude as false positives.",
    )
    parser.add_argument(
        "--zap-false-positive-plugin-ids",
        default="",
        help="Comma-separated ZAP plugin IDs to exclude as false positives.",
    )
    parser.add_argument("--output-md", type=Path, help="Write the markdown report to this path.")
    parser.add_argument("--output-json", type=Path, help="Write the raw summary data to this path.")
    parser.add_argument(
        "--target-url",
        help="Print an OWASP ZAP Docker baseline command for this target URL.",
    )
    parser.add_argument(
        "--zap-spider-minutes",
        type=int,
        default=5,
        help="Minutes for the suggested ZAP baseline spider command.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    zap_alerts = load_zap_json(args.zap_json) if args.zap_json else sample_zap_alerts()
    summary = compare_findings(
        sample_video_conference_stride_findings(),
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
