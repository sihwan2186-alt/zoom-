"""
STRIDE 위협 모델링과 OWASP ZAP 동적 진단 결과 비교 유틸리티.

연구 주제:
화상회의 아키텍처 환경에서 STRIDE 위협 모델링과 OWASP ZAP의
취약점 탐지 효과성 비교 분석
"""
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set


OWASP_TOP10_2021 = {
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
}

STRIDE_TO_OWASP = {
    "Spoofing": {"A01", "A07"},
    "Tampering": {"A03", "A08"},
    "Repudiation": {"A09"},
    "Information Disclosure": {"A02", "A05"},
    "Denial of Service": {"A05"},
    "Elevation of Privilege": {"A01", "A04"},
}

ZAP_KEYWORD_TO_OWASP = {
    "x-frame-options": "A05",
    "content security policy": "A05",
    "content-type": "A05",
    "cookie": "A05",
    "httponly": "A05",
    "secure flag": "A02",
    "strict-transport-security": "A02",
    "server leaks": "A05",
    "cross-domain": "A05",
    "xss": "A03",
    "sql injection": "A03",
    "path traversal": "A01",
    "authentication": "A07",
    "csrf": "A01",
    "ssrf": "A10",
}

RISK_WEIGHT = {
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}


@dataclass
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


@dataclass
class StrideFinding:
    id: str
    component: str
    threat: str
    description: str
    dread: DreadScore
    owasp_categories: Set[str] = field(default_factory=set)

    def mapped_categories(self) -> Set[str]:
        return self.owasp_categories or STRIDE_TO_OWASP.get(self.threat, set())


@dataclass
class ZapAlert:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    description: str = ""
    owasp_category: Optional[str] = None

    def mapped_category(self) -> str:
        if self.owasp_category:
            return self.owasp_category
        haystack = f"{self.name} {self.description}".lower()
        for keyword, category in ZAP_KEYWORD_TO_OWASP.items():
            if keyword in haystack:
                return category
        return "Unmapped"


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
            risk=alert.get("riskdesc", alert.get("risk", "Informational")).split(" ")[0],
            confidence=alert.get("confidence", ""),
            url=first_instance.get("uri") or first_instance.get("url") or "",
            description=alert.get("desc", ""),
        ))
    return results


def compare_findings(stride_findings: Iterable[StrideFinding], zap_alerts: Iterable[ZapAlert]) -> Dict:
    """STRIDE와 ZAP 탐지 결과를 OWASP Top 10 기준으로 비교한다."""
    stride_findings = list(stride_findings)
    zap_alerts = list(zap_alerts)

    stride_by_category = defaultdict(list)
    for finding in stride_findings:
        for category in finding.mapped_categories():
            stride_by_category[category].append(finding)

    zap_by_category = defaultdict(list)
    for alert in zap_alerts:
        zap_by_category[alert.mapped_category()].append(alert)

    all_categories = set(OWASP_TOP10_2021) | set(stride_by_category) | set(zap_by_category)
    matrix = []
    for category in sorted(all_categories):
        if category == "Unmapped":
            label = "Unmapped"
        else:
            label = f"{category} {OWASP_TOP10_2021.get(category, '')}".strip()
        matrix.append({
            "category": label,
            "stride_count": len(stride_by_category.get(category, [])),
            "zap_count": len(zap_by_category.get(category, [])),
            "detected_by_both": bool(stride_by_category.get(category) and zap_by_category.get(category)),
        })

    stride_categories = set(stride_by_category)
    zap_categories = set(zap_by_category) - {"Unmapped"}
    combined_categories = stride_categories | zap_categories

    return {
        "stride_total": len(stride_findings),
        "zap_total": len(zap_alerts),
        "stride_owasp_coverage": len(stride_categories),
        "zap_owasp_coverage": len(zap_categories),
        "combined_owasp_coverage": len(combined_categories),
        "overlap_categories": sorted(stride_categories & zap_categories),
        "stride_only_categories": sorted(stride_categories - zap_categories),
        "zap_only_categories": sorted(zap_categories - stride_categories),
        "zap_risk_distribution": dict(Counter(alert.risk for alert in zap_alerts)),
        "high_priority_stride": [
            finding.id for finding in sorted(
                stride_findings,
                key=lambda item: item.dread.total,
                reverse=True
            )[:5]
        ],
        "matrix": matrix,
    }


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


def render_markdown_report(summary: Dict) -> str:
    """논문 본문에 붙일 수 있는 간단한 비교표를 만든다."""
    lines = [
        "# STRIDE-ZAP 취약점 탐지 비교 요약",
        "",
        f"- STRIDE 탐지 건수: {summary['stride_total']}",
        f"- ZAP 탐지 건수: {summary['zap_total']}",
        f"- STRIDE OWASP 커버리지: {summary['stride_owasp_coverage']}",
        f"- ZAP OWASP 커버리지: {summary['zap_owasp_coverage']}",
        f"- 결합 OWASP 커버리지: {summary['combined_owasp_coverage']}",
        f"- 중복 탐지 카테고리: {', '.join(summary['overlap_categories']) or '없음'}",
        "",
        "| OWASP 카테고리 | STRIDE | ZAP | 동시 탐지 |",
        "|---|---:|---:|---|",
    ]
    for row in summary["matrix"]:
        lines.append(
            f"| {row['category']} | {row['stride_count']} | {row['zap_count']} | "
            f"{'Y' if row['detected_by_both'] else 'N'} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    sample_alerts = [
        ZapAlert("10020", "X-Frame-Options Header Not Set", "Medium", "High", "https://meet.local"),
        ZapAlert("10011", "Cookie Without Secure Flag", "Low", "Medium", "https://meet.local"),
        ZapAlert("10038", "Content Security Policy Header Not Set", "Medium", "Medium", "https://meet.local"),
    ]
    summary = compare_findings(sample_video_conference_stride_findings(), sample_alerts)
    print(render_markdown_report(summary))
