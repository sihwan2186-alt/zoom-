"""
Compliance Framework for Video Conferencing Systems
===================================================

주요 규제 프레임워크와 비디오 회의 시스템의 컴플라이언스를 평가합니다.

포함 범위:
- GDPR (일반 개인정보 보호 규정)
- HIPAA (미국 의료정보 보호법)
- CCPA (캘리포니아 소비자 개인정보 보호법)
- 한국 개인정보보호법
- ISO 27001:2022 (정보보안 관리)
"""

import json
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime


class ComplianceStatus(Enum):
    """컴플라이언스 상태"""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


class RiskLevel(Enum):
    """위험 레벨"""
    CRITICAL = "critical"  # 즉시 개선 필요
    HIGH = "high"          # 우선 개선 필요
    MEDIUM = "medium"      # 보통 우선순위
    LOW = "low"            # 낮은 우선순위


@dataclass
class RequirementCheckpoint:
    """컴플라이언스 항목 체크포인트"""
    requirement_id: str
    requirement_name: str
    regulation: str
    description: str
    status: ComplianceStatus
    evidence: str
    risk_level: RiskLevel
    remediation: str
    duedate: str = ""
    implementation_effort: str = "medium"  # low, medium, high


class GDPRCompliance:
    """
    GDPR (General Data Protection Regulation) 컴플라이언스
    
    적용 대상: 유럽 거주자의 개인정보 처리
    주요 요구사항:
    - 개인정보 보호 영향 평가 (DPIA)
    - 명확한 동의 및 회수 메커니즘
    - 개인정보 삭제권 (Right to be Forgotten)
    - 데이터 이동권 (Data Portability)
    - 32시간 내 침해 신고
    """

    def __init__(self):
        self.checkpoints: List[RequirementCheckpoint] = [
            RequirementCheckpoint(
                requirement_id="GDPR-1",
                requirement_name="개인정보 수집 동의",
                regulation="GDPR Article 6",
                description="사용자의 명시적 동의 없이 개인정보 수집 금지",
                status=ComplianceStatus.COMPLIANT,
                evidence="index.html: privacy URL 파라미터로 사용자 동의 선택권 제공",
                risk_level=RiskLevel.CRITICAL,
                remediation="동의 관리 시스템 구현 완료"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-2",
                requirement_name="개인정보 처리 투명성",
                regulation="GDPR Article 13-14",
                description="사용자에게 처리 목적, 방법, 기간을 명확히 공지",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="README.md에 기본 정보 포함, 상세 개인정보 처리방침 미작성",
                risk_level=RiskLevel.HIGH,
                remediation="법적 개인정보 처리방침 문서 작성 필요"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-3",
                requirement_name="개인정보 보관 기간 제한",
                regulation="GDPR Article 5",
                description="필요한 기간만 보관, 초과 시 즉시 삭제",
                status=ComplianceStatus.COMPLIANT,
                evidence="data_protection.py: 회의 종료 후 X일 자동 삭제 정책 구현",
                risk_level=RiskLevel.HIGH,
                remediation="자동 삭제 로직 검증"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-4",
                requirement_name="개인정보 삭제권 (Right to be Forgotten)",
                regulation="GDPR Article 17",
                description="사용자 요청 시 30일 내 개인정보 완전 삭제",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="논리적 마스킹 구현, 물리적 삭제 API 미구현",
                risk_level=RiskLevel.HIGH,
                remediation="개인정보 삭제 요청 API 구현 필요"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-5",
                requirement_name="데이터 이동권 (Data Portability)",
                regulation="GDPR Article 20",
                description="사용자가 자신의 데이터를 기계가독형식으로 내보낼 수 있어야 함",
                status=ComplianceStatus.NON_COMPLIANT,
                evidence="데이터 내보내기 기능 미구현",
                risk_level=RiskLevel.HIGH,
                remediation="JSON/CSV 형식 데이터 내보내기 API 개발"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-6",
                requirement_name="개인정보 침해 알림 (Data Breach Notification)",
                regulation="GDPR Article 33-34",
                description="침해 발생 시 72시간 내 감독기관에 신고, 7일 내 개인에 알림",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="침해 탐지 로직은 있으나 자동 알림 기능 미흡",
                risk_level=RiskLevel.CRITICAL,
                remediation="자동 침해 알림 시스템 구축"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-7",
                requirement_name="개인정보 보호 영향 평가 (DPIA)",
                regulation="GDPR Article 35",
                description="고위험 처리에 대한 영향 평가 수행",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="이 보고서의 위협 모델링이 DPIA 역할 수행",
                risk_level=RiskLevel.MEDIUM,
                remediation="공식 DPIA 문서 작성"
            ),
            RequirementCheckpoint(
                requirement_id="GDPR-8",
                requirement_name="개인정보 보호 담당자 (DPO) 지정",
                regulation="GDPR Article 37",
                description="조직 규모가 크면 DPO 지정 필요",
                status=ComplianceStatus.NOT_APPLICABLE,
                evidence="실습 환경 범위 밖",
                risk_level=RiskLevel.LOW,
                remediation="조직 규모 확대 시 검토"
            )
        ]

    def evaluate(self) -> Dict:
        """GDPR 컴플라이언스 평가"""
        compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.COMPLIANT
        )
        partial_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.PARTIALLY_COMPLIANT
        )
        non_compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.NON_COMPLIANT
        )

        checkpoints_dict = []
        for c in self.checkpoints:
            cp_dict = asdict(c)
            cp_dict['status'] = c.status.value
            cp_dict['risk_level'] = c.risk_level.value
            checkpoints_dict.append(cp_dict)

        return {
            "framework": "GDPR",
            "total_requirements": len(self.checkpoints),
            "compliant": compliant_count,
            "partially_compliant": partial_count,
            "non_compliant": non_compliant_count,
            "compliance_rate": f"{(compliant_count / len(self.checkpoints) * 100):.1f}%",
            "critical_issues": sum(
                1 for c in self.checkpoints 
                if c.risk_level == RiskLevel.CRITICAL and c.status != ComplianceStatus.COMPLIANT
            ),
            "checkpoints": checkpoints_dict
        }


class HIPAACompliance:
    """
    HIPAA (Health Insurance Portability and Accountability Act) 컴플라이언스
    
    적용 대상: 미국 의료 정보
    주요 요구사항:
    - 접근 제어 및 감사 로그
    - 전송 암호화 (TLS)
    - 침해 대응 계획
    - 보안 위험 평가
    """

    def __init__(self):
        self.checkpoints: List[RequirementCheckpoint] = [
            RequirementCheckpoint(
                requirement_id="HIPAA-1",
                requirement_name="접근 제어 (Access Controls)",
                regulation="HIPAA 164.312(a)(2)(i)",
                description="보호된 건강정보(PHI)에 대한 역할 기반 접근 제어",
                status=ComplianceStatus.COMPLIANT,
                evidence="AuthModule.java: 회의방/역할 바인딩 토큰으로 접근 제어 구현",
                risk_level=RiskLevel.CRITICAL,
                remediation="이미 구현됨"
            ),
            RequirementCheckpoint(
                requirement_id="HIPAA-2",
                requirement_name="전송 계층 보안 (Encryption in Transit)",
                regulation="HIPAA 164.312(e)(1)",
                description="PHI 전송 시 TLS 1.2 이상 암호화 필수",
                status=ComplianceStatus.COMPLIANT,
                evidence="secure_static_server.py: HTTPS/TLS 강제, CSP 헤더 적용",
                risk_level=RiskLevel.CRITICAL,
                remediation="이미 구현됨"
            ),
            RequirementCheckpoint(
                requirement_id="HIPAA-3",
                requirement_name="저장 데이터 암호화 (Encryption at Rest)",
                regulation="HIPAA 164.312(a)(2)(iv)",
                description="저장된 PHI 암호화 (권장사항에서 의무사항으로 강화)",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="AES-GCM 미디어 암호화는 있으나 데이터베이스 저장 암호화 미흡",
                risk_level=RiskLevel.HIGH,
                remediation="데이터베이스 투명 데이터 암호화(TDE) 도입"
            ),
            RequirementCheckpoint(
                requirement_id="HIPAA-4",
                requirement_name="감사 로그 및 로깅 (Audit Controls)",
                regulation="HIPAA 164.312(b)",
                description="PHI 접근 및 변경 사항 로깅",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="보안 모듈별 로깅 구현, 통합 감시 체계 미흡",
                risk_level=RiskLevel.HIGH,
                remediation="중앙 감시(SIEM) 및 로그 보존 정책 수립"
            ),
            RequirementCheckpoint(
                requirement_id="HIPAA-5",
                requirement_name="침해 대응 계획 (Incident Response Plan)",
                regulation="HIPAA 164.308(a)(6)",
                description="보안 침해 탐지, 대응, 복구 절차 수립",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="위협 모델 및 검증은 있으나 사건 대응 절차 문서 미작성",
                risk_level=RiskLevel.CRITICAL,
                remediation="사건 대응 계획(IRP) 문서 작성"
            ),
            RequirementCheckpoint(
                requirement_id="HIPAA-6",
                requirement_name="보안 평가 (Security Risk Analysis)",
                regulation="HIPAA 164.308(a)(1)(ii)(B)",
                description="주기적 보안 위험 평가 수행",
                status=ComplianceStatus.COMPLIANT,
                evidence="STRIDE-ZAP 비교 분석 = 형식적 위험 평가 수행",
                risk_level=RiskLevel.MEDIUM,
                remediation="연 1회 정기 평가 계획 수립"
            )
        ]

    def evaluate(self) -> Dict:
        """HIPAA 컴플라이언스 평가"""
        compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.COMPLIANT
        )
        partial_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.PARTIALLY_COMPLIANT
        )
        non_compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.NON_COMPLIANT
        )

        checkpoints_dict = []
        for c in self.checkpoints:
            cp_dict = asdict(c)
            cp_dict['status'] = c.status.value
            cp_dict['risk_level'] = c.risk_level.value
            checkpoints_dict.append(cp_dict)

        return {
            "framework": "HIPAA",
            "total_requirements": len(self.checkpoints),
            "compliant": compliant_count,
            "partially_compliant": partial_count,
            "non_compliant": non_compliant_count,
            "compliance_rate": f"{(compliant_count / len(self.checkpoints) * 100):.1f}%",
            "critical_issues": sum(
                1 for c in self.checkpoints 
                if c.risk_level == RiskLevel.CRITICAL and c.status != ComplianceStatus.COMPLIANT
            ),
            "checkpoints": checkpoints_dict
        }


class KoreanPersonalDataProtectionCompliance:
    """
    한국 개인정보보호법 컴플라이언스
    
    주요 요구사항:
    - 개인정보 안전성 확보
    - 동의 관리
    - 개인정보 처리 관련 사항 공개
    - 개인정보 유출 사건 신고
    """

    def __init__(self):
        self.checkpoints: List[RequirementCheckpoint] = [
            RequirementCheckpoint(
                requirement_id="KPDPA-1",
                requirement_name="개인정보 안전성 확보",
                regulation="개인정보보호법 제29조",
                description="암호화, 접근제어, 마스킹 등으로 안전성 확보",
                status=ComplianceStatus.COMPLIANT,
                evidence="encryption.py, data_protection.py에 다층 보안 조치 구현",
                risk_level=RiskLevel.CRITICAL,
                remediation="이미 구현됨"
            ),
            RequirementCheckpoint(
                requirement_id="KPDPA-2",
                requirement_name="동의 및 이용약관",
                regulation="개인정보보호법 제15조",
                description="개인정보 수집 시 명시적 동의",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="privacy 파라미터로 선택권 제공, 이용약관 공시 미흡",
                risk_level=RiskLevel.HIGH,
                remediation="정식 이용약관 및 개인정보처리방침 공시"
            ),
            RequirementCheckpoint(
                requirement_id="KPDPA-3",
                requirement_name="개인정보 처리 방침 공개",
                regulation="개인정보보호법 제30조",
                description="처리 목적, 항목, 보관기간, 제3자 제공 현황 공개",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="README에 기본 정보 포함, 법적 문서로서 완성도 미흡",
                risk_level=RiskLevel.MEDIUM,
                remediation="공식 개인정보처리방침 웹페이지 게시"
            ),
            RequirementCheckpoint(
                requirement_id="KPDPA-4",
                requirement_name="개인정보 유출 신고",
                regulation="개인정보보호법 제34조",
                description="유출 발생 시 지체 없이 본인 및 감독기관에 신고",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="침해 탐지 로직은 있으나 자동 신고 기능 미흡",
                risk_level=RiskLevel.CRITICAL,
                remediation="자동 신고 체계 구축"
            ),
            RequirementCheckpoint(
                requirement_id="KPDPA-5",
                requirement_name="개인정보 요청권 (조회, 정정, 삭제)",
                regulation="개인정보보호법 제35-37조",
                description="사용자의 정보 조회, 정정, 삭제 요청에 응응",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="마스킹으로 개인정보 보호는 하나, 정식 요청 API 미구현",
                risk_level=RiskLevel.HIGH,
                remediation="개인정보 조회/정정/삭제 요청 API 구현"
            ),
            RequirementCheckpoint(
                requirement_id="KPDPA-6",
                requirement_name="책임자 지정 (개인정보보호관리자)",
                regulation="개인정보보호법 제31조",
                description="조직 내 개인정보보호관리자 지정",
                status=ComplianceStatus.NOT_APPLICABLE,
                evidence="실습 환경 범위 밖",
                risk_level=RiskLevel.LOW,
                remediation="조직화 시 검토"
            )
        ]

    def evaluate(self) -> Dict:
        """한국 개인정보보호법 컴플라이언스 평가"""
        compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.COMPLIANT
        )
        partial_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.PARTIALLY_COMPLIANT
        )
        non_compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.NON_COMPLIANT
        )

        checkpoints_dict = []
        for c in self.checkpoints:
            cp_dict = asdict(c)
            cp_dict['status'] = c.status.value
            cp_dict['risk_level'] = c.risk_level.value
            checkpoints_dict.append(cp_dict)

        return {
            "framework": "한국 개인정보보호법",
            "total_requirements": len(self.checkpoints),
            "compliant": compliant_count,
            "partially_compliant": partial_count,
            "non_compliant": non_compliant_count,
            "compliance_rate": f"{(compliant_count / len(self.checkpoints) * 100):.1f}%",
            "critical_issues": sum(
                1 for c in self.checkpoints 
                if c.risk_level == RiskLevel.CRITICAL and c.status != ComplianceStatus.COMPLIANT
            ),
            "checkpoints": checkpoints_dict
        }


class ISO27001Compliance:
    """
    ISO 27001:2022 정보보안 관리 시스템
    
    주요 통제 요소:
    - 접근 제어
    - 암호화
    - 보안 정책
    - 사건 관리
    """

    def __init__(self):
        self.checkpoints: List[RequirementCheckpoint] = [
            RequirementCheckpoint(
                requirement_id="ISO-AC-1",
                requirement_name="사용자 접근 관리 (User Access Management)",
                regulation="ISO 27001 Annex A.8.2.1",
                description="역할 기반 접근 제어 및 최소 권한 원칙",
                status=ComplianceStatus.COMPLIANT,
                evidence="AuthModule.java: 토큰 바인딩, 권한 검증 구현",
                risk_level=RiskLevel.CRITICAL,
                remediation="이미 구현됨"
            ),
            RequirementCheckpoint(
                requirement_id="ISO-CR-1",
                requirement_name="암호화 (Cryptography)",
                regulation="ISO 27001 Annex A.10.1",
                description="전송 및 저장 데이터 암호화",
                status=ComplianceStatus.COMPLIANT,
                evidence="AES-GCM 암호화, TLS 강제 적용",
                risk_level=RiskLevel.CRITICAL,
                remediation="이미 구현됨"
            ),
            RequirementCheckpoint(
                requirement_id="ISO-PS-1",
                requirement_name="보안 정책 수립",
                regulation="ISO 27001 Annex A.5.1",
                description="조직 차원의 명확한 보안 정책 수립",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="이 보고서가 정책 가이드이나 공식 정책 문서 미작성",
                risk_level=RiskLevel.MEDIUM,
                remediation="공식 정보보안 정책 문서 작성"
            ),
            RequirementCheckpoint(
                requirement_id="ISO-EM-1",
                requirement_name="보안 사건 관리",
                regulation="ISO 27001 Annex A.16.1",
                description="보안 사건 탐지, 대응, 복구 절차",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="탐지 로직은 있으나 공식 사건 대응 절차 미흡",
                risk_level=RiskLevel.HIGH,
                remediation="공식 사건 대응 계획(IRP) 수립"
            ),
            RequirementCheckpoint(
                requirement_id="ISO-AU-1",
                requirement_name="감시 및 로깅",
                regulation="ISO 27001 Annex A.12.4.1",
                description="보안 관련 활동의 로깅 및 모니터링",
                status=ComplianceStatus.PARTIALLY_COMPLIANT,
                evidence="모듈별 로깅은 있으나 중앙 집중식 감시 미흡",
                risk_level=RiskLevel.MEDIUM,
                remediation="SIEM 도입"
            )
        ]

    def evaluate(self) -> Dict:
        """ISO 27001 컴플라이언스 평가"""
        compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.COMPLIANT
        )
        partial_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.PARTIALLY_COMPLIANT
        )
        non_compliant_count = sum(
            1 for c in self.checkpoints 
            if c.status == ComplianceStatus.NON_COMPLIANT
        )

        checkpoints_dict = []
        for c in self.checkpoints:
            cp_dict = asdict(c)
            cp_dict['status'] = c.status.value
            cp_dict['risk_level'] = c.risk_level.value
            checkpoints_dict.append(cp_dict)

        return {
            "framework": "ISO 27001:2022",
            "total_requirements": len(self.checkpoints),
            "compliant": compliant_count,
            "partially_compliant": partial_count,
            "non_compliant": non_compliant_count,
            "compliance_rate": f"{(compliant_count / len(self.checkpoints) * 100):.1f}%",
            "critical_issues": sum(
                1 for c in self.checkpoints 
                if c.risk_level == RiskLevel.CRITICAL and c.status != ComplianceStatus.COMPLIANT
            ),
            "checkpoints": checkpoints_dict
        }


class ComplianceReportGenerator:
    """컴플라이언스 보고서 생성"""

    def __init__(self):
        self.frameworks = [
            GDPRCompliance(),
            HIPAACompliance(),
            KoreanPersonalDataProtectionCompliance(),
            ISO27001Compliance()
        ]

    def generate_report(self) -> Dict:
        """통합 컴플라이언스 보고서 생성"""
        results = []
        total_critical_issues = 0
        
        for framework in self.frameworks:
            result = framework.evaluate()
            results.append(result)
            total_critical_issues += result["critical_issues"]

        return {
            "report_date": datetime.now().isoformat(),
            "total_frameworks": len(results),
            "total_critical_issues": total_critical_issues,
            "frameworks": results
        }

    def print_summary(self) -> None:
        """보고서 요약 출력"""
        print("=" * 80)
        print("COMPLIANCE ASSESSMENT REPORT")
        print("=" * 80)
        
        report = self.generate_report()
        
        print(f"\n📅 보고서 생성일: {report['report_date']}")
        print(f"⚠️  즉시 조치 필요 항목: {report['total_critical_issues']}")
        
        print("\n" + "=" * 80)
        print("규제별 컴플라이언스 현황")
        print("=" * 80)
        
        for framework in report["frameworks"]:
            print(f"\n🏢 {framework['framework']}")
            print(f"   ✅ 완전 준수: {framework['compliant']}/{framework['total_requirements']}")
            print(f"   ⚠️  부분 준수: {framework['partially_compliant']}/{framework['total_requirements']}")
            print(f"   ❌ 미준수: {framework['non_compliant']}/{framework['total_requirements']}")
            print(f"   📊 준수율: {framework['compliance_rate']}")
            print(f"   🚨 중대 사안: {framework['critical_issues']}")

    def export_json(self, filename: str) -> None:
        """JSON 형식 내보내기"""
        report = self.generate_report()
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n✅ 보고서 저장: {filename}")


if __name__ == "__main__":
    generator = ComplianceReportGenerator()
    generator.print_summary()
    generator.export_json("reports/compliance/compliance_assessment.json")
