"""
Zero Trust Architecture for Video Conferencing Systems
======================================================

Zero Trust 아키텍처는 "절대 신뢰하지 않음, 항상 검증" 원칙에 따라
모든 접근 요청(인증, 인가, 암호화, 기기 보안)을 일관되게 검증합니다.

참고: NIST SP 800-207 Zero Trust Architecture (2020)
"""

import json
import hashlib
import time
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta


class TrustLevel(Enum):
    """신뢰도 레벨 (0 = 신뢰 불가, 100 = 최고 신뢰)"""
    UNKNOWN = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100


class DevicePostureStatus(Enum):
    """기기 보안 상태"""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


@dataclass
class AccessRequest:
    """접근 요청 정보"""
    user_id: str
    device_id: str
    ip_address: str
    conference_room: str
    resource: str
    action: str  # view, modify, record, share 등
    timestamp: float


@dataclass
class UserContext:
    """사용자 컨텍스트 (지속적 검증)"""
    user_id: str
    mfa_verified: bool
    mfa_timestamp: float
    trusted_devices: List[str]
    risk_score: float  # 0-100 (높을수록 위험)
    last_activity: float
    session_age: float


@dataclass
class DeviceContext:
    """기기 컨텍스트 (지속적 검증)"""
    device_id: str
    os: str
    os_version: str
    antivirus_enabled: bool
    firewall_enabled: bool
    disk_encryption: bool
    last_security_update: float
    posture_status: DevicePostureStatus


@dataclass
class NetworkContext:
    """네트워크 컨텍스트 (지속적 검증)"""
    source_ip: str
    country: str
    is_vpn: bool
    network_anomaly_detected: bool
    bandwidth_anomaly: bool
    latency_ms: float


class ZeroTrustPolicyEngine:
    """Zero Trust 정책 엔진"""

    def __init__(self):
        """정책 엔진 초기화"""
        self.policy_rules = self._load_default_policies()
        self.decision_log = []

    def _load_default_policies(self) -> Dict:
        """기본 Zero Trust 정책 로드"""
        return {
            "mfa_required": True,
            "mfa_max_age_seconds": 3600,  # 1시간
            "device_posture_required": True,
            "acceptable_device_postures": [
                DevicePostureStatus.COMPLIANT,
                DevicePostureStatus.PARTIALLY_COMPLIANT
            ],
            "risk_score_threshold": 60,  # 60 이상 = 높은 위험
            "max_session_age_seconds": 28800,  # 8시간
            "continuous_monitoring_interval_seconds": 300,  # 5분마다 검증
            "require_encryption_tls": True,
            "enforce_least_privilege": True,
            "action_based_policies": {
                "view": {"risk_threshold": 30},
                "modify": {"risk_threshold": 20},
                "record": {"risk_threshold": 10},
                "share": {"risk_threshold": 15}
            }
        }

    def evaluate_access(
        self,
        request: AccessRequest,
        user_ctx: UserContext,
        device_ctx: DeviceContext,
        network_ctx: NetworkContext
    ) -> Tuple[bool, float, str]:
        """
        접근 요청 평가 (다층 검증)
        
        Returns:
            (승인 여부, 신뢰도 점수 0-100, 결정 사유)
        """
        decision_factors = []
        trust_scores = []

        # 1. 사용자 검증
        user_trust = self._evaluate_user(user_ctx)
        decision_factors.append(f"User: {user_trust:.1f}")
        trust_scores.append(user_trust)

        # 2. 기기 검증
        device_trust = self._evaluate_device(device_ctx)
        decision_factors.append(f"Device: {device_trust:.1f}")
        trust_scores.append(device_trust)

        # 3. 네트워크 검증
        network_trust = self._evaluate_network(network_ctx)
        decision_factors.append(f"Network: {network_trust:.1f}")
        trust_scores.append(network_trust)

        # 4. 접근 맥락 검증
        context_trust = self._evaluate_context(request, user_ctx)
        decision_factors.append(f"Context: {context_trust:.1f}")
        trust_scores.append(context_trust)

        # 최종 신뢰도 = 가중 평균
        final_trust = (
            user_trust * 0.3 +      # 사용자 30%
            device_trust * 0.25 +   # 기기 25%
            network_trust * 0.2 +   # 네트워크 20%
            context_trust * 0.25    # 맥락 25%
        )

        # 정책 기반 최종 판정
        is_approved, reason = self._apply_policies(
            request, final_trust, user_ctx, device_ctx, network_ctx
        )

        # 로그 기록
        self.decision_log.append({
            "timestamp": time.time(),
            "user_id": request.user_id,
            "request": asdict(request),
            "trust_score": final_trust,
            "decision_factors": decision_factors,
            "approved": is_approved,
            "reason": reason
        })

        return is_approved, final_trust, reason

    def _evaluate_user(self, user_ctx: UserContext) -> float:
        """사용자 신뢰도 평가"""
        score = 100.0

        # MFA 검증 여부 (필수)
        if not user_ctx.mfa_verified:
            score = 0  # MFA 실패 = 접근 불가
            return score

        mfa_age = time.time() - user_ctx.mfa_timestamp
        mfa_max_age = self.policy_rules["mfa_max_age_seconds"]
        if mfa_age > mfa_max_age:
            score *= 0.3  # MFA 만료 = 신뢰도 70% 감소
            return score

        # 위험 점수 평가
        user_risk = user_ctx.risk_score
        score -= (user_risk * 0.4)  # 위험 점수에 따라 감점

        # 세션 나이 평가
        max_age = self.policy_rules["max_session_age_seconds"]
        if user_ctx.session_age > max_age:
            score *= 0.5

        # 활동 이력 평가 (최근 활동이 없으면 신뢰도 감소)
        inactivity = time.time() - user_ctx.last_activity
        if inactivity > 1800:  # 30분 이상 활동 없음
            score *= 0.8

        return max(0, score)

    def _evaluate_device(self, device_ctx: DeviceContext) -> float:
        """기기 신뢰도 평가"""
        score = 100.0

        # 기기 상태 확인 (필수)
        acceptable_postures = self.policy_rules["acceptable_device_postures"]
        if device_ctx.posture_status not in acceptable_postures:
            score = 0
            return score

        # 보안 기능 확인
        security_checks = [
            device_ctx.antivirus_enabled,
            device_ctx.firewall_enabled,
            device_ctx.disk_encryption
        ]
        enabled_count = sum(security_checks)
        score *= (enabled_count / len(security_checks))

        # OS 업데이트 확인
        days_since_update = (time.time() - device_ctx.last_security_update) / 86400
        if days_since_update > 30:
            score *= 0.7
        elif days_since_update > 60:
            score *= 0.4

        return max(0, score)

    def _evaluate_network(self, network_ctx: NetworkContext) -> float:
        """네트워크 신뢰도 평가"""
        score = 100.0

        # 이상 탐지
        if network_ctx.network_anomaly_detected:
            score *= 0.4
        if network_ctx.bandwidth_anomaly:
            score *= 0.6

        # VPN 사용 확인 (권장, 필수 아님)
        if network_ctx.is_vpn:
            score *= 1.1  # VPN 사용 = 신뢰도 증가
        else:
            score *= 0.9

        # 지역 기반 위험도
        high_risk_countries = ["UNKNOWN", "HIGH_RISK_REGION"]
        if network_ctx.country in high_risk_countries:
            score *= 0.7

        # 네트워크 지연도 확인 (비정상적 지연 = 위변조 가능성)
        if network_ctx.latency_ms > 500:
            score *= 0.8

        return max(0, score)

    def _evaluate_context(
        self, request: AccessRequest, user_ctx: UserContext
    ) -> float:
        """접근 맥락 신뢰도 평가"""
        score = 100.0

        # 기기가 신뢰된 기기 목록에 있는가?
        if request.device_id not in user_ctx.trusted_devices:
            score *= 0.7

        # 요청의 리소스와 액션이 일치하는가?
        action_risk_threshold = self.policy_rules["action_based_policies"].get(
            request.action, {}
        ).get("risk_threshold", 50)
        if user_ctx.risk_score > action_risk_threshold:
            score *= 0.6

        return max(0, score)

    def _apply_policies(
        self,
        request: AccessRequest,
        final_trust: float,
        user_ctx: UserContext,
        device_ctx: DeviceContext,
        network_ctx: NetworkContext
    ) -> Tuple[bool, str]:
        """정책 기반 최종 판정"""

        # 1. MFA 필수 확인
        if self.policy_rules["mfa_required"] and not user_ctx.mfa_verified:
            return False, "MFA 미검증"

        # 2. 기기 상태 필수 확인
        if self.policy_rules["device_posture_required"]:
            if device_ctx.posture_status not in self.policy_rules[
                "acceptable_device_postures"
            ]:
                return False, f"기기 상태 미달: {device_ctx.posture_status.value}"

        # 3. 위험 점수 임계값 확인
        if final_trust < 50:
            return False, f"신뢰도 부족 (점수: {final_trust:.1f}/100)"

        # 4. 최소 권한 원칙 (Least Privilege)
        if self.policy_rules["enforce_least_privilege"]:
            action_threshold = self.policy_rules["action_based_policies"].get(
                request.action, {}
            ).get("risk_threshold", 50)
            if final_trust < action_threshold:
                return (
                    False,
                    f"액션 '{request.action}'에 신뢰도 부족 (필요: {action_threshold}, 현재: {final_trust:.1f})"
                )

        return True, f"승인 (신뢰도: {final_trust:.1f}/100)"

    def continuous_monitoring(
        self,
        user_id: str,
        user_ctx: UserContext,
        device_ctx: DeviceContext,
        network_ctx: NetworkContext
    ) -> Tuple[bool, str]:
        """
        지속적 모니터링 (세션 중)
        
        매 5분마다 사용자/기기/네트워크를 재검증하여 세션 유효성 확인
        """
        # 세션 재인증
        request = AccessRequest(
            user_id=user_id,
            device_id=device_ctx.device_id,
            ip_address=network_ctx.source_ip,
            conference_room="monitoring",
            resource="session",
            action="view",
            timestamp=time.time()
        )

        is_approved, trust_score, reason = self.evaluate_access(
            request, user_ctx, device_ctx, network_ctx
        )

        if not is_approved:
            return False, f"세션 재검증 실패: {reason}"

        return True, f"세션 유효 (신뢰도: {trust_score:.1f}/100)"


class ZeroTrustAuditLog:
    """Zero Trust 감사 로그"""

    def __init__(self):
        self.entries = []

    def add_entry(self, entry: Dict) -> None:
        """로그 항목 추가"""
        entry["logged_at"] = datetime.now().isoformat()
        self.entries.append(entry)

    def export_json(self, filename: str) -> None:
        """JSON 형식으로 내보내기"""
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, indent=2, ensure_ascii=False)

    def summary(self) -> Dict:
        """감사 요약"""
        if not self.entries:
            return {"total_decisions": 0}

        approved = sum(1 for e in self.entries if e.get("approved", False))
        denied = len(self.entries) - approved

        return {
            "total_decisions": len(self.entries),
            "approved": approved,
            "denied": denied,
            "approval_rate": f"{(approved / len(self.entries) * 100):.1f}%",
            "timestamp_range": f"{self.entries[0]['logged_at']} ~ {self.entries[-1]['logged_at']}"
        }


# ============================================================================
# 실전 예제
# ============================================================================

def example_zero_trust_evaluation():
    """Zero Trust 정책 적용 예제"""
    print("=" * 70)
    print("Zero Trust Architecture - Access Evaluation Example")
    print("=" * 70)

    engine = ZeroTrustPolicyEngine()

    # 시나리오 1: 완벽한 사용자
    print("\n[시나리오 1] MFA 인증, 규정 준수 기기, 낮은 위험")
    print("-" * 70)

    request1 = AccessRequest(
        user_id="user@example.com",
        device_id="device-001",
        ip_address="203.0.113.10",
        conference_room="secure-meeting-001",
        resource="video_stream",
        action="view",
        timestamp=time.time()
    )

    user_ctx1 = UserContext(
        user_id="user@example.com",
        mfa_verified=True,
        mfa_timestamp=time.time(),  # 방금 인증
        trusted_devices=["device-001", "device-002"],
        risk_score=5.0,  # 매우 낮은 위험도
        last_activity=time.time(),
        session_age=3600  # 1시간 세션
    )

    device_ctx1 = DeviceContext(
        device_id="device-001",
        os="Windows",
        os_version="11",
        antivirus_enabled=True,
        firewall_enabled=True,
        disk_encryption=True,
        last_security_update=time.time() - 10 * 86400,  # 10일 전 업데이트
        posture_status=DevicePostureStatus.COMPLIANT
    )

    network_ctx1 = NetworkContext(
        source_ip="203.0.113.10",
        country="KR",
        is_vpn=True,
        network_anomaly_detected=False,
        bandwidth_anomaly=False,
        latency_ms=50
    )

    approved1, trust1, reason1 = engine.evaluate_access(
        request1, user_ctx1, device_ctx1, network_ctx1
    )

    print(f"✅ 결정: {'승인' if approved1 else '거부'}")
    print(f"📊 신뢰도: {trust1:.1f}/100")
    print(f"📝 사유: {reason1}")

    # 시나리오 2: MFA 미인증 사용자
    print("\n[시나리오 2] MFA 미인증")
    print("-" * 70)

    user_ctx2 = UserContext(
        user_id="user2@example.com",
        mfa_verified=False,  # MFA 미검증
        mfa_timestamp=0,
        trusted_devices=[],
        risk_score=50.0,
        last_activity=time.time(),
        session_age=1800
    )

    device_ctx2 = DeviceContext(
        device_id="device-003",
        os="macOS",
        os_version="13",
        antivirus_enabled=True,
        firewall_enabled=True,
        disk_encryption=True,
        last_security_update=time.time() - 5 * 86400,
        posture_status=DevicePostureStatus.COMPLIANT
    )

    network_ctx2 = NetworkContext(
        source_ip="192.0.2.100",
        country="US",
        is_vpn=False,
        network_anomaly_detected=False,
        bandwidth_anomaly=False,
        latency_ms=80
    )

    approved2, trust2, reason2 = engine.evaluate_access(
        request1, user_ctx2, device_ctx2, network_ctx2
    )

    print(f"❌ 결정: {'승인' if approved2 else '거부'}")
    print(f"📊 신뢰도: {trust2:.1f}/100")
    print(f"📝 사유: {reason2}")

    # 시나리오 3: 비규정 준수 기기
    print("\n[시나리오 3] 보안 미흡 기기 (안티바이러스 비활성화, 디스크 암호화 없음)")
    print("-" * 70)

    user_ctx3 = UserContext(
        user_id="user3@example.com",
        mfa_verified=True,
        mfa_timestamp=time.time(),
        trusted_devices=["device-004"],
        risk_score=10.0,
        last_activity=time.time(),
        session_age=7200
    )

    device_ctx3 = DeviceContext(
        device_id="device-004",
        os="Linux",
        os_version="Ubuntu 22.04",
        antivirus_enabled=False,  # 비활성화
        firewall_enabled=True,
        disk_encryption=False,  # 암호화 없음
        last_security_update=time.time() - 45 * 86400,  # 45일 전
        posture_status=DevicePostureStatus.NON_COMPLIANT
    )

    network_ctx3 = NetworkContext(
        source_ip="198.51.100.1",
        country="KR",
        is_vpn=False,
        network_anomaly_detected=False,
        bandwidth_anomaly=False,
        latency_ms=100
    )

    approved3, trust3, reason3 = engine.evaluate_access(
        request1, user_ctx3, device_ctx3, network_ctx3
    )

    print(f"❌ 결정: {'승인' if approved3 else '거부'}")
    print(f"📊 신뢰도: {trust3:.1f}/100")
    print(f"📝 사유: {reason3}")

    # 감사 요약
    print("\n" + "=" * 70)
    print("감사 로그 요약")
    print("=" * 70)
    audit_log = ZeroTrustAuditLog()
    for entry in engine.decision_log:
        audit_log.add_entry(entry)

    summary = audit_log.summary()
    for key, value in summary.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    example_zero_trust_evaluation()
