"""
AI-Based Threat Modeling for Video Conferencing Systems
========================================================

머신러닝 기반 위협 탐지 및 예측 시스템입니다.

기능:
- 이상 탐지 (Anomaly Detection): 정상 패턴과 다른 접근 행동 감지
- 위협 분류 (Threat Classification): 알려진 위협 패턴 분류
- 예측 분석 (Predictive Analytics): 향후 위협 발생 가능성 예측
- 자동 대응 (Automated Response): 탐지된 위협에 자동 대응
"""

import json
import math
import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
from collections import defaultdict


class ThreatType(Enum):
    """위협 분류"""
    AUTHENTICATION = "authentication"  # 인증 우회
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 권한 상승
    DATA_EXFILTRATION = "data_exfiltration"  # 데이터 유출
    DENIAL_OF_SERVICE = "denial_of_service"  # 서비스 거부
    REPLAY_ATTACK = "replay_attack"  # 재전송 공격
    MAN_IN_THE_MIDDLE = "man_in_the_middle"  # 중간자 공격
    INSIDER_THREAT = "insider_threat"  # 내부자 위협
    UNKNOWN = "unknown"  # 미분류


class AnomalyScore(Enum):
    """이상 점수 레벨"""
    NORMAL = 0.0  # 정상
    ANOMALY_LOW = 0.3  # 경미한 이상
    ANOMALY_MEDIUM = 0.6  # 중간 정도 이상
    ANOMALY_HIGH = 0.9  # 높은 수준 이상


@dataclass
class BehaviorFeature:
    """행동 특성"""
    user_id: str
    timestamp: float
    login_time_hour: int  # 0-23
    login_frequency: int  # 시간당 로그인 횟수
    source_ip_count: int  # 사용하는 IP 주소 개수
    failed_login_attempts: int  # 실패 횟수
    session_duration: int  # 세션 지속 시간 (초)
    resource_access_count: int  # 접근 리소스 개수
    data_transfer_volume: int  # 데이터 전송량 (바이트)
    is_weekend: bool  # 주말 여부
    is_holiday: bool  # 휴일 여부
    is_vpn: bool  # VPN 사용 여부
    device_change: bool  # 새로운 기기 사용 여부


@dataclass
class ThreatDetectionResult:
    """위협 탐지 결과"""
    user_id: str
    anomaly_score: float  # 0-1
    threat_type: ThreatType
    threat_confidence: float  # 0-1
    explanation: str
    recommended_action: str


class AnomalyDetector:
    """이상 탐지 모듈 (Isolation Forest 유사)"""

    def __init__(self):
        """이상 탐지기 초기화"""
        # 정상 행동 프로필 (통계 기반)
        self.normal_profiles = {
            "avg_login_hour": 10,  # 평균 로그인 시간 (업무 시간)
            "avg_login_frequency": 2.5,  # 평균 시간당 로그인
            "avg_source_ip_count": 2,  # 평균 사용 IP 개수
            "avg_session_duration": 3600,  # 평균 세션 길이 (1시간)
            "avg_resource_access": 5,  # 평균 접근 리소스
            "avg_data_transfer": 10_000_000,  # 평균 데이터 전송 (10MB)
        }
        self.std_dev = {
            "login_hour": 2.0,  # 표준편차
            "login_frequency": 1.5,
            "source_ip_count": 1.0,
            "session_duration": 1800,
            "resource_access": 3,
            "data_transfer": 5_000_000,
        }

    def detect_anomaly(self, feature: BehaviorFeature) -> Tuple[float, str]:
        """
        이상 탐지 (Z-score 기반)
        
        Returns:
            (이상 점수 0-1, 상세 설명)
        """
        anomaly_scores = []
        explanations = []

        # 1. 로그인 시간 이상 탐지
        z_hour = self._calculate_zscore(
            feature.login_time_hour,
            self.normal_profiles["avg_login_hour"],
            self.std_dev["login_hour"]
        )
        if z_hour > 2:  # 2 표준편차 이상
            anomaly_scores.append(min(abs(z_hour) / 5, 1.0))
            explanations.append(f"비정상적 로그인 시간: {feature.login_time_hour}시")
        else:
            anomaly_scores.append(0)

        # 2. 로그인 빈도 이상
        z_freq = self._calculate_zscore(
            feature.login_frequency,
            self.normal_profiles["avg_login_frequency"],
            self.std_dev["login_frequency"]
        )
        if z_freq > 2:
            anomaly_scores.append(min(abs(z_freq) / 5, 1.0))
            explanations.append(f"비정상적 로그인 빈도: {feature.login_frequency}회/시간")
        else:
            anomaly_scores.append(0)

        # 3. IP 주소 다양성 이상
        if feature.source_ip_count > self.normal_profiles["avg_source_ip_count"] + 2:
            anomaly_scores.append(0.7)
            explanations.append(f"예상 밖의 많은 IP 주소 사용: {feature.source_ip_count}개")
        else:
            anomaly_scores.append(0)

        # 4. 실패한 로그인 시도
        if feature.failed_login_attempts > 3:
            anomaly_scores.append(min(feature.failed_login_attempts / 10, 1.0))
            explanations.append(f"반복된 로그인 실패: {feature.failed_login_attempts}회")
        else:
            anomaly_scores.append(0)

        # 5. 세션 지속 시간 이상
        z_session = self._calculate_zscore(
            feature.session_duration,
            self.normal_profiles["avg_session_duration"],
            self.std_dev["session_duration"]
        )
        if abs(z_session) > 3:  # 매우 길거나 매우 짧은 세션
            anomaly_scores.append(min(abs(z_session) / 10, 1.0))
            explanations.append(f"비정상적 세션 길이: {feature.session_duration}초")
        else:
            anomaly_scores.append(0)

        # 6. 리소스 접근 이상
        if feature.resource_access_count > self.normal_profiles["avg_resource_access"] * 3:
            anomaly_scores.append(0.8)
            explanations.append(f"과도한 리소스 접근: {feature.resource_access_count}개")
        else:
            anomaly_scores.append(0)

        # 7. 데이터 전송량 이상
        z_data = self._calculate_zscore(
            feature.data_transfer_volume,
            self.normal_profiles["avg_data_transfer"],
            self.std_dev["data_transfer"]
        )
        if z_data > 2:
            anomaly_scores.append(min(z_data / 5, 1.0))
            explanations.append(f"과도한 데이터 전송: {feature.data_transfer_volume / 1_000_000:.1f}MB")
        else:
            anomaly_scores.append(0)

        # 8. 시간대 기반 이상 (평일 근무시간 외)
        is_after_hours = feature.login_time_hour < 9 or feature.login_time_hour > 18
        if is_after_hours and (feature.is_weekend or feature.is_holiday):
            anomaly_scores.append(0.5)
            explanations.append("비정상적 시간대 접근: 휴일/야간")
        else:
            anomaly_scores.append(0)

        # 9. 기기 변경
        if feature.device_change:
            anomaly_scores.append(0.4)
            explanations.append("새로운 기기에서의 접근")
        else:
            anomaly_scores.append(0)

        # 최종 이상 점수 (평균)
        final_anomaly_score = float(np.mean(anomaly_scores))
        final_explanation = " | ".join(explanations) if explanations else "정상 행동"

        return final_anomaly_score, final_explanation

    @staticmethod
    def _calculate_zscore(value: float, mean: float, std: float) -> float:
        """Z-score 계산"""
        if std == 0:
            return 0
        return (value - mean) / std


class ThreatClassifier:
    """위협 분류기 (패턴 매칭)"""

    def __init__(self):
        """분류기 초기화"""
        self.threat_signatures = self._load_threat_signatures()

    def _load_threat_signatures(self) -> Dict[ThreatType, Dict]:
        """위협 패턴 시그니처 로드"""
        return {
            ThreatType.AUTHENTICATION: {
                "indicators": [
                    "failed_login_attempts > 5",
                    "login_frequency > 10",
                    "source_ip_count > 5"
                ],
                "weight": 0.9
            },
            ThreatType.PRIVILEGE_ESCALATION: {
                "indicators": [
                    "resource_access_count > 10",
                    "session_duration > 14400",  # 4시간 이상
                ],
                "weight": 0.8
            },
            ThreatType.DATA_EXFILTRATION: {
                "indicators": [
                    "data_transfer_volume > 100_000_000",  # 100MB 이상
                    "resource_access_count > 5",
                ],
                "weight": 0.85
            },
            ThreatType.DENIAL_OF_SERVICE: {
                "indicators": [
                    "login_frequency > 20",
                    "failed_login_attempts > 10",
                ],
                "weight": 0.8
            },
            ThreatType.REPLAY_ATTACK: {
                "indicators": [
                    "source_ip_count = 1",  # 동일 IP
                    "session_duration < 60",  # 매우 짧은 세션
                ],
                "weight": 0.7
            },
            ThreatType.MAN_IN_THE_MIDDLE: {
                "indicators": [
                    "source_ip_count > 2",
                    "is_vpn = False",  # VPN 미사용
                ],
                "weight": 0.6
            },
            ThreatType.INSIDER_THREAT: {
                "indicators": [
                    "session_duration > 7200",  # 2시간 이상
                    "resource_access_count > 3",
                    "data_transfer_volume > 50_000_000",  # 50MB 이상
                ],
                "weight": 0.75
            }
        }

    def classify(self, feature: BehaviorFeature) -> Tuple[ThreatType, float]:
        """
        행동을 위협 유형으로 분류
        
        Returns:
            (위협 유형, 신뢰도 0-1)
        """
        threat_scores: Dict[ThreatType, float] = {}

        for threat_type, signature in self.threat_signatures.items():
            match_count = 0
            total_count = len(signature["indicators"])

            # 각 지표 확인
            for indicator in signature["indicators"]:
                if self._evaluate_indicator(indicator, feature):
                    match_count += 1

            # 신뢰도 = (일치 지표 수 / 전체 지표 수) * 가중치
            confidence = (match_count / total_count) * signature["weight"] if total_count > 0 else 0
            threat_scores[threat_type] = confidence

        # 가장 높은 신뢰도의 위협 유형 반환
        best_threat = max(threat_scores, key=lambda threat_type: threat_scores[threat_type])
        best_confidence = threat_scores[best_threat]

        return best_threat, best_confidence

    def _evaluate_indicator(self, indicator: str, feature: BehaviorFeature) -> bool:
        """지표 평가"""
        # 간단한 평가 로직 (실제로는 더 복잡한 파서 필요)
        
        if "failed_login_attempts > 5" in indicator:
            return feature.failed_login_attempts > 5
        elif "failed_login_attempts > 10" in indicator:
            return feature.failed_login_attempts > 10
        elif "login_frequency > 10" in indicator:
            return feature.login_frequency > 10
        elif "login_frequency > 20" in indicator:
            return feature.login_frequency > 20
        elif "source_ip_count > 5" in indicator:
            return feature.source_ip_count > 5
        elif "source_ip_count > 2" in indicator:
            return feature.source_ip_count > 2
        elif "source_ip_count = 1" in indicator:
            return feature.source_ip_count == 1
        elif "resource_access_count > 10" in indicator:
            return feature.resource_access_count > 10
        elif "resource_access_count > 5" in indicator:
            return feature.resource_access_count > 5
        elif "resource_access_count > 3" in indicator:
            return feature.resource_access_count > 3
        elif "session_duration > 14400" in indicator:
            return feature.session_duration > 14400
        elif "session_duration > 7200" in indicator:
            return feature.session_duration > 7200
        elif "session_duration < 60" in indicator:
            return feature.session_duration < 60
        elif "data_transfer_volume > 100_000_000" in indicator:
            return feature.data_transfer_volume > 100_000_000
        elif "data_transfer_volume > 50_000_000" in indicator:
            return feature.data_transfer_volume > 50_000_000
        elif "is_vpn = False" in indicator:
            return not feature.is_vpn
        else:
            return False


class ThreatDetectionEngine:
    """종합 위협 탐지 엔진"""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        self.detection_history = []

    def detect_threat(self, feature: BehaviorFeature) -> ThreatDetectionResult:
        """
        행동에서 위협 탐지
        
        Returns:
            위협 탐지 결과
        """
        # 1. 이상 탐지
        anomaly_score, anomaly_explanation = self.anomaly_detector.detect_anomaly(feature)

        # 2. 위협 분류
        threat_type, threat_confidence = self.threat_classifier.classify(feature)

        # 3. 최종 신뢰도 (이상 + 분류)
        final_confidence = (anomaly_score + threat_confidence) / 2

        # 4. 권장 조치
        recommended_action = self._get_recommended_action(threat_type, final_confidence)

        # 5. 상세 설명
        explanation = f"{anomaly_explanation} → 위협: {threat_type.value}"

        result = ThreatDetectionResult(
            user_id=feature.user_id,
            anomaly_score=anomaly_score,
            threat_type=threat_type,
            threat_confidence=final_confidence,
            explanation=explanation,
            recommended_action=recommended_action
        )

        # 히스토리 기록 (Enum을 문자열로 변환)
        result_dict = asdict(result)
        result_dict['threat_type'] = result.threat_type.value
        self.detection_history.append(result_dict)

        return result

    def _get_recommended_action(self, threat_type: ThreatType, confidence: float) -> str:
        """위협 유형과 신뢰도에 따른 권장 조치"""
        
        if confidence > 0.8:
            severity = "높음"
        elif confidence > 0.5:
            severity = "중간"
        else:
            severity = "낮음"

        actions = {
            ThreatType.AUTHENTICATION: f"[{severity}] 세션 즉시 종료, MFA 재검증 요구",
            ThreatType.PRIVILEGE_ESCALATION: f"[{severity}] 권한 검토, 접근 제한",
            ThreatType.DATA_EXFILTRATION: f"[{severity}] 데이터 전송 차단, 감시 강화",
            ThreatType.DENIAL_OF_SERVICE: f"[{severity}] 로그인 시도 제한, IP 차단 검토",
            ThreatType.REPLAY_ATTACK: f"[{severity}] 세션 토큰 갱신, 재인증",
            ThreatType.MAN_IN_THE_MIDDLE: f"[{severity}] VPN 강제, TLS 검증",
            ThreatType.INSIDER_THREAT: f"[{severity}] 감시 강화, 데이터 접근 제한 검토",
            ThreatType.UNKNOWN: f"[{severity}] 수동 검토 필요"
        }

        return actions.get(threat_type, "[낮음] 계속 모니터링")

    def export_detection_history(self, filename: str) -> None:
        """탐지 히스토리 내보내기"""
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.detection_history, f, indent=2, ensure_ascii=False)


# ============================================================================
# 실전 예제
# ============================================================================

def example_ai_threat_detection():
    """AI 기반 위협 탐지 예제"""
    print("=" * 80)
    print("AI-Based Threat Detection Engine")
    print("=" * 80)

    engine = ThreatDetectionEngine()

    # 시나리오 1: 정상 사용자
    print("\n[시나리오 1] 정상 사용자 행동")
    print("-" * 80)

    normal_feature = BehaviorFeature(
        user_id="user001@example.com",
        timestamp=datetime.now().timestamp(),
        login_time_hour=10,  # 업무 시간
        login_frequency=2,  # 시간당 2회
        source_ip_count=1,  # 1개 IP (일정)
        failed_login_attempts=0,
        session_duration=3600,  # 1시간
        resource_access_count=5,
        data_transfer_volume=5_000_000,  # 5MB
        is_weekend=False,
        is_holiday=False,
        is_vpn=True,
        device_change=False
    )

    result1 = engine.detect_threat(normal_feature)
    print(f"위협 유형: {result1.threat_type.value}")
    print(f"신뢰도: {result1.threat_confidence:.2%}")
    print(f"이상 점수: {result1.anomaly_score:.2%}")
    print(f"설명: {result1.explanation}")
    print(f"권장 조치: {result1.recommended_action}")

    # 시나리오 2: 인증 우회 시도
    print("\n[시나리오 2] 인증 우회 시도 (반복된 로그인 실패)")
    print("-" * 80)

    auth_attack_feature = BehaviorFeature(
        user_id="user002@example.com",
        timestamp=datetime.now().timestamp(),
        login_time_hour=23,  # 야간
        login_frequency=15,  # 매우 높은 빈도
        source_ip_count=3,  # 여러 IP
        failed_login_attempts=12,  # 많은 실패
        session_duration=30,  # 매우 짧은 세션
        resource_access_count=0,
        data_transfer_volume=0,
        is_weekend=True,
        is_holiday=False,
        is_vpn=False,
        device_change=True
    )

    result2 = engine.detect_threat(auth_attack_feature)
    print(f"위협 유형: {result2.threat_type.value}")
    print(f"신뢰도: {result2.threat_confidence:.2%}")
    print(f"이상 점수: {result2.anomaly_score:.2%}")
    print(f"설명: {result2.explanation}")
    print(f"권장 조치: {result2.recommended_action}")

    # 시나리오 3: 데이터 유출 시도
    print("\n[시나리오 3] 데이터 유출 시도 (과도한 데이터 전송)")
    print("-" * 80)

    exfiltration_feature = BehaviorFeature(
        user_id="user003@example.com",
        timestamp=datetime.now().timestamp(),
        login_time_hour=15,  # 업무 시간
        login_frequency=1,  # 정상
        source_ip_count=1,  # 동일 IP
        failed_login_attempts=0,
        session_duration=14400,  # 4시간
        resource_access_count=8,  # 많은 리소스
        data_transfer_volume=150_000_000,  # 150MB (비정상)
        is_weekend=False,
        is_holiday=False,
        is_vpn=True,
        device_change=False
    )

    result3 = engine.detect_threat(exfiltration_feature)
    print(f"위협 유형: {result3.threat_type.value}")
    print(f"신뢰도: {result3.threat_confidence:.2%}")
    print(f"이상 점수: {result3.anomaly_score:.2%}")
    print(f"설명: {result3.explanation}")
    print(f"권장 조치: {result3.recommended_action}")

    # 시나리오 4: 내부자 위협
    print("\n[시나리오 4] 내부자 위협 (권한 있는 사용자의 의심 행동)")
    print("-" * 80)

    insider_threat_feature = BehaviorFeature(
        user_id="admin@example.com",
        timestamp=datetime.now().timestamp(),
        login_time_hour=2,  # 새벽
        login_frequency=3,
        source_ip_count=1,
        failed_login_attempts=0,
        session_duration=10800,  # 3시간
        resource_access_count=12,  # 많은 시스템 접근
        data_transfer_volume=80_000_000,  # 80MB
        is_weekend=True,
        is_holiday=True,
        is_vpn=False,  # VPN 미사용
        device_change=True
    )

    result4 = engine.detect_threat(insider_threat_feature)
    print(f"위협 유형: {result4.threat_type.value}")
    print(f"신뢰도: {result4.threat_confidence:.2%}")
    print(f"이상 점수: {result4.anomaly_score:.2%}")
    print(f"설명: {result4.explanation}")
    print(f"권장 조치: {result4.recommended_action}")

    # 탐지 히스토리 내보내기
    print("\n" + "=" * 80)
    print("탐지 히스토리 저장 중...")
    engine.export_detection_history("reports/ai_threat_detection_history.json")
    print("✅ 저장 완료: reports/ai_threat_detection_history.json")


if __name__ == "__main__":
    example_ai_threat_detection()
