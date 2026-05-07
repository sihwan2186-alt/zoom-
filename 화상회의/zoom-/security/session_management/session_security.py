"""
세션 관리 보안 모듈
Zoom 취약점 보완: 안전한 세션 생성, 갱신, 폐기
"""
import os
import secrets
import hashlib
import hmac
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class Session:
    """세션 정보"""
    session_id: str
    user_id: str
    created_at: float
    last_accessed: float
    expires_at: float
    ip_address: str
    user_agent: str
    is_active: bool = True


class SessionManager:
    """세션 관리 모듈"""
    
    # 세션 설정
    SESSION_TIMEOUT = 3600  # 1시간
    REFRESH_INTERVAL = 1800  # 30분
    MAX_SESSIONS_PER_USER = 5
    
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.secret_key = self._generate_secret_key()
        
    def _generate_secret_key(self) -> bytes:
        """비밀 키 생성"""
        return secrets.token_bytes(32)
    
    def create_session(self, user_id: str, ip_address: str = "", user_agent: str = "") -> Session:
        """세션 생성"""
        # 기존 세션 수 확인
        user_sessions = [s for s in self.sessions.values() if s.user_id == user_id]
        if len(user_sessions) >= self.MAX_SESSIONS_PER_USER:
            # 가장 오래된 세션 제거
            oldest = min(user_sessions, key=lambda s: s.last_accessed)
            self.destroy_session(oldest.session_id)
        
        # 세션 ID 생성 (안전한 난수)
        session_id = self._generate_session_id()
        current_time = time.time()
        
        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=current_time,
            last_accessed=current_time,
            expires_at=current_time + self.SESSION_TIMEOUT,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.sessions[session_id] = session
        return session
    
    def _generate_session_id(self) -> str:
        """안전한 세션 ID 생성"""
        random_part = secrets.token_urlsafe(32)
        timestamp = str(int(time.time() * 1000))
        raw = f"{random_part}.{timestamp}"
        
        # HMAC으로 서명
        signature = hmac.new(
            self.secret_key,
            raw.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{random_part}.{timestamp}.{signature[:32]}"
    
    def validate_session(self, session_id: str, ip_address: str = "", user_agent: str = "") -> Tuple[bool, Optional[Session]]:
        """세션 검증"""
        session = self.sessions.get(session_id)
        
        if session is None:
            return False, None
        
        # 만료 확인
        if time.time() > session.expires_at:
            self.destroy_session(session_id)
            return False, None
        
        # IP 주소 변경 확인 (보안)
        if session.ip_address and ip_address and session.ip_address != ip_address:
            # IP 변경 감지 - 경고 발생
            print(f"경고: IP 주소 변경 감지 - {session.ip_address} -> {ip_address}")
            # 실제 구현에서는 세션 폐기 고려
        
        # 사용자 에이전트 변경 확인
        if session.user_agent and user_agent and session.user_agent != user_agent:
            print(f"경고: 사용자 에이전트 변경 감지")
        
        # 마지막 접근 시간 업데이트
        session.last_accessed = time.time()
        
        # 세션 갱신 (정기적)
        if time.time() - session.created_at > self.REFRESH_INTERVAL:
            session.expires_at = time.time() + self.SESSION_TIMEOUT
            print(f"세션 갱신: {session_id[:16]}...")
        
        return True, session
    
    def refresh_session(self, session_id: str) -> bool:
        """세션 갱신"""
        session = self.sessions.get(session_id)
        if session:
            session.last_accessed = time.time()
            session.expires_at = time.time() + self.SESSION_TIMEOUT
            return True
        return False
    
    def destroy_session(self, session_id: str) -> bool:
        """세션 폐기"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            print(f"세션 폐기: {session_id[:16]}...")
            return True
        return False
    
    def destroy_all_user_sessions(self, user_id: str) -> int:
        """사용자의 모든 세션 폐기"""
        user_sessions = [
            sid for sid, s in self.sessions.items()
            if s.user_id == user_id
        ]
        for sid in user_sessions:
            self.destroy_session(sid)
        return len(user_sessions)
    
    def cleanup_expired_sessions(self) -> int:
        """만료된 세션 정리"""
        current_time = time.time()
        expired = [
            sid for sid, session in self.sessions.items()
            if current_time > session.expires_at
        ]
        for sid in expired:
            self.destroy_session(sid)
        return len(expired)
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """세션 정보 조회"""
        session = self.sessions.get(session_id)
        if session:
            return {
                'session_id': session_id[:16] + '...',
                'user_id': session.user_id,
                'created_at': datetime.fromtimestamp(session.created_at).isoformat(),
                'last_accessed': datetime.fromtimestamp(session.last_accessed).isoformat(),
                'expires_at': datetime.fromtimestamp(session.expires_at).isoformat(),
                'is_active': session.is_active
            }
        return None


class SessionFixationProtection:
    """세션 고정 공격 보호"""
    
    def __init__(self):
        self.manager = SessionManager()
        
    def regenerate_session(self, old_session_id: str, user_id: str) -> Optional[Session]:
        """세션 재생성 (세션 고정 공격 방어)"""
        # 기존 세션 정보 확인
        valid, old_session = self.manager.validate_session(old_session_id)
        
        if valid and old_session:
            # 새 세션 생성
            new_session = self.manager.create_session(
                user_id=user_id,
                ip_address=old_session.ip_address,
                user_agent=old_session.user_agent
            )
            
            # 이전 세션 폐기
            self.manager.destroy_session(old_session_id)
            
            print(f"세션 재생성: {old_session_id[:16]}... -> {new_session.session_id[:16]}...")
            return new_session
        
        return None


# 테스트
if __name__ == "__main__":
    # 세션 관리 테스트
    sm = SessionManager()
    
    # 세션 생성
    session = sm.create_session("user123", "192.168.1.1", "Mozilla/5.0")
    print(f"세션 생성: {session.session_id[:30]}...")
    
    # 세션 검증
    valid, sess = sm.validate_session(session.session_id, "192.168.1.1")
    print(f"세션 검증: {'유효' if valid else '무효'}")
    
    # 세션 정보
    info = sm.get_session_info(session.session_id)
    print(f"세션 정보: {info}")
    
    # 세션 고정 공격 방어 테스트
    sfp = SessionFixationProtection()
    new_session = sfp.regenerate_session(session.session_id, "user123")
    print(f"세션 재생성: {'성공' if new_session else '실패'}")
    
    # 만료 세션 정리
    cleaned = sm.cleanup_expired_sessions()
    print(f"정리된 세션: {cleaned}개")