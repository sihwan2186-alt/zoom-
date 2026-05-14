"""
세션 관리 보안 모듈
Zoom 취약점 보완: 안전한 세션 생성, 갱신, 폐기
"""
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Dict, Optional, Tuple


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
    refresh_count: int = 0


class SessionManager:
    """세션 관리 모듈"""

    SESSION_TIMEOUT = 3600  # 1시간
    IDLE_TIMEOUT = 1800  # 30분
    REFRESH_INTERVAL = 1800  # 30분
    MAX_SESSIONS_PER_USER = 5

    def __init__(self, strict_client_binding: bool = True):
        self.sessions: Dict[str, Session] = {}
        self.secret_key = secrets.token_bytes(32)
        self.strict_client_binding = strict_client_binding
        self.audit_log = []

    def create_session(self, user_id: str, ip_address: str = "", user_agent: str = "") -> Session:
        """세션 생성"""
        user_sessions = [
            s for s in self.sessions.values()
            if s.user_id == user_id and s.is_active
        ]
        if len(user_sessions) >= self.MAX_SESSIONS_PER_USER:
            oldest = min(user_sessions, key=lambda s: s.last_accessed)
            self.destroy_session(oldest.session_id)

        current_time = time.time()
        session = Session(
            session_id=self._generate_session_id(),
            user_id=user_id,
            created_at=current_time,
            last_accessed=current_time,
            expires_at=current_time + self.SESSION_TIMEOUT,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.sessions[session.session_id] = session
        self._audit("session_created", session.session_id, user_id)
        return session

    def validate_session(
        self,
        session_id: str,
        ip_address: str = "",
        user_agent: str = ""
    ) -> Tuple[bool, Optional[Session]]:
        """세션 검증"""
        current_time = time.time()
        if not session_id or not self._verify_session_id_signature(session_id):
            self._audit("invalid_session_signature", session_id or "", "")
            return False, None

        session = self.sessions.get(session_id)
        if session is None or not session.is_active:
            return False, None

        if current_time > session.expires_at:
            self.destroy_session(session_id)
            return False, None

        if current_time - session.last_accessed > self.IDLE_TIMEOUT:
            self._audit("session_idle_timeout", session_id, session.user_id)
            self.destroy_session(session_id)
            return False, None

        if session.ip_address and ip_address and session.ip_address != ip_address:
            self._audit("ip_changed", session_id, session.user_id, f"{session.ip_address}->{ip_address}")
            if self.strict_client_binding:
                self.destroy_session(session_id)
                return False, None

        if session.user_agent and user_agent and session.user_agent != user_agent:
            self._audit("user_agent_changed", session_id, session.user_id)
            if self.strict_client_binding:
                self.destroy_session(session_id)
                return False, None

        session.last_accessed = current_time

        if current_time - session.created_at > self.REFRESH_INTERVAL:
            session.created_at = current_time
            session.expires_at = current_time + self.SESSION_TIMEOUT
            session.refresh_count += 1
            self._audit("session_refreshed", session_id, session.user_id)

        return True, session

    def refresh_session(self, session_id: str) -> bool:
        """세션 갱신"""
        if not session_id or not self._verify_session_id_signature(session_id):
            return False
        session = self.sessions.get(session_id)
        if not session or not session.is_active or time.time() > session.expires_at:
            return False
        session.last_accessed = time.time()
        session.expires_at = time.time() + self.SESSION_TIMEOUT
        session.refresh_count += 1
        self._audit("session_refreshed", session_id, session.user_id)
        return True

    def destroy_session(self, session_id: str) -> bool:
        """세션 폐기"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        session.is_active = False
        del self.sessions[session_id]
        self._audit("session_destroyed", session_id, session.user_id)
        return True

    def destroy_all_user_sessions(self, user_id: str) -> int:
        """사용자의 모든 세션 폐기"""
        user_sessions = [
            sid for sid, session in self.sessions.items()
            if session.user_id == user_id
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
        if not session:
            return None
        return {
            "session_id": session_id[:16] + "...",
            "user_id": session.user_id,
            "created_at": datetime.fromtimestamp(session.created_at).isoformat(),
            "last_accessed": datetime.fromtimestamp(session.last_accessed).isoformat(),
            "expires_at": datetime.fromtimestamp(session.expires_at).isoformat(),
            "idle_expires_at": datetime.fromtimestamp(session.last_accessed + self.IDLE_TIMEOUT).isoformat(),
            "is_active": session.is_active,
            "refresh_count": session.refresh_count,
        }

    def build_session_cookie_header(
        self,
        session_id: str,
        cookie_name: str = "vc_session",
        max_age: Optional[int] = None,
        same_site: str = "Strict",
    ) -> str:
        """브라우저 전달용 보안 세션 쿠키 헤더를 생성한다."""
        if not session_id or not self._verify_session_id_signature(session_id):
            raise ValueError("invalid session id")
        if same_site not in {"Strict", "Lax", "None"}:
            raise ValueError("same_site must be Strict, Lax, or None")
        if max_age is None:
            max_age = self.SESSION_TIMEOUT

        cookie = (
            f"{cookie_name}={session_id}; Max-Age={int(max_age)}; Path=/; "
            "HttpOnly; Secure; "
            f"SameSite={same_site}"
        )
        return cookie

    def _generate_session_id(self) -> str:
        """안전한 세션 ID 생성"""
        random_part = secrets.token_urlsafe(32)
        timestamp = str(int(time.time() * 1000))
        raw = f"{random_part}.{timestamp}"
        signature = hmac.new(self.secret_key, raw.encode(), hashlib.sha256).hexdigest()
        return f"{random_part}.{timestamp}.{signature[:32]}"

    def _verify_session_id_signature(self, session_id: str) -> bool:
        """세션 ID의 HMAC 서명 형식을 검증한다."""
        parts = session_id.split(".")
        if len(parts) != 3:
            return False
        random_part, timestamp, signature = parts
        raw = f"{random_part}.{timestamp}"
        expected = hmac.new(self.secret_key, raw.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(signature, expected)

    def _audit(self, event: str, session_id: str, user_id: str, detail: str = "") -> None:
        """A09 로깅/모니터링 실패 항목을 검증할 수 있는 감사 로그."""
        self.audit_log.append({
            "event": event,
            "session_id": session_id[:16] + "..." if session_id else "",
            "user_id": user_id,
            "detail": detail,
            "timestamp": datetime.now(UTC).isoformat(),
        })


class SessionFixationProtection:
    """세션 고정 공격 보호"""

    def __init__(self, manager: Optional[SessionManager] = None):
        self.manager = manager or SessionManager()

    def regenerate_session(self, old_session_id: str, user_id: str) -> Optional[Session]:
        """세션 재생성 (세션 고정 공격 방어)"""
        valid, old_session = self.manager.validate_session(old_session_id)
        if not valid or not old_session:
            return None

        new_session = self.manager.create_session(
            user_id=user_id,
            ip_address=old_session.ip_address,
            user_agent=old_session.user_agent,
        )
        self.manager.destroy_session(old_session_id)
        return new_session


if __name__ == "__main__":
    sm = SessionManager()

    session = sm.create_session("user123", "192.168.1.1", "Mozilla/5.0")
    print(f"세션 생성: {session.session_id[:30]}...")

    valid, _ = sm.validate_session(session.session_id, "192.168.1.1", "Mozilla/5.0")
    print(f"세션 검증: {'유효' if valid else '무효'}")

    info = sm.get_session_info(session.session_id)
    print(f"세션 정보: {info}")
    print(f"보안 쿠키 헤더: {sm.build_session_cookie_header(session.session_id)[:80]}...")

    sfp = SessionFixationProtection(sm)
    new_session = sfp.regenerate_session(session.session_id, "user123")
    print(f"세션 재생성: {'성공' if new_session else '실패'}")

    cleaned = sm.cleanup_expired_sessions()
    print(f"정리된 세션: {cleaned}개")
