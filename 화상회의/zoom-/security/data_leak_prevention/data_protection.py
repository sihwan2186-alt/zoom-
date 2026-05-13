"""
데이터 유출 방지 모듈
Zoom 취약점 보완: 메타데이터 보호, 데이터 마스킹
"""
import re
import hashlib
import json
from datetime import datetime
from typing import Dict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class MetadataProtection:
    """메타데이터 보호 모듈"""
    
    def __init__(self):
        self.sensitive_fields = [
            'ip_address', 'email', 'phone', 'real_name',
            'meeting_id', 'user_id', 'session_id', 'jwt', 'token',
            'auth_token', 'password', 'secret'
        ]

    def anonymize_user_data(self, user_data: Dict) -> Dict:
        """사용자 데이터 익명화"""
        anonymized = user_data.copy()

        # 이메일 마스킹
        if 'email' in anonymized:
            email = anonymized['email']
            if '@' in email:
                local, domain = email.split('@', 1)
                anonymized['email'] = f"{local[:2]}***@{domain}"

        # IP 주소 마스킹
        if 'ip_address' in anonymized:
            ip = anonymized['ip_address']
            parts = ip.split('.')
            if len(parts) == 4:
                anonymized['ip_address'] = f"{parts[0]}.{parts[1]}.***.***"

        # 전화번호 마스킹
        if 'phone' in anonymized:
            phone = anonymized['phone']
            anonymized['phone'] = re.sub(r'\d', '*', phone[:-4]) + phone[-4:]

        for key in ('user_id', 'session_id', 'meeting_id'):
            if key in anonymized:
                anonymized[key] = self.hash_sensitive_data(str(anonymized[key]))[:12]

        return anonymized

    def remove_metadata(self, data: Dict) -> Dict:
        """메타데이터 제거"""
        clean_data = {}

        for key, value in data.items():
            if key.lower() not in self.sensitive_fields:
                clean_data[key] = value

        return clean_data

    def hash_sensitive_data(self, data: str) -> str:
        """민감 데이터 해시화"""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def redact_url(self, url: str) -> str:
        """로그에 남는 URL에서 JWT, token, password 등 민감 쿼리를 제거한다."""
        split = urlsplit(url)
        redacted = []
        sensitive = set(self.sensitive_fields)
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            if key.lower() in sensitive:
                redacted.append((key, "redacted"))
            else:
                redacted.append((key, value))
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(redacted), split.fragment))

    def redact_log_record(self, record: Dict) -> Dict:
        """운영 로그의 민감정보를 마스킹한다."""
        result = {}
        for key, value in record.items():
            lower_key = key.lower()
            if lower_key in self.sensitive_fields:
                result[key] = "[redacted]"
            elif isinstance(value, str) and ('?' in value or 'token=' in value.lower() or 'jwt=' in value.lower()):
                result[key] = self.redact_url(value)
            else:
                result[key] = value
        return result


class DataMasking:
    """데이터 마스킹 모듈"""
    
    def __init__(self):
        self.mask_patterns = {
            'credit_card': r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
            'ssn': r'\d{6}-?\d{7}',
            'phone': r'01[016789]-?\d{3,4}-?\d{4}',
            'email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
            'jwt': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        }

    def mask_credit_card(self, text: str) -> str:
        """신용카드 번호 마스킹"""
        pattern = self.mask_patterns['credit_card']
        return re.sub(pattern, '****-****-****-****', text)

    def mask_ssn(self, text: str) -> str:
        """주민등록번호 마스킹"""
        pattern = self.mask_patterns['ssn']
        return re.sub(pattern, '******-*******', text)

    def mask_phone(self, text: str) -> str:
        """전화번호 마스킹"""
        pattern = self.mask_patterns['phone']
        return re.sub(pattern, '***-****-****', text)

    def mask_email(self, text: str) -> str:
        """이메일 마스킹"""
        return re.sub(self.mask_patterns['email'], '[email-redacted]', text)

    def mask_jwt(self, text: str) -> str:
        """JWT 마스킹"""
        return re.sub(self.mask_patterns['jwt'], '[jwt-redacted]', text)

    def mask_all(self, text: str) -> str:
        """모든 민감 정보 마스킹"""
        text = self.mask_credit_card(text)
        text = self.mask_ssn(text)
        text = self.mask_phone(text)
        text = self.mask_email(text)
        text = self.mask_jwt(text)
        return text


class MeetingDataProtection:
    """회의 데이터 보호"""
    
    def __init__(self):
        self.metadata_protection = MetadataProtection()
        self.data_masking = DataMasking()
        
    def protect_meeting_record(self, meeting_data: Dict) -> Dict:
        """회의 기록 보호"""
        protected = meeting_data.copy()

        # 참여자 정보 익명화
        if 'participants' in protected:
            protected['participants'] = [
                self.metadata_protection.anonymize_user_data(p)
                for p in protected['participants']
            ]

        for text_field in ('chat', 'transcript', 'title', 'description'):
            if text_field in protected and isinstance(protected[text_field], str):
                protected[text_field] = self.data_masking.mask_all(protected[text_field])

        # 메타데이터 제거
        protected = self.metadata_protection.remove_metadata(protected)

        return protected

    def generate_temporary_link(self, meeting_id: str, expiry_minutes: int = 60) -> Dict:
        """임시 링크 생성"""
        import secrets

        token = secrets.token_urlsafe(32)
        expiry = datetime.now().timestamp() + (expiry_minutes * 60)

        return {
            'meeting_id_hash': self.metadata_protection.hash_sensitive_data(meeting_id)[:12],
            'temporary_token': token,
            'expires_at': expiry,
            'url': f"https://jitsi.meet/temp/{token}"
        }


# 테스트
if __name__ == "__main__":
    # 메타데이터 보호 테스트
    mp = MetadataProtection()
    user_data = {
        'username': 'testuser',
        'email': 'user@example.com',
        'ip_address': '192.168.1.100',
        'phone': '010-1234-5678'
    }
    anonymized = mp.anonymize_user_data(user_data)
    print("익명화 결과:", anonymized)
    
    # 데이터 마스킹 테스트
    dm = DataMasking()
    text = "신용카드: 1234-5678-9012-3456, 전화: 010-1234-5678"
    masked = dm.mask_all(text)
    print("마스킹 결과:", masked)

    log_record = {
        'path': 'https://meet.local/room?jwt=abc.def.ghi&token=secret&lang=ko',
        'session_id': 'session-secret'
    }
    print("로그 마스킹:", mp.redact_log_record(log_record))
    
    # 회의 데이터 보호 테스트
    mdp = MeetingDataProtection()
    meeting_data = {
        'title': '보안 회의',
        'participants': [
            {'username': 'user1', 'email': 'user1@company.com', 'ip_address': '10.0.0.1'},
            {'username': 'user2', 'email': 'user2@company.com', 'ip_address': '10.0.0.2'}
        ],
        'chat': '담당자 이메일 user1@company.com, 전화 010-1234-5678'
    }
    protected = mdp.protect_meeting_record(meeting_data)
    print("보호된 회의 데이터:", json.dumps(protected, indent=2, ensure_ascii=False))
