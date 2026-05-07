"""
데이터 유출 방지 모듈
Zoom 취약점 보완: 메타데이터 보호, 데이터 마스킹
"""
import re
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional


class MetadataProtection:
    """메타데이터 보호 모듈"""
    
    def __init__(self):
        self.sensitive_fields = [
            'ip_address', 'email', 'phone', 'real_name',
            'meeting_id', 'user_id', 'session_id'
        ]
        
    def anonymize_user_data(self, user_data: Dict) -> Dict:
        """사용자 데이터 익명화"""
        anonymized = user_data.copy()
        
        # 이메일 마스킹
        if 'email' in anonymized:
            email = anonymized['email']
            if '@' in email:
                local, domain = email.split('@')
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
        return hashlib.sha256(data.encode()).hexdigest()


class DataMasking:
    """데이터 마스킹 모듈"""
    
    def __init__(self):
        self.mask_patterns = {
            'credit_card': r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
            'ssn': r'\d{3}-\d{2}-\d{4}',
            'phone': r'\d{3}-\d{4}-\d{4}'
        }
        
    def mask_credit_card(self, text: str) -> str:
        """신용카드 번호 마스킹"""
        pattern = self.mask_patterns['credit_card']
        return re.sub(pattern, '****-****-****-****', text)
    
    def mask_ssn(self, text: str) -> str:
        """주민등록번호 마스킹"""
        pattern = self.mask_patterns['ssn']
        return re.sub(pattern, '***-**-****', text)
    
    def mask_phone(self, text: str) -> str:
        """전화번호 마스킹"""
        pattern = self.mask_patterns['phone']
        return re.sub(pattern, '***-****-****', text)
    
    def mask_all(self, text: str) -> str:
        """모든 민감 정보 마스킹"""
        text = self.mask_credit_card(text)
        text = self.mask_ssn(text)
        text = self.mask_phone(text)
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
            
        # 메타데이터 제거
        protected = self.metadata_protection.remove_metadata(protected)
        
        return protected
    
    def generate_temporary_link(self, meeting_id: str, expiry_minutes: int = 60) -> Dict:
        """임시 링크 생성"""
        import secrets
        
        token = secrets.token_urlsafe(32)
        expiry = datetime.now().timestamp() + (expiry_minutes * 60)
        
        return {
            'meeting_id': meeting_id,
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
    
    # 회의 데이터 보호 테스트
    mdp = MeetingDataProtection()
    meeting_data = {
        'title': '보안 회의',
        'participants': [
            {'username': 'user1', 'email': 'user1@company.com', 'ip_address': '10.0.0.1'},
            {'username': 'user2', 'email': 'user2@company.com', 'ip_address': '10.0.0.2'}
        ]
    }
    protected = mdp.protect_meeting_record(meeting_data)
    print("보호된 회의 데이터:", json.dumps(protected, indent=2, ensure_ascii=False))