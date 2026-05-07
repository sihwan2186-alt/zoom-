"""
버퍼 오버플로우 탐지 모듈
Zoom 취약점 보완: 입력 검증, 샌드박스 실행
"""
import re
import ctypes
import os
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """검증 결과"""
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_input: Optional[str] = None


class InputValidation:
    """입력 검증 모듈"""
    
    # 보안 위험 패턴
    DANGEROUS_PATTERNS = [
        r'[\x00-\x08\x0b\x0c\x0e-\x1f]',  # 제어 문자
        r'<script',                        # XSS
        r'javascript:',                    # JS 인젝션
        r'on\w+\s*=',                      # 이벤트 핸들러
        r'\.\./',                          # 경로 탐색
        r'[\|;&`$]',                       # 명령 주입
    ]
    
    # 최대 길이 제한
    MAX_INPUT_LENGTH = 10000
    MAX_STRING_LENGTH = 1000
    MAX_ARRAY_LENGTH = 100
    
    def __init__(self):
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.DANGEROUS_PATTERNS
        ]
        
    def validate_input(self, user_input: str) -> ValidationResult:
        """입력 검증"""
        # 길이 검증
        if len(user_input) > self.MAX_INPUT_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_message=f"입력 길이 초과 (최대: {self.MAX_INPUT_LENGTH})"
            )
            
        # 위험 패턴 검증
        for pattern in self.compiled_patterns:
            if pattern.search(user_input):
                return ValidationResult(
                    is_valid=False,
                    error_message="위험한 입력 패턴 detected"
                )
                
        # 정제된 입력 반환
        sanitized = self.sanitize_input(user_input)
        return ValidationResult(
            is_valid=True,
            sanitized_input=sanitized
        )
    
    def sanitize_input(self, user_input: str) -> str:
        """입력 정제"""
        # 제어 문자 제거
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', user_input)
        
        # HTML 엔티티 이스케이프
        html_escape = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        for char, escape in html_escape.items():
            sanitized = sanitized.replace(char, escape)
            
        return sanitized
    
    def validate_string_length(self, text: str, max_length: int = None) -> bool:
        """문자열 길이 검증"""
        if max_length is None:
            max_length = self.MAX_STRING_LENGTH
        return len(text) <= max_length
    
    def validate_array_size(self, array: list) -> bool:
        """배열 크기 검증"""
        return len(array) <= self.MAX_ARRAY_LENGTH


class BufferOverflowDetector:
    """버퍼 오버플로우 탐지"""
    
    def __init__(self):
        self.input_validation = InputValidation()
        self.detection_log = []
        
    def check_buffer_size(self, data: str, buffer_size: int) -> Tuple[bool, str]:
        """버퍼 크기 확인"""
        if len(data) > buffer_size:
            msg = f"버퍼 오버플로우 위험: 입력 {len(data)} > 버퍼 {buffer_size}"
            self.detection_log.append(msg)
            return False, msg
        return True, "안전"
    
    def detect_heap_overflow(self, data: bytes) -> bool:
        """힙 오버플로우 탐지"""
        # 널 종료 문자 확인
        if b'\x00' not in data[:-1]:
            self.detection_log.append("힙 오버플로우 가능성: 널 종료 문자 누락")
            return True
        return False
    
    def detect_stack_overflow(self, data: str) -> bool:
        """스택 오버플로우 탐지"""
        # 재귀 호출 깊이 확인 (시뮬레이션)
        if len(data) > 10000:
            self.detection_log.append("스택 오버플로우 가능성: 과도한 데이터")
            return True
        return False


class SandboxExecution:
    """샌드박스 실행 환경"""
    
    def __init__(self):
        self.allowed_modules = [
            'os', 'sys', 'json', 'datetime', 'hashlib'
        ]
        self.max_memory_mb = 100
        self.max_execution_time = 5  # 초
        
    def is_module_allowed(self, module_name: str) -> bool:
        """모듈 허용 여부 확인"""
        return module_name in self.allowed_modules
        
    def execute_in_sandbox(self, code: str, input_data: str = "") -> Tuple[bool, str]:
        """샌드박스에서 코드 실행"""
        # 기본적인 실행 시뮬레이션
        # 실제 구현에서는 subprocess 또는 container 사용
        
        # 입력 검증
        validation = self.input_validation.validate_input(input_data)
        if not validation.is_valid:
            return False, f"입력 검증 실패: {validation.error_message}"
            
        #危险 코드 패턴 확인
        dangerous = ['exec', 'eval', 'compile', '__import__', 'open(']
        for pattern in dangerous:
            if pattern in code:
                return False, f"위험한 코드 패턴: {pattern}"
                
        return True, "안전하게 실행됨"
    
    def check_memory_limit(self, memory_usage_mb: float) -> bool:
        """메모리 제한 확인"""
        return memory_usage_mb <= self.max_memory_mb


# 테스트
if __name__ == "__main__":
    # 입력 검증 테스트
    iv = InputValidation()
    
    test_inputs = [
        "正常な入力",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "a" * 2000
    ]
    
    for inp in test_inputs:
        result = iv.validate_input(inp)
        print(f"입력: {inp[:30]}... -> 유효: {result.is_valid}")
        if result.error_message:
            print(f"  오류: {result.error_message}")
    
    # 버퍼 오버플로우 탐지 테스트
    bod = BufferOverflowDetector()
    is_safe, msg = bod.check_buffer_size("test data", 10)
    print(f"버퍼 확인: {msg}")
    
    # 샌드박스 실행 테스트
    sandbox = SandboxExecution()
    success, result = sandbox.execute_in_sandbox("print('hello')", "test")
    print(f"샌드박스 실행: {result}")