"""
버퍼 오버플로우 탐지 모듈
화상회의 플랫폼 보완: 입력 검증, 샌드박스 실행
"""
import html
import re
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse


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
        r'[\|;`$]',                        # 명령 주입
    ]

    MEETING_ID_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$')
    USERNAME_PATTERN = re.compile(r'^[가-힣A-Za-z0-9._ -]{2,40}$')

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
        if not isinstance(user_input, str):
            return ValidationResult(False, "입력은 문자열이어야 합니다")

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
                    error_message="위험한 입력 패턴이 탐지되었습니다"
                )

        # 정제된 입력 반환
        sanitized = self.sanitize_input(user_input)
        return ValidationResult(
            is_valid=True,
            sanitized_input=sanitized
        )

    def validate_meeting_id(self, meeting_id: str) -> ValidationResult:
        """회의방 ID 추측/주입 위험을 낮추기 위한 allow-list 검증."""
        if not self.MEETING_ID_PATTERN.fullmatch(meeting_id or ""):
            return ValidationResult(
                False,
                "회의방 ID는 8~64자의 영문/숫자/하이픈/밑줄만 허용합니다"
            )
        return ValidationResult(True, sanitized_input=meeting_id)

    def validate_display_name(self, display_name: str) -> ValidationResult:
        """사용자 표시명 XSS 및 제어문자 방어."""
        base = self.validate_input(display_name)
        if not base.is_valid:
            return base
        if not self.USERNAME_PATTERN.fullmatch(display_name):
            return ValidationResult(False, "표시명 형식이 허용 범위를 벗어났습니다")
        return ValidationResult(True, sanitized_input=base.sanitized_input)

    def validate_scan_scope(self, target_url: str, allowed_hosts: set[str]) -> ValidationResult:
        """OWASP ZAP 실행 전 허용된 테스트베드 URL인지 확인한다."""
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ValidationResult(False, "스캔 대상 URL 형식이 올바르지 않습니다")
        if parsed.hostname not in allowed_hosts:
            return ValidationResult(False, "허용되지 않은 호스트는 스캔할 수 없습니다")
        return ValidationResult(True, sanitized_input=target_url)

    def sanitize_input(self, user_input: str) -> str:
        """입력 정제"""
        # 제어 문자 제거
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', user_input)

        # HTML 엔티티 이스케이프
        sanitized = html.escape(sanitized, quote=True)
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
        if buffer_size < 0:
            raise ValueError("buffer_size must be non-negative")
        if len(data) > buffer_size:
            msg = f"버퍼 오버플로우 위험: 입력 {len(data)} > 버퍼 {buffer_size}"
            self.detection_log.append(msg)
            return False, msg
        return True, "안전"

    def detect_heap_overflow(self, data: bytes) -> bool:
        """힙 오버플로우 탐지"""
        # 널 종료 문자 확인
        if not data.endswith(b'\x00'):
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
        self.input_validation = InputValidation()
        self.allowed_modules = [
            'json', 'datetime', 'hashlib'
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

        # 위험 코드 패턴 확인
        dangerous = ['exec', 'eval', 'compile', '__import__', 'open(', 'subprocess', 'socket']
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
        "정상적인 입력",
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
