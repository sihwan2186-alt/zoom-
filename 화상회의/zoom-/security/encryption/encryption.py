import os
import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, Tuple

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover - exercised on machines without cryptography
    default_backend = None
    hashes = None
    padding = None
    rsa = None
    Cipher = None
    algorithms = None
    modes = None
    PBKDF2HMAC = None


AES_PREFIX = b"ZGCM1"
FALLBACK_PREFIX = b"ZHMAC1"


class CryptoDependencyError(RuntimeError):
    """Raised when a production cryptographic primitive is unavailable."""


class EncryptionModule:
    """화상회의 데이터 보호용 암호화 모듈.

    cryptography 패키지가 있으면 AES-256-GCM을 사용한다. 패키지가 없는
    학습/보고서 환경에서는 HMAC 기반 인증 스트림을 사용해 흐름을 시연한다.
    fallback은 실험용이며 운영 암호화로 쓰면 안 된다.
    """

    def __init__(self):
        self.key_size = 256  # AES-256
        self.algorithm = "AES-256-GCM" if self.has_aes_gcm() else "HMAC-SHA256 stream demo"

    @staticmethod
    def has_aes_gcm() -> bool:
        return Cipher is not None and algorithms is not None and modes is not None

    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """PBKDF2 기반 키 생성"""
        if salt is None:
            salt = os.urandom(16)

        if PBKDF2HMAC is not None:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode("utf-8"))
        else:
            key = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                200000,
                dklen=32
            )
        return key, salt

    def encrypt_aes256(self, plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """AES-256-GCM 암호화"""
        self._validate_key(key)

        if not self.has_aes_gcm():
            return self._encrypt_fallback(plaintext, key, aad)

        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return AES_PREFIX + iv + encryptor.tag + ciphertext

    def decrypt_aes256(self, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """AES-256-GCM 복호화"""
        self._validate_key(key)

        if ciphertext.startswith(FALLBACK_PREFIX):
            return self._decrypt_fallback(ciphertext, key, aad)

        if ciphertext.startswith(AES_PREFIX):
            payload = ciphertext[len(AES_PREFIX):]
        else:
            payload = ciphertext  # backward compatibility: iv + tag + data

        if len(payload) < 28:
            raise ValueError("ciphertext is too short")

        if not self.has_aes_gcm():
            raise CryptoDependencyError("AES-GCM payload requires the cryptography package")

        iv = payload[:12]
        tag = payload[12:28]
        data = payload[28:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(data) + decryptor.finalize()

    def encrypt_media_packet(self, packet: bytes, key: bytes, meeting_id: str, sequence: int) -> bytes:
        """회의 ID와 패킷 번호를 AAD로 묶어 재전송/변조 탐지에 활용한다."""
        aad = f"{meeting_id}:{sequence}".encode("utf-8")
        return self.encrypt_aes256(packet, key, aad=aad)

    def decrypt_media_packet(self, packet: bytes, key: bytes, meeting_id: str, sequence: int) -> bytes:
        aad = f"{meeting_id}:{sequence}".encode("utf-8")
        return self.decrypt_aes256(packet, key, aad=aad)

    def _validate_key(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")

    def _encrypt_fallback(self, plaintext: bytes, key: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(12)
        stream = self._keystream(key, nonce, len(plaintext))
        cipher = bytes(a ^ b for a, b in zip(plaintext, stream))
        tag = hmac.new(key, nonce + aad + cipher, hashlib.sha256).digest()
        return FALLBACK_PREFIX + nonce + tag + cipher

    def _decrypt_fallback(self, payload: bytes, key: bytes, aad: bytes) -> bytes:
        data = payload[len(FALLBACK_PREFIX):]
        if len(data) < 44:
            raise ValueError("ciphertext is too short")
        nonce = data[:12]
        tag = data[12:44]
        cipher = data[44:]
        expected = hmac.new(key, nonce + aad + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentication tag mismatch")
        stream = self._keystream(key, nonce, len(cipher))
        return bytes(a ^ b for a, b in zip(cipher, stream))

    def _keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        blocks = []
        counter = 0
        while sum(len(block) for block in blocks) < length:
            counter_bytes = counter.to_bytes(4, "big")
            blocks.append(hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest())
            counter += 1
        return b"".join(blocks)[:length]


class KeyManagement:
    """분산형 키 관리 - Jitsi Meet 기반 보완"""

    def __init__(self):
        self.keys = {}

    def generate_session_key(self) -> bytes:
        """세션 키 생성"""
        return os.urandom(32)  # 256비트 키

    def generate_user_keypair(self):
        """사용자 키쌍 생성 (RSA-4096)"""
        if rsa is None:
            raise CryptoDependencyError("RSA key generation requires the cryptography package")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def encrypt_with_public_key(self, public_key, data: bytes) -> bytes:
        """공개키로 암호화"""
        if padding is None:
            raise CryptoDependencyError("RSA-OAEP requires the cryptography package")
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_with_private_key(self, private_key, ciphertext: bytes) -> bytes:
        """개인키로 복호화"""
        if padding is None:
            raise CryptoDependencyError("RSA-OAEP requires the cryptography package")
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


@dataclass
class ElectronicEnvelope:
    """논문에서 다룬 전자봉투 방식의 최소 구현 모델."""
    encrypted_payload: bytes
    wrapped_keys: Dict[str, bytes]
    meeting_id: str
    sequence: int


class EnvelopeService:
    """세션키로 미디어를 암호화하고 참여자 공개키로 세션키를 감싼다."""

    def __init__(self):
        self.encryption = EncryptionModule()
        self.key_management = KeyManagement()

    def seal(
        self,
        media_packet: bytes,
        recipient_public_keys: Dict[str, object],
        meeting_id: str,
        sequence: int,
    ) -> ElectronicEnvelope:
        session_key = self.key_management.generate_session_key()
        encrypted_payload = self.encryption.encrypt_media_packet(
            media_packet,
            session_key,
            meeting_id,
            sequence
        )
        wrapped_keys = {
            participant_id: self.key_management.encrypt_with_public_key(public_key, session_key)
            for participant_id, public_key in recipient_public_keys.items()
        }
        return ElectronicEnvelope(encrypted_payload, wrapped_keys, meeting_id, sequence)

    def open_for_recipient(
        self,
        envelope: ElectronicEnvelope,
        recipient_id: str,
        recipient_private_key: object,
    ) -> bytes:
        wrapped_key = envelope.wrapped_keys[recipient_id]
        session_key = self.key_management.decrypt_with_private_key(recipient_private_key, wrapped_key)
        return self.encryption.decrypt_media_packet(
            envelope.encrypted_payload,
            session_key,
            envelope.meeting_id,
            envelope.sequence
        )


# 테스트
if __name__ == "__main__":
    enc = EncryptionModule()
    km = KeyManagement()

    # 키 생성 테스트
    key, salt = enc.generate_key("secure_password")
    print(f"생성된 키: {key.hex()[:32]}...")
    print(f"솔트: {salt.hex()}")

    # 암호화 테스트
    message = "Zoom 보안 강화 메시지".encode("utf-8")
    encrypted = enc.encrypt_aes256(message, key)
    print(f"암호화 완료: {len(encrypted)} bytes")

    # 복호화 테스트
    decrypted = enc.decrypt_aes256(encrypted, key)
    print(f"복호화 결과: {decrypted.decode('utf-8')}")

    packet = enc.encrypt_media_packet(b"frame-001", key, "secure-room", 1)
    print(f"미디어 패킷 복호화: {enc.decrypt_media_packet(packet, key, 'secure-room', 1).decode()}")

    # RSA 키쌍 테스트
    if rsa is not None:
        priv, pub = km.generate_user_keypair()
        print("RSA-4096 키쌍 생성 완료")
    else:
        print("cryptography 패키지가 없어 RSA 전자봉투 데모는 건너뜁니다.")
