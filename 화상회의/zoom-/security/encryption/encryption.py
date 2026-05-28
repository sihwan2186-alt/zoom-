import os
import hmac
import hashlib
import importlib
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Dict, Iterable, Optional, Tuple


def optional_module(module_name: str) -> ModuleType | None:
    """Return an optional dependency module without triggering static import errors."""
    try:
        return importlib.import_module(module_name)
    except ImportError:  # pragma: no cover - exercised on machines without cryptography
        return None


crypto_backends = optional_module("cryptography.hazmat.backends")
hashes: Any = optional_module("cryptography.hazmat.primitives.hashes")
padding: Any = optional_module("cryptography.hazmat.primitives.asymmetric.padding")
rsa: Any = optional_module("cryptography.hazmat.primitives.asymmetric.rsa")
crypto_ciphers = optional_module("cryptography.hazmat.primitives.ciphers")
crypto_algorithms: Any = optional_module("cryptography.hazmat.primitives.ciphers.algorithms")
crypto_modes: Any = optional_module("cryptography.hazmat.primitives.ciphers.modes")
crypto_pbkdf2 = optional_module("cryptography.hazmat.primitives.kdf.pbkdf2")

default_backend = getattr(crypto_backends, "default_backend", None)
Cipher = getattr(crypto_ciphers, "Cipher", None)
PBKDF2HMAC = getattr(crypto_pbkdf2, "PBKDF2HMAC", None)


AES_PREFIX = b"ZGCM1"
FALLBACK_PREFIX = b"ZHMAC1"


class CryptoDependencyError(RuntimeError):
    """Raised when a production cryptographic primitive is unavailable."""


def require_crypto(value: Any, message: str) -> Any:
    """Return an optional cryptography object after a runtime availability check."""
    if value is None:
        raise CryptoDependencyError(message)
    return value


def crypto_backend() -> Any:
    backend_factory = require_crypto(
        default_backend,
        "cryptography backend requires the cryptography package",
    )
    return backend_factory()


def aes_gcm_cipher(key: bytes, iv: bytes, tag: bytes | None = None) -> Any:
    cipher_factory = require_crypto(Cipher, "AES-GCM requires the cryptography package")
    algorithms_module = require_crypto(
        crypto_algorithms,
        "AES-GCM algorithms require the cryptography package",
    )
    modes_module = require_crypto(crypto_modes, "AES-GCM modes require the cryptography package")
    gcm_mode = modes_module.GCM(iv) if tag is None else modes_module.GCM(iv, tag)
    return cipher_factory(algorithms_module.AES(key), gcm_mode, backend=crypto_backend())


class EncryptionModule:
    """화상회의 데이터 보호용 암호화 모듈.

    cryptography 패키지가 있으면 AES-256-GCM을 사용한다. 패키지가 없는
    학습/보고서 환경에서는 HMAC 기반 인증 스트림을 사용해 흐름을 시연한다.
    fallback은 실험용이며 운영 암호화로 쓰면 안 된다.
    """

    def __init__(self, allow_demo_fallback: bool = True):
        self.key_size = 256  # AES-256
        self.allow_demo_fallback = allow_demo_fallback
        self._seen_media_packets = set()
        self.algorithm = "AES-256-GCM" if self.has_aes_gcm() else "HMAC-SHA256 stream demo"

    @staticmethod
    def has_aes_gcm() -> bool:
        return Cipher is not None and crypto_algorithms is not None and crypto_modes is not None

    def generate_key(self, password: str, salt: Optional[bytes] = None) -> tuple:
        """PBKDF2 기반 키 생성"""
        if salt is None:
            salt = os.urandom(16)

        if PBKDF2HMAC is not None and hashes is not None and default_backend is not None:
            pbkdf2_factory = require_crypto(PBKDF2HMAC, "PBKDF2 requires the cryptography package")
            hashes_module = require_crypto(hashes, "PBKDF2 hashes require the cryptography package")
            kdf = pbkdf2_factory(
                algorithm=hashes_module.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
                backend=crypto_backend()
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
            if not self.allow_demo_fallback:
                raise CryptoDependencyError("AES-GCM requires the cryptography package")
            return self._encrypt_fallback(plaintext, key, aad)

        iv = os.urandom(12)
        cipher = aes_gcm_cipher(key, iv)
        encryptor = cipher.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return AES_PREFIX + iv + encryptor.tag + ciphertext

    def decrypt_aes256(self, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
        """AES-256-GCM 복호화"""
        self._validate_key(key)

        if ciphertext.startswith(FALLBACK_PREFIX):
            if not self.allow_demo_fallback:
                raise CryptoDependencyError("fallback ciphertext is disabled in production mode")
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

        cipher = aes_gcm_cipher(key, iv, tag)
        decryptor = cipher.decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(data) + decryptor.finalize()

    def derive_epoch_key(self, base_key: bytes, meeting_id: str, epoch: int) -> bytes:
        """회의 epoch별 미디어 키를 분리한다."""
        self._validate_key(base_key)
        context = f"video-conference-media:{meeting_id}:{epoch}".encode("utf-8")
        return hmac.new(base_key, context, hashlib.sha256).digest()

    def build_media_aad(self, meeting_id: str, sender_id: str, epoch: int, sequence: int) -> bytes:
        """SFrame 계열처럼 라우팅 메타데이터를 인증 데이터로 묶는다."""
        return f"{meeting_id}:{sender_id}:{epoch}:{sequence}".encode("utf-8")

    def encrypt_media_packet(
        self,
        packet: bytes,
        key: bytes,
        meeting_id: str,
        sequence: int,
        sender_id: str = "participant",
        epoch: int = 0,
    ) -> bytes:
        """회의/참가자/epoch/패킷 번호를 AAD로 묶어 재전송/변조 탐지에 활용한다."""
        epoch_key = self.derive_epoch_key(key, meeting_id, epoch)
        aad = self.build_media_aad(meeting_id, sender_id, epoch, sequence)
        return self.encrypt_aes256(packet, epoch_key, aad=aad)

    def decrypt_media_packet(
        self,
        packet: bytes,
        key: bytes,
        meeting_id: str,
        sequence: int,
        sender_id: str = "participant",
        epoch: int = 0,
        reject_replay: bool = True,
    ) -> bytes:
        replay_key = (meeting_id, sender_id, epoch, sequence)
        if reject_replay and replay_key in self._seen_media_packets:
            raise ValueError("replayed media packet")
        epoch_key = self.derive_epoch_key(key, meeting_id, epoch)
        aad = self.build_media_aad(meeting_id, sender_id, epoch, sequence)
        plaintext = self.decrypt_aes256(packet, epoch_key, aad=aad)
        if reject_replay:
            self._seen_media_packets.add(replay_key)
        return plaintext

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
        output = bytearray()
        counter = 0
        while len(output) < length:
            counter_bytes = counter.to_bytes(4, "big")
            output.extend(hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest())
            counter += 1
        return bytes(output[:length])


class KeyManagement:
    """분산형 키 관리 - 화상회의 E2EE 보완 모델"""

    def __init__(self):
        self.keys = {}

    def generate_session_key(self) -> bytes:
        """세션 키 생성"""
        return os.urandom(32)  # 256비트 키

    def generate_user_keypair(self):
        """사용자 키쌍 생성 (RSA-4096)"""
        rsa_module = require_crypto(rsa, "RSA key generation requires the cryptography package")
        private_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=crypto_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def encrypt_with_public_key(self, public_key, data: bytes) -> bytes:
        """공개키로 암호화"""
        padding_module = require_crypto(padding, "RSA-OAEP requires the cryptography package")
        hashes_module = require_crypto(hashes, "RSA-OAEP hashes require the cryptography package")
        return public_key.encrypt(
            data,
            padding_module.OAEP(
                mgf=padding_module.MGF1(algorithm=hashes_module.SHA256()),
                algorithm=hashes_module.SHA256(),
                label=None
            )
        )
    
    def decrypt_with_private_key(self, private_key, ciphertext: bytes) -> bytes:
        """개인키로 복호화"""
        padding_module = require_crypto(padding, "RSA-OAEP requires the cryptography package")
        hashes_module = require_crypto(hashes, "RSA-OAEP hashes require the cryptography package")
        return private_key.decrypt(
            ciphertext,
            padding_module.OAEP(
                mgf=padding_module.MGF1(algorithm=hashes_module.SHA256()),
                algorithm=hashes_module.SHA256(),
                label=None
            )
        )


@dataclass
class GroupKeyEpoch:
    """회의 참여자 변화에 따라 갱신되는 그룹 키 상태."""
    meeting_id: str
    epoch: int
    active_participants: Tuple[str, ...]
    base_key: bytes
    reason: str


class ConferenceKeySchedule:
    """참가자 입장/퇴장/강퇴 시 새 epoch 키를 발급하는 최소 모델."""

    def __init__(self, meeting_id: str, participants: Iterable[str] = ()):
        self.meeting_id = meeting_id
        self.epoch = GroupKeyEpoch(
            meeting_id=meeting_id,
            epoch=0,
            active_participants=tuple(sorted(set(participants))),
            base_key=os.urandom(32),
            reason="initial",
        )

    def current_media_key(self, encryption: EncryptionModule) -> bytes:
        return encryption.derive_epoch_key(
            self.epoch.base_key,
            self.epoch.meeting_id,
            self.epoch.epoch,
        )

    def rotate_for_membership_change(self, participants: Iterable[str], reason: str) -> GroupKeyEpoch:
        """화상회의 E2EE/MLS 연구에서 강조하는 membership liveness를 코드 모델에 반영한다."""
        self.epoch = GroupKeyEpoch(
            meeting_id=self.meeting_id,
            epoch=self.epoch.epoch + 1,
            active_participants=tuple(sorted(set(participants))),
            base_key=os.urandom(32),
            reason=reason,
        )
        return self.epoch


@dataclass
class ElectronicEnvelope:
    """논문에서 다룬 전자봉투 방식의 최소 구현 모델."""
    encrypted_payload: bytes
    wrapped_keys: Dict[str, bytes]
    meeting_id: str
    sequence: int
    sender_id: str = "participant"
    epoch: int = 0


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
        sender_id: str = "participant",
        epoch: int = 0,
    ) -> ElectronicEnvelope:
        session_key = self.key_management.generate_session_key()
        encrypted_payload = self.encryption.encrypt_media_packet(
            media_packet,
            session_key,
            meeting_id,
            sequence,
            sender_id=sender_id,
            epoch=epoch,
        )
        wrapped_keys = {
            participant_id: self.key_management.encrypt_with_public_key(public_key, session_key)
            for participant_id, public_key in recipient_public_keys.items()
        }
        return ElectronicEnvelope(encrypted_payload, wrapped_keys, meeting_id, sequence, sender_id, epoch)

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
            envelope.sequence,
            sender_id=envelope.sender_id,
            epoch=envelope.epoch,
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
    message = "화상회의 보안 강화 메시지".encode("utf-8")
    encrypted = enc.encrypt_aes256(message, key)
    print(f"암호화 완료: {len(encrypted)} bytes")

    # 복호화 테스트
    decrypted = enc.decrypt_aes256(encrypted, key)
    print(f"복호화 결과: {decrypted.decode('utf-8')}")

    packet = enc.encrypt_media_packet(b"frame-001", key, "secure-room", 1, sender_id="user123", epoch=0)
    print(f"미디어 패킷 복호화: {enc.decrypt_media_packet(packet, key, 'secure-room', 1, sender_id='user123', epoch=0).decode()}")

    schedule = ConferenceKeySchedule("secure-room", ["user123", "user456"])
    new_epoch = schedule.rotate_for_membership_change(["user123"], "participant_left")
    print(f"그룹 키 epoch 갱신: {new_epoch.epoch}, 참여자: {new_epoch.active_participants}")

    # RSA 키쌍 테스트
    if rsa is not None:
        priv, pub = km.generate_user_keypair()
        print("RSA-4096 키쌍 생성 완료")
    else:
        print("cryptography 패키지가 없어 RSA 전자봉투 데모는 건너뜁니다.")
