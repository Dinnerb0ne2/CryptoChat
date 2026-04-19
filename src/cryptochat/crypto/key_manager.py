from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


@dataclass(frozen=True)
class KeyPair:
    private_pem: bytes
    public_pem: bytes


class KeyManager:
    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> KeyPair:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyPair(private_pem=private_pem, public_pem=public_pem)

    @staticmethod
    def save_key_pair(key_pair: KeyPair, private_path: str | Path, public_path: str | Path) -> None:
        Path(private_path).write_bytes(key_pair.private_pem)
        Path(public_path).write_bytes(key_pair.public_pem)

    @staticmethod
    def load_private_key(private_path: str | Path) -> RSAPrivateKey:
        data = Path(private_path).read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("expected RSA private key")
        return key

    @staticmethod
    def load_public_key(public_path: str | Path) -> RSAPublicKey:
        data = Path(public_path).read_bytes()
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("expected RSA public key")
        return key
