# crypto.py
import os
import json
from typing import Optional
from .algorithm.rsa import RSA, _RSAKey


class CryptoManager:
    def __init__(self, config: dict):
        self.config = config
        self.private_key: Optional[_RSAKey] = None
        self.public_key: Optional[_RSAKey] = None
        self.server_public_key: Optional[_RSAKey] = None
        self._load_key_params()
        self._clean_old_keys()
        self._generate_keys()

    def _load_key_params(self) -> None:
        self.key_length = int(self.config.get("key_length", 2048))
        self.private_key_path = self.config.get("private_key_path", "client_private.pem")
        self.public_key_path = self.config.get("public_key_path", "client_public.pem")

    def _clean_old_keys(self) -> None:
        for path in [self.private_key_path, self.public_key_path]:
            if os.path.exists(path):
                os.remove(path)

    def _generate_keys(self) -> None:
        self.private_key = RSA.generate(self.key_length)
        self.public_key = RSA.publickey(self.private_key)
        self._save_keys()

    def _save_keys(self) -> None:
        with open(self.private_key_path, "wb") as f:
            f.write(RSA.export_private_key(self.private_key))
        with open(self.public_key_path, "wb") as f:
            f.write(RSA.export_public_key(self.public_key))

    def set_server_public_key(self, pub_key_pem: str) -> None:
        self.server_public_key = RSA.load_pem(pub_key_pem.encode())

    def encrypt(self, data: dict) -> bytes:
        # Encrypt data (only sensitive fields)
        if not self.server_public_key:
            raise ValueError("Server public key not set")
        
        # List of fields that need encryption
        sensitive_fields = ["nickname", "message", "ip", "password", "room_password"]
        encrypted_data = {}
        
        for key, value in data.items():
            if key in sensitive_fields and value is not None:
                # Encrypt sensitive fields with RSA
                encrypted_value = RSA.encrypt(str(value).encode(), self.server_public_key)
                encrypted_data[key] = encrypted_value.hex()
            else:
                # Keep non-sensitive fields as is (e.g., request type, timestamp)
                encrypted_data[key] = value
        
        return json.dumps(encrypted_data).encode()

    def decrypt(self, encrypted_data: bytes) -> dict:
        # Decrypt data sent from server
        if not self.private_key:
            raise ValueError("Private key not initialized")
        
        data = json.loads(encrypted_data.decode())
        decrypted_data = {}
        
        # List of fields that need decryption
        sensitive_fields = ["nickname", "message", "ip"]
        
        for key, value in data.items():
            if key in sensitive_fields and value is not None:
                # Decrypt sensitive fields with RSA
                ciphertext = bytes.fromhex(value)
                decrypted_value = RSA.decrypt(ciphertext, self.private_key).decode()
                decrypted_data[key] = decrypted_value
            else:
                # Keep non-sensitive fields as is
                decrypted_data[key] = value
        
        return decrypted_data

    def get_public_key_pem(self) -> str:
        """Get client's public key in PEM format (for sending to server)"""
        return RSA.export_public_key(self.public_key).decode()