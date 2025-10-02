# crypto.py
import os
import json
import random
import base64
import secrets
from typing import Optional, Tuple
from .algorithm.aes import AES
from .algorithm.rsa import RSA, _RSAKey


class CryptoManager:
    def __init__(self, config: dict):
        self.config = config
        self.private_key: Optional[_RSAKey] = None
        self.public_key: Optional[_RSAKey] = None
        self.server_public_key: Optional[_RSAKey] = None
        self.aes_key: Optional[bytes] = None  # Session key for AES encryption
        self._load_key_params()
        self._clean_old_keys()
        self._generate_keys()

    def _load_key_params(self) -> None:
        self.key_length = int(self.config.get("key_length", 2048))
        self.private_key_path = self.config.get("private_key_path", "client_private.pem")
        self.public_key_path = self.config.get("public_key_path", "client_public.pem")
        self.aes_key_size = 16  # 128-bit AES key

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
        self.server_public_key = RSA._load_pem(pub_key_pem.encode())
        # Generate AES session key and encrypt with server public key
        self.aes_key = get_random_bytes(self.aes_key_size)

    def rsa_encrypt(self, data: bytes, pub_key: _RSAKey) -> bytes:
        """Encrypt data using RSA public key"""
        return RSA.encrypt(data, pub_key)

    def rsa_decrypt(self, data: bytes, priv_key: _RSAKey) -> bytes:
        """Decrypt data using RSA private key"""
        return RSA.decrypt(data, priv_key)

    def aes_encrypt(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES, returns (ciphertext, nonce, tag)"""
        if not self.aes_key:
            raise ValueError("AES key not initialized")
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data, AES.block_size))
        return ciphertext, cipher.nonce, tag

    def aes_decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt data using AES"""
        if not self.aes_key:
            raise ValueError("AES key not initialized")
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
        return unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)

    def encrypt(self, data: dict) -> bytes:
        """Encrypt data: sensitive fields with AES, AES key with RSA"""
        if not self.server_public_key or not self.aes_key:
            raise ValueError("Server public key or AES key not initialized")
        
        # Encrypt AES key
        encrypted_aes_key = self.rsa_encrypt(self.aes_key, self.server_public_key)
        
        # Encrypt sensitive fields
        sensitive_fields = ["nickname", "message", "ip", "password", "room_password"]
        encrypted_data = {}
        
        for key, value in data.items():
            if key in sensitive_fields and value is not None:
                # Encrypt each sensitive field individually with AES
                ciphertext, nonce, tag = self.aes_encrypt(str(value).encode('utf-8'))
                encrypted_data[key] = {
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "nonce": base64.b64encode(nonce).decode(),
                    "tag": base64.b64encode(tag).decode()
                }
            else:
                encrypted_data[key] = value
        
        # Assemble final data
        result = {
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
            "data": encrypted_data
        }
        
        return json.dumps(result).encode('utf-8')

    def decrypt(self, encrypted_data: bytes) -> dict:
        """Decrypt data: first decrypt AES key, then decrypt sensitive fields with AES"""
        if not self.private_key:
            raise ValueError("Private key not initialized")
        
        try:
            data = json.loads(encrypted_data.decode('utf-8'))
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-8 data received")
        
        # Decrypt AES key
        encrypted_aes_key = base64.b64decode(data["encrypted_aes_key"])
        self.aes_key = self.rsa_decrypt(encrypted_aes_key, self.private_key)
        
        # Decrypt sensitive fields
        sensitive_fields = ["nickname", "message", "ip"]
        decrypted_data = {}
        
        for key, value in data["data"].items():
            if key in sensitive_fields and value is not None:
                try:
                    ciphertext = base64.b64decode(value["ciphertext"])
                    nonce = base64.b64decode(value["nonce"])
                    tag = base64.b64decode(value["tag"])
                    
                    decrypted_bytes = self.aes_decrypt(ciphertext, nonce, tag)
                    decrypted_data[key] = decrypted_bytes.decode('utf-8')
                except Exception as e:
                    raise ValueError(f"Decryption failed for {key}: {str(e)}")
            else:
                decrypted_data[key] = value
        
        return decrypted_data

    def get_public_key_pem(self) -> str:
        """Get client public key in PEM format"""
        return RSA.export_public_key(self.public_key).decode()

    def get_encrypted_aes_key(self) -> bytes:
        """Get AES key encrypted with server public key"""
        if not self.server_public_key or not self.aes_key:
            raise ValueError("Server public key or AES key not initialized")
        return self.rsa_encrypt(self.aes_key, self.server_public_key)