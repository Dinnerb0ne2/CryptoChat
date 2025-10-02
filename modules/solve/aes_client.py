import os
import json
from typing import Optional
from ..algorithm.aes import AES
from ..algorithm.rsa import RSA, _RSAKey


class AesClient:
    def __init__(self, config: dict):
        self.config = config
        self.aes: Optional[AES] = None  # AES实例，密钥交换后初始化
        self.rsa = RSA(int(config.get("rsa_key_length", 2048)))
        self.private_key: _RSAKey = self.rsa.generate()  # 生成RSA密钥对
        self.public_key: _RSAKey = self.rsa.publickey(self.private_key)
        self.server_public_key: Optional[_RSAKey] = None

    def get_public_key_pem(self) -> str:
        """获取客户端RSA公钥（PEM格式，用于发送给服务器）"""
        return self.rsa.export_public_key(self.public_key).decode()

    def set_server_public_key(self, pub_key_pem: str) -> bytes:
        """
        接收服务器RSA公钥，生成AES密钥并加密后返回
        :param pub_key_pem: 服务器公钥（PEM格式）
        :return: 加密后的AES密钥（用于发送给服务器）
        """
        self.server_public_key = RSA._load_pem(pub_key_pem.encode())
        
        # 生成随机AES密钥（128/256位）
        key_length = int(self.config.get("key_length", 128))
        aes_key = os.urandom(key_length // 8)  #  cryptographically secure random
        
        # 用服务器公钥加密AES密钥
        encrypted_aes_key = self.rsa.encrypt(aes_key, self.server_public_key)
        
        # 初始化AES实例
        self.aes = AES(aes_key, key_length)
        return encrypted_aes_key

    def encrypt_message(self, data: dict) -> bytes:
        """加密聊天数据（敏感字段全加密）"""
        if not self.aes:
            raise ValueError("AES未初始化（未完成密钥交换）")
        
        # 序列化数据为JSON字符串
        data_str = json.dumps(data, ensure_ascii=False)
        # AES加密（包含随机IV，密文开头已附加IV）
        return self.aes.encrypt(data_str)

    def decrypt_message(self, encrypted_data: bytes) -> dict:
        """解密服务器发送的消息"""
        if not self.aes:
            raise ValueError("AES未初始化（未完成密钥交换）")
        
        # AES解密
        decrypted_str = self.aes.decrypt(encrypted_data).decode('utf-8')
        # Deserialize JSON
        return json.loads(decrypted_str)