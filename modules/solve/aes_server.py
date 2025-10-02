import json
from typing import Dict, Optional
import socket
from ..algorithm.aes import AES
from ..algorithm.rsa import RSA, _RSAKey


class AesServer:
    def __init__(self, config: dict):
        self.config = config
        self.clients: Dict[socket.socket, AES] = {}  # 客户端socket -> AES实例
        self.rsa = RSA(int(config.get("rsa_key_length", 2048)))
        self.private_key: _RSAKey = self.rsa.generate()  # 生成RSA密钥对
        self.public_key: _RSAKey = self.rsa.publickey(self.private_key)

    def get_public_key_pem(self) -> str:
        """获取服务器RSA公钥（PEM格式，用于发送给客户端）"""
        return self.rsa.export_public_key(self.public_key).decode()

    def handle_client_key_exchange(self, client_socket: socket.socket, encrypted_aes_key: bytes) -> None:
        """
        处理客户端发送的加密AES密钥，完成密钥交换
        :param client_socket: 客户端连接socket
        :param encrypted_aes_key: 加密的AES密钥
        """
        # 用服务器私钥解密AES密钥
        aes_key = self.rsa.decrypt(encrypted_aes_key, self.private_key)
        
        # 初始化AES实例（使用客户端发送的密钥）
        key_length = int(self.config.get("key_length", 128))
        self.clients[client_socket] = AES(aes_key, key_length)

    def encrypt_message(self, client_socket: socket.socket, data: dict) -> bytes:
        """加密发送给客户端的消息"""
        if client_socket not in self.clients:
            raise ValueError("客户端未完成密钥交换")
        
        # 序列化数据为JSON字符串
        data_str = json.dumps(data, ensure_ascii=False)
        # AES加密
        return self.clients[client_socket].encrypt(data_str)

    def decrypt_message(self, client_socket: socket.socket, encrypted_data: bytes) -> dict:
        """解密客户端发送的消息"""
        if client_socket not in self.clients:
            raise ValueError("客户端未完成密钥交换")
        
        # AES解密
        decrypted_str = self.clients[client_socket].decrypt(encrypted_data).decode('utf-8')
        # 反序列化JSON
        return json.loads(decrypted_str)

    def remove_client(self, client_socket: socket.socket) -> None:
        """移除客户端连接及对应的AES实例"""
        if client_socket in self.clients:
            del self.clients[client_socket]