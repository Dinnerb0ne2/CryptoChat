from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(plaintext: str, public_pem: bytes) -> dict[str, bytes]:
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public_pem must contain an RSA public key")
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return {"encrypted_key": encrypted_key, "nonce": nonce, "ciphertext": ciphertext}


def decrypt_message(payload: dict[str, bytes], private_pem: bytes) -> str:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_pem must contain an RSA private key")
    aes_key = private_key.decrypt(
        payload["encrypted_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(payload["nonce"], payload["ciphertext"], None)
    return plaintext.decode("utf-8")
