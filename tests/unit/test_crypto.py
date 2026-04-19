from cryptochat.crypto import KeyManager, decrypt_message, encrypt_message


def test_hybrid_encrypt_decrypt_roundtrip() -> None:
    pair = KeyManager.generate_key_pair()
    payload = encrypt_message("hello", pair.public_pem)
    plain = decrypt_message(payload, pair.private_pem)
    assert plain == "hello"
