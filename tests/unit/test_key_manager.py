from pathlib import Path

from cryptochat.crypto import KeyManager


def test_key_manager_save_load(tmp_path: Path) -> None:
    pair = KeyManager.generate_key_pair()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    KeyManager.save_key_pair(pair, private_path, public_path)
    private_key = KeyManager.load_private_key(private_path)
    public_key = KeyManager.load_public_key(public_path)
    assert private_key.key_size == 2048
    assert public_key.key_size == 2048

