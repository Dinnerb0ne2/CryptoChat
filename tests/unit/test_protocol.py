from cryptochat.network.protocol import decode_packet, encode_packet


def test_protocol_encode_decode() -> None:
    raw = encode_packet({"a": 1, "b": "x"})
    parsed = decode_packet(raw)
    assert parsed == {"a": 1, "b": "x"}
