"""The little ABI the shadow adapter needs: selectors, static-word encoding, and decoding of words and of dynamic arrays. No third-party code."""
from keccak import keccak256


def selector(signature: str) -> bytes:
    return keccak256(signature.encode())[:4]


def word(v) -> bytes:
    if isinstance(v, bytes):
        assert len(v) <= 32
        return v.rjust(32, b"\0") if len(v) < 32 else v
    if isinstance(v, str):
        h = v[2:] if v.startswith("0x") else v
        return bytes.fromhex(h).rjust(32, b"\0")
    assert v >= 0
    return v.to_bytes(32, "big")


def encode_args(*args) -> bytes:
    """abi.encode of static words (uint*, bytes32, address given as ints, 0x-hex strings or bytes)."""
    return b"".join(word(a) for a in args)


def calldata(signature: str, *args) -> bytes:
    return selector(signature) + encode_args(*args)


def words(raw) -> list:
    if isinstance(raw, str):
        h = raw[2:] if raw.startswith("0x") else raw
        raw = bytes.fromhex(h)
    assert len(raw) % 32 == 0, f"not whole words ({len(raw)} bytes)"
    return [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]


def hexw(v: int) -> str:
    return "0x" + v.to_bytes(32, "big").hex()


def addr(v: int) -> str:
    return "0x" + v.to_bytes(32, "big")[12:].hex()


def dyn_array(w: list, offset_word: int) -> list:
    """The items (as words) of a dynamic array of static single-word elements whose head offset is in word `offset_word`."""
    off = w[offset_word] // 32
    n = w[off]
    return w[off + 1:off + 1 + n]


def dyn_struct_array(w: list, offset_word: int, width: int) -> list:
    """The rows of a dynamic array of static structs of `width` words."""
    off = w[offset_word] // 32
    n = w[off]
    return [w[off + 1 + i * width:off + 1 + (i + 1) * width] for i in range(n)]


def dyn_bytes(raw: bytes, byte_offset: int) -> bytes:
    n = int.from_bytes(raw[byte_offset:byte_offset + 32], "big")
    return raw[byte_offset + 32:byte_offset + 32 + n]
