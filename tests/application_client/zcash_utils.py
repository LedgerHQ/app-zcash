import hashlib
from io import BytesIO
from typing import Literal

import base58  # type: ignore[import-not-found]

UINT64_MAX: int = 2**64 - 1
UINT32_MAX: int = 2**32 - 1
UINT16_MAX: int = 2**16 - 1

# Version prefix of a mainnet transparent P2PKH ("t1...") address.
T_ADDRESS_VERSION_BYTES: bytes = b"\x1c\xb8"
PUBKEY_HASH_SIZE: int = 20

try:

    def _ripemd160():
        return hashlib.new("ripemd160")  # type: ignore # pylint: disable=C3001
except ValueError:
    _ripemd160 = None  # type: ignore


def ripemd160(data: bytes) -> bytes:
    # if _ripemd160 is not None:
    #    h = _ripemd160()
    #    h.update(data)
    #    return h.digest()
    # fallback
    from Crypto.Hash import RIPEMD160  # type: ignore # pylint: disable=C0415

    h = RIPEMD160.new()
    h.update(data)
    return h.digest()


def write_varint(n: int) -> bytes:
    # 0xFC is the last value a single byte may carry: 0xFD, 0xFE and 0xFF are the prefixes of the
    # extended forms. The bound is `< 0xFD`, and `_write_compactsize` in zcash_verify_sign.py, which
    # re-encodes independently to check a signature, uses that one.
    if n < 0xFD:
        return n.to_bytes(1, byteorder="little")

    if n <= UINT16_MAX:
        return b"\xfd" + n.to_bytes(2, byteorder="little")

    if n <= UINT32_MAX:
        return b"\xfe" + n.to_bytes(4, byteorder="little")

    if n <= UINT64_MAX:
        return b"\xff" + n.to_bytes(8, byteorder="little")

    raise ValueError(f"Can't write to varint: '{n}'!")


def read_varint(buf: BytesIO, prefix: bytes | None = None) -> int:
    b: bytes = prefix if prefix else buf.read(1)

    if not b:
        raise ValueError(f"Can't read prefix: '{b.hex()}'!")

    n: int = {b"\xfd": 2, b"\xfe": 4, b"\xff": 8}.get(b, 1)  # default to 1

    b = buf.read(n) if n > 1 else b

    if len(b) != n:
        raise ValueError("Can't read varint!")

    return int.from_bytes(b, byteorder="little")


def read(buf: BytesIO, size: int) -> bytes:
    b: bytes = buf.read(size)

    if len(b) < size:
        raise ValueError(f"Can't read {size} bytes in buffer!")

    return b


def read_uint(buf: BytesIO, bit_len: int, byteorder: Literal["big", "little"] = "little") -> int:
    size: int = bit_len // 8
    b: bytes = buf.read(size)

    if len(b) < size:
        raise ValueError(f"Can't read u{bit_len} in buffer!")

    return int.from_bytes(b, byteorder)


def read_compactsize(buf, i):
    if i >= len(buf):
        raise ValueError(f"Can't read a CompactSize prefix at offset {i} of {len(buf)} bytes!")

    b = buf[i]
    if b < 0xFD:
        return b, i + 1

    width = {0xFD: 2, 0xFE: 4}.get(b, 8)
    start = i + 1
    end = start + width

    # Slicing past the end yields a short slice that int.from_bytes converts without complaint,
    # and the offset would then advance as if the whole field had been read. Every later field is
    # read from the wrong position and still produces plausible numbers, so a truncated buffer
    # turns into wrong values rather than an error.
    if end > len(buf):
        raise ValueError(f"Can't read a {width}-byte CompactSize at offset {start} of {len(buf)} bytes!")

    return int.from_bytes(buf[start:end], "little"), end


def t_address_from_pubkey(pub_key: bytes) -> str:
    # Compress the public key
    if pub_key[64] % 2 == 0:
        prefix = b"\x02"
    else:
        prefix = b"\x03"
    compressed_pub_key = prefix + pub_key[1:33]

    # Perform SHA256 followed by RIPEMD160
    sha256_hash = hashlib.sha256(compressed_pub_key).digest()

    ripemd160_hash = ripemd160(sha256_hash)

    # Prepend the network byte (0x1C, 0xB8 for mainnet)
    addr_payload = T_ADDRESS_VERSION_BYTES + ripemd160_hash
    # Calculate the checksum
    checksum = hashlib.sha256(hashlib.sha256(addr_payload).digest()).digest()[:4]
    # Construct the final address bytes
    addr = addr_payload + checksum
    # Encode in Base58
    addr = base58.b58encode(addr)

    return addr.decode("ascii")


def pubkey_hash_from_t_address(address: str) -> bytes:
    """Inverse of `t_address_from_pubkey`: recover the 20-byte public key hash a t-address pays to.

    Lets a test derive the P2PKH script of an arbitrary destination instead of carrying a
    hardcoded address-to-hash table that has to be kept in sync by hand.
    """
    payload = base58.b58decode_check(address)

    version, pubkey_hash = payload[: len(T_ADDRESS_VERSION_BYTES)], payload[len(T_ADDRESS_VERSION_BYTES) :]
    if version != T_ADDRESS_VERSION_BYTES:
        raise ValueError(f"{address} is not a mainnet transparent P2PKH address (version {version.hex()})")
    if len(pubkey_hash) != PUBKEY_HASH_SIZE:
        raise ValueError(f"{address} does not carry a {PUBKEY_HASH_SIZE}-byte public key hash")

    return pubkey_hash
