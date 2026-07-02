import hashlib
from io import BytesIO
from typing import Optional, Literal

import base58 # type: ignore[import-not-found]

UINT64_MAX: int = 2**64-1
UINT32_MAX: int = 2**32-1
UINT16_MAX: int = 2**16-1

try:
    _ripemd160 = lambda: hashlib.new("ripemd160") # type: ignore # pylint: disable=C3001
except ValueError:
    _ripemd160 = None # type: ignore

def ripemd160(data: bytes) -> bytes:
    #if _ripemd160 is not None:
    #    h = _ripemd160()
    #    h.update(data)
    #    return h.digest()
    # fallback
    from Crypto.Hash import RIPEMD160 # type: ignore # pylint: disable=C0415
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def write_varint(n: int) -> bytes:
    if n < 0xFC:
        return n.to_bytes(1, byteorder="little")

    if n <= UINT16_MAX:
        return b"\xFD" + n.to_bytes(2, byteorder="little")

    if n <= UINT32_MAX:
        return b"\xFE" + n.to_bytes(4, byteorder="little")

    if n <= UINT64_MAX:
        return b"\xFF" + n.to_bytes(8, byteorder="little")

    raise ValueError(f"Can't write to varint: '{n}'!")


def read_varint(buf: BytesIO,
                prefix: Optional[bytes] = None) -> int:
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


def read_uint(buf: BytesIO,
              bit_len: int,
              byteorder: Literal['big', 'little'] = 'little') -> int:
    size: int = bit_len // 8
    b: bytes = buf.read(size)

    if len(b) < size:
        raise ValueError(f"Can't read u{bit_len} in buffer!")

    return int.from_bytes(b, byteorder)

def read_compactsize(buf, i):
    b = buf[i]
    if b < 0xfd:
        return b, i+1
    if b == 0xfd:
        return int.from_bytes(buf[i+1:i+3], 'little'), i+3
    if b == 0xfe:
        return int.from_bytes(buf[i+1:i+5], 'little'), i+5
    return int.from_bytes(buf[i+1:i+9], 'little'), i+9

def t_address_from_pubkey(pub_key: bytes) -> str:
    # Compress the public key
    if pub_key[64] % 2 == 0:
        prefix = b'\x02'
    else:
        prefix = b'\x03'
    compressed_pub_key = prefix + pub_key[1:33]

    # Perform SHA256 followed by RIPEMD160
    sha256_hash = hashlib.sha256(compressed_pub_key).digest()

    ripemd160_hash = ripemd160(sha256_hash)

    # Prepend the network byte (0x1C, 0xB8 for mainnet)
    network_bytes = b'\x1C\xB8'  # for t-addresses
    addr_payload = network_bytes + ripemd160_hash
    # Calculate the checksum
    checksum = hashlib.sha256(hashlib.sha256(addr_payload).digest()).digest()[:4]
    # Construct the final address bytes
    addr = addr_payload + checksum
    # Encode in Base58
    addr = base58.b58encode(addr)

    return addr.decode('ascii')
