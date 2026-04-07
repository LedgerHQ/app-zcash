from typing import Tuple
from struct import unpack
from .zcash_command_sender import MAGIC_TRUSTED_INPUT

# remainder, data_len, data
def pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
    return buffer[size:], buffer[0:size]

# remainder, data_len, data
def pop_size_prefixed_buf_from_buf(buffer:bytes) -> Tuple[bytes, int, bytes]:
    data_len = buffer[0]
    return buffer[1+data_len:], data_len, buffer[1:data_len+1]

def pop_fixed_len_from_buf(buffer:bytes, data_len:int) -> Tuple[bytes, bytes]:
    return buffer[1+data_len:], buffer[:data_len+1]

# Unpack from response:
# response = app_name (var)
def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")

# Unpack from response:
# response = MAJOR (1)
#            MINOR (1)
#            PATCH (1)
def unpack_get_version_response(response: bytes) -> Tuple[int, int, int]:
    assert len(response) == 8
    major, minor, patch = unpack("BBB", response[2:5])
    return (major, minor, patch)

# Unpack from response:
# response = format_id (1)
#            app_name_raw_len (1)
#            app_name_raw (var)
#            version_raw_len (1)
#            version_raw (var)
#            unused_len (1)
#            unused (var)
def unpack_get_app_and_version_response(response: bytes) -> Tuple[str, str]:
    response, _ = pop_sized_buf_from_buffer(response, 1)
    response, _, app_name_raw = pop_size_prefixed_buf_from_buf(response)
    response, _, version_raw = pop_size_prefixed_buf_from_buf(response)
    response, _, _ = pop_size_prefixed_buf_from_buf(response)

    assert len(response) == 0

    return app_name_raw.decode("ascii"), version_raw.decode("ascii")

# Unpack from response:
# response = len(pub_key) (1) || pub_key (var) ||
#            len(addr) (1) || addr (var) || bip32_chain_code (32)
def unpack_get_public_key_response(response: bytes) -> Tuple[bytes, str, bytes]:
    response, pub_key_len, pub_key = pop_size_prefixed_buf_from_buf(response)
    response, address_len, addr = pop_size_prefixed_buf_from_buf(response)
    response, chain_code = pop_fixed_len_from_buf(response, 32)

    addr_str = addr.decode("ascii")

    assert pub_key_len == 65
    assert address_len > 0
    assert len(response) == 0

    return pub_key, addr_str, chain_code

# *Description*                                                                       | *Length*
# Magic version (*32*)                                                                | 1
# Flags                                                                               | 1
# Nonce                                                                               | 2
# Associated transaction hash                                                         | 32
# Index in associated transaction (little endian)                                     | 4
# Associated amount (little endian)                                                   | 8
# Signature                                                                           | 8
def unpack_trusted_input_response(response: bytes) -> Tuple[bytes, int, int, bytes, bytes]:
    assert len(response) == 56
    magic, _flags, nonce, txid, trusted_input_idx, amount, sign =  unpack("<BBH32sIQ8s", response)
    assert magic == MAGIC_TRUSTED_INPUT

    return (txid, trusted_input_idx, amount, sign, nonce)
