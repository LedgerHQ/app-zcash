"""Legacy round of `test_sign_tx_v5_old` as raw APDUs, up to HASH_SIGN.

No APDU carries a path, so the mainnet and testnet builds both run it.
"""

from typing import Callable

# GET_TRUSTED_INPUT over the previous transaction, output 0.
_TRUSTED_INPUT_ROUND = [
    "e04200001100000000050000800a27a726b4d0d6c201",
    "e04280002598cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b",
    "e04280003248304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736",
    "e042800032c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b46",
    "e04280000b9c616e758230a5ffffffff",
    "e04280000102",
    "e0428000221595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac",
    "e042800022a245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac",
    "e042800003000000",
]
_TRUSTED_INPUT_LAST = "e0428000090000000004f9081a00"
_INPUT_SCRIPT = "e04480801d76a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac00000000"
_OUTPUTS = "e04a80002301958ddd04000000001976a91431352ad6f20315d1233d6e6da7ec1d6958f2bf1988ac"
# HASH_SIGN extra header data; it triggers the review.
_EXTRA_HEADER = "e04800000b0000000000000100000000"
# User validation code length, locktime, sighash type and expiry, after the path in HASH_SIGN.
_SIGN_SUFFIX = "00" + "00000000" + "01" + "00000000"


def _send(transport, apdu: str) -> bytes:
    sw, data = transport.exchange_raw(apdu)
    assert sw == 0x9000
    return data


def open_legacy_change_info(transport) -> str:
    """Run the first round up to its outputs and return the trusted input."""
    for apdu in _TRUSTED_INPUT_ROUND:
        _send(transport, apdu)
    trusted_input = _send(transport, _TRUSTED_INPUT_LAST).hex()

    for apdu in [
        "e04400050d050000800a27a726b4d0d6c201",
        "e04480053b0138" + trusted_input + "19",
        _INPUT_SCRIPT,
        "e04480050400000000",
    ]:
        _send(transport, apdu)
    return trusted_input


def open_legacy_signing(transport, approve: Callable[[], None]) -> None:
    """Run both rounds of the transaction up to HASH_SIGN, approving the review with `approve`."""
    trusted_input = open_legacy_change_info(transport)
    _send(transport, _OUTPUTS)

    with transport.exchange_async_raw(_EXTRA_HEADER):
        approve()
    assert transport.get_async_response().status == 0x9000

    for apdu in [
        "e04400800d050000800a27a726b4d0d6c201",
        "e04480803b0138" + trusted_input + "19",
        _INPUT_SCRIPT,
    ]:
        _send(transport, apdu)


def change_info_apdu(path: list[int]) -> str:
    """HASH_INPUT_FINALIZE_FULL declaring `path` as the change path."""
    data = _pack_path(path)
    return "e04aff00" + f"{len(bytes.fromhex(data)):02x}" + data


def _pack_path(path: list[int]) -> str:
    return bytes([len(path)]).hex() + "".join(f"{component:08x}" for component in path)


def hash_sign_apdu(path: list[int]) -> str:
    """HASH_SIGN for the key at `path` (BIP-32 components, hardening bit included)."""
    data = _pack_path(path) + _SIGN_SUFFIX
    return "e0480000" + f"{len(bytes.fromhex(data)):02x}" + data
