import hashlib
from io import BytesIO

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der
from application_client.zcash_utils import read_varint

# pylint: disable=R0917, R0914

ZCASH_HEADERS_HASH_PERSONALIZATION = b"ZTxIdHeadersHash"
ZCASH_TRANSPARENT_HASH_PERSONALIZATION = b"ZTxIdTranspaHash"
ZCASH_PREVOUTS_HASH_PERSONALIZATION = b"ZTxIdPrevoutHash"
ZCASH_SEQUENCE_HASH_PERSONALIZATION = b"ZTxIdSequencHash"
ZCASH_OUTPUTS_HASH_PERSONALIZATION = b"ZTxIdOutputsHash"
ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION = b"ZTxTrAmountsHash"
ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION = b"ZTxTrScriptsHash"
ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION = b"Zcash___TxInHash"
ZCASH_TX_PERSONALIZATION_PREFIX = b"ZcashTxHash_"
ZCASH_SAPLING_HASH_PERSONALIZATION = b"ZTxIdSaplingHash"
ZCASH_ORCHARD_HASH_PERSONALIZATION = b"ZTxIdOrchardHash"

def nu5_txid_digests(tx_bytes: bytes) -> dict:
    """Compute ZIP-244 transaction ID digests for a V5 transparent-only transaction."""
    tx = _parse_v5_tx(tx_bytes)
    inputs = tx["inputs"]
    outputs = tx["outputs"]

    prevouts_hash = _blake2b_256(
        ZCASH_PREVOUTS_HASH_PERSONALIZATION,
        b"".join(inp["prev_txid"] + inp["prev_vout"] for inp in inputs),
    )
    sequence_hash = _blake2b_256(
        ZCASH_SEQUENCE_HASH_PERSONALIZATION,
        b"".join(inp["sequence"] for inp in inputs),
    )
    outputs_hash = _blake2b_256(
        ZCASH_OUTPUTS_HASH_PERSONALIZATION,
        b"".join(
            out["value"] + _write_compactsize(len(out["script"])) + out["script"]
            for out in outputs
        ),
    )
    transparent_digest = _blake2b_256(
        ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
        prevouts_hash + sequence_hash + outputs_hash,
    )
    header_digest = _blake2b_256(
        ZCASH_HEADERS_HASH_PERSONALIZATION,
        tx["version"]
        + tx["branch_id"].to_bytes(4, byteorder="little")
        + tx["locktime"].to_bytes(4, byteorder="little")
        + tx["expiry"].to_bytes(4, byteorder="little"),
    )
    sapling_digest = _blake2b_256(ZCASH_SAPLING_HASH_PERSONALIZATION, b"")
    orchard_digest = _blake2b_256(ZCASH_ORCHARD_HASH_PERSONALIZATION, b"")

    personal = ZCASH_TX_PERSONALIZATION_PREFIX + tx["branch_id"].to_bytes(4, byteorder="little")
    final_digest = _blake2b_256(
        personal,
        header_digest + transparent_digest + sapling_digest + orchard_digest,
    )
    return {
        "final_digest": final_digest,
        "header_digest": header_digest,
        "transparent_digest": transparent_digest,
        "sapling_digest": sapling_digest,
        "orchard_digest": orchard_digest,
    }


def check_tx_v5_signature_validity(
    public_key: bytes,
    signature: bytes,
    tx_bytes: bytes,
    input_index: int,
    input_amounts: list[int],
    sighash_type: int = 0x01,
) -> bool:
    # Reset signature first bit (parity info) if set
    normalized_signature = bytearray(signature)
    normalized_signature[0] &= 0xFE
    signature = bytes(normalized_signature)

    sighash = _nu5_signature_hash(
        tx_bytes=tx_bytes,
        input_index=input_index,
        input_amounts=input_amounts,
        sighash_type=sighash_type,
    )

    pk = VerifyingKey.from_string(public_key, curve=SECP256k1)
    return pk.verify_digest(signature=signature, digest=sighash, sigdecode=sigdecode_der)


def _nu5_signature_hash(
    tx_bytes: bytes,
    input_index: int,
    input_amounts: list[int],
    sighash_type: int,
) -> bytes:
    tx = _parse_v5_tx(tx_bytes)
    inputs = tx["inputs"]
    outputs = tx["outputs"]

    if not 0 <= input_index < len(inputs):
        raise ValueError(f"Input index out of range: {input_index}")

    if len(input_amounts) != len(inputs):
        raise ValueError("Input amounts length mismatch")

    locktime = tx["locktime"]
    expiry_height = tx["expiry"]

    prevouts_hash = _blake2b_256(
        ZCASH_PREVOUTS_HASH_PERSONALIZATION,
        b"".join(inp["prev_txid"] + inp["prev_vout"] for inp in inputs),
    )
    sequence_hash = _blake2b_256(
        ZCASH_SEQUENCE_HASH_PERSONALIZATION,
        b"".join(inp["sequence"] for inp in inputs),
    )
    outputs_hash = _blake2b_256(
        ZCASH_OUTPUTS_HASH_PERSONALIZATION,
        b"".join(
            out["value"]
            + _write_compactsize(len(out["script"]))
            + out["script"]
            for out in outputs
        ),
    )
    amounts_hash = _blake2b_256(
        ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION,
        b"".join(_int64_le_bytes(amount) for amount in input_amounts),
    )

    scripts_hash = _blake2b_256(
        ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
        b"".join(_write_compactsize(len(inp["script"])) + inp["script"] for inp in inputs),
    )

    input_data = inputs[input_index]
    script_pubkey = input_data["script"]
    amount = input_amounts[input_index]

    txin_sig_digest = _blake2b_256(
        ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION,
        input_data["prev_txid"]
        + input_data["prev_vout"]
        + _int64_le_bytes(amount)
        + _write_compactsize(len(script_pubkey))
        + script_pubkey
        + input_data["sequence"],
    )
    transparent_digest = _blake2b_256(
        ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
        bytes([sighash_type & 0xFF])
        + prevouts_hash
        + amounts_hash
        + scripts_hash
        + sequence_hash
        + outputs_hash
        + txin_sig_digest,
    )

    header_digest = _blake2b_256(
        ZCASH_HEADERS_HASH_PERSONALIZATION,
        tx["version"]
        + tx["branch_id"].to_bytes(4, byteorder="little")
        + locktime.to_bytes(4, byteorder="little")
        + expiry_height.to_bytes(4, byteorder="little"),
    )
    sapling_digest = _blake2b_256(ZCASH_SAPLING_HASH_PERSONALIZATION, b"")
    orchard_digest = _blake2b_256(ZCASH_ORCHARD_HASH_PERSONALIZATION, b"")

    personal = ZCASH_TX_PERSONALIZATION_PREFIX + tx["branch_id"].to_bytes(
        4, byteorder="little"
    )

    return _blake2b_256(
        personal,
        header_digest + transparent_digest + sapling_digest + orchard_digest,
    )


def _parse_v5_tx(tx_bytes: bytes) -> dict:
    buf = BytesIO(tx_bytes)
    version = _read_exact(buf, 8)
    branch_id = int.from_bytes(_read_exact(buf, 4), byteorder="little")
    locktime = int.from_bytes(_read_exact(buf, 4), byteorder="little")
    expiry = int.from_bytes(_read_exact(buf, 4), byteorder="little")

    vin_count = read_varint(buf)
    inputs = []
    for _ in range(vin_count):
        prev_txid = _read_exact(buf, 32)
        prev_vout = _read_exact(buf, 4)
        script_len = read_varint(buf)
        script = _read_exact(buf, script_len)
        sequence = _read_exact(buf, 4)
        inputs.append(
            {
                "prev_txid": prev_txid,
                "prev_vout": prev_vout,
                "script": script,
                "sequence": sequence,
            }
        )

    vout_count = read_varint(buf)
    outputs = []
    for _ in range(vout_count):
        value = _read_exact(buf, 8)
        script_len = read_varint(buf)
        script = _read_exact(buf, script_len)
        outputs.append({"value": value, "script": script})

    sapling_spends = read_varint(buf)
    sapling_outputs = read_varint(buf)
    orchard_actions = read_varint(buf)
    if sapling_spends or sapling_outputs or orchard_actions:
        raise ValueError("Sapling/Orchard data not supported in NU5 helper")

    if buf.read(1):
        raise ValueError("Unexpected trailing data in transaction")

    return {
        "version": version,
        "branch_id": branch_id,
        "locktime": locktime,
        "expiry": expiry,
        "inputs": inputs,
        "outputs": outputs,
    }


def _read_exact(buf: BytesIO, size: int) -> bytes:
    data = buf.read(size)
    if len(data) != size:
        raise ValueError(f"Unable to read {size} bytes from transaction")
    return data


def _write_compactsize(value: int) -> bytes:
    if value < 0xFD:
        return value.to_bytes(1, byteorder="little")
    if value <= 0xFFFF:
        return b"\xFD" + value.to_bytes(2, byteorder="little")
    if value <= 0xFFFFFFFF:
        return b"\xFE" + value.to_bytes(4, byteorder="little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xFF" + value.to_bytes(8, byteorder="little")
    raise ValueError(f"CompactSize value too large: {value}")


def _int64_le_bytes(value: int) -> bytes:
    if not -(2**63) <= value <= 2**63 - 1:
        raise ValueError(f"Value out of range for int64: {value}")
    return value.to_bytes(8, byteorder="little", signed=True)


def _blake2b_256(personal: bytes, data: bytes) -> bytes:
    if len(personal) != 16:
        raise ValueError("Blake2b personalization must be 16 bytes")
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()
