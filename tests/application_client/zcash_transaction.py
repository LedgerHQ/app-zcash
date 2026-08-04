import json
from dataclasses import dataclass
from struct import pack, unpack_from

from .zcash_utils import UINT64_MAX, read_compactsize, write_varint

V6_TX_HEADER = 0x80000006
V6_VERSION_GROUP_ID = 0xD884B698

# Orchard and Ironwood actions share this layout and this ZIP-244 digest grouping.
ACTION_COMPACT_SIZE = 32 + 32 + 32 + 52  # nullifier + cmx + ephemeral_key + enc_ciphertext[..52]
ACTION_MEMO_SIZE = 512
ACTION_NONCOMPACT_SIZE = 32 + 32 + 16 + 80  # cv + rk + enc_ciphertext[564..] + out_ciphertext
MEMO_CHUNK_SIZE = 128
# flags + valueBalance, plus the anchor for a v5 Orchard bundle only: v6 moved the anchor to
# the authorizing digest, which a trusted input never computes.
ACTION_DIGEST_DATA_SIZE = 1 + 8
ACTION_DIGEST_DATA_SIZE_V5 = ACTION_DIGEST_DATA_SIZE + 32


class TransactionError(Exception):
    pass


@dataclass
class Transaction:
    nonce: int
    coin: str
    value: str
    to: str
    memo: str

    def serialize(self) -> bytes:
        if not 0 <= self.nonce <= UINT64_MAX:
            raise TransactionError(f"Bad nonce: '{self.nonce}'!")

        if len(self.to) != 40:
            raise TransactionError(f"Bad address: '{self.to}'!")

        # Serialize the transaction data to a JSON-formatted string
        return json.dumps(
            {
                "nonce": self.nonce,
                "coin": self.coin,
                "value": self.value,
                "to": self.to,
                "memo": self.memo,
            }
        ).encode("utf-8")


#  V5 TX format:
#  [ nVersion | flags ]           4 bytes
#  [ nGroupId ]                   4 bytes
#  [ nConsensusBranchId ]         4 bytes
#  [ nLockTime ]                  4 bytes (LE)
#  [ nExpiryHeight ]              4 bytes (LE)
#
#  [ vin_count ]                  CompactSize
#    for each vin:
#      [ prev_txid ]              32 bytes (LE)
#      [ prev_vout ]               4 bytes (LE)
#      [ scriptSig_len ]           CompactSize
#      [ scriptSig ]               N bytes
#      [ sequence ]                4 bytes (LE)
#
#  [ vout_count ]                 CompactSize
#    for each vout:
#      [ value ]                   8 bytes (LE, zatoshis)
#      [ scriptPubKey_len ]        CompactSize
#      [ scriptPubKey ]            N bytes
#
#  [ nSaplingSpends ]             CompactSize
#  [ nSaplingOutputs ]            CompactSize
#  [ nOrchardActions ]            CompactSize
#
#  -- witness data (excluded from txid) --
#
# NOTE: lockTime and expiryHeight are, for some reason,
# serialized at the end of the transaction data
# (as if it was a v4 transaction format).
def is_v6_transaction(buf: bytes) -> bool:
    return len(buf) >= 8 and unpack_from("<I", buf, 0)[0] == V6_TX_HEADER and unpack_from("<I", buf, 4)[0] == V6_VERSION_GROUP_ID


def append_action_bundle_chunks(chunks: list[bytes], buf: bytes, i: int, action_count: int, digest_data_size: int) -> int:
    if action_count == 0:
        return i

    for _ in range(action_count):
        chunks.append(buf[i : i + ACTION_COMPACT_SIZE])
        i += ACTION_COMPACT_SIZE

    memo_remaining = action_count * ACTION_MEMO_SIZE
    while memo_remaining > 0:
        memo_chunk = min(MEMO_CHUNK_SIZE, memo_remaining)
        chunks.append(buf[i : i + memo_chunk])
        i += memo_chunk
        memo_remaining -= memo_chunk

    for _ in range(action_count):
        chunks.append(buf[i : i + ACTION_NONCOMPACT_SIZE])
        i += ACTION_NONCOMPACT_SIZE

    chunks.append(buf[i : i + digest_data_size])
    return i + digest_data_size


def split_tx_to_chunks(buf: bytes, is_v4_nu6: bool = False) -> list[bytes]:
    # pylint: disable=R0914 disable=R0915 disable=R0912

    i = 0
    locktime = b""
    expiry = b""
    chunks = []

    header_v5_size = 4 * 5
    header_v4_size = 4 * 3
    is_v6 = not is_v4_nu6 and is_v6_transaction(buf)

    if is_v4_nu6:
        i += header_v4_size
    else:
        locktime = buf[header_v4_size : header_v4_size + 4]
        expiry = buf[header_v4_size + 4 : header_v4_size + 4 * 2]
        i += header_v5_size

    vin_n, i = read_compactsize(buf, i)
    header_bytes = bytes(buf[0:header_v4_size]) + bytes(buf[i - 1 : i])
    chunks.append(header_bytes)

    for _ in range(vin_n):
        prevout_start = i
        i += 32 + 4
        slen, i = read_compactsize(buf, i)
        chunks.append(buf[prevout_start:i])

        script_start = i
        i = i + slen + 4

        chunks.append(buf[script_start:i])

    vout_n, i = read_compactsize(buf, i)
    chunks.append(buf[i - 1 : i])

    for _ in range(vout_n):
        value_start = i
        i += 8
        plen, i = read_compactsize(buf, i)
        chunks.append(buf[value_start:i])

        script_pk_start = i
        i = i + plen
        chunks.append(buf[script_pk_start:i])

    # Sapling, Orchard and — for v6 only — Ironwood action counts
    sapling_start = i
    sap_sp, i = read_compactsize(buf, i)
    sap_out, i = read_compactsize(buf, i)
    orch, i = read_compactsize(buf, i)
    ironwood = 0
    if is_v6:
        ironwood, i = read_compactsize(buf, i)
    chunks.append(buf[sapling_start:i])

    # Sapling data (if any)
    if sap_sp > 0 or sap_out > 0:
        # valueBalance
        balance_start = i
        i += 8

        # A v6 spends non-compact digest omits the anchor (ZIP-229), which moves to the
        # authorizing data, so no anchor is streamed at all for a v6.
        if sap_sp > 0 and not is_v6:
            # anchor
            i += 32

        # balance (+ anchor if present) must be in a single chunk
        chunks.append(buf[balance_start:i])

        # Sapling spends
        for _ in range(sap_sp):
            spend_start = i
            i += 32 + 32 + 32  # cv + nullifier + rk
            chunks.append(buf[spend_start:i])

        # Sapling outputs: compact part
        for _ in range(sap_out):
            compact_start = i
            i += 32 + 32 + 52  # cmu + ephemeral_key + enc_ciphertext[..52]
            chunks.append(buf[compact_start:i])

        # Sapling outputs: memo data (512 bytes per output), split into 128-byte chunks
        memo_remaining = sap_out * 512
        while memo_remaining > 0:
            memo_chunk = min(128, memo_remaining)
            chunks.append(buf[i : i + memo_chunk])
            i += memo_chunk
            memo_remaining -= memo_chunk

        # Sapling outputs: non-compact part
        for _ in range(sap_out):
            non_compact_start = i
            i += 32 + 16 + 80
            chunks.append(buf[non_compact_start:i])

    # Shielded action bundles, streamed one after the other
    digest_data_size = ACTION_DIGEST_DATA_SIZE if is_v6 else ACTION_DIGEST_DATA_SIZE_V5
    i = append_action_bundle_chunks(chunks, buf, i, orch, digest_data_size)
    i = append_action_bundle_chunks(chunks, buf, i, ironwood, digest_data_size)

    # Extra data
    if is_v4_nu6:
        chunks.append(buf[i:])
        i += len(buf[i:])
    else:
        chunks.append(locktime + pack("b", 0x04) + expiry)

    # Every byte of a fixture must be accounted for. Leftovers mean the fixture and this
    # chunker disagree on the layout, which is exactly the misframing worth catching.
    if i != len(buf):
        print(f"Not consumed bytes: {buf[i:].hex()}")
    assert i == len(buf), "Transaction splitting did not consume all bytes!"

    return chunks


def split_tx_v5_for_hash_input(buf: bytes) -> dict[str, object]:
    # pylint: disable=R0914,R0915

    i = 0

    header_size = 4 * 5
    header_quirk_size = 4 * 3

    locktime = buf[header_quirk_size : header_quirk_size + 4]
    expiry = buf[header_quirk_size + 4 : header_quirk_size + 8]

    i += header_size

    vin_n, i = read_compactsize(buf, i)
    header = bytes(buf[0:header_quirk_size])

    inputs = []
    for _ in range(vin_n):
        prevout_start = i
        i += 32 + 4
        prevout = buf[prevout_start:i]

        script_len, i = read_compactsize(buf, i)
        script = buf[i : i + script_len]
        i += script_len

        sequence = buf[i : i + 4]
        i += 4

        inputs.append(
            {
                "prev": prevout,
                "script": script,
                "sequence": sequence,
            }
        )

    vout_n, i = read_compactsize(buf, i)

    outputs = []
    for _ in range(vout_n):
        value = buf[i : i + 8]
        i += 8

        script_len, i = read_compactsize(buf, i)
        script = buf[i : i + script_len]
        i += script_len

        outputs.append(
            {
                "value": value,
                "script": script,
            }
        )

    shielded_prefix_start = i
    sap_sp, i = read_compactsize(buf, i)
    assert sap_sp == 0, "Sapling spends not supported in this chunking function!"
    sap_out, i = read_compactsize(buf, i)
    assert sap_out == 0, "Sapling outputs not supported in this chunking function!"
    orch, i = read_compactsize(buf, i)
    shielded_prefix = buf[shielded_prefix_start:i]

    shielded_chunks = []
    if orch > 0:
        for _ in range(orch):
            compact_start = i
            i += 32 + 32 + 32 + 52
            shielded_chunks.append(buf[compact_start:i])

        memo_remaining = orch * 512
        while memo_remaining > 0:
            memo_chunk = min(128, memo_remaining)
            shielded_chunks.append(buf[i : i + memo_chunk])
            i += memo_chunk
            memo_remaining -= memo_chunk

        for _ in range(orch):
            non_compact_start = i
            i += 32 + 32 + 16 + 80
            shielded_chunks.append(buf[non_compact_start:i])

        digest_start = i
        i += 1 + 8 + 32
        shielded_chunks.append(buf[digest_start:i])

    # Real Orchard transactions include authorization data after the digest section.
    # It is excluded from ZIP-244 hashing, so only the digest-relevant prefix is chunked.
    if i != len(buf) and orch == 0:
        assert i == len(buf), "Transaction splitting did not consume all bytes!"

    return {
        "header": header,
        "inputs": inputs,
        "outputs": outputs,
        "shielded_prefix": shielded_prefix,
        "shielded_chunks": shielded_chunks,
        "locktime": locktime,
        "expiry": expiry,
    }


def _extract_raw_tx_v5_outputs(buf: bytes) -> list[dict[str, bytes]]:
    i = 4 * 5

    vin_n, i = read_compactsize(buf, i)
    for _ in range(vin_n):
        i += 32 + 4
        script_len, i = read_compactsize(buf, i)
        i += script_len + 4

    vout_n, i = read_compactsize(buf, i)
    outputs = []
    for _ in range(vout_n):
        value = buf[i : i + 8]
        i += 8
        script_len, i = read_compactsize(buf, i)
        script = buf[i : i + script_len]
        i += script_len
        outputs.append({"value": value, "script": script})

    return outputs


def convert_raw_tx_v5_orchard_to_app_format(buf: bytes, prevout_txs: bytes | list[bytes]) -> bytes:
    """Convert a raw NU5 Orchard transaction into the app parser's digest-oriented layout."""
    # pylint: disable=too-many-locals,R0915
    prevout_tx_list = [prevout_txs] if isinstance(prevout_txs, bytes) else prevout_txs
    i = 0
    header_size = 4 * 5
    tx = bytearray(buf[:header_size])
    i += header_size

    vin_n, i = read_compactsize(buf, i)
    if len(prevout_tx_list) not in (1, vin_n):
        raise ValueError("Expected either one prevout tx or one prevout tx per input")

    tx.extend(write_varint(vin_n))
    for input_idx in range(vin_n):
        prev_txid = buf[i : i + 32]
        i += 32 + 4
        prev_vout = int.from_bytes(buf[i - 4 : i], byteorder="little")
        script_len, i = read_compactsize(buf, i)
        script_end = i + script_len
        sequence = buf[script_end : script_end + 4]
        i = script_end + 4

        prevout_tx = prevout_tx_list[min(input_idx, len(prevout_tx_list) - 1)]
        prevout_outputs = _extract_raw_tx_v5_outputs(prevout_tx)
        if prev_vout >= len(prevout_outputs):
            raise ValueError(f"Prevout index out of range: {prev_vout}")

        script_pubkey = prevout_outputs[prev_vout]["script"]
        tx.extend(prev_txid)
        tx.extend(prev_vout.to_bytes(4, byteorder="little"))
        tx.extend(write_varint(len(script_pubkey)))
        tx.extend(script_pubkey)
        tx.extend(sequence)

    vout_n, i = read_compactsize(buf, i)
    tx.extend(write_varint(vout_n))
    for _ in range(vout_n):
        output_start = i
        i += 8
        script_len, i = read_compactsize(buf, i)
        i += script_len
        tx.extend(buf[output_start:i])

    sapling_spends, i = read_compactsize(buf, i)
    sapling_outputs, i = read_compactsize(buf, i)
    orchard_actions, i = read_compactsize(buf, i)

    assert sapling_spends == 0, "Raw Sapling spends are not supported in this converter!"
    assert sapling_outputs == 0, "Raw Sapling outputs are not supported in this converter!"

    tx.extend(write_varint(sapling_spends))
    tx.extend(write_varint(sapling_outputs))
    tx.extend(write_varint(orchard_actions))

    compact_chunks = []
    memo_chunks = []
    noncompact_chunks = []
    for _ in range(orchard_actions):
        cv = buf[i : i + 32]
        i += 32
        nullifier = buf[i : i + 32]
        i += 32
        rk = buf[i : i + 32]
        i += 32
        cmx = buf[i : i + 32]
        i += 32
        ephemeral_key = buf[i : i + 32]
        i += 32
        enc_ciphertext = buf[i : i + 580]
        i += 580
        out_ciphertext = buf[i : i + 80]
        i += 80

        assert len(enc_ciphertext) == 580, "Invalid Orchard encCiphertext size!"
        assert len(out_ciphertext) == 80, "Invalid Orchard outCiphertext size!"

        compact_chunks.append(nullifier + cmx + ephemeral_key + enc_ciphertext[:52])
        memo_chunks.append(enc_ciphertext[52:564])
        noncompact_chunks.append(cv + rk + enc_ciphertext[564:] + out_ciphertext)

    flags = buf[i : i + 1]
    value_balance = buf[i + 1 : i + 1 + 8]
    anchor = buf[i + 1 + 8 : i + 1 + 8 + 32]

    assert len(flags) == 1, "Missing Orchard flags!"
    assert len(value_balance) == 8, "Missing Orchard value balance!"
    assert len(anchor) == 32, "Missing Orchard anchor!"

    tx.extend(b"".join(compact_chunks))
    tx.extend(b"".join(memo_chunks))
    tx.extend(b"".join(noncompact_chunks))
    tx.extend(flags + value_balance + anchor)

    return bytes(tx)
