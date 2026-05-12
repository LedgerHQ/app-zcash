import json
from dataclasses import dataclass
from struct import pack
from .zcash_utils import UINT64_MAX, read_compactsize

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
        return json.dumps({
            "nonce": self.nonce,
            "coin": self.coin,
            "value": self.value,
            "to": self.to,
            "memo": self.memo
        }).encode('utf-8')

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
def split_tx_to_chunks(buf: bytes, is_v4_nu6: bool = False) -> list[bytes]:
    # pylint: disable=R0914 disable=R0915 disable=R0912

    i = 0
    locktime = bytes()
    expiry = bytes()
    chunks = []

    header_v5_size = 4 * 5
    header_v4_size = 4 * 3

    if is_v4_nu6:
        i += header_v4_size
    else:
        locktime = buf[header_v4_size:header_v4_size+4]
        expiry   = buf[header_v4_size+4:header_v4_size+4*2]
        i += header_v5_size

    vin_n, i = read_compactsize(buf, i)
    header_bytes = bytes(buf[0:header_v4_size]) + bytes(buf[i - 1:i])
    chunks.append(header_bytes)

    for _ in range(vin_n):
        prevout_start = i
        i += 32 + 4
        slen, i   = read_compactsize(buf, i)
        chunks.append(buf[prevout_start:i])

        script_start = i
        i = i + slen + 4

        chunks.append(buf[script_start:i])

    vout_n, i = read_compactsize(buf, i)
    chunks.append(buf[i-1:i])

    for _ in range(vout_n):
        value_start = i
        i += 8
        plen, i  = read_compactsize(buf, i)
        chunks.append(buf[value_start:i])

        script_pk_start = i
        i = i + plen
        chunks.append(buf[script_pk_start:i])

    # Sapling and Orchard fields
    sapling_start = i
    sap_sp, i = read_compactsize(buf, i)
    sap_out,i = read_compactsize(buf, i)
    orch, i   = read_compactsize(buf, i)
    chunks.append(buf[sapling_start:i])

    # Sapling data (if any)
    if sap_sp > 0 or sap_out > 0:
        # valueBalance
        balance_start = i
        i += 8

        if sap_sp > 0:
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
            chunks.append(buf[i:i + memo_chunk])
            i += memo_chunk
            memo_remaining -= memo_chunk

        # Sapling outputs: non-compact part
        for _ in range(sap_out):
            non_compact_start = i
            i += 32 + 16 + 80
            chunks.append(buf[non_compact_start:i])

    # Orchard data (if any)
    if orch > 0:
        # Orchard actions: compact part
        for _ in range(orch):
            compact_start = i
            i += 32 + 32 + 32 + 52  # nullifier + cmx + ephemeral_key + enc_ciphertext[..52]
            chunks.append(buf[compact_start:i])

        # Orchard memos (512 bytes per action), split into 128-byte chunks
        memo_remaining = orch * 512
        while memo_remaining > 0:
            memo_chunk = min(128, memo_remaining)
            chunks.append(buf[i:i + memo_chunk])
            i += memo_chunk
            memo_remaining -= memo_chunk

        # Orchard actions: non-compact part
        for _ in range(orch):
            non_compact_start = i
            i += 32 + 32 + 16 + 80  # nullifier + cmx + out_ciphertext + zkproof
            chunks.append(buf[non_compact_start:i])

        # Orchard digest data (flags + valueBalance + anchor)
        digest_start = i
        i += 1 + 8 + 32
        chunks.append(buf[digest_start:i])

    # Extra data
    if is_v4_nu6:
        chunks.append(buf[i:])
        i += len(buf[i:])
    else:
        chunks.append(locktime + pack("b", 0x04) + expiry)

    print(f"Not consumed bytes: {buf[i:].hex()}")
    assert i == len(buf), "Transaction splitting did not consume all bytes!"

    return chunks

def split_tx_v5_for_hash_input(buf: bytes) -> dict[str, object]:
    # pylint: disable=R0914,R0915

    i = 0

    header_size = 4 * 5
    header_quirk_size = 4 * 3

    locktime = buf[header_quirk_size:header_quirk_size + 4]
    expiry = buf[header_quirk_size + 4:header_quirk_size + 8]

    i += header_size

    vin_n, i = read_compactsize(buf, i)
    header = bytes(buf[0:header_quirk_size])

    inputs = []
    for _ in range(vin_n):
        prevout_start = i
        i += 32 + 4
        prevout = buf[prevout_start:i]

        script_len, i = read_compactsize(buf, i)
        script = buf[i:i + script_len]
        i += script_len

        sequence = buf[i:i + 4]
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
        value = buf[i:i + 8]
        i += 8

        script_len, i = read_compactsize(buf, i)
        script = buf[i:i + script_len]
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
            shielded_chunks.append(buf[i:i + memo_chunk])
            i += memo_chunk
            memo_remaining -= memo_chunk

        for _ in range(orch):
            non_compact_start = i
            i += 32 + 32 + 16 + 80
            shielded_chunks.append(buf[non_compact_start:i])

        digest_start = i
        i += 1 + 8 + 32
        shielded_chunks.append(buf[digest_start:i])

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
