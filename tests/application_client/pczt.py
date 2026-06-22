from dataclasses import dataclass
from typing import NamedTuple

from application_client.zcash_utils import read_compactsize

PCZT_DEFAULT_SEED_FINGERPRINT: bytes = bytes(32)

ORCHARD_FIELD_SIZE: int = 32
ORCHARD_ENC_CIPHERTEXT_SIZE: int = 580
ORCHARD_OUT_CIPHERTEXT_SIZE: int = 80


@dataclass
class PcztGlobal:
    tx_version: int = 5
    version_group_id: int = 0x26A7270A
    consensus_branch_id: int = 0xC2D6D0B4
    fallback_lock_time: int | None = 0
    expiry_height: int = 0
    coin_type: int = 133
    tx_modifiable: int = 0

    def tx_header_bytes(self) -> bytes:
        return (
            (self.tx_version | 0x80000000).to_bytes(4, byteorder="little")
            + self.version_group_id.to_bytes(4, byteorder="little")
            + self.consensus_branch_id.to_bytes(4, byteorder="little")
            + (self.fallback_lock_time or 0).to_bytes(4, byteorder="little")
            + self.expiry_height.to_bytes(4, byteorder="little")
        )


@dataclass
class PcztTransparentInput:
    prevout_txid: bytes
    prevout_index: int
    value: int
    script_pubkey: bytes
    sequence: bytes
    signing_path: str
    sighash_type: int = 0x01


@dataclass
class PcztTransparentOutput:
    value: int
    script_pubkey: bytes
    signing_path: str | None = None
    bip32_derivation_pubkey: bytes | None = None


class PcztOrchardAction(NamedTuple):
    cv_net: bytes
    nullifier: bytes
    rk: bytes
    alpha: bytes
    signing_path: str
    cmx: bytes
    ephemeral_key: bytes
    enc_ciphertext: bytes
    out_ciphertext: bytes


@dataclass
class PcztOrchardBundle:
    actions: list[PcztOrchardAction]
    flags: int
    value_balance: int
    anchor: bytes


def pczt_orchard_bundle_from_raw_tx(
    raw_transaction: bytes,
    signing_path: str,
    alpha: bytes,
) -> PcztOrchardBundle:
    if len(alpha) != ORCHARD_FIELD_SIZE:
        raise ValueError("Orchard alpha must be 32 bytes")

    index = 4 * 5
    index = _skip_transparent_inputs(raw_transaction, index)
    index = _skip_transparent_outputs(raw_transaction, index)

    sapling_spends, index = read_compactsize(raw_transaction, index)
    sapling_outputs, index = read_compactsize(raw_transaction, index)
    orchard_action_count, index = read_compactsize(raw_transaction, index)

    if sapling_spends != 0 or sapling_outputs != 0:
        raise ValueError("Raw Sapling fields are not supported in PCZT test helper")

    actions = []
    for _ in range(orchard_action_count):
        action, index = _read_orchard_action(raw_transaction, index, signing_path, alpha)
        actions.append(action)

    flags = raw_transaction[index]
    value_balance = int.from_bytes(
        raw_transaction[index + 1 : index + 9],
        byteorder="little",
        signed=True,
    )
    anchor = raw_transaction[index + 9 : index + 41]

    if len(anchor) != ORCHARD_FIELD_SIZE:
        raise ValueError("Missing raw Orchard anchor")

    return PcztOrchardBundle(
        actions=actions,
        flags=flags,
        value_balance=value_balance,
        anchor=anchor,
    )


def _skip_transparent_inputs(raw_transaction: bytes, index: int) -> int:
    transparent_input_count, index = read_compactsize(raw_transaction, index)
    for _ in range(transparent_input_count):
        index += 32 + 4
        script_len, index = read_compactsize(raw_transaction, index)
        index += script_len + 4

    return index


def _skip_transparent_outputs(raw_transaction: bytes, index: int) -> int:
    transparent_output_count, index = read_compactsize(raw_transaction, index)
    for _ in range(transparent_output_count):
        index += 8
        script_len, index = read_compactsize(raw_transaction, index)
        index += script_len

    return index


def _read_orchard_action(
    raw_transaction: bytes,
    index: int,
    signing_path: str,
    alpha: bytes,
) -> tuple[PcztOrchardAction, int]:
    fields = []
    for _ in range(5):
        field, index = _read_bytes(raw_transaction, index, ORCHARD_FIELD_SIZE)
        fields.append(field)

    enc_ciphertext, index = _read_bytes(
        raw_transaction,
        index,
        ORCHARD_ENC_CIPHERTEXT_SIZE,
    )
    out_ciphertext, index = _read_bytes(
        raw_transaction,
        index,
        ORCHARD_OUT_CIPHERTEXT_SIZE,
    )

    return (
        PcztOrchardAction(
            cv_net=fields[0],
            nullifier=fields[1],
            rk=fields[2],
            alpha=alpha,
            signing_path=signing_path,
            cmx=fields[3],
            ephemeral_key=fields[4],
            enc_ciphertext=enc_ciphertext,
            out_ciphertext=out_ciphertext,
        ),
        index,
    )


def _read_bytes(raw_transaction: bytes, index: int, size: int) -> tuple[bytes, int]:
    end = index + size
    value = raw_transaction[index:end]
    if len(value) != size:
        raise ValueError("Invalid raw Orchard action ciphertext sizes")

    return value, end
