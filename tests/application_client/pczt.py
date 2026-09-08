from dataclasses import dataclass

from application_client.zcash_utils import read_compactsize, write_varint

PCZT_DEFAULT_SEED_FINGERPRINT: bytes = bytes(32)

ORCHARD_FIELD_SIZE: int = 32
ORCHARD_RAW_ADDRESS_SIZE: int = 43
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


@dataclass
class PcztOrchardAction:  # pylint: disable=too-many-instance-attributes
    cv_net: bytes
    nullifier: bytes
    spend_recipient: bytes
    spend_rho: bytes
    spend_rseed: bytes
    rk: bytes
    alpha: bytes
    signing_path: str
    cmx: bytes
    ephemeral_key: bytes
    enc_ciphertext: bytes
    out_ciphertext: bytes
    rcv: bytes
    rseed: bytes = bytes(ORCHARD_FIELD_SIZE)
    spend_value: int = 0
    value: int = 0
    recipient: bytes = bytes(ORCHARD_RAW_ADDRESS_SIZE)


@dataclass
class PcztOrchardBundle:
    actions: list[PcztOrchardAction]
    flags: int
    value_balance: int
    anchor: bytes


@dataclass
class PcztIronwoodAction:  # pylint: disable=too-many-instance-attributes
    cv_net: bytes
    nullifier: bytes
    spend_recipient: bytes
    spend_rho: bytes
    spend_rseed: bytes
    rk: bytes
    alpha: bytes
    signing_path: str
    cmx: bytes
    ephemeral_key: bytes
    enc_ciphertext: bytes
    out_ciphertext: bytes
    rcv: bytes
    rseed: bytes = bytes(ORCHARD_FIELD_SIZE)
    spend_value: int = 0
    value: int = 0
    recipient: bytes = bytes(ORCHARD_RAW_ADDRESS_SIZE)
    note_plaintext_version: int | None = None


@dataclass
class PcztIronwoodBundle:
    actions: list[PcztIronwoodAction]
    flags: int
    value_balance: int
    anchor: bytes


def pczt_transaction_bytes(
    pczt_global: PcztGlobal,
    transparent_inputs: list[PcztTransparentInput],
    transparent_outputs: list[PcztTransparentOutput],
    orchard_bundle: PcztOrchardBundle | None = None,
) -> bytes:
    """Serialize the PCZT parts into the canonical v5 transaction the device signs over.

    Both the standalone suite and the swap suite need these bytes to verify a returned
    signature, so the serializer lives next to the dataclasses it walks.
    """
    tx = bytearray(pczt_global.tx_header_bytes())
    tx.extend(write_varint(len(transparent_inputs)))

    for txin in transparent_inputs:
        tx.extend(txin.prevout_txid)
        tx.extend(txin.prevout_index.to_bytes(4, byteorder="little"))
        tx.extend(write_varint(len(txin.script_pubkey)))
        tx.extend(txin.script_pubkey)
        tx.extend(txin.sequence)

    tx.extend(write_varint(len(transparent_outputs)))
    for txout in transparent_outputs:
        tx.extend(txout.value.to_bytes(8, byteorder="little"))
        tx.extend(write_varint(len(txout.script_pubkey)))
        tx.extend(txout.script_pubkey)

    tx.extend(write_varint(0))
    tx.extend(write_varint(0))

    if orchard_bundle is None:
        tx.extend(write_varint(0))
        return bytes(tx)

    tx.extend(write_varint(len(orchard_bundle.actions)))

    for action in orchard_bundle.actions:
        tx.extend(action.nullifier)
        tx.extend(action.cmx)
        tx.extend(action.ephemeral_key)
        tx.extend(action.enc_ciphertext[:52])

    for action in orchard_bundle.actions:
        tx.extend(action.enc_ciphertext[52:564])

    for action in orchard_bundle.actions:
        tx.extend(action.cv_net)
        tx.extend(action.rk)
        tx.extend(action.enc_ciphertext[564:])
        tx.extend(action.out_ciphertext)

    tx.extend(orchard_bundle.flags.to_bytes(1, byteorder="little"))
    tx.extend(orchard_bundle.value_balance.to_bytes(8, byteorder="little", signed=True))
    tx.extend(orchard_bundle.anchor)

    return bytes(tx)


def pczt_orchard_bundle_from_raw_tx(
    raw_transaction: bytes,
    signing_path: str,
    alpha: bytes,
    rcv_values: list[bytes] | None = None,
    rseed_values: list[bytes] | None = None,
    spend_note_fields: list[tuple[bytes, bytes, bytes]] | None = None,
) -> PcztOrchardBundle:
    # pylint: disable=too-many-positional-arguments,too-many-locals,too-many-branches
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

    rcv_values = [] if rcv_values is None else rcv_values
    if len(rcv_values) != orchard_action_count:
        raise ValueError("Raw Orchard actions require one rcv per action")
    for rcv in rcv_values:
        if len(rcv) != ORCHARD_FIELD_SIZE:
            raise ValueError("Orchard rcv must be 32 bytes")

    rseed_values = [] if rseed_values is None else rseed_values
    if len(rseed_values) != orchard_action_count:
        raise ValueError("Raw Orchard actions require one output rseed per action")
    for rseed in rseed_values:
        if len(rseed) != ORCHARD_FIELD_SIZE:
            raise ValueError("Orchard output rseed must be 32 bytes")

    spend_note_fields = [] if spend_note_fields is None else spend_note_fields
    if len(spend_note_fields) != orchard_action_count:
        raise ValueError("Raw Orchard actions require one spend note field set per action")
    for spend_recipient, spend_rho, spend_rseed in spend_note_fields:
        if len(spend_recipient) != ORCHARD_RAW_ADDRESS_SIZE:
            raise ValueError("Orchard spend recipient must be 43 bytes")
        if len(spend_rho) != ORCHARD_FIELD_SIZE:
            raise ValueError("Orchard spend rho must be 32 bytes")
        if len(spend_rseed) != ORCHARD_FIELD_SIZE:
            raise ValueError("Orchard spend rseed must be 32 bytes")

    actions = []
    for rcv, rseed, (spend_recipient, spend_rho, spend_rseed) in zip(rcv_values, rseed_values, spend_note_fields, strict=True):
        action, index = _read_orchard_action(
            raw_transaction,
            index,
            signing_path,
            alpha,
            rcv,
            rseed,
            spend_recipient,
            spend_rho,
            spend_rseed,
        )
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
    rcv: bytes,
    rseed: bytes,
    spend_recipient: bytes,
    spend_rho: bytes,
    spend_rseed: bytes,
) -> tuple[PcztOrchardAction, int]:
    # pylint: disable=too-many-positional-arguments
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
            spend_recipient=spend_recipient,
            spend_rho=spend_rho,
            spend_rseed=spend_rseed,
            rk=fields[2],
            alpha=alpha,
            signing_path=signing_path,
            cmx=fields[3],
            ephemeral_key=fields[4],
            enc_ciphertext=enc_ciphertext,
            out_ciphertext=out_ciphertext,
            rcv=rcv,
            rseed=rseed,
        ),
        index,
    )


def _read_bytes(raw_transaction: bytes, index: int, size: int) -> tuple[bytes, int]:
    end = index + size
    value = raw_transaction[index:end]
    if len(value) != size:
        raise ValueError("Invalid raw Orchard action ciphertext sizes")

    return value, end
