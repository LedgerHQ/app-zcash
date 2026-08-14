# pylint: disable=too-many-lines

import struct
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from struct import pack

from ragger.backend.interface import RAPDU, BackendInterface
from ragger.bip import (
    CurveChoice,
    calculate_public_key_and_chaincode,
    pack_derivation_path,
)

from application_client.pczt import (
    PCZT_DEFAULT_SEED_FINGERPRINT,
    PcztGlobal,
    PcztIronwoodBundle,
    PcztOrchardBundle,
    PcztTransparentInput,
    PcztTransparentOutput,
    pczt_orchard_bundle_from_raw_tx,
)
from application_client.zcash_transaction import (
    split_tx_to_chunks,
    split_tx_v5_for_hash_input,
)
from application_client.zcash_utils import write_varint

MAGIC_TRUSTED_INPUT: int = 0x32

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_FIRST = 0x00
    # Parameter 1 for next APDU numbers.
    P1_NEXT = 0x80
    # Parameter 1 for last APDU number.
    P1_LAST = 0x01

    # Parameter 1 for no screen confirmation for GET_PUBLIC_KEY.
    P1_GET_PUBLIC_KEY_NO_DISPLAY = 0x00
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_GET_PUBLIC_KEY_DISPLAY = 0x01
    P1_GET_VK_FIRST = 0x00
    P1_GET_VK_CONTINUE = 0x80

    # Parameter 1 for first APDU number for HASH_INPUT_START.
    P1_HASH_INPUT_START_FIRST = 0x00
    # Parameter 1 for next APDU numbers for HASH_INPUT_START.
    P1_HASH_INPUT_START_NEXT = 0x80

    # Parameter 1 for more APDU to receive for HASH_INPUT_FINALIZE_FULL.
    P1_FINALIZE_FULL_MORE = 0x00
    # Parameter 1 for last APDU to receive for HASH_INPUT_FINALIZE_FULL.
    P1_FINALIZE_FULL_LAST = 0x80
    # Parameter 1 for change information for HASH_INPUT_FINALIZE_FULL.
    P1_FINALIZE_FULL_CHANGEINFO = 0xFF


class P2(IntEnum):
    # Parameter 2 default value
    P2_NONE = 0x00

    # Parameter 2 for HASH_INPUT_START to continue hashing after sending trusted inputs.
    P2_HASH_INPUT_START_NEW = 0x00
    # Parameter 2 for HASH_INPUT_START to indicate that the transaction is a Sapling transaction.
    P2_HASH_INPUT_START_SAPLING = 0x05
    # Parameter 2 for HASH_INPUT_START to indicate that to continue hashing after sending trusted inputs.
    P2_HASH_INPUT_START_CONTINUE = 0x80

    # Parameter 2 for HASH_INPUT_FINALIZE_FULL
    P2_FINALIZE_FULL_DEFAULT = 0x00

    # Parameter 2 for the last PCZT data APDU.
    P2_PCZT_FINISHED = 0x01


class InsType(IntEnum):
    GET_VERSION = 0xC4
    GET_APP_NAME = 0x04
    GET_WALLET_PUBLIC_KEY = 0x40
    GET_TRUSTED_INPUT = 0x42
    HASH_INPUT_START = 0x44
    HASH_INPUT_FINALIZE_FULL = 0x4A
    HASH_SIGN = 0x48
    GET_VK = 0x50
    GET_SHIELDED_ADDRESS = 0x51
    PCZT_HEADER = 0x52
    PCZT_TRANSPARENT_INPUT = 0x53
    PCZT_TRANSPARENT_OUTPUT = 0x54
    PCZT_SIGN_TRANSPARENT = 0x55
    PCZT_ORCHARD_ACTION = 0x56
    PCZT_SIGN_ORCHARD = 0x57
    PCZT_IRONWOOD_ACTION = 0x58
    PCZT_SIGN_IRONWOOD = 0x59


class GetVkMode(IntEnum):
    UFVK = 0x00
    ORCHARD_FVK = 0x01


class GetShieldedAddressMode(IntEnum):
    UADDRESS = 0x00
    ORCHARD_RAW_ADDRESS = 0x01


class Errors(IntEnum):
    SW_DENY = 0x6985
    SW_WRONG_P1P2 = 0x6B00
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_WRONG_APDU_LENGTH = 0x6E03
    SW_APP_WRONG_APDU_LENGTH = 0x6700
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_DISPLAY_AMOUNT_FAIL = 0xB003
    SW_WRONG_TX_LENGTH = 0xB004
    SW_TX_PARSING_FAIL = 0xB005
    SW_TX_HASH_FAIL = 0xB006
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008
    SW_INVALID_TRANSACTION = 0x6A80


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


@dataclass
class ForgeTxParams:
    recipient_publickey: str
    send_amount: int
    prevout_txid: bytes
    vout_idx: int
    locktime: int
    expiry: int


@dataclass
class ApduResponse:
    status: int
    data: bytes


class ZcashCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend
        self.tx_chunks: dict = {}
        self.trusted_inputs: list[bytes] = []
        self.pczt_transparent_inputs: list[PcztTransparentInput] = []
        self.pczt_transparent_outputs: list[PcztTransparentOutput] = []
        self.last_response: ApduResponse | RAPDU | None = None

    def exchange_raw(self, data: str) -> tuple[int, bytes]:
        data_bytes = bytes.fromhex(data)
        res = self.backend.exchange_raw(data_bytes)
        return res.status, res.data

    @contextmanager
    def exchange_async_raw(self, data: str) -> Generator[None, None, None]:
        data_bytes = bytes.fromhex(data)
        with self.backend.exchange_async_raw(data_bytes):
            yield

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=0xB0,  # specific CLA for BOLOS
            ins=0x01,  # specific INS for get_app_and_version
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=b"",
        )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_FIRST, p2=P2.P2_NONE, data=b"")

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_FIRST, p2=P2.P2_NONE, data=b"")

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_WALLET_PUBLIC_KEY,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path),
        )

    @staticmethod
    def _pack_derivation_paths(path: str, transparent_path: str | None = None) -> bytes:
        data = pack_derivation_path(path)
        if transparent_path is not None:
            data += pack_derivation_path(transparent_path)
        return data

    def get_shielded_address(
        self,
        path: str,
        mode: GetShieldedAddressMode = GetShieldedAddressMode.UADDRESS,
        transparent_path: str | None = None,
    ) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_SHIELDED_ADDRESS,
            p1=P1.P1_FIRST,
            p2=mode,
            data=self._pack_derivation_paths(path, transparent_path),
        )

    def _collect_ufvk_response(
        self,
        response: RAPDU,
        mode: GetVkMode,
        continue_response: bool = False,
    ) -> RAPDU:
        if continue_response or mode != GetVkMode.UFVK or len(response.data) < 2:
            return response

        total_response_len = 2 + int.from_bytes(response.data[:2], byteorder="big")
        response_data = bytearray(response.data)

        while len(response_data) < total_response_len:
            continuation = self.backend.exchange(
                cla=CLA,
                ins=InsType.GET_VK,
                p1=P1.P1_GET_VK_CONTINUE,
                p2=mode,
                data=b"",
            )
            response_data.extend(continuation.data)
            response = continuation

        return ApduResponse(status=response.status, data=bytes(response_data))

    @contextmanager
    def get_vk_with_confirmation(
        self,
        path: str,
        navigate: Callable[[], None],
        mode: GetVkMode = GetVkMode.UFVK,
        transparent_path: str | None = None,
    ) -> Generator[ApduResponse | RAPDU | None, None, None]:
        self.last_response = None

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=mode,
            data=self._pack_derivation_paths(path, transparent_path),
        ):
            navigate()

        response = self.backend.last_async_response
        if response is not None:
            self.last_response = self._collect_ufvk_response(response, mode)

        yield self.last_response

    @contextmanager
    def get_public_key_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_WALLET_PUBLIC_KEY,
            p1=P1.P1_GET_PUBLIC_KEY_DISPLAY,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path),
        ) as response:
            yield response

    @contextmanager
    def get_shielded_address_with_confirmation(
        self,
        path: str,
        mode: GetShieldedAddressMode = GetShieldedAddressMode.UADDRESS,
        transparent_path: str | None = None,
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_SHIELDED_ADDRESS,
            p1=P1.P1_GET_PUBLIC_KEY_DISPLAY,
            p2=mode,
            data=self._pack_derivation_paths(path, transparent_path),
        ) as response:
            yield response

    def get_trusted_input(self, transaction: bytes, trusted_input_idx: int, is_v4_nu6: bool = False) -> RAPDU:
        chunks = split_tx_to_chunks(transaction, is_v4_nu6)
        # convert trusted-input index to 4 bytes big endian
        trusted_idx = pack(">I", trusted_input_idx)
        # prepend the trusted input index to the first chunk
        chunks[0] = bytes(trusted_idx + chunks[0])

        p1 = P1.P1_FIRST

        for c in chunks[:-1]:
            self.backend.exchange(cla=CLA, ins=InsType.GET_TRUSTED_INPUT, p1=p1, p2=P2.P2_NONE, data=c)
            p1 = P1.P1_NEXT

        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_TRUSTED_INPUT,
            p1=P1.P1_NEXT,
            p2=P2.P2_NONE,
            data=chunks[-1],
        )

    def _send_trusted_inputs_and_header(self, continue_hashing: bool):
        header = self.tx_chunks["header"]
        inputs = self.tx_chunks["inputs"]
        inputs_num = len(inputs)

        # Send header chunk
        self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_INPUT_START,
            p1=P1.P1_FIRST,
            p2=(P2.P2_HASH_INPUT_START_CONTINUE if continue_hashing else P2.P2_HASH_INPUT_START_SAPLING),
            data=header + inputs_num.to_bytes(1, byteorder="big"),
        )

        # Send trusted inputs chunks
        for idx, inp in enumerate(inputs):
            flag = 0x01
            trusted_input_data = self.trusted_inputs[idx]
            trusted_input_len = len(trusted_input_data)
            script = inp["script"]
            script_len = len(script)
            sequence = inp["sequence"]

            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_START,
                p1=P1.P1_HASH_INPUT_START_NEXT,
                p2=P2.P2_HASH_INPUT_START_SAPLING,
                data=flag.to_bytes(1, byteorder="big")
                + trusted_input_len.to_bytes(1, byteorder="big")
                + trusted_input_data
                + script_len.to_bytes(1, byteorder="big"),
            )

            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_START,
                p1=P1.P1_HASH_INPUT_START_NEXT,
                p2=P2.P2_HASH_INPUT_START_SAPLING,
                data=script + sequence,
            )

    @contextmanager
    def _hash_input_finalize_outputs(
        self,
        change_path: str | None = None,
    ) -> Generator[None, None, None]:
        # Send outputs chunks
        outputs: list[dict] = self.tx_chunks["outputs"]  # type: ignore
        outputs_num = len(outputs)
        outputs_num_bytes = outputs_num.to_bytes(1, byteorder="big")

        if change_path:
            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_FINALIZE_FULL_CHANGEINFO,
                p2=P2.P2_FINALIZE_FULL_DEFAULT,
                data=pack_derivation_path(change_path),
            )

        for out in outputs[:-1]:
            value = out["value"]
            script = out["script"]
            script_len = len(script)

            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_FINALIZE_FULL_MORE,
                p2=P2.P2_FINALIZE_FULL_DEFAULT,
                data=outputs_num_bytes + value + script_len.to_bytes(1, byteorder="big") + script,
            )

            outputs_num_bytes = b""

        value = outputs[-1]["value"]
        script = outputs[-1]["script"]
        script_len = len(script)

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.HASH_INPUT_FINALIZE_FULL,
            p1=P1.P1_FINALIZE_FULL_MORE,
            p2=P2.P2_FINALIZE_FULL_DEFAULT,
            data=outputs_num_bytes + value + script_len.to_bytes(1, byteorder="big") + script,
        ) as response:
            yield response

    @contextmanager
    def hash_input(
        self,
        transaction: bytes,
        trusted_inputs: list[bytes],
        change_path: str | None = None,
    ) -> Generator[None, None, None]:
        self.tx_chunks = split_tx_v5_for_hash_input(transaction)
        self.trusted_inputs = trusted_inputs
        self.pczt_transparent_inputs = []
        self.pczt_transparent_outputs = []

        self._send_trusted_inputs_and_header(continue_hashing=False)

        with self._hash_input_finalize_outputs(change_path) as response:
            yield response

    def _pczt_optional_u32(self, value: int | None) -> bytes:
        if value is None:
            return b"\x00"
        return b"\x01" + value.to_bytes(4, byteorder="little")

    def _compressed_pubkey_from_path(self, path: str) -> bytes:
        public_key, _ = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
        pubkey = bytes.fromhex(public_key)

        if len(pubkey) != 65:
            raise ValueError("Unexpected public key length")

        prefix = b"\x02" if pubkey[64] % 2 == 0 else b"\x03"
        return prefix + pubkey[1:33]

    def _build_pczt_header_and_global_payload(
        self,
        pczt_global: PcztGlobal,
        pczt_version: int | None = None,
    ) -> bytes:
        if pczt_version is None:
            pczt_version = 2 if pczt_global.tx_version == 6 else 1
        payload = bytearray(b"PCZT")
        payload.extend(pczt_version.to_bytes(4, byteorder="little"))
        payload.extend(pczt_global.tx_version.to_bytes(4, byteorder="little"))
        payload.extend(pczt_global.version_group_id.to_bytes(4, byteorder="little"))
        payload.extend(pczt_global.consensus_branch_id.to_bytes(4, byteorder="little"))
        payload.extend(self._pczt_optional_u32(pczt_global.fallback_lock_time))
        payload.extend(pczt_global.expiry_height.to_bytes(4, byteorder="little"))
        payload.extend(pczt_global.coin_type.to_bytes(4, byteorder="little"))
        payload.extend(pczt_global.tx_modifiable.to_bytes(1, byteorder="little"))

        return bytes(payload)

    def _checked_pczt_packet(self, payload: bytes, label: str) -> bytes:
        if len(payload) > MAX_APDU_LEN:
            raise ValueError(f"{label} PCZT APDU packet exceeds {MAX_APDU_LEN} bytes")
        return payload

    def _split_pczt_field_packet(self, payload: bytes) -> list[bytes]:
        return split_message(payload, MAX_APDU_LEN)

    def _build_pczt_bip32_derivation_packet(
        self,
        signing_path: str | None,
        pubkey: bytes | None = None,
    ) -> bytes:
        payload = bytearray()
        if signing_path is None:
            if pubkey is not None:
                raise ValueError("bip32_derivation pubkey requires a signing path")
            payload.extend(write_varint(0))
        else:
            payload.extend(write_varint(1))
            if pubkey is None:
                pubkey = self._compressed_pubkey_from_path(signing_path)
            if len(pubkey) != 33:
                raise ValueError("Unexpected compressed public key length")
            payload.extend(pubkey)
            payload.extend(PCZT_DEFAULT_SEED_FINGERPRINT)
            payload.extend(pack_derivation_path(signing_path))

        return self._checked_pczt_packet(bytes(payload), "bip32_derivation")

    def _build_pczt_zip32_derivation_packet(self, signing_path: str) -> bytes:
        payload = bytearray(PCZT_DEFAULT_SEED_FINGERPRINT)
        payload.extend(pack_derivation_path(signing_path))

        return self._checked_pczt_packet(bytes(payload), "zip32_derivation")

    def _build_pczt_transparent_input_packets(
        self,
        transparent_inputs: list[PcztTransparentInput],
    ) -> list[bytes]:
        packets = [
            self._checked_pczt_packet(
                write_varint(len(transparent_inputs)),
                "transparent inputs header",
            )
        ]

        for inp in transparent_inputs:
            packet = bytearray()
            packet.extend(inp.prevout_txid)
            packet.extend(inp.prevout_index.to_bytes(4, byteorder="little"))
            sequence = int.from_bytes(inp.sequence, byteorder="little")
            packet.extend(self._pczt_optional_u32(sequence))
            packet.extend(inp.value.to_bytes(8, byteorder="little"))
            packets.append(self._checked_pczt_packet(bytes(packet), "transparent input small fields"))

            packets.extend(self._split_pczt_field_packet(write_varint(len(inp.script_pubkey)) + inp.script_pubkey))

            packets.append(
                self._checked_pczt_packet(
                    inp.sighash_type.to_bytes(1, byteorder="little") + self._build_pczt_bip32_derivation_packet(inp.signing_path),
                    "transparent input sighash and bip32_derivation",
                )
            )

        return packets

    def _build_pczt_transparent_output_packets(
        self,
        transparent_outputs: list[PcztTransparentOutput],
    ) -> list[bytes]:
        packets = [
            self._checked_pczt_packet(
                write_varint(len(transparent_outputs)),
                "transparent outputs header",
            )
        ]

        for out in transparent_outputs:
            packets.append(
                self._checked_pczt_packet(
                    out.value.to_bytes(8, byteorder="little"),
                    "transparent output value",
                )
            )
            packets.extend(self._split_pczt_field_packet(write_varint(len(out.script_pubkey)) + out.script_pubkey))
            packets.append(
                self._build_pczt_bip32_derivation_packet(
                    out.signing_path,
                    out.bip32_derivation_pubkey,
                )
            )

        return packets

    def _build_pczt_orchard_action_packets(
        self,
        orchard_bundle: PcztOrchardBundle,
        include_rcv: bool = True,
    ) -> list[bytes]:
        # pylint: disable=too-many-branches
        packets = [
            self._checked_pczt_packet(
                write_varint(len(orchard_bundle.actions)),
                "orchard actions header",
            )
        ]

        if not orchard_bundle.actions:
            return packets

        for action in orchard_bundle.actions:
            if len(action.alpha) != 32:
                raise ValueError("Orchard alpha must be 32 bytes")
            if len(action.spend_recipient) != 43:
                raise ValueError("Orchard spend recipient must be 43 bytes")
            if len(action.spend_rho) != 32:
                raise ValueError("Orchard spend rho must be 32 bytes")
            if len(action.spend_rseed) != 32:
                raise ValueError("Orchard spend rseed must be 32 bytes")
            if len(action.recipient) != 43:
                raise ValueError("Orchard recipient must be 43 bytes")
            if include_rcv and action.rcv is None:
                raise ValueError("Orchard rcv is required")
            if action.rcv is not None and len(action.rcv) != 32:
                raise ValueError("Orchard rcv must be 32 bytes")
            if len(action.rseed) != 32:
                raise ValueError("Orchard output rseed must be 32 bytes")
            if not 0 <= action.spend_value <= 0x7FFF_FFFF_FFFF_FFFF:
                raise ValueError("Orchard spend value out of range")
            if not 0 <= action.value <= 0x7FFF_FFFF_FFFF_FFFF:
                raise ValueError("Orchard output value out of range")

            packets.append(
                self._checked_pczt_packet(
                    action.cv_net
                    + action.nullifier
                    + action.rk
                    + action.spend_recipient
                    + action.spend_value.to_bytes(8, byteorder="little")
                    + action.spend_rho
                    + action.spend_rseed
                    + action.alpha,
                    "orchard action spend small fields",
                )
            )
            packets.append(self._build_pczt_zip32_derivation_packet(action.signing_path))
            packets.append(
                self._checked_pczt_packet(
                    action.cmx + action.ephemeral_key,
                    "orchard action output small fields",
                )
            )
            packets.extend(self._split_pczt_field_packet(write_varint(len(action.enc_ciphertext)) + action.enc_ciphertext))
            packets.extend(self._split_pczt_field_packet(write_varint(len(action.out_ciphertext)) + action.out_ciphertext))
            output_metadata = action.recipient + action.value.to_bytes(8, byteorder="little") + action.rseed
            if include_rcv:
                output_metadata += action.rcv
            packets.append(
                self._checked_pczt_packet(
                    output_metadata,
                    "orchard action output metadata",
                )
            )

        trailer = bytearray()
        value_balance = orchard_bundle.value_balance
        trailer.extend(orchard_bundle.flags.to_bytes(1, byteorder="little"))
        trailer.extend(abs(value_balance).to_bytes(8, byteorder="little"))
        trailer.extend((1 if value_balance < 0 else 0).to_bytes(1, byteorder="little"))
        trailer.extend(orchard_bundle.anchor)
        packets.append(self._checked_pczt_packet(bytes(trailer), "orchard bundle trailer"))

        return packets

    def _build_pczt_ironwood_action_packets(
        self,
        ironwood_bundle: PcztIronwoodBundle,
        include_rcv: bool = True,
    ) -> list[bytes]:
        # pylint: disable=too-many-branches
        packets = [
            self._checked_pczt_packet(
                write_varint(len(ironwood_bundle.actions)),
                "ironwood actions header",
            )
        ]

        if not ironwood_bundle.actions:
            return packets

        for action in ironwood_bundle.actions:
            if len(action.alpha) != 32:
                raise ValueError("Ironwood alpha must be 32 bytes")
            if len(action.spend_recipient) != 43:
                raise ValueError("Ironwood spend recipient must be 43 bytes")
            if len(action.spend_rho) != 32:
                raise ValueError("Ironwood spend rho must be 32 bytes")
            if len(action.spend_rseed) != 32:
                raise ValueError("Ironwood spend rseed must be 32 bytes")
            if len(action.recipient) != 43:
                raise ValueError("Ironwood recipient must be 43 bytes")
            if include_rcv and action.rcv is None:
                raise ValueError("Ironwood rcv is required")
            if action.rcv is not None and len(action.rcv) != 32:
                raise ValueError("Ironwood rcv must be 32 bytes")
            if len(action.rseed) != 32:
                raise ValueError("Ironwood output rseed must be 32 bytes")
            if not 0 <= action.spend_value <= 0x7FFF_FFFF_FFFF_FFFF:
                raise ValueError("Ironwood spend value out of range")
            if not 0 <= action.value <= 0x7FFF_FFFF_FFFF_FFFF:
                raise ValueError("Ironwood output value out of range")

            packets.append(
                self._checked_pczt_packet(
                    action.cv_net
                    + action.nullifier
                    + action.rk
                    + action.spend_recipient
                    + action.spend_value.to_bytes(8, byteorder="little")
                    + action.spend_rho
                    + action.spend_rseed
                    + action.alpha,
                    "ironwood action spend small fields",
                )
            )
            packets.append(self._build_pczt_zip32_derivation_packet(action.signing_path))
            packets.append(
                self._checked_pczt_packet(
                    action.cmx + action.ephemeral_key,
                    "ironwood action output small fields",
                )
            )
            packets.extend(self._split_pczt_field_packet(write_varint(len(action.enc_ciphertext)) + action.enc_ciphertext))
            packets.extend(self._split_pczt_field_packet(write_varint(len(action.out_ciphertext)) + action.out_ciphertext))
            output_metadata = action.recipient + action.value.to_bytes(8, byteorder="little") + action.rseed
            if include_rcv:
                output_metadata += action.rcv
            if action.note_plaintext_version is not None:
                output_metadata += bytes([action.note_plaintext_version])
            packets.append(
                self._checked_pczt_packet(
                    output_metadata,
                    "ironwood action output metadata",
                )
            )

        trailer = bytearray()
        value_balance = ironwood_bundle.value_balance
        trailer.extend(ironwood_bundle.flags.to_bytes(1, byteorder="little"))
        trailer.extend(abs(value_balance).to_bytes(8, byteorder="little"))
        trailer.extend((1 if value_balance < 0 else 0).to_bytes(1, byteorder="little"))
        trailer.extend(ironwood_bundle.anchor)
        packets.append(self._checked_pczt_packet(bytes(trailer), "ironwood bundle trailer"))

        return packets

    def _pczt_chunk_p1(self, idx: int, total_chunks: int) -> P1:
        if idx == 0:
            return P1.P1_FIRST
        if idx == total_chunks - 1:
            return P1.P1_LAST
        return P1.P1_NEXT

    def _pczt_chunk_p2(self, idx: int, total_chunks: int, pczt_finished: bool = False) -> P2:
        if pczt_finished and idx == total_chunks - 1:
            return P2.P2_PCZT_FINISHED
        return P2.P2_NONE

    def _send_pczt_header(
        self,
        pczt_global: PcztGlobal,
        pczt_version: int | None = None,
    ) -> None:
        self.backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_HEADER,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=self._build_pczt_header_and_global_payload(pczt_global, pczt_version),
        )

    def _send_pczt_transparent_inputs(
        self,
        transparent_inputs: list[PcztTransparentInput],
    ) -> None:
        packets = self._build_pczt_transparent_input_packets(
            transparent_inputs,
        )

        for idx, packet in enumerate(packets):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_TRANSPARENT_INPUT,
                p1=self._pczt_chunk_p1(idx, len(packets)),
                p2=P2.P2_NONE,
                data=packet,
            )

    @contextmanager
    def _send_pczt_transparent_outputs(
        self,
        transparent_outputs: list[PcztTransparentOutput],
    ) -> Generator[None, None, None]:
        packets = self._build_pczt_transparent_output_packets(
            transparent_outputs,
        )

        for idx, packet in enumerate(packets[:-1]):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_TRANSPARENT_OUTPUT,
                p1=self._pczt_chunk_p1(idx, len(packets)),
                p2=P2.P2_NONE,
                data=packet,
            )

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.PCZT_TRANSPARENT_OUTPUT,
            p1=self._pczt_chunk_p1(len(packets) - 1, len(packets)),
            p2=P2.P2_NONE,
            data=packets[-1],
        ) as response:
            yield response

    def _send_pczt_transparent_outputs_sync(
        self,
        transparent_outputs: list[PcztTransparentOutput],
    ) -> None:
        packets = self._build_pczt_transparent_output_packets(
            transparent_outputs,
        )

        for idx, packet in enumerate(packets):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_TRANSPARENT_OUTPUT,
                p1=self._pczt_chunk_p1(idx, len(packets)),
                p2=P2.P2_NONE,
                data=packet,
            )

    def _send_pczt_orchard_actions_sync(
        self,
        orchard_bundle: PcztOrchardBundle,
        include_rcv: bool = True,
    ) -> None:
        packets = self._build_pczt_orchard_action_packets(
            orchard_bundle,
            include_rcv=include_rcv,
        )

        for idx, packet in enumerate(packets):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_ORCHARD_ACTION,
                p1=self._pczt_chunk_p1(idx, len(packets)),
                p2=P2.P2_NONE,
                data=packet,
            )

    @contextmanager
    def _send_pczt_orchard_actions(
        self,
        orchard_bundle: PcztOrchardBundle,
        pczt_finished: bool = False,
        include_rcv: bool = True,
    ) -> Generator[None, None, None]:
        packets = self._build_pczt_orchard_action_packets(
            orchard_bundle,
            include_rcv=include_rcv,
        )

        for idx, packet in enumerate(packets[:-1]):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_ORCHARD_ACTION,
                p1=self._pczt_chunk_p1(idx, len(packets)),
                p2=self._pczt_chunk_p2(idx, len(packets), pczt_finished),
                data=packet,
            )

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.PCZT_ORCHARD_ACTION,
            p1=self._pczt_chunk_p1(len(packets) - 1, len(packets)),
            p2=self._pczt_chunk_p2(len(packets) - 1, len(packets), pczt_finished),
            data=packets[-1],
        ) as response:
            yield response

    @contextmanager
    def _send_pczt_ironwood_actions(
        self,
        ironwood_bundle: PcztIronwoodBundle,
        pczt_finished: bool = False,
        include_rcv: bool = True,
    ) -> Generator[None, None, None]:
        packets = self._build_pczt_ironwood_action_packets(
            ironwood_bundle,
            include_rcv=include_rcv,
        )

        for idx, packet in enumerate(packets[:-1]):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_IRONWOOD_ACTION,
                p1=self._pczt_chunk_p1(idx, len(packets)),
                p2=self._pczt_chunk_p2(idx, len(packets), pczt_finished),
                data=packet,
            )

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.PCZT_IRONWOOD_ACTION,
            p1=self._pczt_chunk_p1(len(packets) - 1, len(packets)),
            p2=self._pczt_chunk_p2(len(packets) - 1, len(packets), pczt_finished),
            data=packets[-1],
        ) as response:
            yield response

    def pczt_orchard_bundle_from_raw_tx(
        self,
        raw_transaction: bytes,
        signing_path: str,
        alpha: bytes,
        rcv_values: list[bytes] | None = None,
        spend_note_fields: list[tuple[bytes, bytes, bytes]] | None = None,
    ) -> PcztOrchardBundle:
        # pylint: disable=too-many-positional-arguments
        return pczt_orchard_bundle_from_raw_tx(
            raw_transaction,
            signing_path,
            alpha,
            rcv_values=rcv_values,
            spend_note_fields=spend_note_fields,
        )

    def pczt_sign_transparent(
        self,
        input_index: int = 0,
    ) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_SIGN_TRANSPARENT,
            p1=P1.P1_FIRST,
            p2=input_index,
            data=b"",
        )

    def pczt_sign_orchard(
        self,
        action_index: int = 0,
    ) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_SIGN_ORCHARD,
            p1=P1.P1_FIRST,
            p2=action_index,
            data=b"",
        )

    def pczt_sign_ironwood(
        self,
        action_index: int = 0,
    ) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.PCZT_SIGN_IRONWOOD,
            p1=P1.P1_FIRST,
            p2=action_index,
            data=b"",
        )

    @contextmanager
    def send_pczt(
        self,
        pczt_global: PcztGlobal,
        transparent_inputs: list[PcztTransparentInput],
        transparent_outputs: list[PcztTransparentOutput],
        orchard_bundle: PcztOrchardBundle | None = None,
        ironwood_bundle: PcztIronwoodBundle | None = None,
        pczt_version: int | None = None,
    ) -> Generator[None, None, None]:
        self.trusted_inputs = []
        self.pczt_transparent_inputs = transparent_inputs
        self.pczt_transparent_outputs = transparent_outputs

        self._send_pczt_header(pczt_global, pczt_version)
        self._send_pczt_transparent_inputs(transparent_inputs)
        self._send_pczt_transparent_outputs_sync(
            self.pczt_transparent_outputs,
        )

        if ironwood_bundle is None:
            if orchard_bundle is None:
                orchard_bundle = PcztOrchardBundle(
                    actions=[],
                    flags=0,
                    value_balance=0,
                    anchor=bytes(32),
                )
            with self._send_pczt_orchard_actions(
                orchard_bundle,
                pczt_finished=True,
            ) as response:
                yield response
        else:
            if orchard_bundle is None:
                # V6 Ironwood: advance the state machine through OrchardActionsDone.
                orchard_bundle = PcztOrchardBundle(
                    actions=[],
                    flags=0,
                    value_balance=0,
                    anchor=bytes(32),
                )
            self._send_pczt_orchard_actions_sync(orchard_bundle)
            with self._send_pczt_ironwood_actions(
                ironwood_bundle,
                pczt_finished=True,
            ) as response:
                yield response

    def hash_sign(self, path: str, locktime: int, expiry: int, sighash_type: int = 0x01) -> RAPDU:
        # Send extra header data
        self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_SIGN,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=0x00.to_bytes(2, byteorder="big")
            + locktime.to_bytes(4, byteorder="big")
            + sighash_type.to_bytes(1, byteorder="big")
            + expiry.to_bytes(4, byteorder="big"),
        )

        self._send_trusted_inputs_and_header(continue_hashing=True)

        return self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_SIGN,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path)
            + 0x00.to_bytes(1, byteorder="big")
            + locktime.to_bytes(4, byteorder="big")
            + sighash_type.to_bytes(1, byteorder="big")
            + expiry.to_bytes(4, byteorder="big"),
        )

    def forge_and_get_trusted_input(self, trusted_input_idx: int, send_amount: int) -> bytes:
        amount_hex = send_amount.to_bytes(8, byteorder="little").hex()

        tx = bytes.fromhex(
            "050000800a27a726b4d0d6c2"
            + "0000000000000000"
            + "01"
            + "7acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a"
            + "47304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd"
            + "263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4"
            + "d76a72fa4a6900000000"
            + "01"
            + amount_hex
            + "1976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"
            + "000000"
        )

        return self.get_trusted_input(tx, trusted_input_idx=trusted_input_idx).data

    def forge_tx_v5(self, params: ForgeTxParams) -> bytes:
        # Zcash NU5 header fields
        version = 0x80000005
        version_group_id = 0x26A7270A
        consensus_branch_id = 0xC2D6D0B4
        locktime = params.locktime
        expiry = params.expiry

        script_pubkey_in = bytes.fromhex("76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac")
        sequence = bytes.fromhex("00000000")

        script_pubkey_out = bytes.fromhex("76a914") + bytes.fromhex(params.recipient_publickey) + bytes.fromhex("88ac")

        tx = b""
        tx += struct.pack("<I", version)
        tx += struct.pack("<I", version_group_id)
        tx += struct.pack("<I", consensus_branch_id)
        tx += struct.pack("<I", locktime)
        tx += struct.pack("<I", expiry)

        tx += write_varint(1)  # inputs count
        tx += params.prevout_txid + params.vout_idx.to_bytes(4, byteorder="little")
        tx += write_varint(len(script_pubkey_in))
        tx += script_pubkey_in
        tx += sequence

        tx += write_varint(1)  # outputs count
        tx += struct.pack("<Q", params.send_amount)
        tx += write_varint(len(script_pubkey_out))
        tx += script_pubkey_out

        # Sapling spends, sapling outputs, orchard actions (all zero for this example)
        tx += write_varint(0)
        tx += write_varint(0)
        tx += write_varint(0)

        return tx

    def get_async_response(self) -> ApduResponse | RAPDU | None:
        return self.last_response or self.backend.last_async_response
