from dataclasses import dataclass
from enum import IntEnum
import struct
from typing import Callable, Generator, List, Optional, Tuple
from contextlib import contextmanager
from struct import pack

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path

from application_client.zcash_transaction import (
    split_tx_to_chunks,
    split_tx_v5_for_hash_input,
)
from application_client.zcash_utils import write_varint

MAGIC_TRUSTED_INPUT: int = 0x32

MAX_APDU_LEN: int = 255
PCZT_DEFAULT_SEED_FINGERPRINT: bytes = bytes(32)

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

class HashSignMode(IntEnum):
    Sign = 0x00
    Digest = 0x01
    SpendAuthSig = 0x02
    BindingSig = 0x03

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
    PCZT_TRANSPARENT_INPUT = 0x52
    PCZT_TRANSPARENT_OUTPUT = 0x53
    PCZT_SIGN_TRANSPARENT = 0x54

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
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_DISPLAY_AMOUNT_FAIL = 0xB003
    SW_WRONG_TX_LENGTH = 0xB004
    SW_TX_PARSING_FAIL = 0xB005
    SW_TX_HASH_FAIL = 0xB006
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008
    SW_INVALID_TRANSACTION = 0X6A80


def split_message(message: bytes, max_size: int) -> List[bytes]:
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
        self.last_response: Optional[ApduResponse | RAPDU] = None

    def exchange_raw(self, data: str) -> Tuple[int, bytes]:
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
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_FIRST, p2=P2.P2_NONE, data=b""
        )

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_FIRST, p2=P2.P2_NONE, data=b""
        )

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_WALLET_PUBLIC_KEY,
            p1=P1.P1_FIRST,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path),
        )

    def get_shielded_address(self, path: str, mode: GetShieldedAddressMode = GetShieldedAddressMode.UADDRESS) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_SHIELDED_ADDRESS,
            p1=P1.P1_FIRST,
            p2=mode,
            data=pack_derivation_path(path),
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
    ) -> Generator[Optional[ApduResponse | RAPDU], None, None]:
        self.last_response = None

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_FIRST,
            p2=mode,
            data=pack_derivation_path(path),
        ):
            navigate()

        response = self.backend.last_async_response
        if response is not None:
            self.last_response = self._collect_ufvk_response(response, mode)

        yield self.last_response

    @contextmanager
    def get_public_key_with_confirmation(
        self, path: str
    ) -> Generator[None, None, None]:
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
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_SHIELDED_ADDRESS,
            p1=P1.P1_GET_PUBLIC_KEY_DISPLAY,
            p2=mode,
            data=pack_derivation_path(path),
        ) as response:
            yield response

    def get_trusted_input(
        self, transaction: bytes,
        trusted_input_idx: int,
        is_v4_nu6: bool = False
    )  -> RAPDU:
        chunks = split_tx_to_chunks(transaction, is_v4_nu6)
        # convert trusted-input index to 4 bytes big endian
        trusted_idx = pack(">I", trusted_input_idx)
        # prepend the trusted input index to the first chunk
        chunks[0] = bytes(trusted_idx + chunks[0])

        p1 = P1.P1_FIRST

        for c in chunks[:-1]:
            self.backend.exchange(
                cla=CLA, ins=InsType.GET_TRUSTED_INPUT, p1=p1, p2=P2.P2_NONE, data=c
            )
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
            p2=(
                P2.P2_HASH_INPUT_START_CONTINUE
                if continue_hashing
                else P2.P2_HASH_INPUT_START_SAPLING
            ),
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
        change_or_shielded_path: str | None = None,
    ) -> Generator[None, None, None]:
        # pylint: disable=too-many-locals
        # Send outputs chunks
        outputs: list[dict] = self.tx_chunks["outputs"] # type: ignore
        shielded_prefix: bytes = self.tx_chunks["shielded_prefix"] # type: ignore
        shielded_chunks: list[bytes] = self.tx_chunks["shielded_chunks"] # type: ignore
        outputs_num = len(outputs)
        outputs_num_bytes = outputs_num.to_bytes(1, byteorder="big")
        finalize_chunks: list[bytes] = []

        if change_or_shielded_path:
            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_FINALIZE_FULL_CHANGEINFO,
                p2=P2.P2_FINALIZE_FULL_DEFAULT,
                data=pack_derivation_path(change_or_shielded_path),
            )

        for idx, out in enumerate(outputs):
            value = out["value"]
            script = out["script"]
            script_len = len(script)
            prefix = outputs_num_bytes if idx == 0 else b""
            suffix = shielded_prefix if idx == len(outputs) - 1 else b""

            finalize_chunks.append(
                prefix + value + script_len.to_bytes(1, byteorder="big") + script + suffix
            )

        if not outputs:
            finalize_chunks.append(outputs_num_bytes + shielded_prefix)

        finalize_chunks.extend(shielded_chunks)

        for chunk in finalize_chunks[:-1]:
            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_FINALIZE_FULL_MORE,
                p2=P2.P2_FINALIZE_FULL_DEFAULT,
                data=chunk,
            )

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.HASH_INPUT_FINALIZE_FULL,
            p1=P1.P1_FINALIZE_FULL_MORE,
            p2=P2.P2_FINALIZE_FULL_DEFAULT,
            data=finalize_chunks[-1],
        ) as response:
            yield response

    @contextmanager
    def hash_input(
        self,
        transaction: bytes,
        trusted_inputs: list[bytes],
        change_or_shielded_path: str | None = None,
    ) -> Generator[None, None, None]:
        self.tx_chunks = split_tx_v5_for_hash_input(transaction)
        self.trusted_inputs = trusted_inputs
        self.pczt_transparent_inputs = []
        self.pczt_transparent_outputs = []

        self._send_trusted_inputs_and_header(continue_hashing=False)

        with self._hash_input_finalize_outputs(change_or_shielded_path) as response:
            yield response

    def _pczt_optional_u32(self, value: int | None) -> bytes:
        if value is None:
            return b"\x00"
        return b"\x01" + value.to_bytes(4, byteorder="little")

    def _compressed_pubkey_from_path(self, path: str) -> bytes:
        response = self.get_public_key(path=path).data
        pubkey_len = response[0]
        pubkey = response[1:1 + pubkey_len]

        if pubkey_len != 65 or len(pubkey) != 65:
            raise ValueError("Unexpected public key response")

        prefix = b"\x02" if pubkey[64] % 2 == 0 else b"\x03"
        return prefix + pubkey[1:33]

    def _path_components_from_path(self, path: str) -> list[int]:
        packed_path = pack_derivation_path(path)
        path_len = packed_path[0]

        if len(packed_path) != 1 + path_len * 4:
            raise ValueError("Unexpected derivation path encoding")

        return [
            int.from_bytes(packed_path[1 + idx * 4:1 + (idx + 1) * 4], byteorder="big")
            for idx in range(path_len)
        ]

    def _build_pczt_header_and_global_payload(
        self,
        transaction: bytes,
    ) -> bytes:
        tx_header = int.from_bytes(transaction[0:4], byteorder="little")
        tx_version = tx_header & 0x7FFFFFFF
        version_group_id = int.from_bytes(transaction[4:8], byteorder="little")
        consensus_branch_id = int.from_bytes(transaction[8:12], byteorder="little")
        fallback_lock_time = int.from_bytes(transaction[12:16], byteorder="little")
        expiry_height = int.from_bytes(transaction[16:20], byteorder="little")

        payload = bytearray(b"PCZT")
        payload.extend((1).to_bytes(4, byteorder="little"))
        payload.extend(tx_version.to_bytes(4, byteorder="little"))
        payload.extend(version_group_id.to_bytes(4, byteorder="little"))
        payload.extend(consensus_branch_id.to_bytes(4, byteorder="little"))
        payload.extend(self._pczt_optional_u32(fallback_lock_time))
        payload.extend(expiry_height.to_bytes(4, byteorder="little"))
        payload.extend((133).to_bytes(4, byteorder="little"))  # Zcash SLIP-44 coin type
        payload.extend(b"\x00")  # tx_modifiable

        return bytes(payload)

    def _build_pczt_transparent_input_payload(
        self,
        transaction: bytes,
        transparent_inputs: list[PcztTransparentInput],
    ) -> bytes:
        tx_inputs: list[dict] = self.tx_chunks["inputs"] # type: ignore

        if len(transparent_inputs) != len(tx_inputs):
            raise ValueError("transparent_inputs length must match transaction inputs length")

        payload = bytearray(self._build_pczt_header_and_global_payload(transaction))
        payload.extend(write_varint(len(transparent_inputs)))

        for inp in transparent_inputs:
            payload.extend(inp.prevout_txid)
            payload.extend(inp.prevout_index.to_bytes(4, byteorder="little"))
            sequence = int.from_bytes(inp.sequence, byteorder="little")
            payload.extend(self._pczt_optional_u32(sequence))
            payload.extend(inp.value.to_bytes(8, byteorder="little"))
            payload.extend(write_varint(len(inp.script_pubkey)) + inp.script_pubkey)
            payload.extend(inp.sighash_type.to_bytes(1, byteorder="little"))
            payload.extend(write_varint(1))
            payload.extend(self._compressed_pubkey_from_path(inp.signing_path))
            payload.extend(PCZT_DEFAULT_SEED_FINGERPRINT)
            path_components = self._path_components_from_path(inp.signing_path)
            payload.extend(write_varint(len(path_components)))
            for component in path_components:
                payload.extend(component.to_bytes(4, byteorder="little"))

        return bytes(payload)

    def _build_pczt_transparent_output_payload(
        self,
        transaction: bytes,
        transparent_outputs: list[PcztTransparentOutput],
    ) -> bytes:
        tx_outputs: list[dict] = self.tx_chunks["outputs"] # type: ignore

        if len(transparent_outputs) != len(tx_outputs):
            raise ValueError("transparent_outputs length must match transaction outputs length")

        payload = bytearray(self._build_pczt_header_and_global_payload(transaction))
        payload.extend(write_varint(len(transparent_outputs)))

        for out in transparent_outputs:
            payload.extend(out.value.to_bytes(8, byteorder="little"))
            payload.extend(write_varint(len(out.script_pubkey)) + out.script_pubkey)

        return bytes(payload)

    def _pczt_chunk_p1(self, idx: int, total_chunks: int) -> P1:
        if idx == 0:
            return P1.P1_FIRST
        if idx == total_chunks - 1:
            return P1.P1_LAST
        return P1.P1_NEXT

    def _send_pczt_transparent_inputs(
        self,
        transaction: bytes,
        transparent_inputs: list[PcztTransparentInput],
    ) -> None:
        chunks = split_message(
            self._build_pczt_transparent_input_payload(
                transaction,
                transparent_inputs,
            ),
            MAX_APDU_LEN,
        )

        for idx, chunk in enumerate(chunks):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_TRANSPARENT_INPUT,
                p1=self._pczt_chunk_p1(idx, len(chunks)),
                p2=P2.P2_NONE,
                data=chunk,
            )

    def _pczt_transparent_outputs_from_tx(self) -> list[PcztTransparentOutput]:
        outputs: list[dict] = self.tx_chunks["outputs"] # type: ignore
        return [
            PcztTransparentOutput(
                value=int.from_bytes(out["value"], byteorder="little"),
                script_pubkey=out["script"],
            )
            for out in outputs
        ]

    @contextmanager
    def _send_pczt_transparent_outputs(
        self,
        transaction: bytes,
        transparent_outputs: list[PcztTransparentOutput],
        change_or_shielded_path: str | None = None,
    ) -> Generator[None, None, None]:
        if change_or_shielded_path:
            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_FINALIZE_FULL_CHANGEINFO,
                p2=P2.P2_FINALIZE_FULL_DEFAULT,
                data=pack_derivation_path(change_or_shielded_path),
            )

        chunks = split_message(
            self._build_pczt_transparent_output_payload(
                transaction,
                transparent_outputs,
            ),
            MAX_APDU_LEN,
        )

        for idx, chunk in enumerate(chunks[:-1]):
            self.backend.exchange(
                cla=CLA,
                ins=InsType.PCZT_TRANSPARENT_OUTPUT,
                p1=self._pczt_chunk_p1(idx, len(chunks)),
                p2=P2.P2_NONE,
                data=chunk,
            )

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.PCZT_TRANSPARENT_OUTPUT,
            p1=self._pczt_chunk_p1(len(chunks) - 1, len(chunks)),
            p2=P2.P2_NONE,
            data=chunks[-1],
        ) as response:
            yield response

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

    @contextmanager
    def send_pczt(
        self,
        transaction: bytes,
        transparent_inputs: list[PcztTransparentInput],
        transparent_outputs: list[PcztTransparentOutput] | None = None,
        change_or_shielded_path: str | None = None,
    ) -> Generator[None, None, None]:
        self.tx_chunks = split_tx_v5_for_hash_input(transaction)
        self.trusted_inputs = []
        self.pczt_transparent_inputs = transparent_inputs
        self.pczt_transparent_outputs = (
            transparent_outputs
            if transparent_outputs is not None
            else self._pczt_transparent_outputs_from_tx()
        )

        self._send_pczt_transparent_inputs(transaction, transparent_inputs)

        with self._send_pczt_transparent_outputs(
            transaction,
            self.pczt_transparent_outputs,
            change_or_shielded_path,
        ) as response:
            yield response

    def hash_sign(
        self,
        path: str,
        locktime: Optional[int] = None,
        expiry: Optional[int] = None,
        sighash_type: int = 0x01,
        mode: HashSignMode = HashSignMode.Sign,
        prepare: bool = True,
        binding_signing_key: Optional[bytes] = None,
    ) -> RAPDU:
        # pylint: disable=too-many-positional-arguments
        if (locktime is None) != (expiry is None):
            raise ValueError("locktime and expiry must be provided together")

        if prepare:
            if self.pczt_transparent_inputs:
                raise ValueError("Use pczt_sign_transparent for PCZT transparent signing")

            if locktime is None or expiry is None:
                raise ValueError("locktime and expiry are required when prepare=True")

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

        if mode == HashSignMode.BindingSig:
            if binding_signing_key is None:
                raise ValueError("binding_signing_key is required for BindingSig mode")
            if len(binding_signing_key) != 32:
                raise ValueError("binding_signing_key must be 32 bytes")
            sign_data = binding_signing_key
        else:
            sign_data = pack_derivation_path(path)
            if locktime is not None and expiry is not None:
                sign_data += (
                    0x00.to_bytes(1, byteorder="big")
                    + locktime.to_bytes(4, byteorder="big")
                    + sighash_type.to_bytes(1, byteorder="big")
                    + expiry.to_bytes(4, byteorder="big")
                )

        return self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_SIGN,
            p1=mode,
            p2=P2.P2_NONE,
            data=sign_data,
        )

    def forge_and_get_trusted_input(self, trusted_input_idx: int, send_amount: int) -> bytes:
        amount_hex = send_amount.to_bytes(8, byteorder="little").hex()

        tx = bytes.fromhex(
            "050000800a27a726b4d0d6c2" + "0000000000000000" + "01" +
            "7acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a" +
            "47304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd" +
            "263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4" +
            "d76a72fa4a6900000000" +
            "01" +
            amount_hex + "1976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac" +
            "000000"
        )

        return self.get_trusted_input(tx, trusted_input_idx=trusted_input_idx).data

    def forge_tx_v5(
        self,
        params: ForgeTxParams
    ) -> bytes:
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

    def get_async_response(self) -> Optional[ApduResponse | RAPDU]:
        return self.last_response or self.backend.last_async_response
