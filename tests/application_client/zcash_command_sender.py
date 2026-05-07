from dataclasses import dataclass
from enum import IntEnum
import struct
from typing import Generator, List, Optional, Tuple
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

CLA: int = 0xE0

class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_FIRST = 0x00
    # Parameter 1 for next APDU numbers.
    P1_NEXT = 0x80

    # Parameter 1 for no screen confirmation for GET_PUBLIC_KEY.
    P1_GET_PUBLIC_KEY_NO_DISPLAY = 0x00
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_GET_PUBLIC_KEY_DISPLAY = 0x01
    P1_GET_VK_DISPLAY = 0x01
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
class ApduResponse:
    status: int
    data: bytes

class ZcashCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend
        self.tx_chunks: dict = {}
        self.trusted_inputs: list[bytes] = []
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

    def get_vk(
        self,
        path: Optional[str] = None,
        mode: GetVkMode = GetVkMode.UFVK,
        continue_response: bool = False,
        display: bool = False,
    ) -> RAPDU:
        response = self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1= P1.P1_GET_VK_CONTINUE if continue_response else (
                P1.P1_GET_VK_DISPLAY if display else P1.P1_FIRST
            ),
            p2=mode,
            data=b"" if continue_response else pack_derivation_path(path),
        )

        return self._collect_ufvk_response(response, mode, continue_response)

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
        mode: GetVkMode = GetVkMode.UFVK,
    ) -> Generator[None, None, None]:
        self.last_response = None
        response = self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_DISPLAY,
            p2=mode,
            data=pack_derivation_path(path),
        )

        if mode != GetVkMode.UFVK or len(response.data) < 2:
            self.last_response = response
            yield response
            return

        total_response_len = 2 + int.from_bytes(response.data[:2], byteorder="big")
        response_data = bytearray(response.data)

        while total_response_len - len(response_data) > MAX_APDU_LEN:
            continuation = self.backend.exchange(
                cla=CLA,
                ins=InsType.GET_VK,
                p1=P1.P1_GET_VK_CONTINUE,
                p2=mode,
                data=b"",
            )
            response_data.extend(continuation.data)

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_VK,
            p1=P1.P1_GET_VK_CONTINUE,
            p2=mode,
            data=b"",
        ) as response:
            yield response

        response = self.backend.last_async_response
        if response is not None:
            response_data.extend(response.data)
            self.last_response = ApduResponse(status=response.status, data=bytes(response_data))

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
    def hash_input(
        self,
        transaction: bytes,
        trusted_inputs: list[bytes],
        change_path: str | None = None,
    ) -> Generator[None, None, None]:
        self.tx_chunks = split_tx_v5_for_hash_input(transaction)
        self.trusted_inputs = trusted_inputs

        self._send_trusted_inputs_and_header(continue_hashing=False)

        # Send outputs chunks
        outputs: dict = self.tx_chunks["outputs"] # type: ignore
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

    def hash_sign(
        self, path: str, locktime: int, expiry: int, sighash_type: int = 0x01
    ) -> RAPDU:
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
