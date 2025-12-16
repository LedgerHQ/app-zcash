from enum import IntEnum
from typing import Generator, List, Optional
from contextlib import contextmanager
import struct
import os

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import BtcDerivationPathFormat, bitcoin_pack_derivation_path
from .boilerplate_utils import write_varint


MAX_APDU_LEN: int = 255

CLA: int = 0xE0

class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX   = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01
    # Parameter 1 for subsequent chunks.
    P1_MORE = 0x80

class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80

class InsType(IntEnum):
    GET_VERSION    = 0x03
    GET_APP_NAME   = 0x04
    GET_PUBLIC_KEY = 0x05
    SIGN_TX        = 0x06
    GET_TRUSTED_INPUT = 0x42
    UNTRUSTED_HASH_TX_INPUT_START = 0x44
    UNTRUSTED_HASH_SIGN = 0x48
    UNTRUSTED_HASH_INPUT_FINALIZE_FULL = 0x4A

class Errors(IntEnum):
    SW_DENY                    = 0x6985
    SW_WRONG_P1P2              = 0x6A86
    SW_WRONG_DATA_LENGTH       = 0x6A87
    SW_INS_NOT_SUPPORTED       = 0x6D00
    SW_CLA_NOT_SUPPORTED       = 0x6E00
    SW_WRONG_RESPONSE_LENGTH   = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL    = 0xB002
    SW_DISPLAY_AMOUNT_FAIL     = 0xB003
    SW_WRONG_TX_LENGTH         = 0xB004
    SW_TX_PARSING_FAIL         = 0xB005
    SW_TX_HASH_FAIL            = 0xB006
    SW_BAD_STATE               = 0xB007
    SW_SIGNATURE_FAIL          = 0xB008
    SW_WRONG_AMOUNT            = 0xC000
    SW_WRONG_ADDRESS           = 0xC000
    SW_INVALID_TRANSACTION     = 0X6A80


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x:x + max_size] for x in range(0, len(message), max_size)]


class ZcashCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend


    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(cla=0xB0,  # specific CLA for BOLOS
                                     ins=0x01,  # specific INS for get_app_and_version
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")


    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_VERSION,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")


    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_APP_NAME,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=b"")


    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_PUBLIC_KEY,
                                     p1=P1.P1_START,
                                     p2=P2.P2_LAST,
                                     data=bitcoin_pack_derivation_path(BtcDerivationPathFormat.LEGACY, path))


    @contextmanager
    def get_public_key_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.GET_PUBLIC_KEY,
                                         p1=P1.P1_CONFIRM,
                                         p2=P2.P2_LAST,
                                         data=bitcoin_pack_derivation_path(BtcDerivationPathFormat.LEGACY, path)) as response:
            yield response


    @contextmanager
    def sign_tx(self, path: str, transaction: bytes) -> Generator[None, None, None]:
        self.backend.exchange(cla=CLA,
                              ins=InsType.SIGN_TX,
                              p1=P1.P1_START,
                              p2=P2.P2_MORE,
                              data=bitcoin_pack_derivation_path(BtcDerivationPathFormat.LEGACY, path))
        messages = split_message(transaction, MAX_APDU_LEN)
        idx: int = P1.P1_START + 1

        for msg in messages[:-1]:
            self.backend.exchange(cla=CLA,
                                  ins=InsType.SIGN_TX,
                                  p1=idx,
                                  p2=P2.P2_MORE,
                                  data=msg)
            idx += 1

        with self.backend.exchange_async(cla=CLA,
                                         ins=InsType.SIGN_TX,
                                         p1=idx,
                                         p2=P2.P2_LAST,
                                         data=messages[-1]) as response:
            yield response

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response

    def sign_tx_sync(self, path: str, transaction: bytes) -> Optional[RAPDU]:
        with self.sign_tx(path, transaction):
            pass
        rapdu = self.get_async_response()
        assert isinstance(rapdu, RAPDU)
        return rapdu

    def get_trusted_input(self, path: str, send_amount: int) -> bytes:
        
        ############################################################
        # GET TRUSTED INPUT
        # Instruction: 0x42 (GET_TRUSTED_INPUT)
        
        # First APDU: General data with BIP32 path
        # e04200001100000000050000800a27a726b4d0d6c201
        # e0=CLA, 42=INS, 00=P1, 00=P2, 11=Lc(17 bytes), data=path data
        first_data = bytes([0x00, 0x00, 0x00, 0x00]) + bytes([0x05]) + bitcoin_pack_derivation_path(BtcDerivationPathFormat.LEGACY, path)
        rapdu = self.backend.exchange(cla=CLA,
                                      ins=InsType.GET_TRUSTED_INPUT,
                                      p1=P1.P1_START,  # 0x00
                                      p2=P2.P2_LAST,   # 0x00
                                      data=bytes.fromhex("00000000050000800a27a726b4d0d6c201"))
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        

        amount = struct.pack("<Q", send_amount)  # amount sent (8 bytes, little-endian)
        chunks = [
            bytes.fromhex("7acad6b8eec3158ecee566c0f08ff721d94d44b0cf66ee220ad4f9d1692d2ab5000000006a"),
            bytes.fromhex("47304402200d6900cafe4189b9dfebaa965584f39e07cf6086ed5a97c84a5a76035dddcf7302206263c8b7202227e0ab33dd"),
            bytes.fromhex("263e04f7a4384d34daa9279bfdebb03bf4b62123590121023e7c3ab4b4a42466f2c72c79afd426a0714fed74f884cd11abb4"),
            bytes.fromhex("d76a72fa4a6900000000"),
            bytes.fromhex("01"),
            amount+bytes.fromhex("1976a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac"),
            bytes.fromhex("000000"),  
        ]
        
        # Send transaction input chunks
        for chunk in chunks:
            rapdu = self.backend.exchange(cla=CLA,
                                         ins=InsType.GET_TRUSTED_INPUT,
                                         p1=P1.P1_MORE,  # 0x80
                                         p2=P2.P2_LAST,  # 0x00
                                         data=chunk)
            assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        
        # Final APDU: Get the trusted input (txid)
        # Returns the trusted input bytes
        final_data = bytes.fromhex("000000000400000000")
        rapdu = self.backend.exchange(cla=CLA,
                                     ins=InsType.GET_TRUSTED_INPUT,
                                     p1=P1.P1_MORE,  # 0x80
                                     p2=P2.P2_LAST,  # 0x00
                                     data=final_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        
        # Return the trusted input (txid) from the response
        return rapdu.data
    
    @contextmanager
    def sign_zec_tx_sync(self, path: str, recipient_publickey: str, send_amount: int) -> Generator[None, None, None]:
        
        txid_bytes = self.get_trusted_input(path, send_amount)  # transaction bytes would be parsed here

        
        # Extract parameters from transaction structure
        # For now, defining as variables in function body with Zcash NU5 defaults
        version: int = 0x80000005  # Zcash transaction version (NU5)
        inputs_count: int = 1
        version_group_id: int = 0x26A7270A  # Zcash NU5 version group ID
        consensus_branch_id: int = 0xC2D6D0B4 #0x4dec4df0  # Zcash NU5 consensus branch ID
        p2: int = 0x05  # Default to sapling (based on expected APDU: e04400050d...)
        
        first_apdu_data: bytes = struct.pack("<I", version)  # version = 0x80000005
        
        #first_apdu_data += struct.pack("<I", timestamp)
        
        first_apdu_data += struct.pack("<I", version_group_id)  # 0x26A7270A
        
        first_apdu_data += struct.pack("<I", consensus_branch_id)  # 0x4dec4df0
        
        first_apdu_data += write_varint(inputs_count)
        
        self.backend.exchange(cla=CLA,
                              ins=InsType.UNTRUSTED_HASH_TX_INPUT_START,
                              p1=P1.P1_START,  # 0x00 for first round
                              p2=p2,  # Transaction type (0x05 for sapling)
                              data=first_apdu_data)
        
        
        p1_idx: int = 0x80  # P1 for subsequent chunks (0x80 = more data)
        
        
        script_size = 0x19  # Script size
        
        # Build first input APDU data
        # Structure: flags (0x01, 0x38) + txid (32 bytes) + script_size (1 byte)
        input_apdu_data = bytes([0x01, 0x38]) + txid_bytes + bytes([script_size])
        
        self.backend.exchange(cla=CLA,
                              ins=InsType.UNTRUSTED_HASH_TX_INPUT_START,
                              p1=p1_idx,  # 0x80
                              p2=P2.P2_MORE,  # 0x05 (sapling) - keep same P2 for input data
                              data=input_apdu_data)
        
        # Send input script (scriptSig + sequence)
        # Example script: P2PKH script (76a914...) + sequence (00000000)
        script_data_hex = "76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
        script_data = bytes.fromhex(script_data_hex)
        
        # Send script with P2=0x80 (more data) to indicate more transaction data follows
        self.backend.exchange(cla=CLA,
                              ins=InsType.UNTRUSTED_HASH_TX_INPUT_START,
                              p1=p1_idx,  # 0x80
                              p2=P2.P2_MORE,  # 0x80 (more data to follow)
                              data=script_data)
        
        amount = struct.pack("<Q", send_amount)
        address = bytes.fromhex(recipient_publickey) 
        finalize_data = bytes.fromhex("01") + amount + bytes.fromhex("1976a914") + address + bytes.fromhex("88ac")
        rapdu = self.backend.exchange(cla=CLA,
                                      ins=InsType.UNTRUSTED_HASH_INPUT_FINALIZE_FULL,
                                      p1=P1.P1_MORE,  # 0x80
                                      p2=P2.P2_LAST,  # 0x00
                                      data=finalize_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        
        sign_data = bytes.fromhex("0000000000000100000000")
        rapdu = self.backend.exchange(cla=CLA,
                                     ins=InsType.UNTRUSTED_HASH_SIGN,
                                     p1=P1.P1_START,  # 0x00
                                     p2=P2.P2_LAST,   # 0x00
                                     data=sign_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        
        #OUTPUTS
        done_data = bytes.fromhex("050000800a27a726b4d0d6c201")  # BIP32 path
        rapdu = self.backend.exchange(cla=CLA,
                                     ins=InsType.UNTRUSTED_HASH_TX_INPUT_START,
                                     p1=P1.P1_START,  # 0x00
                                     p2=P2.P2_MORE,   # 0x80 (indicates done/hash completion)
                                     data=done_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        
        script_size = 0x19  # Output index (25 in decimal)
        input_apdu_data = bytes([0x01, 0x38]) + txid_bytes + bytes([script_size])
        rapdu = self.backend.exchange(cla=CLA,
                                      ins=InsType.UNTRUSTED_HASH_TX_INPUT_START,
                                      p1=P1.P1_MORE,  # 0x80
                                      p2=P2.P2_MORE,  # 0x80 (more data)
                                      data=input_apdu_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        
        script_data_hex = "76a914effcdc2e850d1c35fa25029ddbfad5928c9d702f88ac00000000"
        script_data = bytes.fromhex(script_data_hex)
        rapdu = self.backend.exchange(cla=CLA,
                                      ins=InsType.UNTRUSTED_HASH_TX_INPUT_START,
                                      p1=P1.P1_MORE,  # 0x80
                                      p2=P2.P2_MORE,  # 0x80 (more data)
                                      data=script_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"

        # SIGN REQUEST - HASH_SIGN (0x48)
        sign_request_data = bytes.fromhex("058000002c8000008580000002000000000000000200000000000100000000")
        rapdu = self.backend.exchange(cla=CLA,
                                     ins=InsType.UNTRUSTED_HASH_SIGN,
                                     p1=P1.P1_START,  # 0x00
                                     p2=P2.P2_LAST,   # 0x00
                                     data=sign_request_data)
        assert rapdu.status == 0x9000, f"Expected 0x9000, got {hex(rapdu.status)}"
        #sig1 = rapdu.data  # Signature is in the response data

