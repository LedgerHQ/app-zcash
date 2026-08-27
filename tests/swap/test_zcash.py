import pytest
from application_client.pczt import (
    PcztGlobal,
    PcztTransparentInput,
    PcztTransparentOutput,
    pczt_transaction_bytes,
)
from application_client.zcash_command_sender import (
    FORGED_UTXO_SCRIPT_PUBKEY,
    ForgeTxParams,
    ZcashCommandSender,
)
from application_client.zcash_command_sender import (
    Errors as ZcashErrors,
)
from application_client.zcash_currency_utils import ZCASH_PATH
from application_client.zcash_response_unpacker import (
    unpack_get_public_key_response,
    unpack_trusted_input_response,
)
from application_client.zcash_utils import pubkey_hash_from_t_address
from application_client.zcash_verify_sign import check_tx_v5_signature_validity
from ledger_app_clients.exchange.test_runner import (
    ALL_TESTS_EXCEPT_MEMO_AND_THORSWAP,
    ExchangeTestRunner,
)
from ragger.error import ExceptionRAPDU

from . import cal_helper as cal

VALID_DESTINATION_1: str = "t1MSQFN2D2Tv7a2EQwsXHXXUc1hVeTJMR8m"
VALID_DESTINATION_2: str = "t1NNh42d2omDRtdBryQGtedE5sRFmzEMuBw"
VALID_REFUND: str = "t1LBsxhHpmugntmxBVBNh6MSvq2CmUE6g9X"

LOCKTIME: int = 0x00
EXPIRY: int = 0x00
SIGHASH_TYPE: int = 0x01
# Single input, so it is both the trusted input slot on the legacy path and the PCZT input index.
INPUT_INDEX: int = 0

# P2PKH script opcodes, spelled out rather than carried as a hex blob.
OP_DUP: int = 0x76
OP_HASH160: int = 0xA9
OP_EQUALVERIFY: int = 0x88
OP_CHECKSIG: int = 0xAC

# Outpoint of the UTXO the PCZT path spends. The device never resolves it — unlike the legacy
# path it is handed the input value directly, with no trusted input to vouch for it — so any
# 32-byte identifier does; it only has to stay stable, since it enters the signature digest.
PCZT_PREVOUT_TXID: bytes = bytes.fromhex("58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a")
PCZT_SEQUENCE: bytes = bytes.fromhex("00000000")


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    """Build the P2PKH script paying to a public key hash."""
    return bytes([OP_DUP, OP_HASH160, len(pubkey_hash)]) + pubkey_hash + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def script_for_destination(address: str) -> bytes:
    """Build the script paying to a transparent destination address."""
    return p2pkh_script(pubkey_hash_from_t_address(address))


class ZcashTests(ExchangeTestRunner):
    """Swap scenarios signed through the legacy trusted-input path."""

    # The coin configuration of our currency. Replace by your own
    currency_configuration = cal.ZCASH_CURRENCY_CONFIGURATION
    # A valid template address of a supposed trade partner.
    valid_destination_1 = VALID_DESTINATION_1
    # A memo to use associated with the destination address if applicable.
    valid_destination_memo_1 = ""
    # A second valid template address of a supposed trade partner.
    valid_destination_2 = VALID_DESTINATION_2
    # A second memo to use associated with the destination address if applicable.
    valid_destination_memo_2 = ""
    # The address of the Speculos seed on the ZCASH_PATH.
    valid_refund = VALID_REFUND
    valid_refund_memo = ""

    # Values we ask the ExchangeTestRunner to use in the test setup
    valid_send_amount_1 = 1000000
    valid_send_amount_2 = 666000
    valid_fees_1 = 10000
    valid_fees_2 = 6600

    # Fake addresses to test the address rejection code.
    fake_refund = "abcdabcd"
    fake_refund_memo = "bla"
    fake_payout = "abcdabcd"
    fake_payout_memo = "bla"

    # The error code we expect our application to respond when encountering errors.
    signature_refusal_error_code = ZcashErrors.SW_DENY
    wrong_amount_error_code = ZcashErrors.SW_INVALID_TRANSACTION
    wrong_destination_error_code = ZcashErrors.SW_INVALID_TRANSACTION
    wrong_fees_error_code = ZcashErrors.SW_INVALID_TRANSACTION

    def get_public_key(self, client: ZcashCommandSender) -> bytes:
        response = client.get_public_key(path=ZCASH_PATH).data
        public_key, _, _ = unpack_get_public_key_response(response)
        return public_key

    # The final transaction to craft and send as part of the SWAP finalization.
    # This function will be called by the ExchangeTestRunner in a callback like way
    def perform_final_tx(self, destination, send_amount, fees, memo):
        # Create the transaction that will be sent to the device for signing
        print(f"Performing final TX with destination: {destination}, send_amount: {send_amount}, fees: {fees}, memo: {memo}")

        client = ZcashCommandSender(self.backend)

        # Get a trusted input to forge the transaction
        trusted_input_bytes = client.forge_and_get_trusted_input(INPUT_INDEX, send_amount + fees)
        txid_bytes, _, _, _, _ = unpack_trusted_input_response(trusted_input_bytes)

        # Get the public key
        public_key = self.get_public_key(client)

        # Forge TX
        tx_bytes = client.forge_tx_v5(
            ForgeTxParams(
                recipient_publickey=pubkey_hash_from_t_address(destination).hex(),
                send_amount=send_amount,
                prevout_txid=txid_bytes,
                vout_idx=INPUT_INDEX,
                locktime=LOCKTIME,
                expiry=EXPIRY,
            )
        )

        # Send TX
        # Start hashing TX
        with client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input_bytes]):
            pass

        # Finalize and sign
        resp = client.hash_sign(path=ZCASH_PATH, locktime=LOCKTIME, expiry=EXPIRY, sighash_type=SIGHASH_TYPE).data
        signature = resp[:-1]

        # Check the signature validity
        assert check_tx_v5_signature_validity(
            public_key=public_key,
            signature=signature,
            tx_bytes=tx_bytes,
            input_index=INPUT_INDEX,
            input_amounts=[send_amount + fees],
        )


class ZcashPcztTests(ZcashTests):
    """The same swap scenarios, signed through the PCZT path instead of the legacy one.

    Only the crafting and signing half differs: the addresses, amounts and expected status
    words are the ones declared by `ZcashTests`, so both paths are held to the same contract.
    """

    def sign_pczt(self, transparent_outputs: list[PcztTransparentOutput], input_value: int) -> None:
        """Craft a one-input PCZT paying the given outputs, sign it, and verify the signature.

        The device derives the fee it cross-checks as inputs minus outputs, so the caller sets
        the input value to what the transaction is meant to spend in total.
        """
        client = ZcashCommandSender(self.backend)
        public_key = self.get_public_key(client)

        pczt_global = PcztGlobal()
        transparent_input = PcztTransparentInput(
            prevout_txid=PCZT_PREVOUT_TXID,
            prevout_index=INPUT_INDEX,
            value=input_value,
            script_pubkey=FORGED_UTXO_SCRIPT_PUBKEY,
            sequence=PCZT_SEQUENCE,
            signing_path=ZCASH_PATH,
        )

        with client.send_pczt(
            pczt_global=pczt_global,
            transparent_inputs=[transparent_input],
            transparent_outputs=transparent_outputs,
        ):
            # In swap mode the Exchange cross-check stands in for the review screen, so there is
            # no display to navigate here — the same reason the legacy path enters `hash_input`
            # with an empty body.
            pass

        resp = client.pczt_sign_transparent(input_index=INPUT_INDEX).data
        signature = resp[:-1]

        assert check_tx_v5_signature_validity(
            public_key=public_key,
            signature=signature,
            tx_bytes=pczt_transaction_bytes(pczt_global, [transparent_input], transparent_outputs),
            input_index=INPUT_INDEX,
            input_amounts=[input_value],
        )

    def perform_final_tx(self, destination, send_amount, fees, memo):
        print(f"Performing final PCZT TX with destination: {destination}, send_amount: {send_amount}, fees: {fees}, memo: {memo}")

        self.sign_pczt(
            transparent_outputs=[PcztTransparentOutput(value=send_amount, script_pubkey=script_for_destination(destination))],
            input_value=send_amount + fees,
        )

    def perform_final_tx_restart_after_partial_signature(self, destination, send_amount, fees, memo):
        """Start a second transaction after one signature has already been returned.

        Two transparent inputs leave the app waiting for the second signature once the first has
        been handed back, which is the only window where the swap session still serves APDUs with a
        signature already out. The PCZT header resets the transaction state but deliberately keeps
        `swap_params`, so without a guard the cross-check would clear a second transaction on the
        strength of the same Exchange trade and the user would pay the approved amount twice, out of
        different UTXOs.

        The second transaction repeats the shape of the first on purpose: what has to be refused is
        a second transaction at all, whatever it pays.
        """
        client = ZcashCommandSender(self.backend)

        total_value = send_amount + fees
        first_value = total_value // 2
        transparent_inputs = [
            PcztTransparentInput(
                prevout_txid=PCZT_PREVOUT_TXID,
                prevout_index=index,
                value=value,
                script_pubkey=FORGED_UTXO_SCRIPT_PUBKEY,
                sequence=PCZT_SEQUENCE,
                signing_path=ZCASH_PATH,
            )
            for index, value in enumerate((first_value, total_value - first_value))
        ]
        transparent_outputs = [
            PcztTransparentOutput(value=send_amount, script_pubkey=script_for_destination(destination))
        ]

        def send() -> None:
            with client.send_pczt(
                pczt_global=PcztGlobal(),
                transparent_inputs=transparent_inputs,
                transparent_outputs=transparent_outputs,
            ):
                # No display to navigate: in swap mode the Exchange cross-check stands in for the
                # review screen.
                pass

        send()

        # Sign the first input only, leaving the second one outstanding.
        client.pczt_sign_transparent(input_index=0)

        send()

    def perform_final_tx_restart_via_trusted_input_after_partial_signature(self, destination, send_amount, fees, memo):
        """The same second transaction, opened with GET_TRUSTED_INPUT instead of a PCZT header.

        `reset_for_new_transaction` is where the guard lives, and both the PCZT header and the first
        packet of a trusted-input round call it. The helper above covers the header only. The legacy
        path is still reached in production through coin-bitcoin's Zcash adapter, so leaving its
        entry point uncovered would assert the guard on one caller and trust it on the other.
        """
        client = ZcashCommandSender(self.backend)

        total_value = send_amount + fees
        first_value = total_value // 2
        transparent_inputs = [
            PcztTransparentInput(
                prevout_txid=PCZT_PREVOUT_TXID,
                prevout_index=index,
                value=value,
                script_pubkey=FORGED_UTXO_SCRIPT_PUBKEY,
                sequence=PCZT_SEQUENCE,
                signing_path=ZCASH_PATH,
            )
            for index, value in enumerate((first_value, total_value - first_value))
        ]
        transparent_outputs = [
            PcztTransparentOutput(value=send_amount, script_pubkey=script_for_destination(destination))
        ]

        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=transparent_inputs,
            transparent_outputs=transparent_outputs,
        ):
            # No display to navigate: in swap mode the Exchange cross-check stands in for the
            # review screen.
            pass

        # Sign the first input only, leaving the second one outstanding.
        client.pczt_sign_transparent(input_index=0)

        # First packet of a trusted-input round: the trusted-input index, a v5 header, one input.
        # The guard fires before any of it is parsed, so what follows never matters.
        client.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")

    def perform_final_tx_restart_via_hash_input_start_after_partial_signature(self, destination, send_amount, fees, memo):
        """The same second transaction, opened with the legacy HASH_INPUT_START round.

        The third and last caller of `reset_for_new_transaction`. A first packet that does not
        continue an earlier round (P1 0x00, P2 0x05) makes `resets_context` true, which skips the
        guards on top of the handler and lands straight on the guarded reset.
        """
        client = ZcashCommandSender(self.backend)

        total_value = send_amount + fees
        first_value = total_value // 2
        transparent_inputs = [
            PcztTransparentInput(
                prevout_txid=PCZT_PREVOUT_TXID,
                prevout_index=index,
                value=value,
                script_pubkey=FORGED_UTXO_SCRIPT_PUBKEY,
                sequence=PCZT_SEQUENCE,
                signing_path=ZCASH_PATH,
            )
            for index, value in enumerate((first_value, total_value - first_value))
        ]
        transparent_outputs = [PcztTransparentOutput(value=send_amount, script_pubkey=script_for_destination(destination))]

        with client.send_pczt(
            pczt_global=PcztGlobal(),
            transparent_inputs=transparent_inputs,
            transparent_outputs=transparent_outputs,
        ):
            # No display to navigate: in swap mode the Exchange cross-check stands in for the
            # review screen.
            pass

        # Sign the first input only, leaving the second one outstanding.
        client.pczt_sign_transparent(input_index=0)

        # First packet of a legacy signing round: a v4 header and one input. The guard fires before
        # `comm.get_data()` is even reached, so what the packet carries never matters.
        client.exchange_raw("e0440005050400000001")

    def perform_final_tx_two_external_outputs(self, destination, send_amount, fees, memo):
        """Pay the approved amount to two recipients instead of one.

        Neither output carries a BIP32 derivation, so the device sees two *external* outputs.
        The total paid out and the fee still match what Exchange approved, which leaves the
        external output count as the only thing the cross-check can object to.
        """
        other_destination = VALID_DESTINATION_2 if destination == VALID_DESTINATION_1 else VALID_DESTINATION_1
        first_amount = send_amount // 2

        self.sign_pczt(
            transparent_outputs=[
                PcztTransparentOutput(value=first_amount, script_pubkey=script_for_destination(destination)),
                PcztTransparentOutput(value=send_amount - first_amount, script_pubkey=script_for_destination(other_destination)),
            ],
            input_value=send_amount + fees,
        )


# We use a class to reuse the same Speculos instance (faster performances)
class TestsZcash:
    # Run all the tests applicable to our setup: here we don't test fees mismatch, memo mismatch, and Thorswap / LiFi
    @pytest.mark.parametrize("test_to_run", ALL_TESTS_EXCEPT_MEMO_AND_THORSWAP)
    def test_zcash(self, backend, exchange_navigation_helper, test_to_run):
        # Call run_test method of ExchangeTestRunner
        ZcashTests(backend, exchange_navigation_helper).run_test(test_to_run)


# The classes below deliberately keep the `test_zcash` method name. The golden snapshots compared
# during a swap belong to the Exchange app's review, and Ragger keys their directory on the test
# *function* name alone (`request.node.name.split("[")[0]`). The Zcash app draws nothing in swap
# mode, so those screens are identical whichever signing path finalises the transaction: sharing
# one set of snapshots asserts that identity, where a per-class name would fork a duplicate set.
class TestsZcashPczt:
    @pytest.mark.parametrize("test_to_run", ALL_TESTS_EXCEPT_MEMO_AND_THORSWAP)
    def test_zcash(self, backend, exchange_navigation_helper, test_to_run):
        ZcashPcztTests(backend, exchange_navigation_helper).run_test(test_to_run)


class TestsZcashPcztSeveralExternalOutputs:
    # This one keeps its own name, and therefore its own snapshots: it drives the `swap_valid_1`
    # scenario to a refusal, so Exchange ends on its failure modal where that scenario's golden
    # records a success.
    def test_zcash_pczt_several_external_outputs(self, backend, exchange_navigation_helper):
        # The generic scenarios always craft a single external output, so the one-external-output
        # rule of the cross-check is only reachable from a case written here.
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = ZcashPcztTests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = test_class.perform_final_tx_two_external_outputs
            test_class.run_test("swap_valid_1")
        assert e.value.status == ZcashErrors.SW_INVALID_TRANSACTION


class TestsZcashPcztRestartAfterPartialSignature:
    # Keeps its own name, and so its own snapshots: like the case above it drives `swap_valid_1` to
    # a refusal, where that scenario's shared golden records a success.
    #
    # The three entry points are parameters of one function rather than three functions, so that
    # they share that one snapshot set. Ragger keys the snapshot directory on the function name
    # alone, and the Exchange screens are identical either way — the Zcash app draws nothing in swap
    # mode, and all three runs refuse at the same point of the same scenario.
    #
    # `reset_for_new_transaction` carries the guard and has exactly three callers, one per case
    # here. The two legacy ones are still reached in production through coin-bitcoin's Zcash
    # adapter, so asserting the guard on the PCZT caller and trusting it on the others would not do.
    @pytest.mark.parametrize("restart_entry_point", ["pczt_header", "trusted_input", "hash_input_start"])
    def test_zcash_pczt_restart_after_partial_signature(self, backend, exchange_navigation_helper, restart_entry_point):
        # The generic scenarios sign every input and let the app exit, so the window this covers —
        # a swap session still running with a signature already released — only exists here.
        with pytest.raises(ExceptionRAPDU) as e:
            test_class = ZcashPcztTests(backend, exchange_navigation_helper)
            test_class.perform_final_tx = {
                "pczt_header": test_class.perform_final_tx_restart_after_partial_signature,
                "trusted_input": test_class.perform_final_tx_restart_via_trusted_input_after_partial_signature,
                "hash_input_start": test_class.perform_final_tx_restart_via_hash_input_start_after_partial_signature,
            }[restart_entry_point]
            test_class.run_test("swap_valid_1")
        assert e.value.status == ZcashErrors.SW_BAD_STATE
