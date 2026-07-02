from importlib.resources import path
import pytest
from ledger_app_clients.exchange.test_runner import ExchangeTestRunner, ALL_TESTS_EXCEPT_MEMO_AND_THORSWAP

from application_client.zcash_currency_utils import ZCASH_PATH
from application_client.zcash_command_sender import ForgeTxParams, ZcashCommandSender, Errors as ZcashErrors
from application_client.zcash_response_unpacker import unpack_get_public_key_response, unpack_trusted_input_response
from application_client.zcash_verify_sign import check_tx_v5_signature_validity

from . import cal_helper as cal


VALID_DESTINATION_1: str = "t1MSQFN2D2Tv7a2EQwsXHXXUc1hVeTJMR8m"
VALID_DESTINATION_2: str = "t1NNh42d2omDRtdBryQGtedE5sRFmzEMuBw"
VALID_REFUND: str        = "t1LBsxhHpmugntmxBVBNh6MSvq2CmUE6g9X"

# Map t-addresses to public keys
RECIPIENT_PUBLIC_KEYS = {
    VALID_DESTINATION_1: "271C49F4743E2478890F7DC607360935CFF0DE54",
    VALID_DESTINATION_2: "3160C750E722B32E6BDF2B581F26027755804C4C"
}

class ZcashTests(ExchangeTestRunner):
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

    # The final transaction to craft and send as part of the SWAP finalization.
    # This function will be called by the ExchangeTestRunner in a callback like way
    def perform_final_tx(self, destination, send_amount, fees, memo):
        LOCKTIME = 0x00
        EXPIRY = 0x00
        SIGHASH_TYPE = 0x01
        TRUSTED_INPUT_IDX = 0

        # Create the transaction that will be sent to the device for signing
        print(f"Performing final TX with destination: {destination}, send_amount: {send_amount}, fees: {fees}, memo: {memo}")

        recipient_public_key = RECIPIENT_PUBLIC_KEYS[destination]
        client = ZcashCommandSender(self.backend)

        # Get a trusted input to forge the transaction
        trusted_input_bytes = client.forge_and_get_trusted_input(TRUSTED_INPUT_IDX, send_amount + fees)
        txid_bytes, _, _, _, _ = unpack_trusted_input_response(trusted_input_bytes)

        # Get the public key
        response = client.get_public_key(path=ZCASH_PATH).data
        public_key, _, _ = unpack_get_public_key_response(response)

        # Forge TX
        tx_bytes = client.forge_tx_v5(
            ForgeTxParams(
                recipient_publickey=recipient_public_key,
                send_amount=send_amount,
                prevout_txid=txid_bytes,
                vout_idx=TRUSTED_INPUT_IDX,
                locktime=LOCKTIME,
                expiry=EXPIRY
            )
        )

        # Send TX
        # Start hashing TX
        with client.hash_input(transaction=tx_bytes, trusted_inputs=[trusted_input_bytes]):
            pass

        # Finalize and sign
        resp = client.hash_sign(
            path=ZCASH_PATH,
            locktime=LOCKTIME,
            expiry=EXPIRY,
            sighash_type=SIGHASH_TYPE
        ).data
        signature = resp[:-1]

        # Check the signature validity
        assert check_tx_v5_signature_validity(
            public_key=public_key,
            signature=signature,
            tx_bytes=tx_bytes,
            input_index=TRUSTED_INPUT_IDX,
            input_amounts=[send_amount + fees],
        )

# We use a class to reuse the same Speculos instance (faster performances)
class TestsZcash:
    # Run all the tests applicable to our setup: here we don't test fees mismatch, memo mismatch, and Thorswap / LiFi
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_AND_THORSWAP)
    def test_zcash(self, backend, exchange_navigation_helper, test_to_run):
        # Call run_test method of ExchangeTestRunner
        ZcashTests(backend, exchange_navigation_helper).run_test(test_to_run)
