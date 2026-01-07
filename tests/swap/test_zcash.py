import pytest
from ledger_app_clients.exchange.test_runner import ExchangeTestRunner, ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES

from application_client.zcash_currency_utils import ZEC_PATH
from application_client.zcash_command_sender import ZcashCommandSender, Errors as ZcashErrors

from . import cal_helper as cal

# ExchangeTestRunner implementation for Boilerplate.
# BoilerplateTests extends ExchangeTestRunner and in doing so inherits all necessary boilerplate and
# test management features.
# We only need to set the values we want to use for our test and the final payment request
class ZcashTests(ExchangeTestRunner):
    # The coin configuration of our currency. Replace by your own
    currency_configuration = cal.ZEC_CURRENCY_CONFIGURATION
    # A valid template address of a supposed trade partner.
    valid_destination_1 = "t1MSQFN2D2Tv7a2EQwsXHXXUc1hVeTJMR8m"# 1CB8271C49F4743E2478890F7DC607360935CFF0DE548B7D51D2 old: "t1PtKQ4GS7s4jPFqFY3f6CZgBkY4Y42osMJ"
    # A memo to use associated with the destination address if applicable.
    valid_destination_memo_1 = ""
    # A second valid template address of a supposed trade partner.
    valid_destination_2 = "t1NNh42d2omDRtdBryQGtedE5sRFmzEMuBw"# 1CB83160C750E722B32E6BDF2B581F26027755804C4C1345FD5A old: "t1fLA4MCGqNYjPH1Yjj232uiwFHFGQR1B7M"
    # A second memo to use associated with the destination address if applicable.
    valid_destination_memo_2 = ""
    # The address of the Speculos seed on the ZEC_PATH.
    valid_refund = "t1LBsxhHpmugntmxBVBNh6MSvq2CmUE6g9X"
    valid_refund_memo = ""

    # Values we ask the ExchangeTestRunner to use in the test setup
    valid_send_amount_1 = 1000
    valid_send_amount_2 = 666
    valid_fees_1 = 0
    valid_fees_2 = 0

    # Fake addresses to test the address rejection code.
    fake_refund = "abcdabcd"
    fake_refund_memo = "bla"
    fake_payout = "abcdabcd"
    fake_payout_memo = "bla"

    # The error code we expect our application to respond when encountering errors.
    signature_refusal_error_code = ZcashErrors.SW_DENY
    wrong_amount_error_code = ZcashErrors.SW_INVALID_TRANSACTION
    wrong_destination_error_code = ZcashErrors.SW_INVALID_TRANSACTION

    # The final transaction to craft and send as part of the SWAP finalization.
    # This function will be called by the ExchangeTestRunner in a callback like way
    def perform_final_tx(self, destination, send_amount, fees, memo):
        
        recipient_publickey = ""
        if destination == "t1MSQFN2D2Tv7a2EQwsXHXXUc1hVeTJMR8m" :# 1CB8271C49F4743E2478890F7DC607360935CFF0DE548B7D51D2 
            recipient_publickey = "271C49F4743E2478890F7DC607360935CFF0DE54"

        if destination == "t1NNh42d2omDRtdBryQGtedE5sRFmzEMuBw" :# 1CB83160C750E722B32E6BDF2B581F26027755804C4C1345FD5A
            recipient_publickey = "3160C750E722B32E6BDF2B581F26027755804C4C"
        
        # Send the TX
        ZcashCommandSender(self.backend).sign_zec_tx_sync(path=ZEC_PATH, recipient_publickey=recipient_publickey, send_amount=send_amount)
        

# We use a class to reuse the same Speculos instance (faster performances)
class TestsZcash:
    # Run all the tests applicable to our setup: here we don't test fees mismatch, memo mismatch, and Thorswap / LiFi
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_zcash(self, backend, exchange_navigation_helper, test_to_run):
        # Call run_test method of ExchangeTestRunner
        ZcashTests(backend, exchange_navigation_helper).run_test(test_to_run)
