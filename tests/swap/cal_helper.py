from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration
from ragger.bip import BtcDerivationPathFormat, bitcoin_pack_derivation_path
from ragger.utils import create_currency_config
from application_client.zcash_currency_utils import ZEC_PATH

# Define a configuration for each currency used in our tests: native coins and tokens

# ZEC token currency definition
ZEC_CONF = create_currency_config("ZEC", "Zcash", sub_coin_config=None)
# Serialized derivation path for the Boilerplate app
ZEC_PACKED_DERIVATION_PATH = bitcoin_pack_derivation_path(BtcDerivationPathFormat.LEGACY, ZEC_PATH) #pack_derivation_path(ZEC_PATH)#
# Coin configuration mock as stored in CAL for the SWAP feature
ZEC_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="ZEC", conf=ZEC_CONF, packed_derivation_path=ZEC_PACKED_DERIVATION_PATH)