from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration
from ragger.utils import create_currency_config
from application_client.zcash_currency_utils import ZCASH_PATH, ZCASH_TICKER
from ragger.bip import BtcDerivationPathFormat, bitcoin_pack_derivation_path

# ZCASH native currency definition
ZCASH_CONF = create_currency_config(ZCASH_TICKER, "Zcash", sub_coin_config=None)
# Serialized derivation path for the Boilerplate app
ZCASH_PACKED_DERIVATION_PATH = bitcoin_pack_derivation_path(BtcDerivationPathFormat.LEGACY, ZCASH_PATH)
# Coin configuration mock as stored in CAL for the SWAP feature
ZCASH_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker=ZCASH_TICKER, conf=ZCASH_CONF, packed_derivation_path=ZCASH_PACKED_DERIVATION_PATH)
