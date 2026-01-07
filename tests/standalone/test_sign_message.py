from bitcoin_client.bitcoin_base_cmd import AddrType
from utils import automation


@automation("automations/sign_message.json")
def test_sign_message(cmd):
    result = cmd.sign_message(
            message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks.",
            bip32_path = "m/44'/133'/0'/0/0",
    )

    print(result)
    assert result == "MUUCIQDZt/sSeUiqgUTCLWz2AWwdPKn05D0Su9iu1zxUb1S5OwIgFZd6seHE0WjRFb4QAdlWYhOmt1/FvCgtILfz1QGe1YM="

