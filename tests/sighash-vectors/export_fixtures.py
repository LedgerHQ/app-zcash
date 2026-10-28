"""Export the NU7 signing fixtures as JSON for the digest generator.

Run from `tests/`: python3 sighash-vectors/export_fixtures.py > sighash-vectors/fixtures.json
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from standalone.test_pczt_ironwood import (  # noqa: E402  pylint: disable=wrong-import-position
    _TRANSPARENT_INPUT_SCRIPT,
    _TRANSPARENT_OUTPUT_299K,
    _ironwood_bundle_with_external_recipient,
)

# The transparent input of `test_pczt_nu7_transparent_only_signs`.
_TRANSPARENT_INPUT = {
    "txid": "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a",
    "index": 0,
    "value": 300000,
    "script": _TRANSPARENT_INPUT_SCRIPT.hex(),
    "sequence": 0,
}


def _ironwood(bundle):
    return {
        "flags": bundle.flags,
        "value_balance": bundle.value_balance,
        "anchor": bundle.anchor.hex(),
        "actions": [
            {
                "cv_net": action.cv_net.hex(),
                "nullifier": action.nullifier.hex(),
                "rk": action.rk.hex(),
                "cmx": action.cmx.hex(),
                "ephemeral_key": action.ephemeral_key.hex(),
                "enc_ciphertext": action.enc_ciphertext.hex(),
                "out_ciphertext": action.out_ciphertext.hex(),
            }
            for action in bundle.actions
        ],
    }


json.dump(
    {
        "ironwood_payment": {
            "transparent_inputs": [],
            "transparent_outputs": [],
            "ironwood": _ironwood(_ironwood_bundle_with_external_recipient()),
        },
        "transparent_only": {
            "transparent_inputs": [_TRANSPARENT_INPUT],
            "transparent_outputs": [
                {"value": _TRANSPARENT_OUTPUT_299K.value, "script": _TRANSPARENT_OUTPUT_299K.script_pubkey.hex()}
            ],
            "ironwood": None,
        },
    },
    sys.stdout,
    indent=2,
)
