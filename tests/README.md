The `application_client` directory contains the minimalist python client for crafting and sending APDUs to the application.
It is extracted in order to be able to be used in both tests setup.

The `standalone` directory contains the standalone tests of the application, when it is started from the Dashboard of the device (main use case).

The `swap` directory contains the tests of the **SWAP** feature of the application, when it is started by the Exchange application through the `os_lib_call` API.
This setup needs the Exchange and Ethereum binaries compiled.

PCZT Orchard spend-authorizing signatures are verified against the action's
randomized verification key and an independently computed transaction digest.
Retained signature vectors must verify too. Byte-for-byte comparison is not
appropriate when an optimization changes how many blinded SDK operations consume
the emulator's deterministic random stream before the randomized signature.

`test_usb_reply.py` pauses emulator ticker events to verify immediate USB HID
replies and sends overlapping commands during review to check that approval and
rejection still apply to the original transaction.

Recipient-reuse regressions cover malformed recipient keys, wrong ownership, rho,
rseed and nullifiers for Orchard and Ironwood. The crypto unit tests compare raw
and validated-recipient nullifiers and reject mismatched account/base material.

`test_pczt_key_reuse.py` uses distinct public notes and randomized keys to cover
multiple real spends, leading dummy actions, both pools, wrong account/rk after
cache reuse, and recovery with a fresh valid transaction. Orchard signatures are
checked with the independent Python verifier. See `key-reuse/README.md` for the
separate on-device key-vector harness covering both normalization signs.

The app uses the published SDK 1.37 `io_new` on every supported target. The app
checks the PIN before dispatching Zcash commands. Built-in commands and framing
errors follow the SDK behavior described in [APDU.md](../docs/APDU.md). The ticker
test is emulator-only and does not establish physical USB, BLE or NFC timings.
`test_error_cmd.py` checks strict short/extended APDU lengths, four-byte empty
commands and successful communication after framing errors.
