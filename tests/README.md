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

Recipient-reuse regressions cover malformed recipient keys, wrong ownership, rho,
rseed and nullifiers for Orchard and Ironwood. The crypto unit tests compare raw
and validated-recipient nullifiers and reject mismatched account/base material.

`test_pczt_key_reuse.py` uses distinct public notes and randomized keys to cover
multiple real spends, leading dummy actions, both pools, wrong account/rk after
cache reuse, and recovery with a fresh valid transaction. Orchard signatures are
checked with the independent Python verifier. See `key-reuse/README.md` for the
separate on-device key-vector harness covering both normalization signs.

The NU7 PCZT tests check each signature against a digest the device had no part in:
`sighash-vectors/` rebuilds the fixture transactions with the published `zcash_primitives`
and prints their NU7 and NU6.3 signature digests, and each signature must verify under its
own branch and fail under the other. `sighash-vectors/export_fixtures.py` writes the fixture
fields it reads; the run command is in `sighash-vectors/src/main.rs`.

`test_usb_reply.py` pauses emulator ticker events to verify immediate USB HID
replies and sends overlapping commands during review to check that approval and
rejection still apply to the original transaction. The ticker test is
emulator-only and does not establish physical USB, BLE or NFC timings.
`test_error_cmd.py` checks strict short/extended APDU lengths, four-byte empty
commands and successful communication after framing errors.

The app runs the SDK's `io_new` path (1.37.1 or later) on every supported target.
`io-regression/` compiles that SDK I/O source against a scripted OS: framing
errors, built-in replies, overlapping commands during review, rejection of every
APDU on a locked device, and the swap panic handler's return to Exchange. See
[APDU.md](../docs/APDU.md) for the locked-device contract.
