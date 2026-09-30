# I/O boundary regressions

Run `python3 tests/io-regression/run.py` in the Ledger build container. The runner
uses `cargo metadata --locked` to locate the same published SDK used by the app.
It compiles the SDK's command decoder, built-in handlers, and review callbacks
with scripted OS calls and transport packets. The tests check framing errors,
built-in replies, and overlapping command rejection without rerouting the
original reply.

The runner also compiles the application's actual swap panic handler in a small
`no_std` host executable. A failed error response must still return to Exchange,
without another panic. Both successful and failed sends are exercised. A separate
test checks the real SDK's fallible and panicking send contracts against a failing
transport. None of these fixtures are linked into the application.

`--sdk-dir PATH` runs the SDK tests against another source tree. These host tests
do not exercise the app's PIN check or physical PIN screens. Device lock behavior
and physical USB/BLE delivery still require hardware checks. The accepted
locked-device behavior is documented in [APDU.md](../../docs/APDU.md).
