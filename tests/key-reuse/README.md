# Ledger key reuse tests

This separate SDK test executable checks combined FVK/ASK derivation and randomized
verification keys against four public vectors generated with Python integer curve
arithmetic. Both ASK sign-normalization branches are covered. No wallet secrets
are used, and the harness is never linked into the application.

Regenerate `src/vectors.rs` with `python tests/key-reuse/generate_vectors.py` using
the repository's Python test dependencies. Build in the Ledger environment with
`cargo test --manifest-path tests/key-reuse/Cargo.toml --lib --no-run --release
--target flex --locked`, then run the produced ELF in Speculos with `--model flex
--display headless`. Set `LEDGER_SDK_PATH` to the Flex secure SDK. The normal SDK
8 KiB test heap is sufficient; the app's heap is unchanged.

The harness has its own lockfile because its SDK unit-test feature must not be
unified into an app installation build. It uses the same vendored crypto patches
and SDK as the application, with no experimental scalar multiplication backend.
