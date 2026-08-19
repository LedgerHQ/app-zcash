# Ledger Zcash App Development Guide

This is a Rust application for Ledger hardware wallets using the `ledger_device_sdk`. Supported devices are
declared in `ledger_app.toml`.

The rules in the `ledger-app-ai-instructions` submodule apply in full and are authoritative over this file:
`EMBEDDED.instructions.md` (hardware and security constraints, UI and clear signing, secrets, comments),
`RUST.instructions.md`, `TEST.instructions.md` and `REVIEW.instructions.md`. This guide adds only what is
specific to this app.

## Core Development Principles

**Logging**: instrument key points so a failure can be diagnosed under Speculos:
- Entry/exit of important functions
- Before/after critical operations (crypto, parsing, validation)
- Both success and failure paths
- Use the SDK log macros — `debug!`, `info!`, `error!` from `ledger_device_sdk::log` — not `debug_print`

**Never log secret or key-derived material.** Spending keys, seeds, `ask`/`nk`/`ivk` values and anything
derived from them must not be printed on any path, including debug builds. Logging a value because it would
help debugging does not make it safe to log. Amounts, addresses and derivation paths already appear in
existing traces; secrets never do, and that boundary is deliberate.

**Security overrides availability**: on anything unexpected, return an error. No fallbacks, no default
values, no clamping.

## Architecture

**APDU Command Flow**: strict request-response over APDU:
1. `Comm` receives an APDU with CLA=0xe0, INS, P1, P2
2. The `Instruction` enum in `src/main.rs` parses the header into strongly-typed commands, rejecting
   unsupported P1/P2 combinations there rather than in the handlers
3. Handlers in `src/handlers/` process commands and return `Result<(), AppSW>`
4. `AppSW` maps errors to status words (e.g. `0x6985` = Deny, `0xB007` = BadState)

**Two signing protocols share one `TxContext`**, and that sharing is the subtlest part of the codebase:
- **Legacy** (INS `0x42`/`0x44`/`0x48`/`0x4A`) — trusted-input transparent and V4 Sapling signing,
  inherited from the Bitcoin app lineage. Contract: `docs/APDU.md`
- **PCZT** (INS `0x52`–`0x59`) — Orchard and Ironwood shielded signing over a partially-created
  transaction, streamed field by field. Contract: `docs/PCZT_APDU.md`

Both write the same `TxContext`, so a legacy instruction that does not reset it must refuse to run while a
PCZT session is active (`PcztParser::is_session_active`). Preserve that guard when touching
`src/handlers/`. The PCZT side is a state machine (`PcztParserState`): every entry point matches only the
states its own section owns, and any other state is a `BadState` error — do not add a permissive arm.

`docs/APDU.md` and `docs/PCZT_APDU.md` are the contract the host is written against. If code and doc
disagree, that is a defect in one of them; do not silently follow the code.

**UI System**: NBGL for all supported devices:
- Home screen via `NbglHomeAndSettings` in `src/app_ui/menu.rs`
- Transaction and address review via `NbglReview` with `Field` arrays (`src/app_ui/sign.rs`)
- Device glyphs via `include_gif!()` in `src/app_ui.rs`

## Build & Test Workflow

**Building** (requires the Ledger Docker image or the VS Code extension):
```bash
cargo ledger build flex          # one of: nanox | nanosplus | stax | flex | apex_p
# output: target/<target>/release/zcash
```

**Functional tests with Ragger**:
```bash
pip install -r tests/standalone/requirements.txt
pytest tests/standalone/ --device flex        # device names differ from cargo targets: nanos+ -> nanosp
```
Tests use the `ZcashCommandSender` client in `tests/application_client/` and `scenario_navigator` for UI
automation. Build APDUs from named fields with `struct.pack`; raw hex payloads are against the test rules.
Never delete snapshots by hand; regenerate deliberately with `--golden_run` scoped by `-k`.

**Crypto crate unit tests**:
```bash
cargo test -p ledger_zcash_crypto --features unit_test --target apex_p
```
These are SDK `TestType` cases run by `sdk_test_runner` under Speculos, not `#[test]` functions. Without the
feature and a device target they compile away and the run reports success over an empty set.

## Key Patterns

**Error Handling**: handlers return `Result<(), AppSW>`. Never use `unwrap()` or `expect()` outside
`build.rs` and cases where failure is genuinely impossible and commented as such. Map SDK errors to specific
`AppSW` variants.

**BIP32 Paths**: length byte + 4-byte chunks; `Bip32Path` in `src/utils/bip32_path.rs` validates the format
via `TryFrom<&[u8]>`. Derivation is restricted to the coin-specific prefixes declared in `Cargo.toml`
(`[package.metadata.ledger] path`).

**Cryptography**: never reimplement primitives in app code — call the SDK, or `ledger_zcash_crypto` for the
Pallas/Sinsemilla/RedPallas work this chain needs. Shielded key derivation goes through `src/zip32.rs`.
Vendored forks of `orchard`, `sapling-crypto` and `reddsa` live in `vendor/`; the local delta is described by
`vendor/patches/`, and changing a vendored crate means regenerating those.

**Settings Storage**: NVM via `AtomicStorage` in `src/settings.rs`, linked to the `.nvm_data` section and
surfaced through the `NbglHomeAndSettings` switch UI.

**Device-Specific Code**: `#[cfg(target_os = "...")]` for glyphs, icons and screen differences between Nano
and the touch devices.

## Critical Constraints

- `#![no_std]`: use `alloc::vec::Vec`, `alloc::format!`, never `std::`
- Heap is 8192 bytes by default; the declared wire bounds are larger than it, so do not assume an allocation
  succeeds, and do not raise a bound without checking what it costs at runtime
- Stack is the binding limit on Nano X: avoid recursion, keep large values off shared frames, and use
  `#[inline(never)]` where a frame would otherwise be coalesced into a caller's
- APDU payload is at most 255 bytes per packet; anything larger is streamed and must be bounded before
  being accumulated
- Transaction review must reach `show_status_and_home_if_needed()` so NBGL displays the success or failure
  screen
