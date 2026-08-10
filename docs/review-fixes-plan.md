# Review Fixes Plan — PR #32 Must-Fix Items

## Context

PR #32 (`feat/zcash-integration/ironwood-pczt-v2`) received a review (semeano, 2026-08-06)
with one blocking HIGH finding and one JIRA/description update. These are the only items
that must be fixed before merge.

## Global Constraints

- Branch: `feat/zcash-integration/ironwood-pczt-v2`
- Worktree root: `.workspace/firmware/app-zcash/.worktrees/ironwood-pczt-v2`
- All commits must follow the existing commit style (lowercase imperative, no AI mentions)
- No new behaviour must be introduced — only fill-in existing placeholders and fix descriptions
- Docker image for tests: `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest`
- Mount project root to `/app` inside the container
- The test file is `tests/standalone/test_pczt_ironwood.py`
- The generator test is in `vendor/orchard/src/note_encryption.rs::gen_v3_ironwood_test_vectors`

## Task 1 — Generate V3 test vectors and unblock `test_pczt_ironwood_v3_real_output_accepted`

### Objective

Run the `gen_v3_ironwood_test_vectors` Rust test inside Docker to produce the three
placeholder constants that `test_pczt_ironwood_v3_real_output_accepted` needs, fill them
in, and lift the `@pytest.mark.skip`.

### Background

`test_pczt_ironwood_v3_real_output_accepted` (test_pczt_ironwood.py:1202) is currently
decorated with `@pytest.mark.skip` and contains three placeholder constants:

```python
_V3_REAL_EPK = bytes(32)   # replace with gen_v3_ironwood_test_vectors output
_V3_REAL_CMX = bytes(32)   # replace with gen_v3_ironwood_test_vectors output
_V3_REAL_ENC_CIPHERTEXT = bytes(580)  # replace with gen_v3_ironwood_test_vectors output
```

The generator (`vendor/orchard/src/note_encryption.rs::gen_v3_ironwood_test_vectors`) is
deterministic: it uses fixed inputs (recipient = `_INTERNAL_RECIPIENT`, nullifier =
`_DUMMY_NULLIFIER`, rseed = 0x35||zeros, esk = 0x37||zeros, value = 10000, NoteVersion::V3)
and prints Python-formatted hex constants for `_V3_REAL_EPK`, `_V3_REAL_CMX`, and
`_V3_REAL_ENC_CIPHERTEXT`.

### Why Docker is needed

`vendor/orchard` depends on `ledger_zcash_crypto`, which depends on `ledger_device_sdk`
(a no_std embedded crate). This does not compile on macOS. Inside Docker with the Ledger
dev-tools image, the `unit_test` feature on `ledger_zcash_crypto` enables a host-compatible
mock environment.

### Steps

1. Add `features = ["unit_test"]` to `ledger_zcash_crypto` dev-dependency in
   `vendor/orchard/Cargo.toml.orig`. Since `Cargo.toml` in vendor is auto-generated,
   edit `Cargo.toml.orig` and also reflect the change in `Cargo.toml` by adding:
   ```toml
   [dev-dependencies.ledger_zcash_crypto]
   path = "../../ledger_zcash_crypto"
   features = ["unit_test"]
   ```
   This enables `unit_test` only for test builds, not for the app firmware.

2. Run in Docker (mount project root to `/app`):
   ```bash
   cd /app/vendor/orchard && cargo test -- gen_v3_ironwood_test_vectors --nocapture 2>&1
   ```
   If that fails because `-p orchard` is needed, try from the project root:
   ```bash
   cd /app && cargo test -p orchard -- gen_v3_ironwood_test_vectors --nocapture 2>&1
   ```
   Capture the output. It will contain lines like:
   ```
   _V3_REAL_EPK = bytes.fromhex(
       "..."
   )
   _V3_REAL_CMX = bytes.fromhex(
       "..."
   )
   _V3_REAL_ENC_CIPHERTEXT = bytes.fromhex(
       "..."
   )
   ```

3. In `tests/standalone/test_pczt_ironwood.py`:
   a. Replace the three `bytes(32)` / `bytes(580)` placeholders (lines ~1225-1227) with the
      actual hex values from the generator output. Use the `bytes.fromhex(...)` syntax as
      printed.
   b. Remove the `@pytest.mark.skip(...)` decorator from
      `test_pczt_ironwood_v3_real_output_accepted` (lines ~1202-1209).
   c. The test's skip message currently says:
      "Unblock by running `gen_v3_ironwood_test_vectors` in vendor/orchard under Speculos..."
      Remove this entire multi-line skip decorator.

4. Run the new test in Docker with `--golden_run` to generate its snapshot:
   ```bash
   cd /app && pytest tests/standalone/ -k "test_pczt_ironwood_v3_real_output_accepted" \
     --device nanosp --golden_run -v 2>&1
   ```
   Then run without `--golden_run` to confirm it passes:
   ```bash
   cd /app && pytest tests/standalone/ -k "test_pczt_ironwood_v3_real_output_accepted" \
     --device nanosp -v 2>&1
   ```
   Repeat for the other devices listed in `ledger_app.toml`.

5. Commit everything: Cargo.toml changes, test file changes, new snapshot files.

### Acceptance criteria

- `test_pczt_ironwood_v3_real_output_accepted` is NOT decorated with `@pytest.mark.skip`
- The three placeholder constants contain real hex values (not `bytes(32)` / `bytes(580)`)
- The test passes on all supported devices without `--golden_run`

---

## Task 2 — Update PR #32 description

### Objective

Fix three factual errors in the PR body and link the JIRA ticket.

### Steps

1. Update the PR body on GitHub using `gh pr edit 32 --repo LedgerHQ/app-zcash`:
   a. **G4 description**: Replace "The note commitment check is skipped for V3 (V3 formula not on-device)"
      with: "For V3, the device recomputes `cmx` using `note_commitment_v3` (ZIP 2005 quantum-recoverable formula) and verifies it against the wire-supplied value. The cmx skip applies only to zero-value dummy outputs (G5)."
   b. **Test count**: Replace "6 new Ragger tests" with "9 new Ragger test functions (8 executing, 1 previously skipped — now unblocked by this fix)".
   c. **Version bump checklist**: Change the unchecked box `[ ] Application version has been bumped` to `[x] Application version has been bumped` and update the inline comment to: "Bumped 3.8.0→3.9.0 in this PR; deferred from base Ironwood branch."
   d. **JIRA ticket**: The PR body starts with `Closes NAPPS-[MISSING]` — this requires creating the JIRA ticket first. Leave this item with a note: `Closes NAPPS-[MISSING] <!-- JIRA ticket must be linked before merge — see below -->`. Do NOT fabricate a ticket number.
   e. **Internal planning reference**: Remove `IW-DEV-05-pczt-v2-enablement` from the Related section — replace with just the spec file path reference, no internal planning ID.

### Acceptance criteria

- PR description G4 accurately describes `note_commitment_v3` recomputation
- Test count updated to reflect the correct number
- Version bump checklist item is checked
- Internal planning ID `IW-DEV-05` is removed from the PR body
