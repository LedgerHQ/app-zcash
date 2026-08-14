# Changelog

## 3.9.2

- Bound the Ironwood PCZT parser's stack usage to the Orchard path's, and keep the Orchard and
  Ironwood note ciphertexts off the action-finalisation frame
- Reject a V2 note plaintext version byte in an Ironwood bundle
- Refuse to sign when a shielded output address cannot be encoded, instead of displaying raw bytes
- Zeroize the account's Orchard viewing keys along with the transaction context
- Return an error instead of panicking when the spend authorizing key derives to zero
- Run the `ledger_zcash_crypto` unit tests under the SDK test harness
- Update the vendored `orchard` to 0.15.5 and `zcash_primitives` to 0.30.0

## 3.9.1

- Recompute the Ironwood spend nullifier from the V3 note commitment
- Verify the recomputed `cmx` for V3 dummy outputs
- Restrict V3 note plaintext acceptance to the Ironwood pool

## 3.9.0

- Add PCZT v2 support (Ironwood NoteVersion::V3 outputs)

## 3.8.0

- Extend private address flow with public address

## 3.7.0

- Various security fixes

## 3.6.0

- Add PCZT support

## 3.5.0

- Add clear signing support for Orchard transactions

## 3.4.0

- Add support for the NU6.2 branch ID (0x5437f330).

## 3.3.0

- Add support for Orchard shielded transactions

## 3.2.0

- Always prompt the user on the `GET_VK` command.

## 3.1.0

### Added

- Added the `GET_VK` and `GET_SHIELD_ADDR` commands.

## 3.0.0

### Changed

- Ported the application to Rust with full feature parity with the original implementation.
