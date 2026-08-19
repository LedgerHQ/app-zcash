# Changelog

## 3.9.2

- Require a five-component BIP-44 path for a change output, so a ZIP-32 account path can no longer
  be accepted as change and remove an output from the review screen
- Restrict the derivation paths accepted by public-key and viewing-key export to the app's own
  prefixes, and answer with a status word where the derivation syscall aborted
- Include the Ironwood node in the signature digest of every V6 transaction, with its empty-input
  value when the bundle carries no action, and accept an empty Ironwood bundle (ZIP 229)
- Reject an Ironwood bundle on a transaction that declared V5
- Accept only the documented P1 values for `GET_TRUSTED_INPUT`
- Refuse a trusted input for an output index the transaction does not contain
- Refuse a V4 transaction carrying shielded components, whose txid this parser does not cover
- Bound the legacy parser's shielded component counts and the PCZT transparent script size
- Build `pasta_curves` with `repr-c`, which the point conversion in `ledger_zcash_crypto` relies on,
  and enforce the layout with a compile-time assertion
- Stop the reply to an unsupported instruction from varying with P1/P2
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
