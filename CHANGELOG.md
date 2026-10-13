# Changelog

## 3.9.5

Performance release. Validating a shielded transaction repeated work the same
transaction had already done; this removes the repetition without removing a check.
Replies also no longer wait for the next ticker event, which the SDK's new I/O path
allows once it refuses every APDU on a locked device.

- Reuse the account key, the viewing keys and the note material already derived for
  a transaction across its shielded actions, keeping every per-action account,
  randomized-key, ownership, nullifier and commitment check, and failing closed when
  an action names a different account
- Keep fixed and locally derived curve points in full coordinates instead of
  compressing and decoding them again before each operation
- Derive the viewing key and the spend authorizing key in a single pass, and retain
  the normalized authorizing scalar from the first action that spends so the later
  ones reuse it. A transaction that spends nothing never derives one
- Reuse the recipient already checked by ownership verification when validating the
  nullifier of the same action
- Compute each Sinsemilla step as one doubling and one addition instead of two
  additions, over the same refusals
- Compute the diversifier square-root ratio directly instead of inverting the divisor
  and searching for a root
- Drop the viewing keys once validation is over rather than at the end of the
  transaction, so they do not outlive the review wait, and wipe the full viewing key
  along with the incoming and outgoing ones
- Use the SDK's new I/O path (`io_new`) on every target: a reply leaves as soon as its
  command completes, instead of waiting for the next ticker event
- Require SDK 1.38.0. Its `io_new` path answers `DeviceLocked` to every APDU on a locked
  device, the SDK's own built-in commands included, and while a command is in flight
  answers only the built-in GET_VERSION: quit and certificate load received during a
  review are refused with `CmdNotAccepted`
- Reject an APDU whose payload length differs from its declared length
- Return to Exchange after a swap panic even when the error reply cannot be sent
- Count a reply the transport fails to deliver as a failed command: the transaction is
  reset, and a swap reports a failure to Exchange
- Reserve a shielded action's ciphertext buffer at its full size, and refuse with
  `NotEnoughMemorySpace` when it does not fit. It grew packet by packet, which needed
  about twice its size at once, and a failed growth exited the app: a t→z with 30 or
  more transparent inputs did so on every device
- Accept a shielded transaction's change split across several notes of the account
  being spent, as wallets do to keep part of the balance spendable while the rest
  confirms: up to five change notes beside one recipient, and four notes when
  shielding or rebalancing. The review still shows at most four shielded outputs, and
  at most six are retained, change notes included. A transparent change output stays
  single, and rules out a shielded one
- Refuse with `NotEnoughMemorySpace` a transaction whose remaining actions or review the
  heap cannot hold, instead of exiting the app: 32 transparent inputs beside 32 shielded
  actions, or beside four recipients and a change note, did so on every device

## 3.9.4

- Initialize the BLAKE2b context that hashes a shielded output's memo for the review. A memo
  holding any byte outside printable ASCII is shown as a digest rather than as text, and that
  digest was computed with a context the app never initialized

## 3.9.3

Security release addressing the findings of an external code security scan of 3.9.2.

- Draw the randomness of nonces and blinding factors through a syscall whose failure can be
  checked, and refuse to sign when it reports one, instead of signing over a buffer the device
  never filled
- Zeroize RedPallas signing keys and the secret intermediates of a signature, and redact them
  from debug formatting
- Zeroize the Orchard spending key, through a regenerated vendor patch so the change survives the
  next dependency refresh
- Stop logging the randomized spend authorizing key and the Orchard viewing key
- Refuse a `HASH_INPUT_START` continuation sent before the transaction has been reviewed or after
  it has completed, and refuse any legacy round that would resume a completed transaction
- Bind one Exchange approval to one signed transaction, so a partial signature on a multi-input
  transaction can no longer be followed by a second transaction under the same approval
- Cover `locktime` and `expiry_height` by the transaction review, which now runs on the header
  `HASH_SIGN` carries rather than at the end of the output stream
- Display the outputs of a transaction that pays only itself, which the change filter would
  otherwise have left with no visible destination and no visible amount
- Require the hardening BIP-44 mandates on a change path, and the app's own hardened prefixes on
  an exported derivation path
- Refuse to sign when a change output returns to a different account than the one being spent,
  on both the legacy and the PCZT paths, and whether that output is transparent or a shielded
  note the review never shows
- Refuse a transparent input whose scriptPubKey is not the 25-byte P2PKH shape, the only one the
  app can sign for, rather than signing over a script no key it derives can spend
- Raise the transparent input bound to a count measured on the smallest device, which pinning that
  shape makes affordable by fixing what each input retains
- Bound the input script size the legacy signing parser will allocate for
- Bound the Orchard derivations of one run, which the Secure Element does not reclaim before the
  next power cycle
- Refuse a swap amount or fee that Zcash cannot represent, rather than keeping its low 64 bits
- Refuse a swap whose destination carries an extra ID, which a transparent Zcash output has
  nowhere to hold
- Show each memo with the output it belongs to, under a label carrying that output's index
- Bound what a transaction's memos may claim on the heap, and allocate what is kept fallibly
- Refuse a request to display an address in the mode that has no displayable form
- Name the exported account on the viewing-key confirmation screen
- Move the Ledger SDK to 1.37.0, which refuses an APDU arriving while a command is still being
  processed

## 3.9.2

- Accept a P2SH (t3) `scriptPubKey` on a transparent output, displaying it for review instead of
  refusing the transaction outright
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
