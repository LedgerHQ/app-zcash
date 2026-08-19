# PCZT APDU framing

This document describes the APDU `data` framing used by the app-specific
`PCZT_*` commands. Every APDU `data` payload MUST be at most 255 bytes.

The byte order inside fields follows the compact PCZT subset parsed by the app:
`Pczt` header and `common::Global` are sent once in `PCZT_HEADER`, followed by
transparent or Orchard bundle fields in the same order as the `pczt` crate
structs. Fields marked `SKIPPED` in the Rust parser are not sent.

PCZT `bip32_derivation` and `zip32_derivation` paths use the standard app
`Bip32Path` encoding: `path_len u8` followed by that many big-endian `u32`
components.

## Common rules

- The bundle command order is fixed:
  `PCZT_HEADER`, then `PCZT_TRANSPARENT_INPUT`, then
  `PCZT_TRANSPARENT_OUTPUT`, then `PCZT_ORCHARD_ACTION`, and for V6
  transactions `PCZT_IRONWOOD_ACTION`.
- `PCZT_HEADER` is sent exactly once and contains only the `Pczt` header and
  `common::Global` fields.
- `PCZT_TRANSPARENT_INPUT` and `PCZT_TRANSPARENT_OUTPUT` are always sent. Use
  count `0` when either transparent section is empty.
- `PCZT_ORCHARD_ACTION` is always sent. Use Orchard action count `0` when the
  transaction has no Orchard actions.
- `PCZT_IRONWOOD_ACTION` is always sent for a V6 transaction, and only for one.
  Use Ironwood action count `0` when the transaction has no Ironwood actions;
  omitting the command leaves a V6 transaction unsignable, because V6 defers the
  user review to Ironwood finalization. See "Empty Ironwood bundle" below.
- `P1_FIRST`, `P1_NEXT`, and `P1_LAST` frame the APDU packet sequence for one
  `PCZT_*` command.
- A one-packet command uses `P1_FIRST`.
- `P2_PCZT_CONTINUE` means more PCZT bundle commands may still follow.
- `P2_PCZT_FINISHED` is set on the last APDU packet of the **last bundle
  command**. For V5 transactions this is the last packet of
  `PCZT_ORCHARD_ACTION`. For V6 transactions this is the last packet of
  `PCZT_IRONWOOD_ACTION`; the last `PCZT_ORCHARD_ACTION` packet must use
  `P2_PCZT_CONTINUE` instead. Signing commands are accepted only after this
  marker.
- Small neighboring fields may be grouped into one APDU packet.
- Large `Vec<u8>` fields are sent as their own APDU packet sequence. The first
  packet contains the CompactSize byte length followed by field bytes. If the
  field does not fit in one APDU, following packets continue with only field
  bytes.
- `bip32_derivation` and `zip32_derivation` fields MUST each fit in, and be sent
  as, one APDU packet.
- The current app limits are: at most 10 transparent inputs, at most 10
  transparent outputs, at most 10 Orchard actions, and at most 10 Ironwood
  actions.
- A transparent `script_pubkey` is at most 252 bytes. Every transparent input's
  script is retained for the whole session, so the bound is what keeps ten of
  them inside the device heap. 252 is also the largest value a one-byte
  CompactSize encodes, which is the limit the host applies on its own side.

## PCZT_HEADER

Single packet:

- magic bytes `PCZT`
- PCZT version `u32`
- `common::Global`:
  - `tx_version u32`
  - `version_group_id u32`
  - `consensus_branch_id u32`
  - `fallback_lock_time Option<u32>`
  - `expiry_height u32`
  - `coin_type u32`
  - `tx_modifiable u8`

The PCZT version field encodes the PCZT wire-format revision:

- Version `1` is required for V5 (Orchard) transactions.
- Version `2` is required for V6 (Ironwood) transactions.

The app rejects a mismatch between the PCZT version and the transaction version.

## PCZT_TRANSPARENT_INPUT

Packet sequence:

1. Count packet:
   - transparent input count as CompactSize

2. For each `transparent::Input`, in order:
   - Small input packet:
     - `prevout_txid [u8; 32]`
     - `prevout_index u32`
     - `sequence Option<u32>`
     - `value u64`
   - `script_pubkey Vec<u8>` packet sequence:
     - first packet: CompactSize byte length + script bytes
     - continuation packets: script bytes only
   - Signing data packet:
     - `sighash_type u8`, must be `SIGHASH_ALL`
     - `bip32_derivation` as one complete packet payload:
       - CompactSize entry count, currently exactly `1`
       - compressed public key `[u8; 33]`
       - seed fingerprint `[u8; 32]`
       - derivation path as `Bip32Path`

## PCZT_TRANSPARENT_OUTPUT

Packet sequence:

1. Count packet:
   - transparent output count as CompactSize

2. For each `transparent::Output`, in order:
   - Value packet:
     - `value u64`
   - `script_pubkey Vec<u8>` packet sequence:
     - first packet: CompactSize byte length + script bytes
     - continuation packets: script bytes only
   - `bip32_derivation` packet:
     - CompactSize entry count, currently `0` or `1`
     - if present, compressed public key `[u8; 33]`
     - if present, seed fingerprint `[u8; 32]`
     - if present, derivation path as `Bip32Path`

## PCZT_ORCHARD_ACTION

Packet sequence:

1. Count packet:
   - Orchard action count as CompactSize

2. For each `orchard::Action`, in order:
   - Spend small fields packet:
     - `cv_net [u8; 32]`
     - `nullifier [u8; 32]`
     - `rk [u8; 32]`
     - `spend_recipient [u8; 43]`, raw Orchard payment address
     - `spend_value u64`
     - `spend_rho [u8; 32]`
     - `spend_rseed [u8; 32]`
     - `alpha [u8; 32]`
   - `zip32_derivation` packet:
     - seed fingerprint `[u8; 32]`
     - derivation path as `Bip32Path`
   - Output small fields packet:
     - `cmx [u8; 32]`
     - `ephemeral_key [u8; 32]`
   - `enc_ciphertext Vec<u8>` packet sequence:
     - first packet: CompactSize byte length + ciphertext bytes
     - continuation packets: ciphertext bytes only
   - `out_ciphertext Vec<u8>` packet sequence:
     - first packet: CompactSize byte length + ciphertext bytes
     - continuation packets: ciphertext bytes only
   - Output metadata packet:
     - `recipient [u8; 43]`, raw Orchard payment address
     - `value u64`
     - `rseed [u8; 32]`
     - `rcv [u8; 32]`

3. Bundle trailer packet, only when Orchard action count is greater than `0`:
   - `flags u8`
   - `value_sum` magnitude `u64`
   - `value_sum` negative-sign flag `u8`
   - `anchor [u8; 32]`

### Orchard validation requirements

The app does not trust host-supplied Orchard display fields directly. Before an
action is accepted:

- `rk` is recomputed from the signing key selected by `zip32_derivation` and the
  disclosed `alpha`.
- `cv_net` must match `ValueCommitment(spend_value - value, rcv)`.
- `spend_recipient` must derive from the signing Orchard FVK's external or
  internal IVK.
- `nullifier` is recomputed from the signing FVK's `nk`, `spend_recipient`,
  `spend_value`, `spend_rho`, and `spend_rseed`.
- The output must decrypt with the prepared Orchard decipher keys. For
  decryptable outputs, the decrypted value and raw Orchard receiver must match
  `value` and `recipient`.
- A zero-valued undecryptable output is accepted only as a dummy output: the app
  recomputes the Orchard note commitment from `recipient`, `value == 0`, the
  action nullifier used as `rho`, and output `rseed`, and compares it with
  `cmx`. Validated dummy outputs are omitted from the clear-sign review list.
- Non-zero undecryptable outputs are rejected.

Dummy spends are not represented by this compact APDU subset.

## PCZT_IRONWOOD_ACTION

Sent only for V6 transactions. The per-action wire layout is identical to
`PCZT_ORCHARD_ACTION` — the same packet types in the same order.

Packet sequence:

1. Count packet:
   - Ironwood action count as CompactSize. Count `0` is valid and carries no
     per-action or trailer packet — see "Empty Ironwood bundle" below.

2. For each Ironwood action, in order: same packet sequence as
   `PCZT_ORCHARD_ACTION` per-action (spend small fields, `zip32_derivation`,
   output small fields, `enc_ciphertext`, `out_ciphertext`, output metadata).

3. Bundle trailer packet:
   - `flags u8`
   - `value_balance` magnitude `u64`
   - `value_balance` negative-sign flag `u8`
   - `anchor [u8; 32]` — committed to the Ironwood authorizing-data digest;
     not included in the txid sighash

The last APDU packet of the bundle trailer carries `P2_PCZT_FINISHED`,
triggering the device review screen and enabling signing commands. An empty
bundle has no trailer, so its count packet carries the marker instead.

### Empty Ironwood bundle

A V6 transaction that neither spends nor creates an Ironwood note — an
Orchard-only spend after NU6.3 — sends this command with action count `0` and
nothing else. The count packet is then the whole command, so it carries
`P1_FIRST` and, being also the last packet of the last bundle command,
`P2_PCZT_FINISHED`. It is what triggers the review screen.

Count `0` is accepted rather than rejected for two independent reasons:

- ZIP 229 makes `ironwood_digest_v6` a child of `txid_digest_v6` for **every** V6
  transaction, taking its empty-input value when the bundle has no actions. The
  node is part of the signed digest tree either way, exactly as the Orchard node
  is, so an empty bundle is not a transaction without an Ironwood commitment.
- A V6 transaction defers its user review to Ironwood finalization, so this
  command is where the review happens. Omitting it leaves the transaction
  reviewed by nothing and therefore unsignable — the device fails closed, but the
  host gets no diagnostic naming the missing section.

An Ironwood bundle on a transaction that declared V5 is rejected, whatever its
action count.

### Ironwood validation requirements

Ironwood action validation applies the same cryptographic checks as Orchard
(see above): `rk` recomputation, `cv_net` verification, recipient derivation,
`nullifier` recomputation, and output note-commitment check for dummy outputs.

**The Ironwood value pool carries V3 note plaintexts only.** One note plaintext version is valid
per value pool — Orchard holds V2, Ironwood holds V3 (`BundleVersion::note_version` upstream) — so a
plaintext belonging to the other pool is not a compatibility case to accommodate but a note this
bundle cannot hold.

When the output metadata packet is 116 bytes, the final byte is `notePlaintextVersion` and it **must
be `0x03`**. Any other value is rejected with "Bad PCZT ironwood notePlaintextVersion". The 115-byte
form (no `notePlaintextVersion` byte) is still valid and means `0x03`: the parser's per-action reset
leaves the field at that value, so the two encodings agree.

- Non-zero-value outputs: the device deciphers `enc_ciphertext` via the standard IVK/OVK
  trial-decryption path, which accepts a decrypted plaintext only if its lead byte is `0x03`. After
  successful decryption the device verifies `cmx` using the ZIP 2005 quantum-recoverable commitment
  formula (`note_commitment_v3`), whose BLAKE2b-512 rcm derivation additionally binds `g_d`, `pk_d`,
  `value`, `rho` and `psi`. This ties the displayed recipient and value to the exact `cmx` that
  enters the signature digest.
- Zero-value (dummy) outputs: the device recomputes `cmx` with the same V3 formula and verifies it
  against the wire value. Dummy outputs carry no displayed value or recipient; their value
  contribution is independently constrained via `cv_net`.

A V2-format ciphertext therefore does not decrypt in this pool. The output is then only accepted on
the dummy path, which requires a zero value **and** a `cmx` that matches the V3 recomputation — so a
genuine V2 note is refused rather than accepted under the V2 formula.
