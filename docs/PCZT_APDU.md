# PCZT APDU framing

This document describes the APDU `data` framing used by the app-specific
`PCZT_*` commands. Every APDU `data` payload MUST be at most 255 bytes.

The byte order inside fields follows the compact PCZT subset parsed by the app:
`Pczt` header and `common::Global` are sent once in `PCZT_HEADER`, followed by
transparent or Orchard bundle fields in the same order as the `pczt` crate
structs. Fields marked `SKIPPED` in the Rust parser are not sent.

## Common rules

- The bundle command order is fixed:
  `PCZT_HEADER`, then `PCZT_TRANSPARENT_INPUT`, then
  `PCZT_TRANSPARENT_OUTPUT`, then `PCZT_ORCHARD_ACTION`.
- `PCZT_HEADER` is sent exactly once and contains only the `Pczt` header and
  `common::Global` fields.
- `PCZT_TRANSPARENT_INPUT` and `PCZT_TRANSPARENT_OUTPUT` are always sent. Use
  count `0` when either transparent section is empty.
- `PCZT_ORCHARD_ACTION` is always sent. Use Orchard action count `0` when the
  transaction has no Orchard actions.
- `P1_FIRST`, `P1_NEXT`, and `P1_LAST` frame the APDU packet sequence for one
  `PCZT_*` command.
- A one-packet command uses `P1_FIRST`.
- `P2_PCZT_CONTINUE` means more PCZT bundle commands may still follow.
- `P2_PCZT_FINISHED` is valid only on the last APDU packet of
  `PCZT_ORCHARD_ACTION`. Signing commands are accepted only after this marker.
- Small neighboring fields may be grouped into one APDU packet.
- Large `Vec<u8>` fields are sent as their own APDU packet sequence. The first
  packet contains the CompactSize byte length followed by field bytes. If the
  field does not fit in one APDU, following packets continue with only field
  bytes.
- `bip32_derivation` and `zip32_derivation` fields MUST each fit in, and be sent
  as, one APDU packet.
- The current app limits are: at most 10 transparent inputs, at most 10
  transparent outputs, and at most 10 Orchard actions.

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
       - derivation path component count as CompactSize
       - derivation path components as little-endian `u32`

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
     - if present, derivation path component count as CompactSize
     - if present, derivation path components as little-endian `u32`

## PCZT_ORCHARD_ACTION

Packet sequence:

1. Count packet:
   - Orchard action count as CompactSize

2. For each `orchard::Action`, in order:
   - Spend small fields packet:
     - `cv_net [u8; 32]`
     - `nullifier [u8; 32]`
     - `rk [u8; 32]`
     - `alpha [u8; 32]`
   - `zip32_derivation` packet:
     - seed fingerprint `[u8; 32]`
     - derivation path component count as CompactSize
     - derivation path components as little-endian `u32`
   - Output small fields packet:
     - `cmx [u8; 32]`
     - `ephemeral_key [u8; 32]`
   - `enc_ciphertext Vec<u8>` packet sequence:
     - first packet: CompactSize byte length + ciphertext bytes
     - continuation packets: ciphertext bytes only
   - `out_ciphertext Vec<u8>` packet sequence:
     - first packet: CompactSize byte length + ciphertext bytes
     - continuation packets: ciphertext bytes only

3. Bundle trailer packet, only when Orchard action count is greater than `0`:
   - `flags u8`
   - `value_sum` magnitude `u64`
   - `value_sum` negative-sign flag `u8`
   - `anchor [u8; 32]`
