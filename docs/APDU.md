# APDU commands

This document describes the app-specific APDU commands used by the Zcash app.
All commands use `CLA = 0xE0`. Unless stated otherwise, `P2 = 0x00` and the
APDU data payload is at most 255 bytes.

The standard BIP32 path encoding used by key/address commands is:

- `path_len u8`
- `path_len` big-endian `u32` path components

Example: `m/32'/133'/0'` is encoded as one length byte `0x03`, followed by
three big-endian `u32` components.

String responses are encoded as:

- `len u16` big-endian UTF-8 byte length
- UTF-8 bytes

PCZT command payload framing is documented separately in
[PCZT_APDU.md](./PCZT_APDU.md).

## Status words

Beyond `0x9000`, these are the app-specific codes a host has to map. Each is
stated again with the command that returns it.

| Status word | Name | Meaning |
| --- | --- | --- |
| `0x6986` | `ConditionsOfUseNotSatisfied` | The request contradicts what the user approved — chiefly a change output whose account is not the one being spent. |
| `0xB007` | `BadState` | The command has no meaning in the current phase: a continuation opened before the review, or any round resuming a finished transaction. |
| `0x6A80` | `IncorrectData` | Malformed payload, or a derivation path outside the shape the command accepts. |
| `0x6A84` | `NotEnoughMemorySpace` | An allocation the device refused: retained memo text past its per-transaction budget, or an Orchard derivation past the per-run cap. |
| `0x6B00` | `WrongP1P2` | The P1/P2 combination has no meaning for this command. |
| `0x6F03` | `RngFailure` | The hardware random number generator reported a failure. No signature is produced. |
| `0x6985` | `Deny` | The user rejected the review. |

Under swap, refusals reach the host as `IncorrectData`: the Exchange app maps
every application error code onto it, so the finer codes this app defines serve
its own logs rather than host discrimination.

`0x6901` `CmdNotAccepted` comes from the device SDK, not from this app. From SDK
1.37 the legacy I/O layer refuses a frame it takes for an APDU while a review is
on screen, and it can answer the first display command of a session. A host does
better to tolerate and retry it than to surface it as a failure.

## Accepted derivation paths

The app is installed with two BIP32 prefixes: `44'/133'` for the transparent tree
and `32'/133'` for the shielded one. The OS refuses anything outside them, but the
app checks the prefix itself and answers `IncorrectData` (`0x6A80`), because an OS
refusal surfaces through the derivation syscall as an abort rather than as a
status word.

Beyond the prefix, each command constrains the shape it accepts, and the
constraint differs by purpose: signing needs to know whether a path is a change
path, whereas key export must not dictate a shape to the host. The requirement is
stated with each command below.

## Legacy transparent signing commands

Four commands implement the transparent and V4-Sapling signing flow the app inherits from
the legacy Bitcoin app: the host builds the transaction incrementally, and each input amount
is authenticated by a device-issued *trusted input* rather than trusted from the wire.

The INS values and their semantics are those of `app-bitcoin-legacy`
(`lib-app-bitcoin/apdu/apdu_constants.h`), whose `doc/btc.asc` specifies the payload framing.
Only the deviations below are Zcash-specific; the shielded flow uses the PCZT commands instead.

| INS | Name | P1 | P2 |
| --- | --- | --- | --- |
| `0x42` | `GET_TRUSTED_INPUT` | `0x00` first chunk, `0x80` next chunk | `0x00` |
| `0x44` | `HASH_INPUT_START` | `0x00` first chunk, `0x80` next chunk | `0x05` Sapling, `0x80` continue |
| `0x4A` | `HASH_INPUT_FINALIZE_FULL` | `0x00` more, `0x80` last, `0xFF` change info | `0x00` |
| `0x48` | `HASH_SIGN` | `0x00` | `0x00` |

Zcash deviations:

- V4, V5 and V6 transaction versions are all accepted; `P2 = 0x05` selects the Sapling variant
  and `0x80` continues an in-progress hash.
- Anchor streaming depends on the version: a V5 Orchard bundle commits to its anchor in the
  hashed preimage, whereas in a V6 transaction both shielded bundles moved the anchor to the
  authorizing digest (ZIP 229), which a trusted input never computes — so the host streams no
  anchor at all.
- `HASH_INPUT_FINALIZE_FULL` with `P1 = 0xFF` supplies change information, which the app uses
  to decide which outputs to display for approval. The change path must be a five-component
  BIP-44 path with purpose, coin type and account hardened and the address index unhardened,
  and its account must be the one the signing path spends from — otherwise the app parses the
  transaction but refuses to sign it, with `ConditionsOfUseNotSatisfied` (`0x6986`) on the
  `0x48` that asks for the signature. Change is filtered out of the review, so an output
  returning to another account would otherwise be paid without ever being displayed.
- **The review runs on the first `HASH_SIGN`, not at the end of `HASH_INPUT_FINALIZE_FULL`.**
  `locktime` and `expiry_height` only reach the device with the eleven-byte header that
  `HASH_SIGN` carries, so reviewing earlier would ask the user to approve a transaction whose
  validity window is still unknown and which the host could then choose freely. The host order
  is unchanged — `0x4A` outputs, then the eleven-byte `0x48` header, then `0x44`
  FIRST+CONTINUE, then the `0x48` that asks for the signature — but the APDU that carries a
  user refusal is now the first `0x48` rather than the last `0x4A`.
- A `HASH_INPUT_START` continuation (`P2 = 0x80`) is refused before the review has happened or
  after the transaction has completed, and no legacy round may resume a transaction the device
  has already finished. Both answer `BadState` (`0xB007`).

## INS_GET_WALLET_PUBLIC_KEY

- INS: `0x40`
- P1:
  - `0x00`: derive without displaying the address
  - `0x01`: display the transparent address for user approval
- P2: `0x00`
- Data: BIP32 path. Only the prefix is constrained — purpose `44'` or `32'`
  followed by the Zcash coin type, both hardened — so the host may request the
  two-component prefix itself, an account-level path, or any deeper one. A path
  outside the two prefixes, or one whose prefix components are not hardened,
  returns `IncorrectData`. The hardening bit is part of the comparison: the app
  declares `44'/133'` and `32'/133'`, so an unhardened prefix is a path the OS
  will not derive, and it answers that by taking the app down rather than with a
  status word.
- Response:
  - `public_key_len u8`
  - secp256k1 public key bytes, currently 65 bytes
  - `address_len u8`
  - transparent address ASCII bytes
  - chain code `[u8; 32]`

If P1 is `0x01` and the user rejects the address, the command returns `Deny`
with an empty response.

## INS_GET_FIRMWARE_VERSION

- INS: `0xC4`
- P1: `0x00`
- P2: `0x00`
- Data: empty.
- Response: 8 bytes:
  - legacy version prefix `0x38`
  - architecture id `0x30`
  - app major version `u8`
  - app minor version `u8`
  - app patch version `u8`
  - SDK major version `u8`
  - SDK minor version `u8`
  - API level `u8`

## INS_GET_VK

- INS: `0x50`
- P1:
  - `0x00`: start a viewing-key response
  - `0x80`: continue a pending viewing-key response
- P2:
  - `0x00`: unified full viewing key
  - `0x01`: Orchard full viewing key bytes
- Data:
  - P1 `0x00`, P2 `0x00`: Orchard BIP32 account path followed by transparent BIP32 account path.
  - P1 `0x00`, P2 `0x01`: Orchard BIP32 account path.
  - P1 `0x80`: empty.

  Both P2 modes require the Orchard path to be exactly the three-component ZIP-32
  account form `m/32'/<coin_type>'/<account>'`, with purpose and coin type
  hardened and the account hardened; the transparent path of the unified mode must
  likewise be the three-component account form `m/44'/<coin_type>'/<account>'`,
  with purpose and coin type compared hardening bit included and the account
  hardened. The two accounts must match. Anything else returns `IncorrectData`.
  The restriction applies to both modes, not only the unified one: a viewing key
  exposes an account's entire shielded history, and the confirmation screen shows
  the key bytes rather than the path it came from.
- Response:
  - P2 `0x00`: string response containing the UFVK.
  - P2 `0x01`: raw Orchard FVK bytes.

The response is chunked into APDU response payloads of at most 255 bytes. Use
P1 `0x80` with empty data until the full response has been collected. For UFVK,
the first two response bytes encode the total UTF-8 string length.

The command displays the requested viewing key on the device before returning
the first response chunk, naming the account the key belongs to alongside it.
User rejection returns `Deny` with an empty response.

Both P2 modes derive an Orchard key, so this command draws on the same
per-run derivation cap as `INS_GET_SHIELD_ADDR` and answers
`NotEnoughMemorySpace` (`0x6A84`) past it.

## INS_GET_SHIELD_ADDR

- INS: `0x51`
- P1:
  - `0x00`: derive without displaying the address
  - `0x01`: display the address for user approval, accepted with P2 `0x00` only
- P2:
  - `0x00`: unified address string response
  - `0x01`: raw Orchard address bytes
- Data:
  - P2 `0x00`: Orchard BIP32 account path followed by transparent BIP32 address path.
  - P2 `0x01`: Orchard BIP32 account path.
- Response:
  - P2 `0x00`: string response containing the unified address.
  - P2 `0x01`: raw Orchard address bytes.

If P1 is `0x01` and the user rejects the address, the command returns `Deny`
with an empty response.

P1 `0x01` combined with P2 `0x01` returns `WrongP1P2` (`0x6B00`), before any
derivation, so a request destined for rejection consumes no Secure Element
resources. A raw Orchard receiver
has no encoding the holder could read back against their own wallet, so there
is no screen this mode could show, and answering a request for the user's
confirmation without asking for it is what the refusal prevents.

Both P2 modes derive an Orchard key, and the Secure Element does not reclaim
what such a derivation consumes until the next power cycle. The app therefore
caps the derivations of one run and answers `NotEnoughMemorySpace` (`0x6A84`)
past the cap. The ceiling sits well above a session of normal use.

## INS_PCZT_HEADER

- INS: `0x52`
- P1: `0x00`
- P2: `0x00`
- Data: PCZT magic bytes, PCZT version, and `common::Global` fields.
- Response: empty.

This command resets the transaction context and starts a new PCZT payload. It
must be sent exactly once before any PCZT bundle command. See
[PCZT_APDU.md](./PCZT_APDU.md#pczt_header) for the exact payload layout.

## INS_PCZT_TRANSPARENT_INPUT

- INS: `0x53`
- P1:
  - `0x00`: first APDU packet for this command
  - `0x80`: continuation APDU packet
  - `0x01`: last APDU packet for this command
- P2:
  - `0x00`: PCZT data continues in later PCZT bundle commands
- Data: transparent input fields.
- Response: empty.

This command is always sent, even when the transparent input count is `0`; in
that case the payload contains only CompactSize input count `0`. See
[PCZT_APDU.md](./PCZT_APDU.md#pczt_transparent_input) for the exact payload
layout.

## INS_PCZT_TRANSPARENT_OUTPUT

- INS: `0x54`
- P1:
  - `0x00`: first APDU packet for this command
  - `0x80`: continuation APDU packet
  - `0x01`: last APDU packet for this command
- P2:
  - `0x00`: PCZT data continues in later PCZT bundle commands
- Data: transparent output fields.
- Response: empty.

This command is always sent, even when the transparent output count is `0`; in
that case the payload contains only CompactSize output count `0`. See
[PCZT_APDU.md](./PCZT_APDU.md#pczt_transparent_output) for the exact payload
layout.

An output's `script_pubkey` must be a standard P2PKH or P2SH script. Any other
form, including OP_RETURN, is refused with `IncorrectData`.

## INS_PCZT_ORCHARD_ACTION

- INS: `0x56`
- P1:
  - `0x00`: first APDU packet for this command
  - `0x80`: continuation APDU packet
  - `0x01`: last APDU packet for this command
- P2:
  - `0x00`: PCZT data continues in later PCZT bundle commands
  - `0x01`: this is the final PCZT data APDU (V5 transactions only)
- Data: Orchard action fields, or action count `0` when there are no Orchard
  actions.
- Response: empty.

This command is still sent when a transaction has no Orchard actions. In that
case its payload is only the CompactSize action count `0`.

The memo text a transaction's shielded outputs may keep for the review is
bounded. Past the budget a memo is shown as its hash instead of its text, and
past that the command returns `NotEnoughMemorySpace` (`0x6A84`). The budget
holds two maximum-length memos, well above what a wallet-built transaction
carries. The same applies to `INS_PCZT_IRONWOOD_ACTION`, which shares the
rendering.

For **V5 transactions**, `P2 = 0x01` on the last APDU marks the PCZT payload
as complete. For **V6 transactions**, the last APDU of this command must use
`P2 = 0x00`; the FINISHED marker moves to the last
`INS_PCZT_IRONWOOD_ACTION` packet instead. See
[PCZT_APDU.md](./PCZT_APDU.md#pczt_orchard_action) for the exact payload
layout.

## INS_PCZT_SIGN_TRANSPARENT

- INS: `0x55`
- P1: `0x00`
- P2: transparent input index to sign.
- Data: empty.
- Response:
  - DER-encoded secp256k1 signature bytes
  - `sighash_type u8`, currently `0x01` (`SIGHASH_ALL`)

The full PCZT payload must have been received and finalized before this command
is accepted. Each transparent input can be signed only once.

If the payload declared a transparent change output, its account must be the one
this input spends from; otherwise the command returns
`ConditionsOfUseNotSatisfied` (`0x6986`) and no signature is produced. Change is
filtered out of the review, so an output returning to another account would
otherwise be hidden from the user while still being paid.

The same check guards every command that releases a signature over the approved
digest — `INS_PCZT_SIGN_ORCHARD`, `INS_PCZT_SIGN_IRONWOOD` and legacy
`HASH_SIGN` — since any one of them alone is enough to redirect the change.

## INS_PCZT_SIGN_ORCHARD

- INS: `0x57`
- P1: `0x00`
- P2: Orchard action index to sign.
- Data: empty.
- Response: Orchard spend authorization signature `[u8; 64]`.

The full PCZT payload must have been received and finalized before this command
is accepted. Each Orchard action can be signed only once.

If the payload declared a transparent change output, its account must be the one
this action spends from; otherwise the command returns
`ConditionsOfUseNotSatisfied` (`0x6986`) and no signature is produced. A shielded
spend can pay transparent change, and that change is filtered out of the review,
so the account binding is checked here as it is on the transparent path.

## INS_PCZT_IRONWOOD_ACTION

- INS: `0x58`
- P1:
  - `0x00`: first APDU packet for this command
  - `0x80`: continuation APDU packet
  - `0x01`: last APDU packet for this command
- P2:
  - `0x00`: PCZT data continues in later PCZT bundle commands
  - `0x01`: this is the final PCZT data APDU (V6 transactions only)
- Data: Ironwood action fields. The wire layout per action is identical to
  `INS_PCZT_ORCHARD_ACTION`.
- Response: empty. The device prompts the user for review after receiving the
  FINISHED marker.

The Ironwood action count must be at least `1`; a count of `0` is rejected.
`P2 = 0x01` on the last packet of this command marks the full V6 PCZT payload
as complete and triggers the device review screen. See
[PCZT_APDU.md](./PCZT_APDU.md#pczt_ironwood_action) for the exact payload
layout.

## INS_PCZT_SIGN_IRONWOOD

- INS: `0x59`
- P1: `0x00`
- P2: Ironwood action index to sign.
- Data: empty.
- Response: Ironwood spend authorization signature `[u8; 64]` (RedPallas
  SpendAuthSig, identical primitive to Orchard).

The full PCZT payload must have been received and finalized before this command
is accepted. Each Ironwood action can be signed only once.

If the payload declared a transparent change output, its account must be the one
this action spends from; otherwise the command returns
`ConditionsOfUseNotSatisfied` (`0x6986`) and no signature is produced — the same
binding as on the Orchard and transparent signing paths.
