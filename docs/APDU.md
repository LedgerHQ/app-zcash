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

## INS_GET_WALLET_PUBLIC_KEY

- INS: `0x40`
- P1:
  - `0x00`: derive without displaying the address
  - `0x01`: display the transparent address for user approval
- P2: `0x00`
- Data: BIP32 path.
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
  - P1 `0x00`: BIP32 account path.
  - P1 `0x80`: empty.
- Response:
  - P2 `0x00`: string response containing the UFVK.
  - P2 `0x01`: raw Orchard FVK bytes.

The response is chunked into APDU response payloads of at most 255 bytes. Use
P1 `0x80` with empty data until the full response has been collected. For UFVK,
the first two response bytes encode the total UTF-8 string length.

The command displays the requested viewing key on the device before returning
the first response chunk. User rejection returns `Deny` with an empty response.

## INS_GET_SHIELD_ADDR

- INS: `0x51`
- P1:
  - `0x00`: derive without displaying the address
  - `0x01`: display the address for user approval
- P2:
  - `0x00`: unified address string response
  - `0x01`: raw Orchard address bytes
- Data: BIP32 account path.
- Response:
  - P2 `0x00`: string response containing the unified address.
  - P2 `0x01`: raw Orchard address bytes.

If P1 is `0x01` and the user rejects the address, the command returns `Deny`
with an empty response.

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

## INS_PCZT_ORCHARD_ACTION

- INS: `0x56`
- P1:
  - `0x00`: first APDU packet for this command
  - `0x80`: continuation APDU packet
  - `0x01`: last APDU packet for this command
- P2:
  - `0x00`: PCZT data continues in later PCZT bundle commands
  - `0x01`: this is the final PCZT data APDU
- Data: Orchard action fields, or action count `0` when there are no Orchard
  actions.
- Response: empty.

This command is still sent when a transaction has no Orchard actions. In that
case its payload is only the CompactSize action count `0`, and P2 `0x01` marks
the PCZT payload as complete. See [PCZT_APDU.md](./PCZT_APDU.md#pczt_orchard_action)
for the exact payload layout.

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

## INS_PCZT_SIGN_ORCHARD

- INS: `0x57`
- P1: `0x00`
- P2: Orchard action index to sign.
- Data: empty.
- Response: Orchard spend authorization signature `[u8; 64]`.

The full PCZT payload must have been received and finalized before this command
is accepted. Each Orchard action can be signed only once.
