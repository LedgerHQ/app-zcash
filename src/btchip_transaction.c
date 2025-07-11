/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdbool.h>
#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_display_variables.h"

// Check if fOverwintered flag is set and if nVersion is >= 0x03
#define TRUSTED_INPUT_OVERWINTER (TX_IS_OVERWINTER && (TX_VERSION >= 0x03))

#define DEBUG_LONG "%d"

void check_transaction_available(unsigned char x) {
    if (btchip_context_D.transactionDataRemaining < x) {
        PRINTF("Check transaction available failed %d < %d\n", btchip_context_D.transactionDataRemaining, x);
        THROW(EXCEPTION);
    }
}

#define OP_HASH160 0xA9
#define OP_EQUAL 0x87
#define OP_CHECKMULTISIG 0xAE

void blake2b_256_init(cx_blake2b_t *blake2b_ctx, const uint8_t perso[static 16]) {
    CX_ASSERT(cx_blake2b_init2_no_throw(blake2b_ctx, 256, NULL, 0, (uint8_t *) perso, 16));
}

void blake2b_256_update(cx_blake2b_t *blake2b_ctx, const uint8_t *data, size_t len) {
    CX_ASSERT(cx_hash_no_throw(&blake2b_ctx->header, 0, data, len, NULL, 0));
}

void blake2b_256_final(cx_blake2b_t *blake2b_ctx, uint8_t digest[static DIGEST_SIZE]) {
    CX_ASSERT(cx_hash_no_throw(&blake2b_ctx->header, CX_LAST, NULL, 0, digest, DIGEST_SIZE));
}

unsigned char transaction_amount_add_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char carry = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short val = a[8 - 1 - i] + b[8 - 1 - i] + (carry ? 1 : 0);
        carry = (val > 255);
        target[8 - 1 - i] = (val & 255);
    }
    return carry;
}

unsigned char transaction_amount_sub_be(unsigned char *target,
                                        unsigned char *a,
                                        unsigned char *b) {
    unsigned char borrow = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        unsigned short tmpA = a[8 - 1 - i];
        unsigned short tmpB = b[8 - 1 - i];
        if (borrow) {
            if (tmpA <= tmpB) {
                tmpA += (255 + 1) - 1;
            } else {
                borrow = 0;
                tmpA--;
            }
        }
        if (tmpA < tmpB) {
            borrow = 1;
            tmpA += 255 + 1;
        }
        target[8 - 1 - i] = (unsigned char)(tmpA - tmpB);
    }

    return borrow;
}

void transaction_offset(unsigned char value) {
    if ((btchip_context_D.transactionHashOption & TRANSACTION_HASH_FULL) != 0) {
        // NOTE: if v4, we end up in the first condition
        if (btchip_context_D.usingOverwinter) {
            PRINTF("--- ADD TO HASH FULL offset:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
            CX_ASSERT(cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.transactionBufferPointer, value, NULL, 0));
        }
        else if (TX_VERSION != 5) {
            PRINTF("--- ADD TO HASH FULL offset:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
            CX_ASSERT(cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0));
        }
    }
    if ((btchip_context_D.transactionHashOption &
         TRANSACTION_HASH_AUTHORIZATION) != 0) {
        PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", value, btchip_context_D.transactionBufferPointer);
        CX_ASSERT(cx_hash_no_throw(&btchip_context_D.transactionHashAuthorization.sha256.header, 0,
                btchip_context_D.transactionBufferPointer, value, NULL, 0));
    }
}

void transaction_offset_increase(unsigned char value) {
    transaction_offset(value);
    btchip_context_D.transactionBufferPointer += value;
    btchip_context_D.transactionDataRemaining -= value;
}

unsigned long int transaction_get_varint(void) {
    unsigned char firstByte;
    check_transaction_available(1);
    firstByte = *btchip_context_D.transactionBufferPointer;
    if (firstByte < 0xFD) {
        transaction_offset_increase(1);
        return firstByte;
    } else if (firstByte == 0xFD) {
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(2);
        result =
            (unsigned long int)(*btchip_context_D.transactionBufferPointer) |
            ((unsigned long int)(*(btchip_context_D.transactionBufferPointer +
                                   1))
             << 8);
        transaction_offset_increase(2);
        return result;
    } else if (firstByte == 0xFE) {
        unsigned long int result;
        transaction_offset_increase(1);
        check_transaction_available(4);
        result =
            btchip_read_u32(btchip_context_D.transactionBufferPointer, 0, 0);
        transaction_offset_increase(4);
        return result;
    } else {
        PRINTF("Varint parsing failed\n");
        THROW(INVALID_PARAMETER);
        return 0;
    }
}

void transaction_parse(unsigned char parseMode) {
    unsigned char optionP2SHSkip2FA =
        ((N_btchip.bkp.config.options & BTCHIP_OPTION_SKIP_2FA_P2SH) != 0);
    btchip_set_check_internal_structure_integrity(0);
    BEGIN_TRY {
        TRY {
            for (;;) {
                switch (btchip_context_D.transactionContext.transactionState) {
                case BTCHIP_TRANSACTION_NONE: {
                    PRINTF("Init transaction parser\n");
                    // Reset transaction state
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs = 0;
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    btchip_context_D.transactionContext.scriptRemaining = 0;
                    memset(
                        btchip_context_D.transactionContext.transactionAmount,
                        0, sizeof(btchip_context_D.transactionContext
                                      .transactionAmount));
                    // TODO : transactionControlFid
                    // Reset hashes
                    if (btchip_context_D.usingOverwinter) {
                        if (btchip_context_D.segwitParsedOnce) {
                            uint8_t parameters[16];
                            memmove(parameters, OVERWINTER_PARAM_SIGHASH, 16);
                            memcpy(parameters + sizeof(parameters) - sizeof(btchip_context_D.consensusBranchId),
                                   btchip_context_D.consensusBranchId,
                                   sizeof(btchip_context_D.consensusBranchId));
                            if (cx_blake2b_init2_no_throw(&btchip_context_D.transactionHashFull.blake2b, 256, NULL, 0, parameters, 16)) {
                                goto fail;
                            }
                        }
                    }
                    else {
                        if (cx_sha256_init_no_throw(&btchip_context_D.transactionHashFull.sha256)) {
                            goto fail;
                        }
                    }
                    if (cx_sha256_init_no_throw(
                        &btchip_context_D.transactionHashAuthorization.sha256)) {
                        goto fail;
                    }
                    if (btchip_context_D.usingSegwit) {
                        btchip_context_D.transactionHashOption = 0;
                        if (!btchip_context_D.segwitParsedOnce) {
                            if (btchip_context_D.usingOverwinter) {
                                if (cx_blake2b_init2_no_throw(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, 256, NULL, 0, (uint8_t *)OVERWINTER_PARAM_PREVOUTS, 16)) {
                                    goto fail;
                                }
                                if (cx_blake2b_init2_no_throw(&btchip_context_D.transactionHashFull.blake2b, 256, NULL, 0, (uint8_t *)OVERWINTER_PARAM_SEQUENCE, 16)) {
                                    goto fail;
                                }
                            }
                            else {
                                if (cx_sha256_init_no_throw(
                                    &btchip_context_D.segwit.hash.hashPrevouts.sha256)) {
                                    goto fail;
                                }
                            }
                        } else {
                            PRINTF("Resume SegWit hash\n");
                            PRINTF("SEGWIT Version\n%.*H\n",sizeof(btchip_context_D.transactionVersion),btchip_context_D.transactionVersion);
                            PRINTF("SEGWIT HashedPrevouts\n%.*H\n",sizeof(btchip_context_D.segwit.cache.hashedPrevouts),btchip_context_D.segwit.cache.hashedPrevouts);
                            PRINTF("SEGWIT HashedSequence\n%.*H\n",sizeof(btchip_context_D.segwit.cache.hashedSequence),btchip_context_D.segwit.cache.hashedSequence);
                            if (btchip_context_D.usingOverwinter)
                                if (TX_VERSION == 5) {
                                    uint8_t header_digest[32];
                                    // Compute header_digest
                                    blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, NU5_PARAM_HEADERS);
                                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b,
                                                       btchip_context_D.transactionVersion,
                                                       sizeof(btchip_context_D.transactionVersion));

                                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.nVersionGroupId, sizeof(btchip_context_D.nVersionGroupId));
                                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b,
                                                       btchip_context_D.consensusBranchId,
                                                       sizeof(btchip_context_D.consensusBranchId));
                                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b,  btchip_context_D.nLockTime, sizeof(btchip_context_D.nLockTime));
                                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b,  btchip_context_D.nExpiryHeight, sizeof(btchip_context_D.nExpiryHeight));

                                    // Save header_digest
                                    blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, header_digest);
                                    memcpy(btchip_context_D.nu5_ctx.header_digest, header_digest, DIGEST_SIZE);
                                }
                                else {
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.transactionVersion, sizeof(btchip_context_D.transactionVersion), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.nVersionGroupId, sizeof(btchip_context_D.nVersionGroupId), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.segwit.cache.hashedPrevouts, sizeof(btchip_context_D.segwit.cache.hashedPrevouts), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.segwit.cache.hashedSequence, sizeof(btchip_context_D.segwit.cache.hashedSequence), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.segwit.cache.hashedOutputs, sizeof(btchip_context_D.segwit.cache.hashedOutputs), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0)) {
                                        goto fail;
                                    }
                                    if (btchip_context_D.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING) {
                                        if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0)) { // sapling hashShieldedSpend)
                                            goto fail;
                                        }
                                        if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, OVERWINTER_NO_JOINSPLITS, 32, NULL, 0)) { // sapling hashShieldedOutputs
                                            goto fail;
                                        }

                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.nLockTime, sizeof(btchip_context_D.nLockTime), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.nExpiryHeight, sizeof(btchip_context_D.nExpiryHeight), NULL, 0)) {
                                        goto fail;
                                    }
                                    if (btchip_context_D.usingOverwinter == ZCASH_USING_OVERWINTER_SAPLING) {
                                        unsigned char valueBalance[8];
                                        memset(valueBalance, 0, sizeof(valueBalance));
                                        if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, valueBalance, sizeof(valueBalance), NULL, 0)) { // sapling valueBalance
                                            goto fail;
                                        }
                                    }
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.sigHashType, sizeof(btchip_context_D.sigHashType), NULL, 0)) {
                                            goto fail;
                                    }
                            }
                            else {
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(btchip_context_D.transactionVersion), btchip_context_D.transactionVersion);
                                if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.sha256.header,
                                                     0,
                                                     btchip_context_D.transactionVersion,
                                                     sizeof(btchip_context_D.transactionVersion),
                                                     NULL,
                                                     0)) {
                                    goto fail;
                                }

                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(btchip_context_D.segwit.cache.hashedPrevouts), btchip_context_D.segwit.cache.hashedPrevouts);
                                if (cx_hash_no_throw(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.segwit.cache.hashedPrevouts,
                                    sizeof(btchip_context_D.segwit.cache
                                           .hashedPrevouts),
                                    NULL, 0)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(btchip_context_D.segwit.cache.hashedSequence), btchip_context_D.segwit.cache.hashedSequence);
                                if (cx_hash_no_throw(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.segwit.cache.hashedSequence,
                                    sizeof(btchip_context_D.segwit.cache
                                           .hashedSequence),
                                    NULL, 0)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH AUTH:\n%.*H\n", sizeof(btchip_context_D.segwit.cache), (unsigned char *)&btchip_context_D.segwit.cache);
                                if (cx_hash_no_throw(&btchip_context_D
                                         .transactionHashAuthorization.sha256.header,
                                    0,
                                    (unsigned char *)&btchip_context_D
                                        .segwit.cache,
                                    sizeof(btchip_context_D.segwit.cache),
                                    NULL, 0)) {
                                    goto fail;
                                }
                            }
                        }
                    }
                    // Parse the beginning of the transaction
                    // Version
                    check_transaction_available(4);
                    memcpy(btchip_context_D.transactionVersion,
                           btchip_context_D.transactionBufferPointer,
                           sizeof(btchip_context_D.transactionVersion));
                    transaction_offset_increase(4);

                    if (btchip_context_D.usingOverwinter ||
                        TRUSTED_INPUT_OVERWINTER) {
                        if (TX_VERSION == 5) {
                            // We will use this hash to compute prevouts digest
                            blake2b_256_init(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, NU5_PARAM_PREVOUT);

                            // We will use this hash to compute sequence digest
                            blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, NU5_PARAM_SEQUENC);

                            // We will use this hash to compute amounts_sig_digest
                            blake2b_256_init(&btchip_context_D.hashAmount.blake2b, NU5_PARAM_AMOUNTS);

                            // We will use this hash to compute scriptpubkeys_sig_digest
                            blake2b_256_init(&btchip_context_D.transactionHashAuthorization.blake2b, NU5_PARAM_SCRIPTS);
                        }

                        // nVersionGroupId
                        check_transaction_available(4);
                        memcpy(btchip_context_D.nVersionGroupId,
                               btchip_context_D.transactionBufferPointer, 4);
                        transaction_offset_increase(4);

                        // For version >= 3 (Overwinter+), read consensus branch ID
                        // NOTE: Ledger specific field, not part of the actual transaction
                        // NOTE: only available for v5 transaction
                        check_transaction_available(4);
                        memcpy(btchip_context_D.consensusBranchId,
                               btchip_context_D.transactionBufferPointer,
                               sizeof(btchip_context_D.consensusBranchId));
                        if (TX_VERSION == 5) {
                            transaction_offset_increase(4);
                        } else {
                            btchip_context_D.transactionBufferPointer += 4;
                            btchip_context_D.transactionDataRemaining -= 4;
                        }
                    }

                    // Number of inputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    PRINTF("Number of inputs : " DEBUG_LONG "\n",btchip_context_D.transactionContext.transactionRemainingInputsOutputs);

                    blake2b_256_init(&btchip_context_D.transactionSaplingFull.blake2b, (uint8_t *) NU5_PARAM_SAPLING);
                    blake2b_256_init(&btchip_context_D.transactionOrchardFull.blake2b, (uint8_t *) NU5_PARAM_ORCHARD);
                    if (btchip_context_D.called_from_swap && parseMode == PARSE_MODE_SIGNATURE) {
                        // remember number of inputs to know when to exit from library
                        // we will count number of already signed inputs and compare with this value
                        // As there are a lot of different states in which we can have different number of input
                        // (when for ex. we sign segregated witness)
                        if (vars.swap_data.totalNumberOfInputs == 0) {
                            vars.swap_data.totalNumberOfInputs =
                                btchip_context_D.transactionContext.transactionRemainingInputsOutputs;
                        }
                        // Reseting the flag, because we should check address ones for each input
                        vars.swap_data.was_address_checked = 0;
                    }
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;

                    __attribute__((fallthrough));
                }

                case BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT: {
                    unsigned char trustedInputFlag = 1;
                    PRINTF("Process input\n");
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more inputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_INPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Proceed with the next input
                    if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
                        check_transaction_available(
                            36); // prevout : 32 hash + 4 index

                        if (TX_VERSION == 5) {
                            blake2b_256_update(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, btchip_context_D.transactionBufferPointer, 36);
                        }
                        transaction_offset_increase(36);

                    }
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        unsigned char trustedInputLength;
                        unsigned char trustedInput[TRUSTED_INPUT_TOTAL_SIZE];
                        unsigned char amount[8];
                        unsigned char *savePointer;

                        // Expect the trusted input flag and trusted input length
                        check_transaction_available(2);
                        switch (*btchip_context_D.transactionBufferPointer) {
                        case 0:
                            if (btchip_context_D.usingSegwit) {
                                PRINTF("Non trusted input used in segwit mode\n");
                                goto fail;
                            }
                            trustedInputFlag = 0;
                            break;
                        case 1:
                            if (btchip_context_D.usingSegwit) {
                                // Segwit inputs can be passed as TrustedInput also
                                PRINTF("Trusted input used in segwit mode\n");
                            }
                            trustedInputFlag = 1;
                            break;
                        case 2:
                            if (!btchip_context_D.usingSegwit) {
                                PRINTF("Segwit input not used in segwit mode\n");
                                goto fail;
                            }
                            trustedInputFlag = 0;
                            break;
                        default:
                            PRINTF("Invalid trusted input flag\n");
                            goto fail;
                        }
                        /*
                        trustedInputLength =
                        *(btchip_context_D.transactionBufferPointer + 1);
                        if (trustedInputLength > sizeof(trustedInput)) {
                          PRINTF("Trusted input too long\n");
                          goto fail;
                        }
                        */
                        // Check TrustedInput (TI) integrity, be it a non-segwit TI or a segwit TI
                        if (trustedInputFlag) {
                            trustedInputLength = *(
                                btchip_context_D.transactionBufferPointer + 1);
                            if ((trustedInputLength > sizeof(trustedInput)) ||
                                (trustedInputLength < 8)) {
                                PRINTF("Invalid trusted input size\n");
                                goto fail;
                            }

                            check_transaction_available(2 + trustedInputLength);
                            // Check TrustedInput Hmac
                            cx_hmac_sha256(
                                (uint8_t *)N_btchip.bkp.trustedinput_key,
                                sizeof(N_btchip.bkp.trustedinput_key),
                                btchip_context_D.transactionBufferPointer + 2,
                                trustedInputLength - 8, trustedInput, trustedInputLength);
                                PRINTF("====> Input HMAC:    %.*H\n", 8, btchip_context_D.transactionBufferPointer + 2 + trustedInputLength - 8);
                                PRINTF("====> Computed HMAC: %.*H\n", 8, trustedInput);

                            if (btchip_secure_memcmp(
                                    trustedInput,       // Contains computed Hmac for now
                                    btchip_context_D.transactionBufferPointer +
                                        2 + trustedInputLength - 8,
                                    8) != 0) {
                                PRINTF("Invalid signature\n");
                                goto fail;
                            }
                            // Hmac is valid. If TrustedInput contains a segwit input, update data pointer & length
                            // to fake the parser into believing a normal segwit input was received. Do not use
                            // transaction_offset_increase() here as it could update the hash being computed.
                            if (btchip_context_D.usingSegwit) {
                                // Overwrite the no longer needed HMAC's 1st byte w/ the input script length byte.
                                *(btchip_context_D.transactionBufferPointer + 1 + TRUSTED_INPUT_SIZE + 1) =
                                    *(btchip_context_D.transactionBufferPointer + 1 + TRUSTED_INPUT_TOTAL_SIZE + 1);
                                // Set tx data pointer on TI header's (i.e. 0x38||0x32||0x00||Nonce (2B)) last byte
                                // before prevout tx hash. Also remove HMAC size from remaining data length.
                                btchip_context_D.transactionBufferPointer += 5;
                                btchip_context_D.transactionDataRemaining -= (5+8);
                            }
                        }
                        // Handle pure segwit inputs, whether trusted or not (i.e. InputHashStart 1st APDU's P2==02
                        // & data[0]=={0x01, 0x02})
                        if (btchip_context_D.usingSegwit) {
                            transaction_offset_increase(1);     // Set tx pointer on 1st byte of hash
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            if (!btchip_context_D.segwitParsedOnce) {
                                if (btchip_context_D.usingOverwinter) {
                                    if (cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, 0, btchip_context_D.transactionBufferPointer, 36, NULL, 0)) {
                                        goto fail;
                                    }
                                }
                                else {
                                    if (cx_hash_no_throw(
                                        &btchip_context_D.segwit.hash.hashPrevouts
                                         .sha256.header,
                                        0,
                                        btchip_context_D.transactionBufferPointer,
                                        36, NULL, 0)) {
                                        goto fail;
                                    }
                                }
                                transaction_offset_increase(36);
                                check_transaction_available(8); // update amount
                                btchip_swap_bytes(
                                    amount,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                                if (transaction_amount_add_be(
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        btchip_context_D.transactionContext
                                            .transactionAmount,
                                        amount)) {
                                    PRINTF("Overflow\n");
                                    goto fail;
                                }
                                PRINTF("Adding amount\n%.*H\n",8,btchip_context_D.transactionBufferPointer);
                                PRINTF("New amount\n%.*H\n",8,btchip_context_D.transactionContext.transactionAmount);

                                if (TX_VERSION == 5) {
                                    // Compute amounts_sig_digest
                                    CX_ASSERT(cx_hash_no_throw(&btchip_context_D.hashAmount.blake2b.header, 0, btchip_context_D.transactionBufferPointer, 8, NULL, 0));
                                }

                                transaction_offset_increase(8);
                            } else {
                                // Add txid
                                if (btchip_context_D.usingOverwinter && (TX_VERSION == 5)) {
                                    blake2b_256_init(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, NU5_PARAM_TX_IN);
                                    blake2b_256_update(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, btchip_context_D.transactionBufferPointer, 36);
                                }
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                                transaction_offset_increase(36);
                                btchip_context_D.transactionHashOption = 0;
                                check_transaction_available(8); // save amount
                                memcpy(
                                    btchip_context_D.inputValue,
                                    btchip_context_D.transactionBufferPointer,
                                    8);
                                transaction_offset_increase(8);
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_FULL;
                                // Append the saved value
                                if (btchip_context_D.usingOverwinter && (TX_VERSION == 5)) {
                                    blake2b_256_update(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, btchip_context_D.inputValue, 8);

                                }
                            }
                        }
                        // Handle non-segwit inputs (i.e. InputHashStart 1st APDU's P2==00 && data[0]==0x00)
                        else if (!trustedInputFlag) {
                            // Only authorized in relaxed wallet and server
                            // modes
                            SB_CHECK(N_btchip.bkp.config.operationMode);
                            switch (SB_GET(N_btchip.bkp.config.operationMode)) {
                            case BTCHIP_MODE_WALLET:
                                if (!optionP2SHSkip2FA) {
                                    PRINTF("Untrusted input not authorized\n");
                                    goto fail;
                                }
                                break;
                            case BTCHIP_MODE_RELAXED_WALLET:
                            case BTCHIP_MODE_SERVER:
                                break;
                            default:
                                PRINTF("Untrusted input not authorized\n");
                                goto fail;
                            }
                            btchip_context_D.transactionBufferPointer++;
                            btchip_context_D.transactionDataRemaining--;
                            check_transaction_available(
                                36); // prevout : 32 hash + 4 index
                            transaction_offset_increase(36);
                            PRINTF("Marking relaxed input\n");
                            btchip_context_D.transactionContext.relaxed = 1;
                            /*
                            PRINTF("Clearing P2SH consumption\n");
                            btchip_context_D.transactionContext.consumeP2SH = 0;
                            */
                        }
                        // Handle non-segwit TrustedInput (i.e. InputHashStart 1st APDU's P2==00 & data[0]==0x01)
                        else if (trustedInputFlag && !btchip_context_D.usingSegwit) {
                            memcpy(
                                trustedInput,
                                btchip_context_D.transactionBufferPointer + 2,
                                trustedInputLength - 8);
                            if (trustedInput[0] != MAGIC_TRUSTED_INPUT) {
                                PRINTF("Failed to verify trusted input signature\n");
                                goto fail;
                            }
                            // Update the hash with prevout data
                            savePointer =
                                btchip_context_D.transactionBufferPointer;
                            /*
                            // Check if a P2SH script is used
                            if ((trustedInput[1] & FLAG_TRUSTED_INPUT_P2SH) ==
                            0) {
                              PRINTF("Clearing P2SH consumption\n");
                              btchip_context_D.transactionContext.consumeP2SH =
                            0;
                            }
                            */
                            btchip_context_D.transactionBufferPointer =
                                trustedInput + 4;
                            PRINTF("Trusted input hash\n%.*H\n",36,btchip_context_D.transactionBufferPointer);
                            transaction_offset(36);

                            btchip_context_D.transactionBufferPointer =
                                savePointer + (2 + trustedInputLength);
                            btchip_context_D.transactionDataRemaining -=
                                (2 + trustedInputLength);

                            // Update the amount

                            btchip_swap_bytes(amount, trustedInput + 40, 8);
                            if (transaction_amount_add_be(
                                    btchip_context_D.transactionContext
                                        .transactionAmount,
                                    btchip_context_D.transactionContext
                                        .transactionAmount,
                                    amount)) {
                                PRINTF("Overflow\n");
                                goto fail;
                            }

                            PRINTF("Adding amount\n%.*H\n",8,(trustedInput + 40));
                            PRINTF("New amount\n%.*H\n",8,btchip_context_D.transactionContext.transactionAmount);
                        }

                        if (!btchip_context_D.usingSegwit) {
                            // Do not include the input script length + value in
                            // the authentication hash
                            btchip_context_D.transactionHashOption =
                                TRANSACTION_HASH_FULL;
                        }
                    }
                    // Read the script length
                    btchip_context_D.transactionContext.scriptRemaining =
                        transaction_get_varint();
                    PRINTF("Script to read " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);

                    if ((parseMode == PARSE_MODE_SIGNATURE) &&
                        !trustedInputFlag && !btchip_context_D.usingSegwit) {
                        // Only proceeds if this is not to be signed - so length
                        // should be null
                        if (btchip_context_D.transactionContext
                                .scriptRemaining != 0) {
                            PRINTF("Request to sign relaxed input\n");
                            if (!optionP2SHSkip2FA) {
                                goto fail;
                            }
                        }
                    }
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT;

                    __attribute__((fallthrough));
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    PRINTF("Process input script, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Scan for P2SH consumption - huge shortcut, but fine
                    // enough
                    // Also usable in SegWit mode
                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        1) {
                        if (*btchip_context_D.transactionBufferPointer ==
                            OP_CHECKMULTISIG) {
                            if (optionP2SHSkip2FA) {
                                PRINTF("Marking P2SH consumption\n");
                                btchip_context_D.transactionContext
                                    .consumeP2SH = 1;
                            }
                        } else {
                            // When using the P2SH shortcut, all inputs must use
                            // P2SH
                            PRINTF("Disabling P2SH consumption\n");
                            btchip_context_D.transactionContext.consumeP2SH = 0;
                        }
                        if (btchip_context_D.usingSegwit && btchip_context_D.segwitParsedOnce && (TX_VERSION == 5)) {
                           CX_ASSERT(cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, 0, btchip_context_D.transactionBufferPointer, 1, NULL, 0));
                        }
                        transaction_offset_increase(1);
                        btchip_context_D.transactionContext.scriptRemaining--;
                    }

                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        if (parseMode == PARSE_MODE_SIGNATURE) {
                            if (!btchip_context_D.usingSegwit) {
                                // Restore dual hash for signature +
                                // authentication
                                btchip_context_D.transactionHashOption =
                                    TRANSACTION_HASH_BOTH;
                            } else {
                                if (btchip_context_D.segwitParsedOnce) {
                                    // Append the saved value
                                    PRINTF("SEGWIT Add value\n%.*H\n",8,btchip_context_D.inputValue);
                                    if (btchip_context_D.usingOverwinter) {
                                        if (TX_VERSION == 5) {
                                            if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.inputValue, 8, NULL, 0)) {
                                                goto fail;
                                            }
                                        }
                                    }
                                    else {
                                        PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(btchip_context_D.inputValue), btchip_context_D.inputValue);
                                        if (cx_hash_no_throw(&btchip_context_D
                                                 .transactionHashFull.sha256.header,
                                            0, btchip_context_D.inputValue, 8,
                                            NULL, 0)) {
                                            goto fail;
                                        }
                                    }
                                }
                            }
                        }
                        // Sequence
                        check_transaction_available(4);
                        if (TX_VERSION == 5) {
                            blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.transactionBufferPointer, 4);
                        }

                        if (btchip_context_D.usingSegwit &&
                            !btchip_context_D.segwitParsedOnce) {
                            if (btchip_context_D.usingOverwinter) {
                                if (TX_VERSION == 5) {
                                } else {
                                    if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, 0, btchip_context_D.transactionBufferPointer, 4, NULL, 0)) {
                                        goto fail;
                                    }
                                }

                            }
                            else {
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", 4, btchip_context_D.transactionBufferPointer);
                                if (cx_hash_no_throw(&btchip_context_D.transactionHashFull
                                         .sha256.header,
                                    0,
                                    btchip_context_D.transactionBufferPointer,
                                    4, NULL, 0)) {
                                    goto fail;
                                }
                            }
                        }
                        if (btchip_context_D.usingSegwit && btchip_context_D.segwitParsedOnce && (TX_VERSION == 5)) {
                            blake2b_256_update(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, btchip_context_D.transactionBufferPointer, 4);
                            uint8_t txin_sig_digest[DIGEST_SIZE];
                            blake2b_256_final(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, txin_sig_digest);

                            cx_blake2b_t *tmp_ctx = &btchip_context_D.segwit.hash.hashPrevouts.blake2b;
                            cx_blake2b_t *tx_ctx = &btchip_context_D.transactionHashFull.blake2b;

                            uint8_t transparent_sig_digest[DIGEST_SIZE];
                            uint8_t sapling_digest[DIGEST_SIZE];
                            uint8_t orchard_digest[DIGEST_SIZE];

                            // Compute transparent_sig_digest
                            blake2b_256_init(tmp_ctx, NU5_PARAM_TRANSPA);
                            blake2b_256_update(tmp_ctx, btchip_context_D.sigHashType, 1);
                            blake2b_256_update(tmp_ctx, btchip_context_D.nu5_ctx.prevouts_sig_digest, DIGEST_SIZE);
                            blake2b_256_update(tmp_ctx, btchip_context_D.nu5_ctx.amounts_sig_digest, DIGEST_SIZE);
                            blake2b_256_update(tmp_ctx, btchip_context_D.nu5_ctx.scriptpubkeys_sig_digest, DIGEST_SIZE);
                            blake2b_256_update(tmp_ctx, btchip_context_D.nu5_ctx.sequence_sig_digest, DIGEST_SIZE);
                            blake2b_256_update(tmp_ctx, btchip_context_D.nu5_ctx.outputs_sig_digest, DIGEST_SIZE);
                            blake2b_256_update(tmp_ctx, txin_sig_digest, DIGEST_SIZE);
                            blake2b_256_final(tmp_ctx, transparent_sig_digest);

                            // Compute sapling_digest. Assume no Sapling spends or outputs are present
                            blake2b_256_init(tmp_ctx, NU5_PARAM_SAPLING);
                            blake2b_256_final(tmp_ctx, sapling_digest);

                            // Compute orchard_digest. Assume there are no Orchard actions
                            blake2b_256_init(tmp_ctx, NU5_PARAM_ORCHARD);
                            blake2b_256_final(tmp_ctx, orchard_digest);

                            // Start to compute signature_digest
                            uint8_t parameters[16];
                            memcpy(parameters, NU5_PARAM_TXID, 12);
                            memcpy(parameters + 12,
                                   btchip_context_D.consensusBranchId,
                                   sizeof(btchip_context_D.consensusBranchId));
                            blake2b_256_init(tx_ctx, parameters);
                            blake2b_256_update(tx_ctx, btchip_context_D.nu5_ctx.header_digest, DIGEST_SIZE);
                            blake2b_256_update(tx_ctx, transparent_sig_digest, DIGEST_SIZE);
                            blake2b_256_update(tx_ctx, sapling_digest, DIGEST_SIZE);
                            blake2b_256_update(tx_ctx, orchard_digest, DIGEST_SIZE);

                            // We dont want to update transactionHashFull
                            btchip_context_D.transactionBufferPointer += 4;
                            btchip_context_D.transactionDataRemaining -= 4;
                        } else {
                            transaction_offset_increase(4);
                        }


                        // Move to next input
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT;
                        continue;
                    }
                    // Save the last script byte for the P2SH check
                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                         .scriptRemaining -
                                     1
                             ? btchip_context_D.transactionContext
                                       .scriptRemaining -
                                   1
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }
                    if (btchip_context_D.usingSegwit && btchip_context_D.segwitParsedOnce && (TX_VERSION == 5)) {
                        uint8_t dataSize = dataAvailable + 1;
                        CX_ASSERT(cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, 0, &dataSize, 1, NULL, 0));
                        CX_ASSERT(cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, 0, btchip_context_D.transactionBufferPointer, dataAvailable, NULL, 0));


                        // We dont want to update transactionHashFull
                        btchip_context_D.transactionBufferPointer += dataAvailable;
                        btchip_context_D.transactionDataRemaining -= dataAvailable;
                    } else {
                        if ((TX_VERSION == 5) && dataAvailable) {
                            // Compute scriptpubkeys_sig_digest
                            uint8_t tmp = dataAvailable + 1;
                            blake2b_256_update(&btchip_context_D.transactionHashAuthorization.blake2b, &tmp, 1);
                            blake2b_256_update(&btchip_context_D.transactionHashAuthorization.blake2b, btchip_context_D.transactionBufferPointer, dataAvailable);
                            tmp = 0xAC;
                            blake2b_256_update(&btchip_context_D.transactionHashAuthorization.blake2b, &tmp, 1);
                        }
                        transaction_offset_increase(dataAvailable);
                    }

                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case BTCHIP_TRANSACTION_INPUT_HASHING_DONE: {
                    PRINTF("Input hashing done\n");
                    if (parseMode == PARSE_MODE_SIGNATURE) {
                        // inputs have been prepared, stop the parsing here
                        if (btchip_context_D.usingSegwit &&
                            !btchip_context_D.segwitParsedOnce) {
                            unsigned char hashedPrevouts[32];
                            unsigned char hashedSequence[32];
                            // Flush the cache
                            if (btchip_context_D.usingOverwinter) {
                                if (cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts.blake2b.header, CX_LAST, hashedPrevouts, 0, hashedPrevouts, 32)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&btchip_context_D.transactionHashFull.blake2b.header, CX_LAST, hashedSequence, 0, hashedSequence, 32)) {
                                    goto fail;
                                }
                            }
                            else {
                                if (cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts
                                         .sha256.header,
                                    CX_LAST, hashedPrevouts, 0, hashedPrevouts, 32)) {
                                    goto fail;
                                }
                                if (cx_sha256_init_no_throw(
                                    &btchip_context_D.segwit.hash.hashPrevouts.sha256)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&btchip_context_D.segwit.hash.hashPrevouts
                                         .sha256.header,
                                    CX_LAST, hashedPrevouts,
                                    sizeof(hashedPrevouts), hashedPrevouts, 32)) {
                                    goto fail;
                                }
                                if (cx_hash_no_throw(&btchip_context_D.transactionHashFull
                                         .sha256.header,
                                    CX_LAST, hashedSequence, 0, hashedSequence, 32)) {
                                    goto fail;
                                }
                                if (cx_sha256_init_no_throw(
                                    &btchip_context_D.transactionHashFull.sha256)) {
                                    goto fail;
                                }
                                PRINTF("--- ADD TO HASH FULL:\n%.*H\n", sizeof(hashedSequence), hashedSequence);
                                if (cx_hash_no_throw(&btchip_context_D.transactionHashFull
                                         .sha256.header,
                                    CX_LAST, hashedSequence,
                                    sizeof(hashedSequence), hashedSequence, 32)) {
                                    goto fail;
                                }

                            }
                            memcpy(
                                btchip_context_D.segwit.cache.hashedPrevouts,
                                hashedPrevouts, sizeof(hashedPrevouts));
                            memcpy(
                                btchip_context_D.segwit.cache.hashedSequence,
                                hashedSequence, sizeof(hashedSequence));
                            PRINTF("hashPrevout\n%.*H\n",32,btchip_context_D.segwit.cache.hashedPrevouts);
                            PRINTF("hashSequence\n%.*H\n",32,btchip_context_D.segwit.cache.hashedSequence);

                            if (TX_VERSION == 5) {
                                // Store amounts_sig_digest
                                blake2b_256_final(&btchip_context_D.hashAmount.blake2b, btchip_context_D.nu5_ctx.amounts_sig_digest);

                                // Store scriptpubkeys_sig_digest
                                blake2b_256_final(&btchip_context_D.transactionHashAuthorization.blake2b, btchip_context_D.nu5_ctx.scriptpubkeys_sig_digest);
                            }
                        }
                        if (btchip_context_D.usingSegwit &&
                            btchip_context_D.segwitParsedOnce) {
                            if (!btchip_context_D.usingOverwinter) {
                                PRINTF("SEGWIT hashedOutputs\n%.*H\n",sizeof(btchip_context_D.segwit.cache.hashedOutputs),btchip_context_D.segwit.cache.hashedOutputs);
                                if (cx_hash_no_throw(
                                    &btchip_context_D.transactionHashFull.sha256.header, 0,
                                    btchip_context_D.segwit.cache.hashedOutputs,
                                    sizeof(btchip_context_D.segwit.cache
                                           .hashedOutputs),
                                    NULL, 0)) {
                                    goto fail;
                                }
                            }
                            btchip_context_D.transactionContext
                                .transactionState =
                                BTCHIP_TRANSACTION_SIGN_READY;
                        } else {
                            btchip_context_D.transactionContext
                                .transactionState =
                                BTCHIP_TRANSACTION_PRESIGN_READY;
                            if (btchip_context_D.usingOverwinter) {
                                if (cx_blake2b_init2_no_throw(&btchip_context_D.transactionHashFull.blake2b, 256, NULL, 0, (uint8_t *)OVERWINTER_PARAM_OUTPUTS, 16)) {
                                    goto fail;
                                }
                            }
                            else
                            if (btchip_context_D.usingSegwit) {
                                if (cx_sha256_init_no_throw(&btchip_context_D.transactionHashFull.sha256)) {
                                    goto fail;
                                }
                            }
                        }
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }

                    if (TX_VERSION == 5) {
                        uint8_t tmp[32];

                        // Store prevout_digest
                        blake2b_256_final(&btchip_context_D.segwit.hash.hashPrevouts.blake2b, tmp);
                        memcpy(btchip_context_D.segwit.cache.hashedPrevouts, tmp, 32);
                        // Store sequence_digest
                        blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, tmp);
                        memcpy(btchip_context_D.segwit.cache.hashedSequence, tmp, 32);
                        // This context will be used for outputs_digest
                        blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, NU5_PARAM_OUTPUTS);
                    }

                    // Number of outputs
                    btchip_context_D.transactionContext
                        .transactionRemainingInputsOutputs =
                        transaction_get_varint();
                    btchip_context_D.transactionContext
                        .transactionCurrentInputOutput = 0;
                    PRINTF("Number of outputs : " DEBUG_LONG "\n",
                        btchip_context_D.transactionContext.transactionRemainingInputsOutputs);
                    // Ready to proceed
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;

                    __attribute__((fallthrough));
                }
                case BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT: {
                    if (btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs == 0) {
                        // No more outputs to hash, move forward
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE;
                        continue;
                    }
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    // Amount
                    check_transaction_available(8);

                    if (TX_VERSION == 5) {
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.transactionBufferPointer, 8);
                    }

                    if ((parseMode == PARSE_MODE_TRUSTED_INPUT) &&
                        (btchip_context_D.transactionContext
                             .transactionCurrentInputOutput ==
                         btchip_context_D.transactionTargetInput)) {
                        // Save the amount
                        memcpy(btchip_context_D.transactionContext
                                    .transactionAmount,
                               btchip_context_D.transactionBufferPointer,
                               8);
                    }
                    transaction_offset_increase(8);
                    // Read the script length
                    btchip_context_D.transactionContext.scriptRemaining =
                        transaction_get_varint();

                    if (TX_VERSION == 5) {
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, (const uint8_t *) &btchip_context_D.transactionContext.scriptRemaining, 1);
                    }

                    PRINTF("Script to read " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    // Move on
                    btchip_context_D.transactionContext.transactionState =
                        BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT;

                    __attribute__((fallthrough));
                }
                case BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT: {
                    unsigned char dataAvailable;
                    PRINTF("Process output script, remaining " DEBUG_LONG "\n",btchip_context_D.transactionContext.scriptRemaining);
                    /*
                    // Special check if consuming a P2SH script
                    if (parseMode == PARSE_MODE_TRUSTED_INPUT) {
                      // Assume the full input script is sent in a single APDU,
                    then do the ghetto validation
                      if ((btchip_context_D.transactionBufferPointer[0] ==
                    OP_HASH160) &&
                          (btchip_context_D.transactionBufferPointer[btchip_context_D.transactionDataRemaining
                    - 1] == OP_EQUAL)) {
                        PRINTF("Marking P2SH output\n");
                        btchip_context_D.transactionContext.consumeP2SH = 1;
                      }
                    }
                    */
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    if (btchip_context_D.transactionContext.scriptRemaining ==
                        0) {
                        // Move to next output
                        btchip_context_D.transactionContext
                            .transactionRemainingInputsOutputs--;
                        btchip_context_D.transactionContext
                            .transactionCurrentInputOutput++;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT;
                        continue;
                    }
                    dataAvailable =
                        (btchip_context_D.transactionDataRemaining >
                                 btchip_context_D.transactionContext
                                     .scriptRemaining
                             ? btchip_context_D.transactionContext
                                   .scriptRemaining
                             : btchip_context_D.transactionDataRemaining);
                    if (dataAvailable == 0) {
                        goto ok;
                    }

                    if (TX_VERSION == 5) {
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.transactionBufferPointer, dataAvailable);
                    }

                    transaction_offset_increase(dataAvailable);
                    btchip_context_D.transactionContext.scriptRemaining -=
                        dataAvailable;
                    break;
                }
                case BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE: {
                    PRINTF("Output hashing done\n");

                    if (btchip_context_D.transactionDataRemaining < 1) {
                        goto ok;
                    }
                    
                    if (TX_VERSION == 5) {
                        uint8_t tmp[32];

                        // Store outputs_digest
                        blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, tmp);
                        memcpy(btchip_context_D.segwit.cache.hashedOutputs, tmp, 32);
                    }

                    // get amount of sapling spends/outputs and orchard actions
                    btchip_context_D.transactionHashOption = 0;
                    btchip_context_D.transactionContext.saplingSpendRemaining = transaction_get_varint();

                    btchip_context_D.saplingOutputCount = transaction_get_varint();

                    btchip_context_D.orchardActionCount = transaction_get_varint();
                    btchip_context_D.transactionHashOption = TRANSACTION_HASH_FULL;


                    if (btchip_context_D.transactionContext.saplingSpendRemaining > 0 || btchip_context_D.saplingOutputCount > 0) {
                        btchip_context_D.transactionHashOption = 0;
                        
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_SAPLING;
                    }
                    else if (btchip_context_D.orchardActionCount > 0) {
                        // init the orchard actions compact hash
                        blake2b_256_init(&btchip_context_D.transactionHashCompact.blake2b, (uint8_t *) NU5_PARAM_ORCHARD_ACTIONS_COMPACT);

                        btchip_context_D.transactionContext.orchardActionsRemaining = btchip_context_D.orchardActionCount;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_ORCHARD_COMPACT;

                    } else if (btchip_context_D.transactionDataRemaining == 0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA;
                    } 
                    goto ok;
                }
                
                case BTCHIP_TRANSACTION_PROCESS_SAPLING: {
                    
                    int value = 8;
                    check_transaction_available(value);
                    memcpy( btchip_context_D.saplingBalance, btchip_context_D.transactionBufferPointer, sizeof(btchip_context_D.saplingBalance));
                    btchip_context_D.transactionBufferPointer += value;
                    btchip_context_D.transactionDataRemaining -= value;
                    

                    if (btchip_context_D.transactionContext.saplingSpendRemaining > 0) {
                        value = 32;
                        check_transaction_available(value);
                        memcpy( btchip_context_D.saplingAnchor, btchip_context_D.transactionBufferPointer, sizeof(btchip_context_D.saplingAnchor));
                        btchip_context_D.transactionBufferPointer += value;
                        btchip_context_D.transactionDataRemaining -= value;
                    }

                    if (btchip_context_D.transactionContext.saplingSpendRemaining > 0) {
                        // We have sapling spends
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_SAPLING_SPENDS;

                        // init the sapling spends compact hash
                        blake2b_256_init(&btchip_context_D.transactionHashCompact.blake2b, (uint8_t *) NU5_PARAM_SAPLING_SPENDS_COMPACT);
                        // init the sapling spends noncompact hash
                        blake2b_256_init(&btchip_context_D.transactionHashNonCompact.blake2b, (uint8_t *) NU5_PARAM_SAPLING_SPENDS_NONCOMPACT);
                        goto ok;
                    } else if (btchip_context_D.transactionContext.saplingSpendRemaining == 0 && btchip_context_D.saplingOutputCount > 0) {
                        // process shielding transaction when we got UTXO as a change from the shielding transaction
                        btchip_context_D.transactionHashOption = 0;
                        
                        // Get empty sapling spends digest
                        uint8_t saplingSpend[DIGEST_SIZE];
                        blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, (uint8_t *)  NU5_PARAM_SAPLING_SPENDS);
                        blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, saplingSpend); 

                        blake2b_256_update(&btchip_context_D.transactionSaplingFull.blake2b, saplingSpend, sizeof(saplingSpend));

                        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_COMPACT;
                        
                        btchip_context_D.transactionContext.saplingOutputRemaining = btchip_context_D.saplingOutputCount;
                        
                        blake2b_256_init(&btchip_context_D.transactionHashCompact.blake2b, (uint8_t *) NU5_PARAM_SAPLING_OUTPUTS_COMPACT);
                        goto ok;
                    }
                    else {
                        // No sapling spends, just continue with extra data
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA; // TODO: should continue to outputs, not valid for current case
                    }
                    break;
                }
                case BTCHIP_TRANSACTION_PROCESS_SAPLING_SPENDS: {
                    
                    if (btchip_context_D.transactionContext.saplingSpendRemaining == 0) {
                        PRINTF("Sapling data corrupted, spends\n");
                        goto fail;
                    }
                    check_transaction_available(96);
                    // update compact hash with cv
                    blake2b_256_update(&btchip_context_D.transactionHashNonCompact.blake2b, btchip_context_D.transactionBufferPointer, 32);
                    btchip_context_D.transactionBufferPointer += 32;
                    btchip_context_D.transactionDataRemaining -= 32;

                    // update compact hash with anchor
                    blake2b_256_update(&btchip_context_D.transactionHashNonCompact.blake2b, btchip_context_D.saplingAnchor, 32);

                    // update NON compact hash with nullifier                    
                    blake2b_256_update(&btchip_context_D.transactionHashCompact.blake2b, btchip_context_D.transactionBufferPointer, 32);
                    btchip_context_D.transactionBufferPointer += 32;
                    btchip_context_D.transactionDataRemaining -= 32;

                    // update compact hash with rk
                    blake2b_256_update(&btchip_context_D.transactionHashNonCompact.blake2b, btchip_context_D.transactionBufferPointer, 32);
                    btchip_context_D.transactionBufferPointer += 32;
                    btchip_context_D.transactionDataRemaining -= 32;
                    
                    btchip_context_D.transactionContext.saplingSpendRemaining -= 1;
                    
                    if (btchip_context_D.transactionContext.saplingSpendRemaining == 0) {
                        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_PROCESS_SAPLING_SPENDS_HASHING;
                        continue;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_SAPLING_SPENDS_HASHING: {
                    // Finalize compact and noncompact sapling spend hashes
                    uint8_t saplingSpend[DIGEST_SIZE];
                    uint8_t saplingSpendCompactDigest[DIGEST_SIZE];
                    uint8_t saplingSpendNonCompactDigest[DIGEST_SIZE];

                    blake2b_256_final(&btchip_context_D.transactionHashCompact.blake2b, saplingSpendCompactDigest);

                    blake2b_256_final(&btchip_context_D.transactionHashNonCompact.blake2b, saplingSpendNonCompactDigest);
                    

                    //Initialize the sapling spend digest context
                    blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, (uint8_t *)  NU5_PARAM_SAPLING_SPENDS);
                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, saplingSpendCompactDigest, sizeof(saplingSpendCompactDigest));
                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, saplingSpendNonCompactDigest, sizeof(saplingSpendNonCompactDigest));
                    blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, saplingSpend); 

                    blake2b_256_update(&btchip_context_D.transactionSaplingFull.blake2b, saplingSpend, sizeof(saplingSpend));
                    
                    if (btchip_context_D.saplingOutputCount > 0) {
                        btchip_context_D.transactionContext.transactionState = BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_COMPACT;
                        
                        btchip_context_D.transactionContext.saplingOutputRemaining = btchip_context_D.saplingOutputCount;
                        
                        blake2b_256_init(&btchip_context_D.transactionHashCompact.blake2b, (uint8_t *) NU5_PARAM_SAPLING_OUTPUTS_COMPACT);
                    } else {
                        // saplingOutputCount == 0, just continue with extra data
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA;
                    }
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_COMPACT: {

                    if (btchip_context_D.transactionContext.saplingOutputRemaining == 0) {
                        PRINTF("Sapling data corrupted, outputs compact\n");
                        goto fail;
                    }

                    long compact_size = 32+32+52; // cmu + ephemeral_key + enc_ciphertext[..52]
                    check_transaction_available(compact_size);
                    // update compact hash with cv
                    blake2b_256_update(&btchip_context_D.transactionHashCompact.blake2b, btchip_context_D.transactionBufferPointer, compact_size);
                    btchip_context_D.transactionBufferPointer += compact_size;
                    btchip_context_D.transactionDataRemaining -= compact_size;
                    
                    btchip_context_D.transactionContext.saplingOutputRemaining -= 1;
                    
                    if (btchip_context_D.transactionContext.saplingOutputRemaining ==0) {
                        blake2b_256_init(&btchip_context_D.transactionHashMemo.blake2b, (uint8_t *) NU5_PARAM_SAPLING_OUTPUTS_MEMO);
                        // memo_size = 512 each APDU will contain quarter of the memo
                        btchip_context_D.transactionContext.saplingOutputRemaining = 4 * btchip_context_D.saplingOutputCount;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_MEMO;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_MEMO: {

                    if (btchip_context_D.transactionContext.saplingOutputRemaining == 0) {
                        PRINTF("Sapling data corrupted, outputs memo\n");
                        goto fail;
                    }

                    const long memo_part_size = 128; // memo_size = 512 each APDU will contain quarter of the memo
                    check_transaction_available(memo_part_size);
                    // update compact hash with cv
                    blake2b_256_update(&btchip_context_D.transactionHashMemo.blake2b, btchip_context_D.transactionBufferPointer, memo_part_size);
                    btchip_context_D.transactionBufferPointer += memo_part_size;
                    btchip_context_D.transactionDataRemaining -= memo_part_size;

                    btchip_context_D.transactionContext.saplingOutputRemaining -= 1;

                    if (btchip_context_D.transactionContext.saplingOutputRemaining == 0) {
                        
                        blake2b_256_init(&btchip_context_D.transactionHashNonCompact.blake2b, (uint8_t *) NU5_PARAM_SAPLING_OUTPUTS_NONCOMPACT);
                        
                        btchip_context_D.transactionContext.saplingOutputRemaining = btchip_context_D.saplingOutputCount;
                        
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_NONCOMPACT;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUTS_NONCOMPACT: {
                    
                    if (btchip_context_D.transactionContext.saplingOutputRemaining == 0) {
                        PRINTF("Sapling data corrupted, outputs noncompact\n");
                        goto fail;
                    }

                    const long non_compact_size = 128; // non_compact_size = 32+16+80
                    check_transaction_available(non_compact_size);
                    // update compact hash with cv
                    blake2b_256_update(&btchip_context_D.transactionHashNonCompact.blake2b, btchip_context_D.transactionBufferPointer, non_compact_size);
                    btchip_context_D.transactionBufferPointer += non_compact_size;
                    btchip_context_D.transactionDataRemaining -= non_compact_size;

                    btchip_context_D.transactionContext.saplingOutputRemaining -= 1;

                    if (btchip_context_D.transactionContext.saplingOutputRemaining == 0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUT_HASHING;
                        continue;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_SAPLING_OUTPUT_HASHING: {
                    // Finalize compact and noncompact sapling spend hashes
                    uint8_t saplingOutputCompactDigest[DIGEST_SIZE];
                    uint8_t saplingOutputMemoDigest[DIGEST_SIZE];
                    uint8_t saplingOutputNonCompactDigest[DIGEST_SIZE];

                    blake2b_256_final(&btchip_context_D.transactionHashCompact.blake2b, saplingOutputCompactDigest);
                    blake2b_256_final(&btchip_context_D.transactionHashMemo.blake2b, saplingOutputMemoDigest);
                    blake2b_256_final(&btchip_context_D.transactionHashNonCompact.blake2b, saplingOutputNonCompactDigest);

                    // Initialize the sapling output digest context
                    uint8_t saplingOutput[DIGEST_SIZE];
                    blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, (uint8_t *) NU5_PARAM_SAPLING_OUTPUTS);
                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, saplingOutputCompactDigest, sizeof(saplingOutputCompactDigest));
                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, saplingOutputMemoDigest, sizeof(saplingOutputMemoDigest));
                    blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, saplingOutputNonCompactDigest, sizeof(saplingOutputNonCompactDigest));
                    blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, saplingOutput); 

                    blake2b_256_update(&btchip_context_D.transactionSaplingFull.blake2b, saplingOutput, sizeof(saplingOutput));

                    blake2b_256_update(&btchip_context_D.transactionSaplingFull.blake2b, btchip_context_D.saplingBalance, sizeof(btchip_context_D.saplingBalance));
                    
                    btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA;
                            
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_ORCHARD_COMPACT: {
                    if (btchip_context_D.transactionContext.orchardActionsRemaining == 0) {
                        PRINTF("Orchard data corrupted, action compact\n");
                        goto fail;
                    }
                    long compact_size = 32+32+32+52; // nullifier + cmx + ephemeralKey + encCiphertext[..52]
                    check_transaction_available(compact_size);
                    blake2b_256_update(&btchip_context_D.transactionHashCompact.blake2b, btchip_context_D.transactionBufferPointer, compact_size);
                    btchip_context_D.transactionBufferPointer += compact_size;
                    btchip_context_D.transactionDataRemaining -= compact_size;
                    
                    btchip_context_D.transactionContext.orchardActionsRemaining -= 1;
                    
                    if (btchip_context_D.transactionContext.orchardActionsRemaining ==0) {
                        blake2b_256_init(&btchip_context_D.transactionHashMemo.blake2b, (uint8_t *) NU5_PARAM_ORCHARD_ACTIONS_MEMOS);
                        // memo_size = 512 each APDU will contain quarter of the memo
                        btchip_context_D.transactionContext.orchardActionsRemaining = 4 * btchip_context_D.orchardActionCount;
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_ORCHARD_MEMO;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_ORCHARD_MEMO: {
                    if (btchip_context_D.transactionContext.orchardActionsRemaining == 0) {
                        PRINTF("Orchard data corrupted, action memo\n");
                        goto fail;
                    }
                    const long memo_part_size = 128; // memo_size = 512 each APDU will contain quarter of the memo
                    check_transaction_available(memo_part_size);
                    // update compact hash with cv
                    blake2b_256_update(&btchip_context_D.transactionHashMemo.blake2b, btchip_context_D.transactionBufferPointer, memo_part_size);
                    btchip_context_D.transactionBufferPointer += memo_part_size;
                    btchip_context_D.transactionDataRemaining -= memo_part_size;

                    btchip_context_D.transactionContext.orchardActionsRemaining -= 1;

                    if (btchip_context_D.transactionContext.orchardActionsRemaining == 0) {
                        
                        blake2b_256_init(&btchip_context_D.transactionHashNonCompact.blake2b, (uint8_t *) NU5_PARAM_ORCHARD_ACTIONS_NONCOMP);
                        
                        btchip_context_D.transactionContext.orchardActionsRemaining = btchip_context_D.orchardActionCount;
                        
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_ORCHARD_NONCOMPACT;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_ORCHARD_NONCOMPACT: {
                    if (btchip_context_D.transactionContext.orchardActionsRemaining == 0) {
                        PRINTF("Orchard data corrupted, action noncompact\n");
                        goto fail;
                    }
                    const long non_compact_size = 160; // non_compact_size = 32+32+16+80
                    check_transaction_available(non_compact_size);                    
                    blake2b_256_update(&btchip_context_D.transactionHashNonCompact.blake2b, btchip_context_D.transactionBufferPointer, non_compact_size);
                    btchip_context_D.transactionBufferPointer += non_compact_size;
                    btchip_context_D.transactionDataRemaining -= non_compact_size;

                    btchip_context_D.transactionContext.orchardActionsRemaining -= 1;

                    if (btchip_context_D.transactionContext.orchardActionsRemaining == 0) {
                        btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_ORCHARD_HASHING;
                    } 
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PROCESS_ORCHARD_HASHING: {
                    // Finalize compact and noncompact orchard spend hashes
                    uint8_t orchardOutputCompactDigest[DIGEST_SIZE];
                    uint8_t orchardOutputMemoDigest[DIGEST_SIZE];
                    uint8_t orchardOutputNonCompactDigest[DIGEST_SIZE];

                    blake2b_256_final(&btchip_context_D.transactionHashCompact.blake2b, orchardOutputCompactDigest);
                    blake2b_256_final(&btchip_context_D.transactionHashMemo.blake2b, orchardOutputMemoDigest);
                    blake2b_256_final(&btchip_context_D.transactionHashNonCompact.blake2b, orchardOutputNonCompactDigest);

                    // Initialize the orchard spend digest context
                    blake2b_256_init(&btchip_context_D.transactionOrchardFull.blake2b, (uint8_t *) NU5_PARAM_ORCHARD);

                    blake2b_256_update(&btchip_context_D.transactionOrchardFull.blake2b, orchardOutputCompactDigest, sizeof(orchardOutputCompactDigest));
                    blake2b_256_update(&btchip_context_D.transactionOrchardFull.blake2b, orchardOutputMemoDigest, sizeof(orchardOutputMemoDigest));
                    blake2b_256_update(&btchip_context_D.transactionOrchardFull.blake2b, orchardOutputNonCompactDigest, sizeof(orchardOutputNonCompactDigest));
                    
                    const long orch_dig_data_size = 1+8+32; // orchard digest data: 1+8+32
                    check_transaction_available(orch_dig_data_size);
                    
                    blake2b_256_update(&btchip_context_D.transactionOrchardFull.blake2b, btchip_context_D.transactionBufferPointer, orch_dig_data_size);
                    btchip_context_D.transactionBufferPointer += orch_dig_data_size;
                    btchip_context_D.transactionDataRemaining -= orch_dig_data_size;
                    btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PROCESS_EXTRA; 
                            
                    goto ok;
                }
                
                case BTCHIP_TRANSACTION_PROCESS_EXTRA: {
                    
                    if (btchip_context_D.transactionDataRemaining < 1) {
                        // No more data to read, ok
                        goto ok;
                    }
                    
                    // get locktime
                    check_transaction_available(4);
                    uint8_t locktime[4];
                    memcpy(locktime,btchip_context_D.transactionBufferPointer,4);
                    btchip_context_D.transactionBufferPointer += 4;
                    btchip_context_D.transactionDataRemaining -= 4;
                    
                    // get extra data size
                    btchip_context_D.transactionHashOption = 0;
                    btchip_context_D.transactionContext.scriptRemaining = transaction_get_varint();
                    btchip_context_D.transactionHashOption = TRANSACTION_HASH_FULL;
                    
                    uint8_t expiryHeight[4];

                    if (TX_VERSION == 5) {
                        if (btchip_context_D.transactionContext.scriptRemaining !=4 ) {
                            PRINTF("Only expiryHeight expected");
                            goto fail; 
                        }
                        // get expiryHeight
                        check_transaction_available(4);
                        memcpy(expiryHeight, btchip_context_D.transactionBufferPointer, 4);
                        btchip_context_D.transactionBufferPointer += 4;
                        btchip_context_D.transactionDataRemaining -= 4;
                    }
                    else {
                        if (btchip_context_D.transactionContext.scriptRemaining != btchip_context_D.transactionDataRemaining) {
                            PRINTF("Data error");
                            goto fail; 
                        }
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, locktime, sizeof(locktime));
                        btchip_context_D.transactionContext.scriptRemaining -= btchip_context_D.transactionDataRemaining;
                        transaction_offset_increase(btchip_context_D.transactionDataRemaining);
                    }
                    
                    if (TX_VERSION == 5) {

                        uint8_t hashHeader[32];
                        uint8_t hashTransparent[32];
                        uint8_t hashSapling[32];
                        uint8_t hashOrchard[32];

                        blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, NU5_PARAM_HEADERS); 
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b,
                                           btchip_context_D.transactionVersion,
                                           sizeof(btchip_context_D.transactionVersion));
                        
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.nVersionGroupId, sizeof(btchip_context_D.nVersionGroupId));
                        
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b,
                                           btchip_context_D.consensusBranchId,
                                           sizeof(btchip_context_D.consensusBranchId));
                        
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, locktime, 4); 
                        
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, expiryHeight, 4);
                        
                        blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, hashHeader);
                 
                        // This context will be used for transparent_digest
                        blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, (uint8_t *) NU5_PARAM_TRANSPA);
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.segwit.cache.hashedPrevouts, 32);
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.segwit.cache.hashedSequence, 32);
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, btchip_context_D.segwit.cache.hashedOutputs, 32);

                        // store transparent_digest
                        blake2b_256_final(&btchip_context_D.transactionHashFull.blake2b, hashTransparent);

                        // store sapling_digest
                        blake2b_256_final(&btchip_context_D.transactionSaplingFull.blake2b, hashSapling);

                        // store orchard_digest
                        blake2b_256_final(&btchip_context_D.transactionOrchardFull.blake2b, hashOrchard);

                        // initialize personalization hash for tx_id
                        uint8_t parameters[16];
                        memcpy(parameters, NU5_PARAM_TXID, 12);
                        memcpy(parameters + 12,
                               btchip_context_D.consensusBranchId,
                               sizeof(btchip_context_D.consensusBranchId));

                        // This context will be used for txid_digest
                        blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, parameters);
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, hashHeader, sizeof(hashHeader));
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, hashTransparent, sizeof(hashTransparent));
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, hashSapling, sizeof(hashSapling));
                        blake2b_256_update(&btchip_context_D.transactionHashFull.blake2b, hashOrchard, sizeof(hashOrchard));
                    } 

                    btchip_context_D.transactionContext.transactionState =
                            BTCHIP_TRANSACTION_PARSED;
                    btchip_context_D.trustedInputProcessed = 1; 
                    continue;
                }

                case BTCHIP_TRANSACTION_PARSED: {
                    PRINTF("Transaction parsed\n");
                    goto ok;
                }

                case BTCHIP_TRANSACTION_PRESIGN_READY: {
                    PRINTF("Presign ready\n");
                    if (TX_VERSION == 5) {
                        blake2b_256_init(&btchip_context_D.transactionHashFull.blake2b, NU5_PARAM_OUTPUTS);
                    }
                    goto ok;
                }

                case BTCHIP_TRANSACTION_SIGN_READY: {
                    PRINTF("Sign ready\n");
                    goto ok;
                }
                }
            }

        fail:
            PRINTF("Transaction parse - fail\n");
            THROW(EXCEPTION);
        ok : {}
        }
        CATCH_OTHER(e) {
            PRINTF("Transaction parse - surprise fail\n");
            btchip_context_D.transactionContext.transactionState =
                BTCHIP_TRANSACTION_NONE;
            btchip_set_check_internal_structure_integrity(1);
            THROW(e);
        }
        // before the finally to restore the surrounding context if an exception
        // is raised during finally
        FINALLY {
            btchip_set_check_internal_structure_integrity(1);
        }
    }
    END_TRY;
}
