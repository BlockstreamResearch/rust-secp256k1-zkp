/**********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SURJECTION_IMPL_H_
#define _SECP256K1_SURJECTION_IMPL_H_

#include <string.h>

#include "../../eckey.h"
#include "../../group.h"
#include "../../scalar.h"
#include "../../hash.h"

SECP256K1_INLINE static void rustsecp256k1zkp_v0_8_0_surjection_genmessage(unsigned char *msg32, const rustsecp256k1zkp_v0_8_0_generator *ephemeral_input_tags, size_t n_input_tags, const rustsecp256k1zkp_v0_8_0_generator *ephemeral_output_tag) {
    /* compute message */
    size_t i;
    unsigned char pk_ser[33];
    size_t pk_len = sizeof(pk_ser);
    rustsecp256k1zkp_v0_8_0_sha256 sha256_en;

    rustsecp256k1zkp_v0_8_0_sha256_initialize(&sha256_en);
    for (i = 0; i < n_input_tags; i++) {
        pk_ser[0] = 2 + (ephemeral_input_tags[i].data[63] & 1);
        memcpy(&pk_ser[1], &ephemeral_input_tags[i].data[0], 32);
        rustsecp256k1zkp_v0_8_0_sha256_write(&sha256_en, pk_ser, pk_len);
    }
    pk_ser[0] = 2 + (ephemeral_output_tag->data[63] & 1);
    memcpy(&pk_ser[1], &ephemeral_output_tag->data[0], 32);
    rustsecp256k1zkp_v0_8_0_sha256_write(&sha256_en, pk_ser, pk_len);
    rustsecp256k1zkp_v0_8_0_sha256_finalize(&sha256_en, msg32);
}

SECP256K1_INLINE static int rustsecp256k1zkp_v0_8_0_surjection_genrand(rustsecp256k1zkp_v0_8_0_scalar *s, size_t ns, const rustsecp256k1zkp_v0_8_0_scalar *blinding_key) {
    size_t i;
    unsigned char sec_input[36];
    rustsecp256k1zkp_v0_8_0_sha256 sha256_en;

    /* compute s values */
    rustsecp256k1zkp_v0_8_0_scalar_get_b32(&sec_input[4], blinding_key);
    for (i = 0; i < ns; i++) {
        int overflow = 0;
        sec_input[0] = i;
        sec_input[1] = i >> 8;
        sec_input[2] = i >> 16;
        sec_input[3] = i >> 24;

        rustsecp256k1zkp_v0_8_0_sha256_initialize(&sha256_en);
        rustsecp256k1zkp_v0_8_0_sha256_write(&sha256_en, sec_input, 36);
        rustsecp256k1zkp_v0_8_0_sha256_finalize(&sha256_en, sec_input);
        rustsecp256k1zkp_v0_8_0_scalar_set_b32(&s[i], sec_input, &overflow);
        if (overflow == 1) {
            memset(sec_input, 0, 32);
            return 0;
        }
    }
    memset(sec_input, 0, 32);
    return 1;
}

SECP256K1_INLINE static int rustsecp256k1zkp_v0_8_0_surjection_compute_public_keys(rustsecp256k1zkp_v0_8_0_gej *pubkeys, size_t n_pubkeys, const rustsecp256k1zkp_v0_8_0_generator *input_tags, size_t n_input_tags, const unsigned char *used_tags, const rustsecp256k1zkp_v0_8_0_generator *output_tag, size_t input_index, size_t *ring_input_index) {
    size_t i;
    size_t j = 0;
    for (i = 0; i < n_input_tags; i++) {
        if (used_tags[i / 8] & (1 << (i % 8))) {
            rustsecp256k1zkp_v0_8_0_ge tmpge;
            rustsecp256k1zkp_v0_8_0_generator_load(&tmpge, &input_tags[i]);
            rustsecp256k1zkp_v0_8_0_ge_neg(&tmpge, &tmpge);

            VERIFY_CHECK(j < SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS);
            VERIFY_CHECK(j < n_pubkeys);
            rustsecp256k1zkp_v0_8_0_gej_set_ge(&pubkeys[j], &tmpge);

            rustsecp256k1zkp_v0_8_0_generator_load(&tmpge, output_tag);
            rustsecp256k1zkp_v0_8_0_gej_add_ge_var(&pubkeys[j], &pubkeys[j], &tmpge, NULL);
            if (ring_input_index != NULL && input_index == i) {
                *ring_input_index = j;
            }
            j++;
        }
    }
    /* Caller needs to ensure that the number of set bits in used_tags (which we counted in j) equals n_pubkeys. */
    VERIFY_CHECK(j == n_pubkeys);
    return 1;
}


#endif
