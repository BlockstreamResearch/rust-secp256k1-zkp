/**********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_WHITELIST_MAIN
#define SECP256K1_MODULE_WHITELIST_MAIN

#include "../../../include/secp256k1_whitelist.h"
#include "whitelist_impl.h"

#define MAX_KEYS SECP256K1_WHITELIST_MAX_N_KEYS  /* shorter alias */

int rustsecp256k1zkp_v0_8_0_whitelist_sign(const rustsecp256k1zkp_v0_8_0_context* ctx, rustsecp256k1zkp_v0_8_0_whitelist_signature *sig, const rustsecp256k1zkp_v0_8_0_pubkey *online_pubkeys, const rustsecp256k1zkp_v0_8_0_pubkey *offline_pubkeys, const size_t n_keys, const rustsecp256k1zkp_v0_8_0_pubkey *sub_pubkey, const unsigned char *online_seckey, const unsigned char *summed_seckey, const size_t index) {
    rustsecp256k1zkp_v0_8_0_gej pubs[MAX_KEYS];
    rustsecp256k1zkp_v0_8_0_scalar s[MAX_KEYS];
    rustsecp256k1zkp_v0_8_0_scalar sec, non;
    unsigned char msg32[32];
    int ret;

    /* Sanity checks */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_8_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(online_pubkeys != NULL);
    ARG_CHECK(offline_pubkeys != NULL);
    ARG_CHECK(n_keys <= MAX_KEYS);
    ARG_CHECK(sub_pubkey != NULL);
    ARG_CHECK(online_seckey != NULL);
    ARG_CHECK(summed_seckey != NULL);
    ARG_CHECK(index < n_keys);

    /* Compute pubkeys: online_pubkey + tweaked(offline_pubkey + address), and message */
    ret = rustsecp256k1zkp_v0_8_0_whitelist_compute_keys_and_message(ctx, msg32, pubs, online_pubkeys, offline_pubkeys, n_keys, sub_pubkey);

    /* Compute signing key: online_seckey + tweaked(summed_seckey) */
    if (ret) {
        ret = rustsecp256k1zkp_v0_8_0_whitelist_compute_tweaked_privkey(ctx, &sec, online_seckey, summed_seckey);
    }
    /* Compute nonce and random s-values */
    if (ret) {
        unsigned char seckey32[32];
        unsigned int count = 0;
        int overflow = 0;

        rustsecp256k1zkp_v0_8_0_scalar_get_b32(seckey32, &sec);
        while (1) {
            size_t i;
            unsigned char nonce32[32];
            int done;
            ret = rustsecp256k1zkp_v0_8_0_nonce_function_default(nonce32, msg32, seckey32, NULL, NULL, count);
            if (!ret) {
                break;
            }
            rustsecp256k1zkp_v0_8_0_scalar_set_b32(&non, nonce32, &overflow);
            memset(nonce32, 0, 32);
            if (overflow || rustsecp256k1zkp_v0_8_0_scalar_is_zero(&non)) {
                count++;
                continue;
            }
            done = 1;
            for (i = 0; i < n_keys; i++) {
                msg32[0] ^= i + 1;
                msg32[1] ^= (i + 1) / 0x100;
                ret = rustsecp256k1zkp_v0_8_0_nonce_function_default(&sig->data[32 * (i + 1)], msg32, seckey32, NULL, NULL, count);
                if (!ret) {
                    break;
                }
                rustsecp256k1zkp_v0_8_0_scalar_set_b32(&s[i], &sig->data[32 * (i + 1)], &overflow);
                msg32[0] ^= i + 1;
                msg32[1] ^= (i + 1) / 0x100;
                if (overflow || rustsecp256k1zkp_v0_8_0_scalar_is_zero(&s[i])) {
                    count++;
                    done = 0;
                    break;
                }
            }
            if (done) {
                break;
            }
        }
        memset(seckey32, 0, 32);
    }
    /* Actually sign */
    if (ret) {
        sig->n_keys = n_keys;
        ret = rustsecp256k1zkp_v0_8_0_borromean_sign(&ctx->ecmult_gen_ctx, &sig->data[0], s, pubs, &non, &sec, &n_keys, &index, 1, msg32, 32);
        /* Signing will change s[index], so update in the sig structure */
        rustsecp256k1zkp_v0_8_0_scalar_get_b32(&sig->data[32 * (index + 1)], &s[index]);
    }

    rustsecp256k1zkp_v0_8_0_scalar_clear(&non);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&sec);
    return ret;
}

int rustsecp256k1zkp_v0_8_0_whitelist_verify(const rustsecp256k1zkp_v0_8_0_context* ctx, const rustsecp256k1zkp_v0_8_0_whitelist_signature *sig, const rustsecp256k1zkp_v0_8_0_pubkey *online_pubkeys, const rustsecp256k1zkp_v0_8_0_pubkey *offline_pubkeys, const size_t n_keys, const rustsecp256k1zkp_v0_8_0_pubkey *sub_pubkey) {
    rustsecp256k1zkp_v0_8_0_scalar s[MAX_KEYS];
    rustsecp256k1zkp_v0_8_0_gej pubs[MAX_KEYS];
    unsigned char msg32[32];
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(online_pubkeys != NULL);
    ARG_CHECK(offline_pubkeys != NULL);
    ARG_CHECK(sub_pubkey != NULL);

    if (sig->n_keys > MAX_KEYS || sig->n_keys != n_keys) {
        return 0;
    }
    for (i = 0; i < sig->n_keys; i++) {
        int overflow = 0;
        rustsecp256k1zkp_v0_8_0_scalar_set_b32(&s[i], &sig->data[32 * (i + 1)], &overflow);
        if (overflow || rustsecp256k1zkp_v0_8_0_scalar_is_zero(&s[i])) {
            return 0;
        }
    }

    /* Compute pubkeys: online_pubkey + tweaked(offline_pubkey + address), and message */
    if (!rustsecp256k1zkp_v0_8_0_whitelist_compute_keys_and_message(ctx, msg32, pubs, online_pubkeys, offline_pubkeys, sig->n_keys, sub_pubkey)) {
        return 0;
    }
    /* Do verification */
    return rustsecp256k1zkp_v0_8_0_borromean_verify(NULL, &sig->data[0], s, pubs, &sig->n_keys, 1, msg32, 32);
}

size_t rustsecp256k1zkp_v0_8_0_whitelist_signature_n_keys(const rustsecp256k1zkp_v0_8_0_whitelist_signature *sig) {
    return sig->n_keys;
}

int rustsecp256k1zkp_v0_8_0_whitelist_signature_parse(const rustsecp256k1zkp_v0_8_0_context* ctx, rustsecp256k1zkp_v0_8_0_whitelist_signature *sig, const unsigned char *input, size_t input_len) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (input_len == 0) {
        return 0;
    }

    sig->n_keys = input[0];
    if (sig->n_keys > MAX_KEYS || input_len != 1 + 32 * (sig->n_keys + 1)) {
        return 0;
    }
    memcpy(&sig->data[0], &input[1], 32 * (sig->n_keys + 1));

    return 1;
}

int rustsecp256k1zkp_v0_8_0_whitelist_signature_serialize(const rustsecp256k1zkp_v0_8_0_context* ctx, unsigned char *output, size_t *output_len, const rustsecp256k1zkp_v0_8_0_whitelist_signature *sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(output_len != NULL);
    ARG_CHECK(sig != NULL);

    if (*output_len < 1 + 32 * (sig->n_keys + 1)) {
        return 0;
    }

    output[0] = sig->n_keys;
    memcpy(&output[1], &sig->data[0], 32 * (sig->n_keys + 1));
    *output_len = 1 + 32 * (sig->n_keys + 1);

    return 1;
}

#endif
