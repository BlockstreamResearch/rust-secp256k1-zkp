/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_H

typedef struct {
    rustsecp256k1zkp_v0_4_0_ge pk;
    rustsecp256k1zkp_v0_4_0_fe second_pk_x;
    const unsigned char *pk_hash;
    int is_tweaked;
    rustsecp256k1zkp_v0_4_0_scalar tweak;
    int internal_key_parity;
} rustsecp256k1zkp_v0_4_0_keyagg_cache_internal;

/* Requires that the saved point is not infinity */
static void rustsecp256k1zkp_v0_4_0_point_save(unsigned char *data, rustsecp256k1zkp_v0_4_0_ge *ge);

static void rustsecp256k1zkp_v0_4_0_point_load(rustsecp256k1zkp_v0_4_0_ge *ge, const unsigned char *data);

static int rustsecp256k1zkp_v0_4_0_keyagg_cache_load(const rustsecp256k1zkp_v0_4_0_context* ctx, rustsecp256k1zkp_v0_4_0_keyagg_cache_internal *cache_i, const rustsecp256k1zkp_v0_4_0_musig_keyagg_cache *cache);

static void rustsecp256k1zkp_v0_4_0_musig_keyaggcoef(rustsecp256k1zkp_v0_4_0_scalar *r, const rustsecp256k1zkp_v0_4_0_keyagg_cache_internal *cache_i, rustsecp256k1zkp_v0_4_0_fe *x);

#endif
