/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "../../field.h"
#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    rustsecp256k1zkp_v0_8_0_ge pk;
    /* If there is no "second" public key, second_pk is set to the point at
     * infinity */
    rustsecp256k1zkp_v0_8_0_ge second_pk;
    unsigned char pk_hash[32];
    /* tweak is identical to value tacc[v] in the specification. */
    rustsecp256k1zkp_v0_8_0_scalar tweak;
    /* parity_acc corresponds to gacc[v] in the spec. If gacc[v] is -1,
     * parity_acc is 1. Otherwise, parity_acc is 0. */
    int parity_acc;
} rustsecp256k1zkp_v0_8_0_keyagg_cache_internal;

/* Save and load points to and from byte arrays, similar to
 * rustsecp256k1zkp_v0_8_0_pubkey_{save,load}. */
static void rustsecp256k1zkp_v0_8_0_point_save(unsigned char *data, rustsecp256k1zkp_v0_8_0_ge *ge);

/* In contrast to pubkey_load, point_load does not attempt to check that data
 * has been initialized, since it is assumed that this check already happened
 * (e.g. by comparing magic bytes) */
static void rustsecp256k1zkp_v0_8_0_point_load(rustsecp256k1zkp_v0_8_0_ge *ge, const unsigned char *data);

/* point_save_ext and point_load_ext are identical to point_save and point_load
 * except that they allow saving and loading the point at infinity */
static void rustsecp256k1zkp_v0_8_0_point_save_ext(unsigned char *data, rustsecp256k1zkp_v0_8_0_ge *ge);

static void rustsecp256k1zkp_v0_8_0_point_load_ext(rustsecp256k1zkp_v0_8_0_ge *ge, const unsigned char *data);

static int rustsecp256k1zkp_v0_8_0_keyagg_cache_load(const rustsecp256k1zkp_v0_8_0_context* ctx, rustsecp256k1zkp_v0_8_0_keyagg_cache_internal *cache_i, const rustsecp256k1zkp_v0_8_0_musig_keyagg_cache *cache);

static void rustsecp256k1zkp_v0_8_0_musig_keyaggcoef(rustsecp256k1zkp_v0_8_0_scalar *r, const rustsecp256k1zkp_v0_8_0_keyagg_cache_internal *cache_i, rustsecp256k1zkp_v0_8_0_ge *pk);

#endif
