/**********************************************************************
 * Copyright (c) 2020 The libsecp256k1 Developers                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stddef.h>

#include "eckey.h"
#include "hash.h"

/* from secp256k1.c */
static int rustsecp256k1zkp_v0_8_0_ec_seckey_tweak_add_helper(rustsecp256k1zkp_v0_8_0_scalar *sec, const unsigned char *tweak);
static int rustsecp256k1zkp_v0_8_0_ec_pubkey_tweak_add_helper(rustsecp256k1zkp_v0_8_0_ge *pubp, const unsigned char *tweak);

static int rustsecp256k1zkp_v0_8_0_ec_commit_pubkey_serialize_const(rustsecp256k1zkp_v0_8_0_ge *pubp, unsigned char *buf33) {
    if (rustsecp256k1zkp_v0_8_0_ge_is_infinity(pubp)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_fe_normalize(&pubp->x);
    rustsecp256k1zkp_v0_8_0_fe_normalize(&pubp->y);
    rustsecp256k1zkp_v0_8_0_fe_get_b32(&buf33[1], &pubp->x);
    buf33[0] = rustsecp256k1zkp_v0_8_0_fe_is_odd(&pubp->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    return 1;
}

/* Compute an ec commitment tweak as hash(pubp, data). */
static int rustsecp256k1zkp_v0_8_0_ec_commit_tweak(unsigned char *tweak32, rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size)
{
    unsigned char rbuf[33];

    if (!rustsecp256k1zkp_v0_8_0_ec_commit_pubkey_serialize_const(pubp, rbuf)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_sha256_write(sha, rbuf, sizeof(rbuf));
    rustsecp256k1zkp_v0_8_0_sha256_write(sha, data, data_size);
    rustsecp256k1zkp_v0_8_0_sha256_finalize(sha, tweak32);
    return 1;
}

/* Compute an ec commitment as pubp + hash(pubp, data)*G. */
static int rustsecp256k1zkp_v0_8_0_ec_commit(rustsecp256k1zkp_v0_8_0_ge* commitp, const rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size) {
    unsigned char tweak[32];

    *commitp = *pubp;
    return rustsecp256k1zkp_v0_8_0_ec_commit_tweak(tweak, commitp, sha, data, data_size)
           && rustsecp256k1zkp_v0_8_0_ec_pubkey_tweak_add_helper(commitp, tweak);
}

/* Compute the seckey of an ec commitment from the original secret key of the pubkey as seckey +
 * hash(pubp, data). */
static int rustsecp256k1zkp_v0_8_0_ec_commit_seckey(rustsecp256k1zkp_v0_8_0_scalar* seckey, rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size) {
    unsigned char tweak[32];
    return rustsecp256k1zkp_v0_8_0_ec_commit_tweak(tweak, pubp, sha, data, data_size)
           && rustsecp256k1zkp_v0_8_0_ec_seckey_tweak_add_helper(seckey, tweak);
}

/* Verify an ec commitment as pubp + hash(pubp, data)*G ?= commitment. */
static int rustsecp256k1zkp_v0_8_0_ec_commit_verify(const rustsecp256k1zkp_v0_8_0_ge* commitp, const rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size) {
    rustsecp256k1zkp_v0_8_0_gej pj;
    rustsecp256k1zkp_v0_8_0_ge p;

    if (!rustsecp256k1zkp_v0_8_0_ec_commit(&p, pubp, sha, data, data_size)) {
        return 0;
    }

    /* Return p == commitp */
    rustsecp256k1zkp_v0_8_0_ge_neg(&p, &p);
    rustsecp256k1zkp_v0_8_0_gej_set_ge(&pj, &p);
    rustsecp256k1zkp_v0_8_0_gej_add_ge_var(&pj, &pj, commitp, NULL);
    return rustsecp256k1zkp_v0_8_0_gej_is_infinity(&pj);
}

