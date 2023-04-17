/***********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_PEDERSEN_IMPL_H_
#define _SECP256K1_PEDERSEN_IMPL_H_

#include <string.h>

#include "../../eckey.h"
#include "../../ecmult_const.h"
#include "../../ecmult_gen.h"
#include "../../group.h"
#include "../../field.h"
#include "../../scalar.h"
#include "../../util.h"

static void rustsecp256k1zkp_v0_8_0_pedersen_scalar_set_u64(rustsecp256k1zkp_v0_8_0_scalar *sec, uint64_t value) {
    unsigned char data[32];
    int i;
    for (i = 0; i < 24; i++) {
        data[i] = 0;
    }
    for (; i < 32; i++) {
        data[i] = value >> 56;
        value <<= 8;
    }
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(sec, data, NULL);
    memset(data, 0, 32);
}

static void rustsecp256k1zkp_v0_8_0_pedersen_ecmult_small(rustsecp256k1zkp_v0_8_0_gej *r, uint64_t gn, const rustsecp256k1zkp_v0_8_0_ge* genp) {
    rustsecp256k1zkp_v0_8_0_scalar s;
    rustsecp256k1zkp_v0_8_0_pedersen_scalar_set_u64(&s, gn);
    rustsecp256k1zkp_v0_8_0_ecmult_const(r, genp, &s, 64);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&s);
}

/* sec * G + value * G2. */
SECP256K1_INLINE static void rustsecp256k1zkp_v0_8_0_pedersen_ecmult(const rustsecp256k1zkp_v0_8_0_ecmult_gen_context *ecmult_gen_ctx, rustsecp256k1zkp_v0_8_0_gej *rj, const rustsecp256k1zkp_v0_8_0_scalar *sec, uint64_t value, const rustsecp256k1zkp_v0_8_0_ge* genp) {
    rustsecp256k1zkp_v0_8_0_gej vj;
    rustsecp256k1zkp_v0_8_0_ecmult_gen(ecmult_gen_ctx, rj, sec);
    rustsecp256k1zkp_v0_8_0_pedersen_ecmult_small(&vj, value, genp);
    /* FIXME: constant time. */
    rustsecp256k1zkp_v0_8_0_gej_add_var(rj, rj, &vj, NULL);
    rustsecp256k1zkp_v0_8_0_gej_clear(&vj);
}

#endif
