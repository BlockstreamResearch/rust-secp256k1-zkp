/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_COMPUTE_TABLE_IMPL_H
#define SECP256K1_ECMULT_GEN_COMPUTE_TABLE_IMPL_H

#include "ecmult_gen_compute_table.h"
#include "group_impl.h"
#include "field_impl.h"
#include "ecmult_gen.h"
#include "util.h"

static void rustsecp256k1zkp_v0_8_0_ecmult_gen_compute_table(rustsecp256k1zkp_v0_8_0_ge_storage* table, const rustsecp256k1zkp_v0_8_0_ge* gen, int bits) {
    int g = ECMULT_GEN_PREC_G(bits);
    int n = ECMULT_GEN_PREC_N(bits);

    rustsecp256k1zkp_v0_8_0_ge* prec = checked_malloc(&default_error_callback, n * g * sizeof(*prec));
    rustsecp256k1zkp_v0_8_0_gej gj;
    rustsecp256k1zkp_v0_8_0_gej nums_gej;
    int i, j;

    /* get the generator */
    rustsecp256k1zkp_v0_8_0_gej_set_ge(&gj, gen);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        rustsecp256k1zkp_v0_8_0_fe nums_x;
        rustsecp256k1zkp_v0_8_0_ge nums_ge;
        int r;
        r = rustsecp256k1zkp_v0_8_0_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = rustsecp256k1zkp_v0_8_0_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        rustsecp256k1zkp_v0_8_0_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        rustsecp256k1zkp_v0_8_0_gej_add_ge_var(&nums_gej, &nums_gej, gen, NULL);
    }

    /* compute prec. */
    {
        rustsecp256k1zkp_v0_8_0_gej gbase;
        rustsecp256k1zkp_v0_8_0_gej numsbase;
        rustsecp256k1zkp_v0_8_0_gej* precj = checked_malloc(&default_error_callback, n * g * sizeof(*precj));  /* Jacobian versions of prec. */
        gbase = gj; /* PREC_G^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < n; j++) {
            /* Set precj[j*PREC_G .. j*PREC_G+(PREC_G-1)] to (numsbase, numsbase + gbase, ..., numsbase + (PREC_G-1)*gbase). */
            precj[j*g] = numsbase;
            for (i = 1; i < g; i++) {
                rustsecp256k1zkp_v0_8_0_gej_add_var(&precj[j*g + i], &precj[j*g + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by PREC_G. */
            for (i = 0; i < bits; i++) {
                rustsecp256k1zkp_v0_8_0_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            rustsecp256k1zkp_v0_8_0_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == n - 2) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                rustsecp256k1zkp_v0_8_0_gej_neg(&numsbase, &numsbase);
                rustsecp256k1zkp_v0_8_0_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        rustsecp256k1zkp_v0_8_0_ge_set_all_gej_var(prec, precj, n * g);
        free(precj);
    }
    for (j = 0; j < n; j++) {
        for (i = 0; i < g; i++) {
            rustsecp256k1zkp_v0_8_0_ge_to_storage(&table[j*g + i], &prec[j*g + i]);
        }
    }
    free(prec);
}

#endif /* SECP256K1_ECMULT_GEN_COMPUTE_TABLE_IMPL_H */
