/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BPPP_PP_NORM_PRODUCT_H
#define SECP256K1_MODULE_BPPP_PP_NORM_PRODUCT_H

#include "../../group.h"
#include "../../scalar.h"
#include "../../ecmult.h"
#include "../../ecmult_gen.h"
#include "../../hash.h"

#include "../bppp/main.h"
#include "../bppp/bppp_util.h"
#include "../bppp/bppp_transcript_impl.h"

/* Computes the inner product of two vectors of scalars
 * with elements starting from offset a and offset b
 * skipping elements according to specified step.
 * Returns: Sum_{i=0..len-1}(a[offset_a + i*step] * b[offset_b + i*step]) */
static int rustsecp256k1zkp_v0_10_0_scalar_inner_product(
    rustsecp256k1zkp_v0_10_0_scalar* res,
    const rustsecp256k1zkp_v0_10_0_scalar* a_vec,
    const size_t a_offset,
    const rustsecp256k1zkp_v0_10_0_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len
) {
    size_t i;
    rustsecp256k1zkp_v0_10_0_scalar_set_int(res, 0);
    for (i = 0; i < len; i++) {
        rustsecp256k1zkp_v0_10_0_scalar term;
        rustsecp256k1zkp_v0_10_0_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        rustsecp256k1zkp_v0_10_0_scalar_add(res, res, &term);
    }
    return 1;
}

/* Computes the q-weighted inner product of two vectors of scalars
 * for elements starting from offset a and offset b respectively with the
 * given step.
 * Returns: Sum_{i=0..len-1}(a[offset_a + step*i] * b[offset_b2 + step*i]*mu^(i+1)) */
static int rustsecp256k1zkp_v0_10_0_weighted_scalar_inner_product(
    rustsecp256k1zkp_v0_10_0_scalar* res,
    const rustsecp256k1zkp_v0_10_0_scalar* a_vec,
    const size_t a_offset,
    const rustsecp256k1zkp_v0_10_0_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len,
    const rustsecp256k1zkp_v0_10_0_scalar* mu
) {
    rustsecp256k1zkp_v0_10_0_scalar mu_pow;
    size_t i;
    rustsecp256k1zkp_v0_10_0_scalar_set_int(res, 0);
    mu_pow = *mu;
    for (i = 0; i < len; i++) {
        rustsecp256k1zkp_v0_10_0_scalar term;
        rustsecp256k1zkp_v0_10_0_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        rustsecp256k1zkp_v0_10_0_scalar_mul(&term, &term, &mu_pow);
        rustsecp256k1zkp_v0_10_0_scalar_mul(&mu_pow, &mu_pow, mu);
        rustsecp256k1zkp_v0_10_0_scalar_add(res, res, &term);
    }
    return 1;
}

/* Compute the powers of rho as rho, rho^2, rho^4 ... rho^(2^(n-1)) */
static void rustsecp256k1zkp_v0_10_0_bppp_powers_of_rho(rustsecp256k1zkp_v0_10_0_scalar *powers, const rustsecp256k1zkp_v0_10_0_scalar *rho, size_t n) {
    size_t i;
    if (n == 0) {
        return;
    }
    powers[0] = *rho;
    for (i = 1; i < n; i++) {
        rustsecp256k1zkp_v0_10_0_scalar_sqr(&powers[i], &powers[i - 1]);
    }
}

typedef struct ecmult_bp_commit_cb_data {
    const rustsecp256k1zkp_v0_10_0_scalar *n;
    const rustsecp256k1zkp_v0_10_0_ge *g;
    const rustsecp256k1zkp_v0_10_0_scalar *l;
    size_t g_len;
} ecmult_bp_commit_cb_data;

static int ecmult_bp_commit_cb(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *cbdata) {
    ecmult_bp_commit_cb_data *data = (ecmult_bp_commit_cb_data*) cbdata;
    *pt = data->g[idx];
    if (idx < data->g_len) {
        *sc = data->n[idx];
    } else {
        *sc = data->l[idx - data->g_len];
    }
    return 1;
}

/* Create a commitment `commit` = vG + n_vec*G_vec + l_vec*H_vec where
   v = |n_vec*n_vec|_mu + <l_vec, c_vec>. |w|_mu denotes mu-weighted norm of w and
   <l, r> denotes inner product of l and r.
*/
static int rustsecp256k1zkp_v0_10_0_bppp_commit(
    const rustsecp256k1zkp_v0_10_0_context* ctx,
    rustsecp256k1zkp_v0_10_0_scratch_space* scratch,
    rustsecp256k1zkp_v0_10_0_ge* commit,
    const rustsecp256k1zkp_v0_10_0_bppp_generators* g_vec,
    const rustsecp256k1zkp_v0_10_0_scalar* n_vec,
    size_t n_vec_len,
    const rustsecp256k1zkp_v0_10_0_scalar* l_vec,
    size_t l_vec_len,
    const rustsecp256k1zkp_v0_10_0_scalar* c_vec,
    size_t c_vec_len,
    const rustsecp256k1zkp_v0_10_0_scalar* mu
) {
    rustsecp256k1zkp_v0_10_0_scalar v, l_c;
    /* First n_vec_len generators are Gs, rest are Hs*/
    VERIFY_CHECK(g_vec->n == (n_vec_len + l_vec_len));
#ifdef VERIFY
    VERIFY_CHECK(l_vec_len == c_vec_len);
#else
    (void)c_vec_len;
#endif

    /* It is possible to extend to support n_vec and c_vec to not be power of
    two. For the initial iterations of the code, we stick to powers of two for simplicity.*/
    VERIFY_CHECK(rustsecp256k1zkp_v0_10_0_is_power_of_two(n_vec_len));
    VERIFY_CHECK(rustsecp256k1zkp_v0_10_0_is_power_of_two(c_vec_len));

    /* Compute v = n_vec*n_vec*mu + l_vec*c_vec */
    rustsecp256k1zkp_v0_10_0_weighted_scalar_inner_product(&v, n_vec, 0 /*a offset */, n_vec, 0 /*b offset*/, 1 /*step*/, n_vec_len, mu);
    rustsecp256k1zkp_v0_10_0_scalar_inner_product(&l_c, l_vec, 0 /*a offset */, c_vec, 0 /*b offset*/, 1 /*step*/, l_vec_len);
    rustsecp256k1zkp_v0_10_0_scalar_add(&v, &v, &l_c);

    {
        ecmult_bp_commit_cb_data data;
        rustsecp256k1zkp_v0_10_0_gej commitj;
        data.g = g_vec->gens;
        data.n = n_vec;
        data.l = l_vec;
        data.g_len = n_vec_len;

        if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, scratch, &commitj, &v, ecmult_bp_commit_cb, (void*) &data, n_vec_len + l_vec_len)) {
            return 0;
        }
        rustsecp256k1zkp_v0_10_0_ge_set_gej_var(commit, &commitj);
    }
    return 1;
}

typedef struct ecmult_x_cb_data {
    const rustsecp256k1zkp_v0_10_0_scalar *n;
    const rustsecp256k1zkp_v0_10_0_ge *g;
    const rustsecp256k1zkp_v0_10_0_scalar *l;
    const rustsecp256k1zkp_v0_10_0_scalar *rho;
    const rustsecp256k1zkp_v0_10_0_scalar *rho_inv;
    size_t G_GENS_LEN; /* Figure out initialization syntax so that this can also be const */
    size_t n_len;
} ecmult_x_cb_data;

static int ecmult_x_cb(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *cbdata) {
    ecmult_x_cb_data *data = (ecmult_x_cb_data*) cbdata;
    if (idx < data->n_len) {
        if (idx % 2 == 0) {
            rustsecp256k1zkp_v0_10_0_scalar_mul(sc, &data->n[idx + 1], data->rho);
            *pt = data->g[idx];
        } else {
            rustsecp256k1zkp_v0_10_0_scalar_mul(sc, &data->n[idx - 1], data->rho_inv);
            *pt = data->g[idx];
        }
    } else {
        idx -= data->n_len;
        if (idx % 2 == 0) {
            *sc = data->l[idx + 1];
            *pt = data->g[data->G_GENS_LEN + idx];
        } else {
            *sc = data->l[idx - 1];
            *pt = data->g[data->G_GENS_LEN + idx];
        }
    }
    return 1;
}

typedef struct ecmult_r_cb_data {
    const rustsecp256k1zkp_v0_10_0_scalar *n1;
    const rustsecp256k1zkp_v0_10_0_ge *g1;
    const rustsecp256k1zkp_v0_10_0_scalar *l1;
    size_t G_GENS_LEN;
    size_t n_len;
} ecmult_r_cb_data;

static int ecmult_r_cb(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *cbdata) {
    ecmult_r_cb_data *data = (ecmult_r_cb_data*) cbdata;
    if (idx < data->n_len) {
        *sc = data->n1[2*idx + 1];
        *pt = data->g1[2*idx + 1];
    } else {
        idx -= data->n_len;
        *sc = data->l1[2*idx + 1];
        *pt = data->g1[data->G_GENS_LEN + 2*idx + 1];
    }
    return 1;
}

/* Recursively compute the norm argument proof satisfying the relation
 * <n_vec, n_vec>_mu + <c_vec, l_vec> = v for some commitment
 * C = v*G + <n_vec, G_vec> + <l_vec, H_vec>. <x, x>_mu is the weighted inner
 * product of x with itself, where the weights are the first n powers of mu.
 * <x, x>_mu = mu*x_1^2 + mu^2*x_2^2 + mu^3*x_3^2 + ... + mu^n*x_n^2.
 * The API computes mu as square of the r challenge (`r^2`).
 *
 * The norm argument is not zero knowledge and does not operate on any secret data.
 * Thus the following code uses variable time operations while computing the proof.
 * This function also modifies the values of n_vec, l_vec, c_vec and g_vec. The caller
 * is expected to copy these values if they need to be preserved.
 *
 * Assumptions: This function is intended to be used in conjunction with the
 * some parent protocol. To use this norm protocol in a standalone manner, the user
 * should add the commitment, generators and initial public data to the transcript hash.
*/
static int rustsecp256k1zkp_v0_10_0_bppp_rangeproof_norm_product_prove(
    const rustsecp256k1zkp_v0_10_0_context* ctx,
    rustsecp256k1zkp_v0_10_0_scratch_space* scratch,
    unsigned char* proof,
    size_t *proof_len,
    rustsecp256k1zkp_v0_10_0_sha256* transcript, /* Transcript hash of the parent protocol */
    const rustsecp256k1zkp_v0_10_0_scalar* rho,
    rustsecp256k1zkp_v0_10_0_ge* g_vec,
    size_t g_vec_len,
    rustsecp256k1zkp_v0_10_0_scalar* n_vec,
    size_t n_vec_len,
    rustsecp256k1zkp_v0_10_0_scalar* l_vec,
    size_t l_vec_len,
    rustsecp256k1zkp_v0_10_0_scalar* c_vec,
    size_t c_vec_len
) {
    rustsecp256k1zkp_v0_10_0_scalar mu_f, rho_f = *rho;
    size_t proof_idx = 0;
    ecmult_x_cb_data x_cb_data;
    ecmult_r_cb_data r_cb_data;
    size_t g_len = n_vec_len, h_len = l_vec_len;
    const size_t G_GENS_LEN = g_len;

#ifdef VERIFY
    {
        size_t log_g_len_ver, log_h_len_ver, num_rounds_ver;
        VERIFY_CHECK(g_len > 0 && h_len > 0); /* Precondition for rustsecp256k1zkp_v0_10_0_bppp_log2() */
        log_g_len_ver = rustsecp256k1zkp_v0_10_0_bppp_log2(g_len);
        log_h_len_ver = rustsecp256k1zkp_v0_10_0_bppp_log2(h_len);
        num_rounds_ver = log_g_len_ver > log_h_len_ver ? log_g_len_ver : log_h_len_ver;
        /* Check proof sizes.*/
        VERIFY_CHECK(*proof_len >= 65 * num_rounds_ver + 64);
        VERIFY_CHECK(g_vec_len == (n_vec_len + l_vec_len) && l_vec_len == c_vec_len);
        VERIFY_CHECK(rustsecp256k1zkp_v0_10_0_is_power_of_two(n_vec_len) && rustsecp256k1zkp_v0_10_0_is_power_of_two(c_vec_len));
    }
#else
    (void)g_vec_len;
    (void)c_vec_len;
#endif

    x_cb_data.n = n_vec;
    x_cb_data.g = g_vec;
    x_cb_data.l = l_vec;
    x_cb_data.G_GENS_LEN = G_GENS_LEN;

    r_cb_data.n1 = n_vec;
    r_cb_data.g1 = g_vec;
    r_cb_data.l1 = l_vec;
    r_cb_data.G_GENS_LEN = G_GENS_LEN;
    rustsecp256k1zkp_v0_10_0_scalar_sqr(&mu_f, &rho_f);


    while (g_len > 1 || h_len > 1) {
        size_t i, num_points;
        rustsecp256k1zkp_v0_10_0_scalar mu_sq, rho_inv, c0_l1, c1_l0, x_v, c1_l1, r_v;
        rustsecp256k1zkp_v0_10_0_gej rj, xj;
        rustsecp256k1zkp_v0_10_0_ge r_ge, x_ge;
        rustsecp256k1zkp_v0_10_0_scalar gamma;

        rustsecp256k1zkp_v0_10_0_scalar_inverse_var(&rho_inv, &rho_f);
        rustsecp256k1zkp_v0_10_0_scalar_sqr(&mu_sq, &mu_f);

        /* Compute the X commitment X = WIP(rho_inv*n0,n1)_mu2 * g + r<n1,G> + <rho_inv*x0, G1> */
        rustsecp256k1zkp_v0_10_0_scalar_inner_product(&c0_l1, c_vec, 0, l_vec, 1, 2, h_len/2);
        rustsecp256k1zkp_v0_10_0_scalar_inner_product(&c1_l0, c_vec, 1, l_vec, 0, 2, h_len/2);
        rustsecp256k1zkp_v0_10_0_weighted_scalar_inner_product(&x_v, n_vec, 0, n_vec, 1, 2, g_len/2, &mu_sq);
        rustsecp256k1zkp_v0_10_0_scalar_mul(&x_v, &x_v, &rho_inv);
        rustsecp256k1zkp_v0_10_0_scalar_add(&x_v, &x_v, &x_v);
        rustsecp256k1zkp_v0_10_0_scalar_add(&x_v, &x_v, &c0_l1);
        rustsecp256k1zkp_v0_10_0_scalar_add(&x_v, &x_v, &c1_l0);

        x_cb_data.rho = &rho_f;
        x_cb_data.rho_inv = &rho_inv;
        x_cb_data.n_len = g_len >= 2 ? g_len : 0;
        num_points = x_cb_data.n_len + (h_len >= 2 ? h_len : 0);

        if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, scratch, &xj, &x_v, ecmult_x_cb, (void*)&x_cb_data, num_points)) {
            return 0;
        }

        rustsecp256k1zkp_v0_10_0_weighted_scalar_inner_product(&r_v, n_vec, 1, n_vec, 1, 2, g_len/2, &mu_sq);
        rustsecp256k1zkp_v0_10_0_scalar_inner_product(&c1_l1, c_vec, 1, l_vec, 1, 2, h_len/2);
        rustsecp256k1zkp_v0_10_0_scalar_add(&r_v, &r_v, &c1_l1);

        r_cb_data.n_len = g_len/2;
        num_points = r_cb_data.n_len + h_len/2;
        if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, scratch, &rj, &r_v, ecmult_r_cb, (void*)&r_cb_data, num_points)) {
            return 0;
        }

        rustsecp256k1zkp_v0_10_0_ge_set_gej_var(&x_ge, &xj);
        rustsecp256k1zkp_v0_10_0_ge_set_gej_var(&r_ge, &rj);
        rustsecp256k1zkp_v0_10_0_bppp_serialize_points(&proof[proof_idx], &x_ge, &r_ge);
        proof_idx += 65;

        /* Obtain challenge gamma for the the next round */
        rustsecp256k1zkp_v0_10_0_sha256_write(transcript, &proof[proof_idx - 65], 65);
        rustsecp256k1zkp_v0_10_0_bppp_challenge_scalar(&gamma, transcript, 0);

        if (g_len > 1) {
            for (i = 0; i < g_len; i = i + 2) {
                rustsecp256k1zkp_v0_10_0_scalar nl, nr;
                rustsecp256k1zkp_v0_10_0_gej gl, gr;
                rustsecp256k1zkp_v0_10_0_scalar_mul(&nl, &n_vec[i], &rho_inv);
                rustsecp256k1zkp_v0_10_0_scalar_mul(&nr, &n_vec[i + 1], &gamma);
                rustsecp256k1zkp_v0_10_0_scalar_add(&n_vec[i/2], &nl, &nr);

                rustsecp256k1zkp_v0_10_0_gej_set_ge(&gl, &g_vec[i]);
                rustsecp256k1zkp_v0_10_0_ecmult(&gl, &gl, &rho_f, NULL);
                rustsecp256k1zkp_v0_10_0_gej_set_ge(&gr, &g_vec[i + 1]);
                rustsecp256k1zkp_v0_10_0_ecmult(&gr, &gr, &gamma, NULL);
                rustsecp256k1zkp_v0_10_0_gej_add_var(&gl, &gl, &gr, NULL);
                rustsecp256k1zkp_v0_10_0_ge_set_gej_var(&g_vec[i/2], &gl);
            }
        }

        if (h_len > 1) {
            for (i = 0; i < h_len; i = i + 2) {
                rustsecp256k1zkp_v0_10_0_scalar temp1;
                rustsecp256k1zkp_v0_10_0_gej grj;
                rustsecp256k1zkp_v0_10_0_scalar_mul(&temp1, &c_vec[i + 1], &gamma);
                rustsecp256k1zkp_v0_10_0_scalar_add(&c_vec[i/2], &c_vec[i], &temp1);

                rustsecp256k1zkp_v0_10_0_scalar_mul(&temp1, &l_vec[i + 1], &gamma);
                rustsecp256k1zkp_v0_10_0_scalar_add(&l_vec[i/2], &l_vec[i], &temp1);

                rustsecp256k1zkp_v0_10_0_gej_set_ge(&grj, &g_vec[G_GENS_LEN + i + 1]);
                rustsecp256k1zkp_v0_10_0_ecmult(&grj, &grj, &gamma, NULL);
                rustsecp256k1zkp_v0_10_0_gej_add_ge_var(&grj, &grj, &g_vec[G_GENS_LEN + i], NULL);
                rustsecp256k1zkp_v0_10_0_ge_set_gej_var(&g_vec[G_GENS_LEN + i/2], &grj);
            }
        }
        g_len = g_len / 2;
        h_len = h_len / 2;
        rho_f = mu_f;
        mu_f = mu_sq;
    }

    rustsecp256k1zkp_v0_10_0_scalar_get_b32(&proof[proof_idx], &n_vec[0]);
    rustsecp256k1zkp_v0_10_0_scalar_get_b32(&proof[proof_idx + 32], &l_vec[0]);
    proof_idx += 64;
    *proof_len = proof_idx;
    return 1;
}

typedef struct ec_mult_verify_cb_data1 {
    const unsigned char *proof;
    const rustsecp256k1zkp_v0_10_0_ge *commit;
    const rustsecp256k1zkp_v0_10_0_scalar *gammas;
} ec_mult_verify_cb_data1;

static int ec_mult_verify_cb1(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *cbdata) {
    ec_mult_verify_cb_data1 *data = (ec_mult_verify_cb_data1*) cbdata;
    if (idx == 0) {
        *pt = *data->commit;
        rustsecp256k1zkp_v0_10_0_scalar_set_int(sc, 1);
        return 1;
    }
    idx -= 1;
    if (idx % 2 == 0) {
        idx /= 2;
        *sc = data->gammas[idx];
        if (!rustsecp256k1zkp_v0_10_0_bppp_parse_one_of_points(pt, &data->proof[65*idx], 0)) {
            return 0;
        }
    } else {
        rustsecp256k1zkp_v0_10_0_scalar neg_one;
        idx /= 2;
        rustsecp256k1zkp_v0_10_0_scalar_set_int(&neg_one, 1);
        rustsecp256k1zkp_v0_10_0_scalar_negate(&neg_one, &neg_one);
        *sc = data->gammas[idx];
        rustsecp256k1zkp_v0_10_0_scalar_sqr(sc, sc);
        rustsecp256k1zkp_v0_10_0_scalar_add(sc, sc, &neg_one);
        if (!rustsecp256k1zkp_v0_10_0_bppp_parse_one_of_points(pt, &data->proof[65*idx], 1)) {
            return 0;
        }
    }
    return 1;
}

typedef struct ec_mult_verify_cb_data2 {
    const rustsecp256k1zkp_v0_10_0_scalar *s_g;
    const rustsecp256k1zkp_v0_10_0_scalar *s_h;
    const rustsecp256k1zkp_v0_10_0_ge *g_vec;
    size_t g_vec_len;
} ec_mult_verify_cb_data2;

static int ec_mult_verify_cb2(rustsecp256k1zkp_v0_10_0_scalar *sc, rustsecp256k1zkp_v0_10_0_ge *pt, size_t idx, void *cbdata) {
    ec_mult_verify_cb_data2 *data = (ec_mult_verify_cb_data2*) cbdata;
    if (idx < data->g_vec_len) {
        *sc = data->s_g[idx];
    } else {
        *sc = data->s_h[idx - data->g_vec_len];
    }
    *pt = data->g_vec[idx];
    return 1;
}

/* Verify the proof. This function modifies the generators, c_vec and the challenge r. The
   caller should make sure to back them up if they need to be reused.
*/
static int rustsecp256k1zkp_v0_10_0_bppp_rangeproof_norm_product_verify(
    const rustsecp256k1zkp_v0_10_0_context* ctx,
    rustsecp256k1zkp_v0_10_0_scratch_space* scratch,
    const unsigned char* proof,
    size_t proof_len,
    rustsecp256k1zkp_v0_10_0_sha256* transcript,
    const rustsecp256k1zkp_v0_10_0_scalar* rho,
    const rustsecp256k1zkp_v0_10_0_bppp_generators* g_vec,
    size_t g_len,
    const rustsecp256k1zkp_v0_10_0_scalar* c_vec,
    size_t c_vec_len,
    const rustsecp256k1zkp_v0_10_0_ge* commit
) {
    rustsecp256k1zkp_v0_10_0_scalar rho_f, mu_f, v, n, l, rho_inv, h_c;
    rustsecp256k1zkp_v0_10_0_scalar *gammas, *s_g, *s_h, *rho_inv_pows;
    rustsecp256k1zkp_v0_10_0_gej res1, res2;
    size_t i = 0, scratch_checkpoint;
    int overflow;
    size_t log_g_len, log_h_len;
    size_t n_rounds;
    size_t h_len = c_vec_len;

    if (g_len == 0 || c_vec_len == 0) {
        return 0;
    }
    log_g_len = rustsecp256k1zkp_v0_10_0_bppp_log2(g_len);
    log_h_len = rustsecp256k1zkp_v0_10_0_bppp_log2(c_vec_len);
    n_rounds = log_g_len > log_h_len ? log_g_len : log_h_len;

    if (g_vec->n != (h_len + g_len) || (proof_len != 65 * n_rounds + 64)) {
        return 0;
    }

    if (!rustsecp256k1zkp_v0_10_0_is_power_of_two(g_len) ||  !rustsecp256k1zkp_v0_10_0_is_power_of_two(h_len)) {
        return 0;
    }

    rustsecp256k1zkp_v0_10_0_scalar_set_b32(&n, &proof[n_rounds*65], &overflow); /* n */
    if (overflow) return 0;
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(&l, &proof[n_rounds*65 + 32], &overflow); /* l */
    if (overflow) return 0;
    if (rustsecp256k1zkp_v0_10_0_scalar_is_zero(rho)) return 0;

    /* Collect the gammas in a new vector */
    scratch_checkpoint = rustsecp256k1zkp_v0_10_0_scratch_checkpoint(&ctx->error_callback, scratch);
    gammas = (rustsecp256k1zkp_v0_10_0_scalar*)rustsecp256k1zkp_v0_10_0_scratch_alloc(&ctx->error_callback, scratch, n_rounds * sizeof(rustsecp256k1zkp_v0_10_0_scalar));
    s_g = (rustsecp256k1zkp_v0_10_0_scalar*)rustsecp256k1zkp_v0_10_0_scratch_alloc(&ctx->error_callback, scratch, g_len * sizeof(rustsecp256k1zkp_v0_10_0_scalar));
    s_h = (rustsecp256k1zkp_v0_10_0_scalar*)rustsecp256k1zkp_v0_10_0_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(rustsecp256k1zkp_v0_10_0_scalar));
    rho_inv_pows = (rustsecp256k1zkp_v0_10_0_scalar*)rustsecp256k1zkp_v0_10_0_scratch_alloc(&ctx->error_callback, scratch, log_g_len * sizeof(rustsecp256k1zkp_v0_10_0_scalar));
    if (gammas == NULL || s_g == NULL || s_h == NULL || rho_inv_pows == NULL) {
        rustsecp256k1zkp_v0_10_0_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    /* Compute powers of rho_inv. Later used in g_factor computations*/
    rustsecp256k1zkp_v0_10_0_scalar_inverse_var(&rho_inv, rho);
    rustsecp256k1zkp_v0_10_0_bppp_powers_of_rho(rho_inv_pows, &rho_inv, log_g_len);

    /* Compute rho_f = rho^(2^log_g_len) */
    rho_f = *rho;
    for (i = 0; i < log_g_len; i++) {
        rustsecp256k1zkp_v0_10_0_scalar_sqr(&rho_f, &rho_f);
    }

    for (i = 0; i < n_rounds; i++) {
        rustsecp256k1zkp_v0_10_0_scalar gamma;
        rustsecp256k1zkp_v0_10_0_sha256_write(transcript, &proof[i * 65], 65);
        rustsecp256k1zkp_v0_10_0_bppp_challenge_scalar(&gamma, transcript, 0);
        gammas[i] = gamma;
    }
    /* s_g[0] = n * \prod_{j=0}^{log_g_len - 1} rho^(2^j)
     *        = n * rho^(2^log_g_len - 1)
     *        = n * rho_f * rho_inv */
    rustsecp256k1zkp_v0_10_0_scalar_mul(&s_g[0], &n, &rho_f);
    rustsecp256k1zkp_v0_10_0_scalar_mul(&s_g[0], &s_g[0], &rho_inv);
    for (i = 1; i < g_len; i++) {
        size_t log_i = rustsecp256k1zkp_v0_10_0_bppp_log2(i);
        size_t nearest_pow_of_two = (size_t)1 << log_i;
        /* This combines the two multiplications of gammas and rho_invs in a
         * single loop.
         * s_g[i] = s_g[i - nearest_pow_of_two]
         *            * e[log_i] * rho_inv^(2^log_i) */
        rustsecp256k1zkp_v0_10_0_scalar_mul(&s_g[i], &s_g[i - nearest_pow_of_two], &gammas[log_i]);
        rustsecp256k1zkp_v0_10_0_scalar_mul(&s_g[i], &s_g[i], &rho_inv_pows[log_i]);
    }
    s_h[0] = l;
    rustsecp256k1zkp_v0_10_0_scalar_set_int(&h_c, 0);
    for (i = 1; i < h_len; i++) {
        size_t log_i = rustsecp256k1zkp_v0_10_0_bppp_log2(i);
        size_t nearest_pow_of_two = (size_t)1 << log_i;
        rustsecp256k1zkp_v0_10_0_scalar_mul(&s_h[i], &s_h[i - nearest_pow_of_two], &gammas[log_i]);
    }
    rustsecp256k1zkp_v0_10_0_scalar_inner_product(&h_c, c_vec, 0 /* a_offset */ , s_h, 0 /* b_offset */, 1 /* step */, h_len);
    /* Compute v = n*n*mu_f + l*h_c where mu_f = rho_f^2 */
    rustsecp256k1zkp_v0_10_0_scalar_sqr(&mu_f, &rho_f);
    rustsecp256k1zkp_v0_10_0_scalar_mul(&v, &n, &n);
    rustsecp256k1zkp_v0_10_0_scalar_mul(&v, &v, &mu_f);
    rustsecp256k1zkp_v0_10_0_scalar_add(&v, &v, &h_c);

    {
        ec_mult_verify_cb_data1 data;
        data.proof = proof;
        data.commit = commit;
        data.gammas = gammas;

        if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, scratch, &res1, NULL, ec_mult_verify_cb1, &data, 2*n_rounds + 1)) {
            rustsecp256k1zkp_v0_10_0_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
    }
    {
        ec_mult_verify_cb_data2 data;
        data.g_vec = g_vec->gens;
        data.g_vec_len = g_len;
        data.s_g = s_g;
        data.s_h = s_h;

        if (!rustsecp256k1zkp_v0_10_0_ecmult_multi_var(&ctx->error_callback, scratch, &res2, &v, ec_mult_verify_cb2, &data, g_len + h_len)) {
            rustsecp256k1zkp_v0_10_0_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
            return 0;
        }
    }

    rustsecp256k1zkp_v0_10_0_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);

    return rustsecp256k1zkp_v0_10_0_gej_eq_var(&res1, &res2);
}
#endif
