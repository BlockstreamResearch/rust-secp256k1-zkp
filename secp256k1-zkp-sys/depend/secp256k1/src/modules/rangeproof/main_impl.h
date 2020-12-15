/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN
#define SECP256K1_MODULE_RANGEPROOF_MAIN

#include "group.h"

#include "modules/rangeproof/pedersen_impl.h"
#include "modules/rangeproof/borromean_impl.h"
#include "modules/rangeproof/rangeproof_impl.h"

/** Alternative generator for secp256k1.
 *  This is the sha256 of 'g' after standard encoding (without compression),
 *  which happens to be a point on the curve. More precisely, the generator is
 *  derived by running the following script with the sage mathematics software.

    import hashlib
    F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    G = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    H = EllipticCurve ([F (0), F (7)]).lift_x(F(int(hashlib.sha256(G.decode('hex')).hexdigest(),16)))
    print('%x %x' % H.xy())
 */
static const rustsecp256k1zkp_v0_1_0_generator rustsecp256k1zkp_v0_1_0_generator_h_internal = {{
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
}};

const rustsecp256k1zkp_v0_1_0_generator *rustsecp256k1zkp_v0_1_0_generator_h = &rustsecp256k1zkp_v0_1_0_generator_h_internal;

static void rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(rustsecp256k1zkp_v0_1_0_ge* ge, const rustsecp256k1zkp_v0_1_0_pedersen_commitment* commit) {
    rustsecp256k1zkp_v0_1_0_fe fe;
    rustsecp256k1zkp_v0_1_0_fe_set_b32(&fe, &commit->data[1]);
    rustsecp256k1zkp_v0_1_0_ge_set_xquad(ge, &fe);
    if (commit->data[0] & 1) {
        rustsecp256k1zkp_v0_1_0_ge_neg(ge, ge);
    }
}

static void rustsecp256k1zkp_v0_1_0_pedersen_commitment_save(rustsecp256k1zkp_v0_1_0_pedersen_commitment* commit, rustsecp256k1zkp_v0_1_0_ge* ge) {
    rustsecp256k1zkp_v0_1_0_fe_normalize(&ge->x);
    rustsecp256k1zkp_v0_1_0_fe_get_b32(&commit->data[1], &ge->x);
    commit->data[0] = 9 ^ rustsecp256k1zkp_v0_1_0_fe_is_quad_var(&ge->y);
}

int rustsecp256k1zkp_v0_1_0_pedersen_commitment_parse(const rustsecp256k1zkp_v0_1_0_context* ctx, rustsecp256k1zkp_v0_1_0_pedersen_commitment* commit, const unsigned char *input) {
    rustsecp256k1zkp_v0_1_0_fe x;
    rustsecp256k1zkp_v0_1_0_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(input != NULL);
    (void) ctx;

    if ((input[0] & 0xFE) != 8 ||
        !rustsecp256k1zkp_v0_1_0_fe_set_b32(&x, &input[1]) ||
        !rustsecp256k1zkp_v0_1_0_ge_set_xquad(&ge, &x)) {
        return 0;
    }
    if (input[0] & 1) {
        rustsecp256k1zkp_v0_1_0_ge_neg(&ge, &ge);
    }
    rustsecp256k1zkp_v0_1_0_pedersen_commitment_save(commit, &ge);
    return 1;
}

int rustsecp256k1zkp_v0_1_0_pedersen_commitment_serialize(const rustsecp256k1zkp_v0_1_0_context* ctx, unsigned char *output, const rustsecp256k1zkp_v0_1_0_pedersen_commitment* commit) {
    rustsecp256k1zkp_v0_1_0_ge ge;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(commit != NULL);

    rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(&ge, commit);

    output[0] = 9 ^ rustsecp256k1zkp_v0_1_0_fe_is_quad_var(&ge.y);
    rustsecp256k1zkp_v0_1_0_fe_normalize_var(&ge.x);
    rustsecp256k1zkp_v0_1_0_fe_get_b32(&output[1], &ge.x);
    return 1;
}

/* Generates a pedersen commitment: *commit = blind * G + value * G2. The blinding factor is 32 bytes.*/
int rustsecp256k1zkp_v0_1_0_pedersen_commit(const rustsecp256k1zkp_v0_1_0_context* ctx, rustsecp256k1zkp_v0_1_0_pedersen_commitment *commit, const unsigned char *blind, uint64_t value, const rustsecp256k1zkp_v0_1_0_generator* gen) {
    rustsecp256k1zkp_v0_1_0_ge genp;
    rustsecp256k1zkp_v0_1_0_gej rj;
    rustsecp256k1zkp_v0_1_0_ge r;
    rustsecp256k1zkp_v0_1_0_scalar sec;
    int overflow;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_1_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(gen != NULL);
    rustsecp256k1zkp_v0_1_0_generator_load(&genp, gen);
    rustsecp256k1zkp_v0_1_0_scalar_set_b32(&sec, blind, &overflow);
    if (!overflow) {
        rustsecp256k1zkp_v0_1_0_pedersen_ecmult(&ctx->ecmult_gen_ctx, &rj, &sec, value, &genp);
        if (!rustsecp256k1zkp_v0_1_0_gej_is_infinity(&rj)) {
            rustsecp256k1zkp_v0_1_0_ge_set_gej(&r, &rj);
            rustsecp256k1zkp_v0_1_0_pedersen_commitment_save(commit, &r);
            ret = 1;
        }
        rustsecp256k1zkp_v0_1_0_gej_clear(&rj);
        rustsecp256k1zkp_v0_1_0_ge_clear(&r);
    }
    rustsecp256k1zkp_v0_1_0_scalar_clear(&sec);
    return ret;
}

/** Takes a list of n pointers to 32 byte blinding values, the first negs of which are treated with positive sign and the rest
 *  negative, then calculates an additional blinding value that adds to zero.
 */
int rustsecp256k1zkp_v0_1_0_pedersen_blind_sum(const rustsecp256k1zkp_v0_1_0_context* ctx, unsigned char *blind_out, const unsigned char * const *blinds, size_t n, size_t npositive) {
    rustsecp256k1zkp_v0_1_0_scalar acc;
    rustsecp256k1zkp_v0_1_0_scalar x;
    size_t i;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(blind_out != NULL);
    ARG_CHECK(blinds != NULL);
    ARG_CHECK(npositive <= n);
    (void) ctx;
    rustsecp256k1zkp_v0_1_0_scalar_set_int(&acc, 0);
    for (i = 0; i < n; i++) {
        rustsecp256k1zkp_v0_1_0_scalar_set_b32(&x, blinds[i], &overflow);
        if (overflow) {
            return 0;
        }
        if (i >= npositive) {
            rustsecp256k1zkp_v0_1_0_scalar_negate(&x, &x);
        }
        rustsecp256k1zkp_v0_1_0_scalar_add(&acc, &acc, &x);
    }
    rustsecp256k1zkp_v0_1_0_scalar_get_b32(blind_out, &acc);
    rustsecp256k1zkp_v0_1_0_scalar_clear(&acc);
    rustsecp256k1zkp_v0_1_0_scalar_clear(&x);
    return 1;
}

/* Takes two lists of commitments and sums the first set and subtracts the second and verifies that they sum to excess. */
int rustsecp256k1zkp_v0_1_0_pedersen_verify_tally(const rustsecp256k1zkp_v0_1_0_context* ctx, const rustsecp256k1zkp_v0_1_0_pedersen_commitment * const* commits, size_t pcnt, const rustsecp256k1zkp_v0_1_0_pedersen_commitment * const* ncommits, size_t ncnt) {
    rustsecp256k1zkp_v0_1_0_gej accj;
    rustsecp256k1zkp_v0_1_0_ge add;
    size_t i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(!pcnt || (commits != NULL));
    ARG_CHECK(!ncnt || (ncommits != NULL));
    (void) ctx;
    rustsecp256k1zkp_v0_1_0_gej_set_infinity(&accj);
    for (i = 0; i < ncnt; i++) {
        rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(&add, ncommits[i]);
        rustsecp256k1zkp_v0_1_0_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    rustsecp256k1zkp_v0_1_0_gej_neg(&accj, &accj);
    for (i = 0; i < pcnt; i++) {
        rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(&add, commits[i]);
        rustsecp256k1zkp_v0_1_0_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    return rustsecp256k1zkp_v0_1_0_gej_is_infinity(&accj);
}

int rustsecp256k1zkp_v0_1_0_pedersen_blind_generator_blind_sum(const rustsecp256k1zkp_v0_1_0_context* ctx, const uint64_t *value, const unsigned char* const* generator_blind, unsigned char* const* blinding_factor, size_t n_total, size_t n_inputs) {
    rustsecp256k1zkp_v0_1_0_scalar sum;
    rustsecp256k1zkp_v0_1_0_scalar tmp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(n_total == 0 || value != NULL);
    ARG_CHECK(n_total == 0 || generator_blind != NULL);
    ARG_CHECK(n_total == 0 || blinding_factor != NULL);
    ARG_CHECK(n_total > n_inputs);
    (void) ctx;

    if (n_total == 0) {
        return 1;
    }

    rustsecp256k1zkp_v0_1_0_scalar_set_int(&sum, 0);
    for (i = 0; i < n_total; i++) {
        int overflow = 0;
        rustsecp256k1zkp_v0_1_0_scalar addend;
        rustsecp256k1zkp_v0_1_0_scalar_set_u64(&addend, value[i]);  /* s = v */

        rustsecp256k1zkp_v0_1_0_scalar_set_b32(&tmp, generator_blind[i], &overflow);
        if (overflow == 1) {
            rustsecp256k1zkp_v0_1_0_scalar_clear(&tmp);
            rustsecp256k1zkp_v0_1_0_scalar_clear(&addend);
            rustsecp256k1zkp_v0_1_0_scalar_clear(&sum);
            return 0;
        }
        rustsecp256k1zkp_v0_1_0_scalar_mul(&addend, &addend, &tmp); /* s = vr */

        rustsecp256k1zkp_v0_1_0_scalar_set_b32(&tmp, blinding_factor[i], &overflow);
        if (overflow == 1) {
            rustsecp256k1zkp_v0_1_0_scalar_clear(&tmp);
            rustsecp256k1zkp_v0_1_0_scalar_clear(&addend);
            rustsecp256k1zkp_v0_1_0_scalar_clear(&sum);
            return 0;
        }
        rustsecp256k1zkp_v0_1_0_scalar_add(&addend, &addend, &tmp); /* s = vr + r' */
        rustsecp256k1zkp_v0_1_0_scalar_cond_negate(&addend, i < n_inputs);  /* s is negated if it's an input */
        rustsecp256k1zkp_v0_1_0_scalar_add(&sum, &sum, &addend);    /* sum += s */
        rustsecp256k1zkp_v0_1_0_scalar_clear(&addend);
    }

    /* Right now tmp has the last pedersen blinding factor. Subtract the sum from it. */
    rustsecp256k1zkp_v0_1_0_scalar_negate(&sum, &sum);
    rustsecp256k1zkp_v0_1_0_scalar_add(&tmp, &tmp, &sum);
    rustsecp256k1zkp_v0_1_0_scalar_get_b32(blinding_factor[n_total - 1], &tmp);

    rustsecp256k1zkp_v0_1_0_scalar_clear(&tmp);
    rustsecp256k1zkp_v0_1_0_scalar_clear(&sum);
    return 1;
}

int rustsecp256k1zkp_v0_1_0_rangeproof_info(const rustsecp256k1zkp_v0_1_0_context* ctx, int *exp, int *mantissa,
 uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, size_t plen) {
    size_t offset;
    uint64_t scale;
    ARG_CHECK(exp != NULL);
    ARG_CHECK(mantissa != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(proof != NULL);
    offset = 0;
    scale = 1;
    (void)ctx;
    return rustsecp256k1zkp_v0_1_0_rangeproof_getheader_impl(&offset, exp, mantissa, &scale, min_value, max_value, proof, plen);
}

int rustsecp256k1zkp_v0_1_0_rangeproof_rewind(const rustsecp256k1zkp_v0_1_0_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const rustsecp256k1zkp_v0_1_0_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_1_0_generator* gen) {
    rustsecp256k1zkp_v0_1_0_ge commitp;
    rustsecp256k1zkp_v0_1_0_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(message_out != NULL || outlen == NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_1_0_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(rustsecp256k1zkp_v0_1_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1zkp_v0_1_0_generator_load(&genp, gen);
    return rustsecp256k1zkp_v0_1_0_rangeproof_verify_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int rustsecp256k1zkp_v0_1_0_rangeproof_verify(const rustsecp256k1zkp_v0_1_0_context* ctx, uint64_t *min_value, uint64_t *max_value,
 const rustsecp256k1zkp_v0_1_0_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_1_0_generator* gen) {
    rustsecp256k1zkp_v0_1_0_ge commitp;
    rustsecp256k1zkp_v0_1_0_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_1_0_ecmult_context_is_built(&ctx->ecmult_ctx));
    rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1zkp_v0_1_0_generator_load(&genp, gen);
    return rustsecp256k1zkp_v0_1_0_rangeproof_verify_impl(&ctx->ecmult_ctx, NULL,
     NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int rustsecp256k1zkp_v0_1_0_rangeproof_sign(const rustsecp256k1zkp_v0_1_0_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const rustsecp256k1zkp_v0_1_0_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_1_0_generator* gen){
    rustsecp256k1zkp_v0_1_0_ge commitp;
    rustsecp256k1zkp_v0_1_0_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(message != NULL || msg_len == 0);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_1_0_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(rustsecp256k1zkp_v0_1_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    rustsecp256k1zkp_v0_1_0_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1zkp_v0_1_0_generator_load(&genp, gen);
    return rustsecp256k1zkp_v0_1_0_rangeproof_sign_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

#endif
