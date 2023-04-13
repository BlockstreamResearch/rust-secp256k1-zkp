/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN
#define SECP256K1_MODULE_RANGEPROOF_MAIN

#include "../../group.h"

#include "modules/generator/main_impl.h"
#include "modules/rangeproof/borromean_impl.h"
#include "modules/rangeproof/rangeproof_impl.h"

int rustsecp256k1zkp_v0_8_0_rangeproof_info(const rustsecp256k1zkp_v0_8_0_context* ctx, int *exp, int *mantissa,
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
    return rustsecp256k1zkp_v0_8_0_rangeproof_getheader_impl(&offset, exp, mantissa, &scale, min_value, max_value, proof, plen);
}

int rustsecp256k1zkp_v0_8_0_rangeproof_rewind(const rustsecp256k1zkp_v0_8_0_context* ctx,
 unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value,
 const rustsecp256k1zkp_v0_8_0_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_8_0_generator* gen) {
    rustsecp256k1zkp_v0_8_0_ge commitp;
    rustsecp256k1zkp_v0_8_0_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(message_out != NULL || outlen == NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_8_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    rustsecp256k1zkp_v0_8_0_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1zkp_v0_8_0_generator_load(&genp, gen);
    return rustsecp256k1zkp_v0_8_0_rangeproof_verify_impl(&ctx->ecmult_gen_ctx,
     blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int rustsecp256k1zkp_v0_8_0_rangeproof_verify(const rustsecp256k1zkp_v0_8_0_context* ctx, uint64_t *min_value, uint64_t *max_value,
 const rustsecp256k1zkp_v0_8_0_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_8_0_generator* gen) {
    rustsecp256k1zkp_v0_8_0_ge commitp;
    rustsecp256k1zkp_v0_8_0_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(min_value != NULL);
    ARG_CHECK(max_value != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    rustsecp256k1zkp_v0_8_0_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1zkp_v0_8_0_generator_load(&genp, gen);
    return rustsecp256k1zkp_v0_8_0_rangeproof_verify_impl(NULL,
     NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int rustsecp256k1zkp_v0_8_0_rangeproof_sign(const rustsecp256k1zkp_v0_8_0_context* ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
 const rustsecp256k1zkp_v0_8_0_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
 const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_8_0_generator* gen){
    rustsecp256k1zkp_v0_8_0_ge commitp;
    rustsecp256k1zkp_v0_8_0_ge genp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(message != NULL || msg_len == 0);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);
    ARG_CHECK(gen != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_8_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    rustsecp256k1zkp_v0_8_0_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1zkp_v0_8_0_generator_load(&genp, gen);
    return rustsecp256k1zkp_v0_8_0_rangeproof_sign_impl(&ctx->ecmult_gen_ctx,
     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

size_t rustsecp256k1zkp_v0_8_0_rangeproof_max_size(const rustsecp256k1zkp_v0_8_0_context* ctx, uint64_t max_value, int min_bits) {
    const int val_mantissa = max_value > 0 ? 64 - rustsecp256k1zkp_v0_8_0_clz64_var(max_value) : 1;
    const int mantissa = min_bits > val_mantissa ? min_bits : val_mantissa;
    const size_t rings = (mantissa + 1) / 2;
    const size_t npubs = rings * 4 - 2 * (mantissa % 2);

    VERIFY_CHECK(ctx != NULL);
    (void) ctx;

    return 10 + 32 * (npubs + rings - 1) + 32 + ((rings - 1 + 7) / 8);
}

#endif
