/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BPPP_MAIN_
#define _SECP256K1_MODULE_BPPP_MAIN_

#include "include/secp256k1_bppp.h"
#include "include/secp256k1_generator.h"
#include "modules/generator/main_impl.h" /* for generator_{load, save} */
#include "hash.h"
#include "util.h"
#include "modules/bppp/main.h"
#include "modules/bppp/bppp_norm_product_impl.h"

rustsecp256k1zkp_v0_8_0_bppp_generators *rustsecp256k1zkp_v0_8_0_bppp_generators_create(const rustsecp256k1zkp_v0_8_0_context *ctx, size_t n) {
    rustsecp256k1zkp_v0_8_0_bppp_generators *ret;
    rustsecp256k1zkp_v0_8_0_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    size_t i;

    VERIFY_CHECK(ctx != NULL);

    ret = (rustsecp256k1zkp_v0_8_0_bppp_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (rustsecp256k1zkp_v0_8_0_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }
    ret->n = n;

    rustsecp256k1zkp_v0_8_0_fe_get_b32(&seed[0], &rustsecp256k1zkp_v0_8_0_ge_const_g.x);
    rustsecp256k1zkp_v0_8_0_fe_get_b32(&seed[32], &rustsecp256k1zkp_v0_8_0_ge_const_g.y);

    rustsecp256k1zkp_v0_8_0_rfc6979_hmac_sha256_initialize(&rng, seed, 64);
    for (i = 0; i < n; i++) {
        rustsecp256k1zkp_v0_8_0_generator gen;
        unsigned char tmp[32] = { 0 };
        rustsecp256k1zkp_v0_8_0_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
        CHECK(rustsecp256k1zkp_v0_8_0_generator_generate(ctx, &gen, tmp));
        rustsecp256k1zkp_v0_8_0_generator_load(&ret->gens[i], &gen);
    }

    return ret;
}

rustsecp256k1zkp_v0_8_0_bppp_generators* rustsecp256k1zkp_v0_8_0_bppp_generators_parse(const rustsecp256k1zkp_v0_8_0_context* ctx, const unsigned char* data, size_t data_len) {
    size_t n = data_len / 33;
    rustsecp256k1zkp_v0_8_0_bppp_generators* ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(data != NULL);

    if (data_len % 33 != 0) {
        return NULL;
    }

    ret = (rustsecp256k1zkp_v0_8_0_bppp_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->n = n;
    ret->gens = (rustsecp256k1zkp_v0_8_0_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }

    while (n--) {
        rustsecp256k1zkp_v0_8_0_generator gen;
        if (!rustsecp256k1zkp_v0_8_0_generator_parse(ctx, &gen, &data[33 * n])) {
            free(ret->gens);
            free(ret);
            return NULL;
        }
        rustsecp256k1zkp_v0_8_0_generator_load(&ret->gens[n], &gen);
    }
    return ret;
}

int rustsecp256k1zkp_v0_8_0_bppp_generators_serialize(const rustsecp256k1zkp_v0_8_0_context* ctx, const rustsecp256k1zkp_v0_8_0_bppp_generators* gens, unsigned char* data, size_t *data_len) {
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(data_len != NULL);
    ARG_CHECK(*data_len >= 33 * gens->n);

    memset(data, 0, *data_len);
    for (i = 0; i < gens->n; i++) {
        rustsecp256k1zkp_v0_8_0_generator gen;
        rustsecp256k1zkp_v0_8_0_generator_save(&gen, &gens->gens[i]);
        rustsecp256k1zkp_v0_8_0_generator_serialize(ctx, &data[33 * i], &gen);
    }

    *data_len = 33 * gens->n;
    return 1;
}

void rustsecp256k1zkp_v0_8_0_bppp_generators_destroy(const rustsecp256k1zkp_v0_8_0_context* ctx, rustsecp256k1zkp_v0_8_0_bppp_generators *gens) {
    VERIFY_CHECK(ctx != NULL);
    (void) ctx;
    if (gens != NULL) {
        free(gens->gens);
        free(gens);
    }
}

#endif
