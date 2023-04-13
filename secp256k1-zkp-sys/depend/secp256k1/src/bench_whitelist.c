/**********************************************************************
 * Copyright (c) 2017 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <stdio.h>

#include "include/secp256k1.h"

#include "include/secp256k1_whitelist.h"
#include "util.h"
#include "bench.h"
#include "hash_impl.h"
#include "scalar_impl.h"
#include "testrand_impl.h"

#define MAX_N_KEYS 30

typedef struct {
    rustsecp256k1zkp_v0_8_0_context* ctx;
    unsigned char online_seckey[MAX_N_KEYS][32];
    unsigned char summed_seckey[MAX_N_KEYS][32];
    rustsecp256k1zkp_v0_8_0_pubkey online_pubkeys[MAX_N_KEYS];
    rustsecp256k1zkp_v0_8_0_pubkey offline_pubkeys[MAX_N_KEYS];
    unsigned char csub[32];
    rustsecp256k1zkp_v0_8_0_pubkey sub_pubkey;
    rustsecp256k1zkp_v0_8_0_whitelist_signature sig;
    size_t n_keys;
} bench_data;

static void bench_whitelist(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int i;
    for (i = 0; i < iters; i++) {
        CHECK(rustsecp256k1zkp_v0_8_0_whitelist_verify(data->ctx, &data->sig, data->online_pubkeys, data->offline_pubkeys, data->n_keys, &data->sub_pubkey) == 1);
    }
}

static void bench_whitelist_setup(void* arg) {
    bench_data* data = (bench_data*)arg;
    int i = 0;
    CHECK(rustsecp256k1zkp_v0_8_0_whitelist_sign(data->ctx, &data->sig, data->online_pubkeys, data->offline_pubkeys, data->n_keys, &data->sub_pubkey, data->online_seckey[i], data->summed_seckey[i], i));
}

static void run_test(bench_data* data, int iters) {
    char str[32];
    sprintf(str, "whitelist_%i", (int)data->n_keys);
    run_benchmark(str, bench_whitelist, bench_whitelist_setup, NULL, data, 100, iters);
}

void random_scalar_order(rustsecp256k1zkp_v0_8_0_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        rustsecp256k1zkp_v0_8_0_testrand256(b32);
        rustsecp256k1zkp_v0_8_0_scalar_set_b32(num, b32, &overflow);
        if (overflow || rustsecp256k1zkp_v0_8_0_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

int main(void) {
    bench_data data;
    size_t i;
    size_t n_keys = 30;
    rustsecp256k1zkp_v0_8_0_scalar ssub;
    int iters = get_iters(5);

    data.ctx = rustsecp256k1zkp_v0_8_0_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Start with subkey */
    random_scalar_order(&ssub);
    rustsecp256k1zkp_v0_8_0_scalar_get_b32(data.csub, &ssub);
    CHECK(rustsecp256k1zkp_v0_8_0_ec_seckey_verify(data.ctx, data.csub) == 1);
    CHECK(rustsecp256k1zkp_v0_8_0_ec_pubkey_create(data.ctx, &data.sub_pubkey, data.csub) == 1);
    /* Then offline and online whitelist keys */
    for (i = 0; i < n_keys; i++) {
        rustsecp256k1zkp_v0_8_0_scalar son, soff;

        /* Create two keys */
        random_scalar_order(&son);
        rustsecp256k1zkp_v0_8_0_scalar_get_b32(data.online_seckey[i], &son);
        CHECK(rustsecp256k1zkp_v0_8_0_ec_seckey_verify(data.ctx, data.online_seckey[i]) == 1);
        CHECK(rustsecp256k1zkp_v0_8_0_ec_pubkey_create(data.ctx, &data.online_pubkeys[i], data.online_seckey[i]) == 1);

        random_scalar_order(&soff);
        rustsecp256k1zkp_v0_8_0_scalar_get_b32(data.summed_seckey[i], &soff);
        CHECK(rustsecp256k1zkp_v0_8_0_ec_seckey_verify(data.ctx, data.summed_seckey[i]) == 1);
        CHECK(rustsecp256k1zkp_v0_8_0_ec_pubkey_create(data.ctx, &data.offline_pubkeys[i], data.summed_seckey[i]) == 1);

        /* Make summed_seckey correspond to the sum of offline_pubkey and sub_pubkey */
        rustsecp256k1zkp_v0_8_0_scalar_add(&soff, &soff, &ssub);
        rustsecp256k1zkp_v0_8_0_scalar_get_b32(data.summed_seckey[i], &soff);
        CHECK(rustsecp256k1zkp_v0_8_0_ec_seckey_verify(data.ctx, data.summed_seckey[i]) == 1);
    }

    /* Run test */
    for (i = 1; i <= n_keys; ++i) {
        data.n_keys = i;
        run_test(&data, iters);
    }

    rustsecp256k1zkp_v0_8_0_context_destroy(data.ctx);
    return(0);
}
