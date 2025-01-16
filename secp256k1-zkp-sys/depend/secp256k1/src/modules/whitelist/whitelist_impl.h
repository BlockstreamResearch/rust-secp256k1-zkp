/**********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_WHITELIST_IMPL_H
#define SECP256K1_WHITELIST_IMPL_H

static int rustsecp256k1zkp_v0_10_1_whitelist_hash_pubkey(rustsecp256k1zkp_v0_10_1_scalar* output, rustsecp256k1zkp_v0_10_1_gej* pubkey) {
    unsigned char h[32];
    unsigned char c[33];
    rustsecp256k1zkp_v0_10_1_sha256 sha;
    int overflow = 0;
    size_t size = 33;
    rustsecp256k1zkp_v0_10_1_ge ge;

    rustsecp256k1zkp_v0_10_1_ge_set_gej(&ge, pubkey);

    rustsecp256k1zkp_v0_10_1_sha256_initialize(&sha);
    if (!rustsecp256k1zkp_v0_10_1_eckey_pubkey_serialize(&ge, c, &size, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_1_sha256_write(&sha, c, size);
    rustsecp256k1zkp_v0_10_1_sha256_finalize(&sha, h);

    rustsecp256k1zkp_v0_10_1_scalar_set_b32(output, h, &overflow);
    if (overflow || rustsecp256k1zkp_v0_10_1_scalar_is_zero(output)) {
        /* This return path is mathematically impossible to hit */
        rustsecp256k1zkp_v0_10_1_scalar_clear(output);
        return 0;
    }
    return 1;
}

static int rustsecp256k1zkp_v0_10_1_whitelist_tweak_pubkey(rustsecp256k1zkp_v0_10_1_gej* pub_tweaked) {
    rustsecp256k1zkp_v0_10_1_scalar tweak;
    rustsecp256k1zkp_v0_10_1_scalar zero;
    int ret;

    rustsecp256k1zkp_v0_10_1_scalar_set_int(&zero, 0);

    ret = rustsecp256k1zkp_v0_10_1_whitelist_hash_pubkey(&tweak, pub_tweaked);
    if (ret) {
        rustsecp256k1zkp_v0_10_1_ecmult(pub_tweaked, pub_tweaked, &tweak, &zero);
    }
    return ret;
}

static int rustsecp256k1zkp_v0_10_1_whitelist_compute_tweaked_privkey(const rustsecp256k1zkp_v0_10_1_context* ctx, rustsecp256k1zkp_v0_10_1_scalar* skey, const unsigned char *online_key, const unsigned char *summed_key) {
    rustsecp256k1zkp_v0_10_1_scalar tweak;
    int ret = 1;
    int overflow = 0;

    rustsecp256k1zkp_v0_10_1_scalar_set_b32(skey, summed_key, &overflow);
    if (overflow || rustsecp256k1zkp_v0_10_1_scalar_is_zero(skey)) {
        ret = 0;
    }
    if (ret) {
        rustsecp256k1zkp_v0_10_1_gej pkeyj;
        rustsecp256k1zkp_v0_10_1_ecmult_gen(&ctx->ecmult_gen_ctx, &pkeyj, skey);
        ret = rustsecp256k1zkp_v0_10_1_whitelist_hash_pubkey(&tweak, &pkeyj);
    }
    if (ret) {
        rustsecp256k1zkp_v0_10_1_scalar sonline;
        rustsecp256k1zkp_v0_10_1_scalar_mul(skey, skey, &tweak);

        rustsecp256k1zkp_v0_10_1_scalar_set_b32(&sonline, online_key, &overflow);
        if (overflow || rustsecp256k1zkp_v0_10_1_scalar_is_zero(&sonline)) {
            ret = 0;
        }
        rustsecp256k1zkp_v0_10_1_scalar_add(skey, skey, &sonline);
        rustsecp256k1zkp_v0_10_1_scalar_clear(&sonline);
        rustsecp256k1zkp_v0_10_1_scalar_clear(&tweak);
    }

    if (!ret) {
        rustsecp256k1zkp_v0_10_1_scalar_clear(skey);
    }
    return ret;
}

/* Takes a list of pubkeys and combines them to form the public keys needed
 * for the ring signature; also produce a commitment to every one that will
 * be our "message". */
static int rustsecp256k1zkp_v0_10_1_whitelist_compute_keys_and_message(const rustsecp256k1zkp_v0_10_1_context* ctx, unsigned char *msg32, rustsecp256k1zkp_v0_10_1_gej *keys, const rustsecp256k1zkp_v0_10_1_pubkey *online_pubkeys, const rustsecp256k1zkp_v0_10_1_pubkey *offline_pubkeys, const int n_keys, const rustsecp256k1zkp_v0_10_1_pubkey *sub_pubkey) {
    unsigned char c[33];
    size_t size = 33;
    rustsecp256k1zkp_v0_10_1_sha256 sha;
    int i;
    rustsecp256k1zkp_v0_10_1_ge subkey_ge;

    rustsecp256k1zkp_v0_10_1_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_10_1_pubkey_load(ctx, &subkey_ge, sub_pubkey);

    /* commit to sub-key */
    if (!rustsecp256k1zkp_v0_10_1_eckey_pubkey_serialize(&subkey_ge, c, &size, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_1_sha256_write(&sha, c, size);
    for (i = 0; i < n_keys; i++) {
        rustsecp256k1zkp_v0_10_1_ge offline_ge;
        rustsecp256k1zkp_v0_10_1_ge online_ge;
        rustsecp256k1zkp_v0_10_1_gej tweaked_gej;

        /* commit to fixed keys */
        rustsecp256k1zkp_v0_10_1_pubkey_load(ctx, &offline_ge, &offline_pubkeys[i]);
        if (!rustsecp256k1zkp_v0_10_1_eckey_pubkey_serialize(&offline_ge, c, &size, SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        rustsecp256k1zkp_v0_10_1_sha256_write(&sha, c, size);
        rustsecp256k1zkp_v0_10_1_pubkey_load(ctx, &online_ge, &online_pubkeys[i]);
        if (!rustsecp256k1zkp_v0_10_1_eckey_pubkey_serialize(&online_ge, c, &size, SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        rustsecp256k1zkp_v0_10_1_sha256_write(&sha, c, size);

        /* compute tweaked keys */
        rustsecp256k1zkp_v0_10_1_gej_set_ge(&tweaked_gej, &offline_ge);
        rustsecp256k1zkp_v0_10_1_gej_add_ge_var(&tweaked_gej, &tweaked_gej, &subkey_ge, NULL);
        rustsecp256k1zkp_v0_10_1_whitelist_tweak_pubkey(&tweaked_gej);
        rustsecp256k1zkp_v0_10_1_gej_add_ge_var(&keys[i], &tweaked_gej, &online_ge, NULL);
    }
    rustsecp256k1zkp_v0_10_1_sha256_finalize(&sha, msg32);
    return 1;
}


#endif
