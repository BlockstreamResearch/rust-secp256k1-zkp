#ifndef SECP256K1_MODULE_SCHNORRSIG_HALFAGG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_HALFAGG_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../../include/secp256k1_schnorrsig_halfagg.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("HalfAgg/randomizer")||SHA256("HalfAgg/randomizer"). */
void rustsecp256k1zkp_v0_10_0_schnorrsig_sha256_tagged_aggregation(rustsecp256k1zkp_v0_10_0_sha256 *sha) {
   rustsecp256k1zkp_v0_10_0_sha256_initialize(sha);
    sha->s[0] = 0xd11f5532ul;
    sha->s[1] = 0xfa57f70ful;
    sha->s[2] = 0x5db0d728ul;
    sha->s[3] = 0xf806ffe1ul;
    sha->s[4] = 0x1d4db069ul;
    sha->s[5] = 0xb4d587e1ul;
    sha->s[6] = 0x50451c2aul;
    sha->s[7] = 0x10fb63e9ul;

    sha->bytes = 64;
}

int rustsecp256k1zkp_v0_10_0_schnorrsig_inc_aggregate(const rustsecp256k1zkp_v0_10_0_context *ctx, unsigned char *aggsig, size_t *aggsig_len, const rustsecp256k1zkp_v0_10_0_xonly_pubkey *all_pubkeys, const unsigned char *all_msgs32, const unsigned char *new_sigs64, size_t n_before, size_t n_new) {
    size_t i;
    size_t n;
    rustsecp256k1zkp_v0_10_0_sha256 hash;
    rustsecp256k1zkp_v0_10_0_scalar s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(aggsig != NULL);
    ARG_CHECK(aggsig_len != NULL);
    ARG_CHECK(new_sigs64 != NULL || n_new == 0);

    /* Check that aggsig_len is large enough, i.e. aggsig_len >= 32*(n+1) */
    n = n_before + n_new;
    ARG_CHECK(n >= n_before);
    ARG_CHECK(all_pubkeys != NULL || n == 0);
    ARG_CHECK(all_msgs32 != NULL || n == 0);
    if ((*aggsig_len / 32) <= 0 || ((*aggsig_len / 32) - 1) < n) {
        return 0;
    }

    /* Prepare hash with common prefix. The prefix is the tag and       */
    /* r_0 || pk_0 || m_0 || .... ||  r_{n'-1} || pk_{n'-1} || m_{n'-1} */
    /* where n' = n_before                                              */
    rustsecp256k1zkp_v0_10_0_schnorrsig_sha256_tagged_aggregation(&hash);
    for (i = 0; i < n_before; ++i) {
        /* serialize pk_i */
        unsigned char pk_ser[32];
        if (!rustsecp256k1zkp_v0_10_0_xonly_pubkey_serialize(ctx, pk_ser, &all_pubkeys[i])) {
            return 0;
        }
        /* write r_i */
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, &aggsig[i*32], 32);
        /* write pk_i */
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, pk_ser, 32);
        /* write m_i*/
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, &all_msgs32[i*32], 32);
    }

    /* Compute s = s_old + sum_{i = n_before}^{n} z_i*s_i */
    /* where s_old = 0 if n_before = 0 */
    rustsecp256k1zkp_v0_10_0_scalar_set_int(&s, 0);
    if (n_before > 0) rustsecp256k1zkp_v0_10_0_scalar_set_b32(&s, &aggsig[n_before*32], NULL);
    for (i = n_before; i < n; ++i) {
        unsigned char pk_ser[32];
        unsigned char hashoutput[32];
        rustsecp256k1zkp_v0_10_0_sha256 hashcopy;
        rustsecp256k1zkp_v0_10_0_scalar si;
        rustsecp256k1zkp_v0_10_0_scalar zi;

        /* Step 0: Serialize pk_i into pk_ser   */
        if (!rustsecp256k1zkp_v0_10_0_xonly_pubkey_serialize(ctx, pk_ser, &all_pubkeys[i])) {
            return 0;
        }

        /* Step 1: z_i = TaggedHash(...) */
        /* 1.a) Write into hash r_i, pk_i, m_i, r_i */
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, &new_sigs64[(i-n_before)*64], 32);
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, pk_ser, 32);
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, &all_msgs32[i*32], 32);
        /* 1.b) Copy the hash */
        hashcopy = hash;
        /* 1.c) Finalize the copy to get zi*/
        rustsecp256k1zkp_v0_10_0_sha256_finalize(&hashcopy, hashoutput);
        /* Note: No need to check overflow, comes from hash */
        rustsecp256k1zkp_v0_10_0_scalar_set_b32(&zi, hashoutput, NULL);

        /* Step 2: s := s + zi*si */
        /* except if i == 0, then zi = 1 implicitly */
        rustsecp256k1zkp_v0_10_0_scalar_set_b32(&si, &new_sigs64[(i-n_before)*64+32], NULL);
        if (i != 0) rustsecp256k1zkp_v0_10_0_scalar_mul(&si, &si, &zi);
        rustsecp256k1zkp_v0_10_0_scalar_add(&s, &s, &si);
    }

    /* copy new rs into aggsig */
    for (i = n_before; i < n; ++i) {
        memcpy(&aggsig[i*32], &new_sigs64[(i-n_before)*64], 32);
    }
    /* copy new s into aggsig */
    rustsecp256k1zkp_v0_10_0_scalar_get_b32(&aggsig[n*32], &s);
    *aggsig_len = 32 * (1 + n);
    return 1;
}

int rustsecp256k1zkp_v0_10_0_schnorrsig_aggregate(const rustsecp256k1zkp_v0_10_0_context *ctx, unsigned char *aggsig, size_t *aggsig_len, const rustsecp256k1zkp_v0_10_0_xonly_pubkey *pubkeys, const unsigned char *msgs32, const unsigned char *sigs64, size_t n) {
    return rustsecp256k1zkp_v0_10_0_schnorrsig_inc_aggregate(ctx, aggsig, aggsig_len, pubkeys, msgs32, sigs64, 0, n);
}

int rustsecp256k1zkp_v0_10_0_schnorrsig_aggverify(const rustsecp256k1zkp_v0_10_0_context *ctx, const rustsecp256k1zkp_v0_10_0_xonly_pubkey *pubkeys, const unsigned char *msgs32, size_t n, const unsigned char *aggsig, size_t aggsig_len) {
    size_t i;
    rustsecp256k1zkp_v0_10_0_gej lhs, rhs;
    rustsecp256k1zkp_v0_10_0_scalar s;
    rustsecp256k1zkp_v0_10_0_sha256 hash;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkeys != NULL || n == 0);
    ARG_CHECK(msgs32 != NULL || n == 0);
    ARG_CHECK(aggsig != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_10_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    /* Check that aggsig_len is correct, i.e., aggsig_len = 32*(n+1) */
    if ((aggsig_len / 32) <= 0 || ((aggsig_len / 32)-1) != n || (aggsig_len % 32) != 0) {
        return 0;
    }

    /* Compute the rhs:               */
    /* Set rhs = 0                    */
    /* For each i in 0,.., n-1, do:   */
    /*     (1) z_i = TaggedHash(...)  */
    /*     (2) T_i = R_i+e_i*P_i      */
    /*     (3) rhs = rhs + z_i*T_i    */
    rustsecp256k1zkp_v0_10_0_gej_set_infinity(&rhs);
    rustsecp256k1zkp_v0_10_0_schnorrsig_sha256_tagged_aggregation(&hash);
    for (i = 0; i < n; ++i) {
        rustsecp256k1zkp_v0_10_0_fe rx;
        rustsecp256k1zkp_v0_10_0_ge rp, pp;
        rustsecp256k1zkp_v0_10_0_scalar ei;
        rustsecp256k1zkp_v0_10_0_gej ppj, ti;

        unsigned char pk_ser[32];
        unsigned char hashoutput[32];
        rustsecp256k1zkp_v0_10_0_sha256 hashcopy;
        rustsecp256k1zkp_v0_10_0_scalar zi;

        /* Step 0: Serialize pk_i into pk_ser   */
        /* We need that in Step 1 and in Step 2 */
        if (!rustsecp256k1zkp_v0_10_0_xonly_pubkey_load(ctx, &pp, &pubkeys[i])) {
            return 0;
        }
        rustsecp256k1zkp_v0_10_0_fe_get_b32(pk_ser, &pp.x);

        /* Step 1: z_i = TaggedHash(...) */
        /* 1.a) Write into hash r_i, pk_i, m_i, r_i */
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, &aggsig[i*32], 32);
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, pk_ser, 32);
        rustsecp256k1zkp_v0_10_0_sha256_write(&hash, &msgs32[i*32], 32);
        /* 1.b) Copy the hash */
        hashcopy = hash;
        /* 1.c) Finalize the copy to get zi*/
        rustsecp256k1zkp_v0_10_0_sha256_finalize(&hashcopy, hashoutput);
        rustsecp256k1zkp_v0_10_0_scalar_set_b32(&zi, hashoutput, NULL);

        /* Step 2: T_i = R_i+e_i*P_i */
        /* 2.a) R_i = lift_x(int(r_i)); fail if that fails */
        if (!rustsecp256k1zkp_v0_10_0_fe_set_b32_limit(&rx, &aggsig[i*32])) {
            return 0;
        }
        if (!rustsecp256k1zkp_v0_10_0_ge_set_xo_var(&rp, &rx, 0)) {
            return 0;
        }

        /* 2.b) e_i = int(hash_{BIP0340/challenge}(bytes(r_i) || pk_i || m_i)) mod n */
        rustsecp256k1zkp_v0_10_0_schnorrsig_challenge(&ei, &aggsig[i*32], &msgs32[i*32], 32, pk_ser);
        rustsecp256k1zkp_v0_10_0_gej_set_ge(&ppj, &pp);
        /* 2.c) T_i = R_i + e_i*P_i */
        rustsecp256k1zkp_v0_10_0_ecmult(&ti, &ppj, &ei, NULL);
        rustsecp256k1zkp_v0_10_0_gej_add_ge_var(&ti, &ti, &rp, NULL);

        /* Step 3: rhs = rhs + zi*T_i  */
        /* Note that if i == 0, then zi = 1 implicitly */
        if (i != 0) rustsecp256k1zkp_v0_10_0_ecmult(&ti, &ti, &zi, NULL);
        rustsecp256k1zkp_v0_10_0_gej_add_var(&rhs, &rhs, &ti, NULL);
    }

    /* Compute the lhs as lhs = s*G */
    rustsecp256k1zkp_v0_10_0_scalar_set_b32(&s, &aggsig[n*32], &overflow);
    if (overflow) {
        return 0;
    }
    rustsecp256k1zkp_v0_10_0_ecmult_gen(&ctx->ecmult_gen_ctx, &lhs, &s);

    /* Check that lhs == rhs */
    rustsecp256k1zkp_v0_10_0_gej_neg(&lhs, &lhs);
    rustsecp256k1zkp_v0_10_0_gej_add_var(&lhs, &lhs, &rhs, NULL);
    return rustsecp256k1zkp_v0_10_0_gej_is_infinity(&lhs);
}

#endif
