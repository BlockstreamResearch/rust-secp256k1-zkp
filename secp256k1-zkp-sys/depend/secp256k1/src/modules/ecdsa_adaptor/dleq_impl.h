#ifndef SECP256K1_DLEQ_IMPL_H
#define SECP256K1_DLEQ_IMPL_H

#include <stdint.h>

#include "../../../include/secp256k1_ecdsa_adaptor.h"

#include "../../../src/eckey.h"
#include "../../../src/ecmult_const.h"
#include "../../../src/group.h"
#include "../../../src/hash.h"
#include "../../../src/scalar.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("DLEQ")||SHA256("DLEQ"). */
static void rustsecp256k1zkp_v0_11_0_nonce_function_dleq_sha256_tagged(rustsecp256k1zkp_v0_11_0_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x8cc4beacul, 0x2e011f3ful, 0x355c75fbul, 0x3ba6a2c5ul,
        0xe96f3aeful, 0x180530fdul, 0x94582499ul, 0x577fd564ul
    };
    rustsecp256k1zkp_v0_11_0_sha256_initialize_midstate(sha, 64, midstate);
}

/* algo argument for nonce_function_ecdsa_adaptor to derive the nonce using a tagged hash function. */
static const unsigned char dleq_algo[] = {'D','L','E','Q'};

static int nonce_function_ecdsa_adaptor_impl(const rustsecp256k1zkp_v0_11_0_hash_ctx *hash_ctx, unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *pk33, const unsigned char *algo, size_t algolen, void *data);

static void rustsecp256k1zkp_v0_11_0_dleq_hash_point(const rustsecp256k1zkp_v0_11_0_hash_ctx *hash_ctx, rustsecp256k1zkp_v0_11_0_sha256 *sha, rustsecp256k1zkp_v0_11_0_ge *p) {
    unsigned char buf[33];

    rustsecp256k1zkp_v0_11_0_eckey_pubkey_serialize33(p, buf);
    rustsecp256k1zkp_v0_11_0_sha256_write(hash_ctx, sha, buf, 33);
}

static int rustsecp256k1zkp_v0_11_0_dleq_nonce(const rustsecp256k1zkp_v0_11_0_hash_ctx *hash_ctx, rustsecp256k1zkp_v0_11_0_scalar *k, const unsigned char *sk32, const unsigned char *gen2_33, const unsigned char *p1_33, const unsigned char *p2_33, rustsecp256k1zkp_v0_11_0_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    rustsecp256k1zkp_v0_11_0_sha256 sha;
    unsigned char buf[32];
    unsigned char nonce[32];

    rustsecp256k1zkp_v0_11_0_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_11_0_sha256_write(hash_ctx, &sha, p1_33, 33);
    rustsecp256k1zkp_v0_11_0_sha256_write(hash_ctx, &sha, p2_33, 33);
    rustsecp256k1zkp_v0_11_0_sha256_finalize(hash_ctx, &sha, buf);
    rustsecp256k1zkp_v0_11_0_sha256_clear(&sha);

    if (noncefp == NULL || noncefp == rustsecp256k1zkp_v0_11_0_nonce_function_ecdsa_adaptor) {
        if (!nonce_function_ecdsa_adaptor_impl(hash_ctx, nonce, buf, sk32, gen2_33, dleq_algo, sizeof(dleq_algo), ndata)) {
            return 0;
        }
    } else if (!noncefp(nonce, buf, sk32, gen2_33, dleq_algo, sizeof(dleq_algo), ndata)) {
        return 0;
    }
    rustsecp256k1zkp_v0_11_0_scalar_set_b32(k, nonce, NULL);
    rustsecp256k1zkp_v0_11_0_memclear_explicit(nonce, sizeof(nonce));
    if (rustsecp256k1zkp_v0_11_0_scalar_is_zero(k)) {
        return 0;
    }

    return 1;
}

/* Generates a challenge as defined in the DLC Specification at
 * https://github.com/discreetlogcontracts/dlcspecs */
static void rustsecp256k1zkp_v0_11_0_dleq_challenge(const rustsecp256k1zkp_v0_11_0_hash_ctx *hash_ctx, rustsecp256k1zkp_v0_11_0_scalar *e, rustsecp256k1zkp_v0_11_0_ge *gen2, rustsecp256k1zkp_v0_11_0_ge *r1, rustsecp256k1zkp_v0_11_0_ge *r2, rustsecp256k1zkp_v0_11_0_ge *p1, rustsecp256k1zkp_v0_11_0_ge *p2) {
    unsigned char buf[32];
    rustsecp256k1zkp_v0_11_0_sha256 sha;

    rustsecp256k1zkp_v0_11_0_nonce_function_dleq_sha256_tagged(&sha);
    rustsecp256k1zkp_v0_11_0_dleq_hash_point(hash_ctx, &sha, p1);
    rustsecp256k1zkp_v0_11_0_dleq_hash_point(hash_ctx, &sha, gen2);
    rustsecp256k1zkp_v0_11_0_dleq_hash_point(hash_ctx, &sha, p2);
    rustsecp256k1zkp_v0_11_0_dleq_hash_point(hash_ctx, &sha, r1);
    rustsecp256k1zkp_v0_11_0_dleq_hash_point(hash_ctx, &sha, r2);
    rustsecp256k1zkp_v0_11_0_sha256_finalize(hash_ctx, &sha, buf);
    rustsecp256k1zkp_v0_11_0_sha256_clear(&sha);

    rustsecp256k1zkp_v0_11_0_scalar_set_b32(e, buf, NULL);
}

/* p[0] = x*G, p[1] = x*Y */
static void rustsecp256k1zkp_v0_11_0_dleq_pair(const rustsecp256k1zkp_v0_11_0_ecmult_gen_context *ecmult_gen_ctx, rustsecp256k1zkp_v0_11_0_ge *p, const rustsecp256k1zkp_v0_11_0_scalar *sk, const rustsecp256k1zkp_v0_11_0_ge *gen2) {
    rustsecp256k1zkp_v0_11_0_gej pj[2];

    rustsecp256k1zkp_v0_11_0_ecmult_gen(ecmult_gen_ctx, &pj[0], sk);
    rustsecp256k1zkp_v0_11_0_ecmult_const(&pj[1], gen2, sk);
    rustsecp256k1zkp_v0_11_0_ge_set_all_gej(p, pj, 2);
}

/* Generates a proof that the discrete logarithm of P1 to the secp256k1 base G is the
 * same as the discrete logarithm of P2 to the base Y */
static int rustsecp256k1zkp_v0_11_0_dleq_prove(const rustsecp256k1zkp_v0_11_0_context* ctx, rustsecp256k1zkp_v0_11_0_scalar *s, rustsecp256k1zkp_v0_11_0_scalar *e, const rustsecp256k1zkp_v0_11_0_scalar *sk, rustsecp256k1zkp_v0_11_0_ge *p1, rustsecp256k1zkp_v0_11_0_ge *gen2, rustsecp256k1zkp_v0_11_0_ge *p2, rustsecp256k1zkp_v0_11_0_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    /* Note: r[2] and k are local to the DLEQ proof, and they differ from the
     * values with the same identifiers in main_impl.h. */
    const rustsecp256k1zkp_v0_11_0_hash_ctx *hash_ctx = rustsecp256k1zkp_v0_11_0_get_hash_context(ctx);
    rustsecp256k1zkp_v0_11_0_ge r[2];
    rustsecp256k1zkp_v0_11_0_scalar k = { 0 };
    unsigned char sk32[32];
    unsigned char gen2_33[33];
    unsigned char p1_33[33];
    unsigned char p2_33[33];
    int ret;

    rustsecp256k1zkp_v0_11_0_eckey_pubkey_serialize33(gen2, gen2_33);
    rustsecp256k1zkp_v0_11_0_eckey_pubkey_serialize33(p1, p1_33);
    rustsecp256k1zkp_v0_11_0_eckey_pubkey_serialize33(p2, p2_33);

    rustsecp256k1zkp_v0_11_0_scalar_get_b32(sk32, sk);

    ret = rustsecp256k1zkp_v0_11_0_dleq_nonce(hash_ctx, &k, sk32, gen2_33, p1_33, p2_33, noncefp, ndata);
    rustsecp256k1zkp_v0_11_0_declassify(ctx, &ret, sizeof(ret));
    if (!ret) {
        rustsecp256k1zkp_v0_11_0_memclear_explicit(sk32, sizeof(sk32));
        return 0;
    }
    /* R1 = k*G, R2 = k*Y */
    rustsecp256k1zkp_v0_11_0_dleq_pair(&ctx->ecmult_gen_ctx, r, &k, gen2);
    /* We declassify the non-secret values r[0] and r[1] to allow using them as
     * branch points. */
    rustsecp256k1zkp_v0_11_0_declassify(ctx, &r[0], sizeof(r[0]));
    rustsecp256k1zkp_v0_11_0_declassify(ctx, &r[1], sizeof(r[1]));

    /* e = tagged hash(p1, gen2, p2, r[0], r[1]) */
    /* s = k + e * sk */
    rustsecp256k1zkp_v0_11_0_dleq_challenge(hash_ctx, e, gen2, &r[0], &r[1], p1, p2);
    rustsecp256k1zkp_v0_11_0_scalar_mul(s, e, sk);
    rustsecp256k1zkp_v0_11_0_scalar_add(s, s, &k);

    rustsecp256k1zkp_v0_11_0_scalar_clear(&k);
    rustsecp256k1zkp_v0_11_0_memclear_explicit(sk32, sizeof(sk32));
    return 1;
}

static int rustsecp256k1zkp_v0_11_0_dleq_verify(const rustsecp256k1zkp_v0_11_0_hash_ctx *hash_ctx, const rustsecp256k1zkp_v0_11_0_scalar *s, const rustsecp256k1zkp_v0_11_0_scalar *e, rustsecp256k1zkp_v0_11_0_ge *p1, rustsecp256k1zkp_v0_11_0_ge *gen2, rustsecp256k1zkp_v0_11_0_ge *p2) {
    rustsecp256k1zkp_v0_11_0_scalar e_neg;
    rustsecp256k1zkp_v0_11_0_scalar e_expected;
    rustsecp256k1zkp_v0_11_0_gej gen2j;
    rustsecp256k1zkp_v0_11_0_gej p1j, p2j;
    rustsecp256k1zkp_v0_11_0_gej rj[2];
    rustsecp256k1zkp_v0_11_0_ge r[2];
    rustsecp256k1zkp_v0_11_0_gej tmpj;

    rustsecp256k1zkp_v0_11_0_gej_set_ge(&p1j, p1);
    rustsecp256k1zkp_v0_11_0_gej_set_ge(&p2j, p2);

    rustsecp256k1zkp_v0_11_0_scalar_negate(&e_neg, e);
    /* R1 = s*G  - e*P1 */
    rustsecp256k1zkp_v0_11_0_ecmult(&rj[0], &p1j, &e_neg, s);
    /* R2 = s*gen2 - e*P2 */
    rustsecp256k1zkp_v0_11_0_ecmult(&tmpj, &p2j, &e_neg, &rustsecp256k1zkp_v0_11_0_scalar_zero);
    rustsecp256k1zkp_v0_11_0_gej_set_ge(&gen2j, gen2);
    rustsecp256k1zkp_v0_11_0_ecmult(&rj[1], &gen2j, s, &rustsecp256k1zkp_v0_11_0_scalar_zero);
    rustsecp256k1zkp_v0_11_0_gej_add_var(&rj[1], &rj[1], &tmpj, NULL);

    if (rustsecp256k1zkp_v0_11_0_gej_is_infinity(&rj[0]) || rustsecp256k1zkp_v0_11_0_gej_is_infinity(&rj[1])) {
        return 0;
    }

    rustsecp256k1zkp_v0_11_0_ge_set_all_gej_var(r, rj, 2);

    rustsecp256k1zkp_v0_11_0_dleq_challenge(hash_ctx, &e_expected, gen2, &r[0], &r[1], p1, p2);

    rustsecp256k1zkp_v0_11_0_scalar_add(&e_expected, &e_expected, &e_neg);
    return rustsecp256k1zkp_v0_11_0_scalar_is_zero(&e_expected);
}

#endif
