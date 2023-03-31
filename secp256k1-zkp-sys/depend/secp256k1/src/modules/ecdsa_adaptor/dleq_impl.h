#ifndef SECP256K1_DLEQ_IMPL_H
#define SECP256K1_DLEQ_IMPL_H

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("DLEQ")||SHA256("DLEQ"). */
static void rustsecp256k1zkp_v0_8_0_nonce_function_dleq_sha256_tagged(rustsecp256k1zkp_v0_8_0_sha256 *sha) {
    rustsecp256k1zkp_v0_8_0_sha256_initialize(sha);
    sha->s[0] = 0x8cc4beacul;
    sha->s[1] = 0x2e011f3ful;
    sha->s[2] = 0x355c75fbul;
    sha->s[3] = 0x3ba6a2c5ul;
    sha->s[4] = 0xe96f3aeful;
    sha->s[5] = 0x180530fdul;
    sha->s[6] = 0x94582499ul;
    sha->s[7] = 0x577fd564ul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_ecdsa_adaptor to derive the nonce using a tagged hash function. */
static const unsigned char dleq_algo[4] = "DLEQ";

static int rustsecp256k1zkp_v0_8_0_dleq_hash_point(rustsecp256k1zkp_v0_8_0_sha256 *sha, rustsecp256k1zkp_v0_8_0_ge *p) {
    unsigned char buf[33];
    size_t size = 33;

    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(p, buf, &size, 1)) {
        return 0;
    }

    rustsecp256k1zkp_v0_8_0_sha256_write(sha, buf, size);
    return 1;
}

static int rustsecp256k1zkp_v0_8_0_dleq_nonce(rustsecp256k1zkp_v0_8_0_scalar *k, const unsigned char *sk32, const unsigned char *gen2_33, const unsigned char *p1_33, const unsigned char *p2_33, rustsecp256k1zkp_v0_8_0_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    rustsecp256k1zkp_v0_8_0_sha256 sha;
    unsigned char buf[32];
    unsigned char nonce[32];
    size_t size = 33;

    if (noncefp == NULL) {
        noncefp = rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor;
    }

    rustsecp256k1zkp_v0_8_0_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_8_0_sha256_write(&sha, p1_33, size);
    rustsecp256k1zkp_v0_8_0_sha256_write(&sha, p2_33, size);
    rustsecp256k1zkp_v0_8_0_sha256_finalize(&sha, buf);

    if (!noncefp(nonce, buf, sk32, gen2_33, dleq_algo, sizeof(dleq_algo), ndata)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(k, nonce, NULL);
    if (rustsecp256k1zkp_v0_8_0_scalar_is_zero(k)) {
        return 0;
    }

    return 1;
}

/* Generates a challenge as defined in the DLC Specification at
 * https://github.com/discreetlogcontracts/dlcspecs */
static void rustsecp256k1zkp_v0_8_0_dleq_challenge(rustsecp256k1zkp_v0_8_0_scalar *e, rustsecp256k1zkp_v0_8_0_ge *gen2, rustsecp256k1zkp_v0_8_0_ge *r1, rustsecp256k1zkp_v0_8_0_ge *r2, rustsecp256k1zkp_v0_8_0_ge *p1, rustsecp256k1zkp_v0_8_0_ge *p2) {
    unsigned char buf[32];
    rustsecp256k1zkp_v0_8_0_sha256 sha;

    rustsecp256k1zkp_v0_8_0_nonce_function_dleq_sha256_tagged(&sha);
    rustsecp256k1zkp_v0_8_0_dleq_hash_point(&sha, p1);
    rustsecp256k1zkp_v0_8_0_dleq_hash_point(&sha, gen2);
    rustsecp256k1zkp_v0_8_0_dleq_hash_point(&sha, p2);
    rustsecp256k1zkp_v0_8_0_dleq_hash_point(&sha, r1);
    rustsecp256k1zkp_v0_8_0_dleq_hash_point(&sha, r2);
    rustsecp256k1zkp_v0_8_0_sha256_finalize(&sha, buf);

    rustsecp256k1zkp_v0_8_0_scalar_set_b32(e, buf, NULL);
}

/* P1 = x*G, P2 = x*Y */
static void rustsecp256k1zkp_v0_8_0_dleq_pair(const rustsecp256k1zkp_v0_8_0_ecmult_gen_context *ecmult_gen_ctx, rustsecp256k1zkp_v0_8_0_ge *p1, rustsecp256k1zkp_v0_8_0_ge *p2, const rustsecp256k1zkp_v0_8_0_scalar *sk, const rustsecp256k1zkp_v0_8_0_ge *gen2) {
    rustsecp256k1zkp_v0_8_0_gej p1j, p2j;

    rustsecp256k1zkp_v0_8_0_ecmult_gen(ecmult_gen_ctx, &p1j, sk);
    rustsecp256k1zkp_v0_8_0_ge_set_gej(p1, &p1j);
    rustsecp256k1zkp_v0_8_0_ecmult_const(&p2j, gen2, sk, 256);
    rustsecp256k1zkp_v0_8_0_ge_set_gej(p2, &p2j);
}

/* Generates a proof that the discrete logarithm of P1 to the secp256k1 base G is the
 * same as the discrete logarithm of P2 to the base Y */
static int rustsecp256k1zkp_v0_8_0_dleq_prove(const rustsecp256k1zkp_v0_8_0_context* ctx, rustsecp256k1zkp_v0_8_0_scalar *s, rustsecp256k1zkp_v0_8_0_scalar *e, const rustsecp256k1zkp_v0_8_0_scalar *sk, rustsecp256k1zkp_v0_8_0_ge *gen2, rustsecp256k1zkp_v0_8_0_ge *p1, rustsecp256k1zkp_v0_8_0_ge *p2, rustsecp256k1zkp_v0_8_0_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    rustsecp256k1zkp_v0_8_0_ge r1, r2;
    rustsecp256k1zkp_v0_8_0_scalar k = { 0 };
    unsigned char sk32[32];
    unsigned char gen2_33[33];
    unsigned char p1_33[33];
    unsigned char p2_33[33];
    int ret = 1;
    size_t pubkey_size = 33;

    rustsecp256k1zkp_v0_8_0_scalar_get_b32(sk32, sk);
    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(gen2, gen2_33, &pubkey_size, 1)) {
        return 0;
    }
    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(p1, p1_33, &pubkey_size, 1)) {
        return 0;
    }
    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(p2, p2_33, &pubkey_size, 1)) {
        return 0;
    }

    ret &= rustsecp256k1zkp_v0_8_0_dleq_nonce(&k, sk32, gen2_33, p1_33, p2_33, noncefp, ndata);
    /* R1 = k*G, R2 = k*Y */
    rustsecp256k1zkp_v0_8_0_dleq_pair(&ctx->ecmult_gen_ctx, &r1, &r2, &k, gen2);
    /* We declassify the non-secret values r1 and r2 to allow using them as
     * branch points. */
    rustsecp256k1zkp_v0_8_0_declassify(ctx, &r1, sizeof(r1));
    rustsecp256k1zkp_v0_8_0_declassify(ctx, &r2, sizeof(r2));

    /* e = tagged hash(p1, gen2, p2, r1, r2) */
    /* s = k + e * sk */
    rustsecp256k1zkp_v0_8_0_dleq_challenge(e, gen2, &r1, &r2, p1, p2);
    rustsecp256k1zkp_v0_8_0_scalar_mul(s, e, sk);
    rustsecp256k1zkp_v0_8_0_scalar_add(s, s, &k);

    rustsecp256k1zkp_v0_8_0_scalar_clear(&k);
    return ret;
}

static int rustsecp256k1zkp_v0_8_0_dleq_verify(const rustsecp256k1zkp_v0_8_0_scalar *s, const rustsecp256k1zkp_v0_8_0_scalar *e, rustsecp256k1zkp_v0_8_0_ge *p1, rustsecp256k1zkp_v0_8_0_ge *gen2, rustsecp256k1zkp_v0_8_0_ge *p2) {
    rustsecp256k1zkp_v0_8_0_scalar e_neg;
    rustsecp256k1zkp_v0_8_0_scalar e_expected;
    rustsecp256k1zkp_v0_8_0_gej gen2j;
    rustsecp256k1zkp_v0_8_0_gej p1j, p2j;
    rustsecp256k1zkp_v0_8_0_gej r1j, r2j;
    rustsecp256k1zkp_v0_8_0_ge r1, r2;
    rustsecp256k1zkp_v0_8_0_gej tmpj;

    rustsecp256k1zkp_v0_8_0_gej_set_ge(&p1j, p1);
    rustsecp256k1zkp_v0_8_0_gej_set_ge(&p2j, p2);

    rustsecp256k1zkp_v0_8_0_scalar_negate(&e_neg, e);
    /* R1 = s*G  - e*P1 */
    rustsecp256k1zkp_v0_8_0_ecmult(&r1j, &p1j, &e_neg, s);
    /* R2 = s*gen2 - e*P2 */
    rustsecp256k1zkp_v0_8_0_ecmult(&tmpj, &p2j, &e_neg, &rustsecp256k1zkp_v0_8_0_scalar_zero);
    rustsecp256k1zkp_v0_8_0_gej_set_ge(&gen2j, gen2);
    rustsecp256k1zkp_v0_8_0_ecmult(&r2j, &gen2j, s, &rustsecp256k1zkp_v0_8_0_scalar_zero);
    rustsecp256k1zkp_v0_8_0_gej_add_var(&r2j, &r2j, &tmpj, NULL);

    rustsecp256k1zkp_v0_8_0_ge_set_gej(&r1, &r1j);
    rustsecp256k1zkp_v0_8_0_ge_set_gej(&r2, &r2j);
    rustsecp256k1zkp_v0_8_0_dleq_challenge(&e_expected, gen2, &r1, &r2, p1, p2);

    rustsecp256k1zkp_v0_8_0_scalar_add(&e_expected, &e_expected, &e_neg);
    return rustsecp256k1zkp_v0_8_0_scalar_is_zero(&e_expected);
}

#endif
