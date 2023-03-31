/**********************************************************************
 * Copyright (c) 2020-2021 Jonas Nick, Jesse Posner                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "../../../include/secp256k1_ecdsa_adaptor.h"
#include "dleq_impl.h"

/* (R, R', s', dleq_proof) */
static int rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_sig_serialize(unsigned char *adaptor_sig162, rustsecp256k1zkp_v0_8_0_ge *r, rustsecp256k1zkp_v0_8_0_ge *rp, const rustsecp256k1zkp_v0_8_0_scalar *sp, const rustsecp256k1zkp_v0_8_0_scalar *dleq_proof_e, const rustsecp256k1zkp_v0_8_0_scalar *dleq_proof_s) {
    size_t size = 33;

    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(r, adaptor_sig162, &size, 1)) {
        return 0;
    }
    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(rp, &adaptor_sig162[33], &size, 1)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_scalar_get_b32(&adaptor_sig162[66], sp);
    rustsecp256k1zkp_v0_8_0_scalar_get_b32(&adaptor_sig162[98], dleq_proof_e);
    rustsecp256k1zkp_v0_8_0_scalar_get_b32(&adaptor_sig162[130], dleq_proof_s);

    return 1;
}

static int rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_sig_deserialize(rustsecp256k1zkp_v0_8_0_ge *r, rustsecp256k1zkp_v0_8_0_scalar *sigr, rustsecp256k1zkp_v0_8_0_ge *rp, rustsecp256k1zkp_v0_8_0_scalar *sp, rustsecp256k1zkp_v0_8_0_scalar *dleq_proof_e, rustsecp256k1zkp_v0_8_0_scalar *dleq_proof_s, const unsigned char *adaptor_sig162) {
    /* If r is deserialized, require that a sigr is provided to receive
     * the X-coordinate */
    VERIFY_CHECK((r == NULL) || (r != NULL && sigr != NULL));
    if (r != NULL) {
        if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_parse(r, &adaptor_sig162[0], 33)) {
            return 0;
        }
    }
    if (sigr != NULL) {
        rustsecp256k1zkp_v0_8_0_scalar_set_b32(sigr, &adaptor_sig162[1], NULL);
        if (rustsecp256k1zkp_v0_8_0_scalar_is_zero(sigr)) {
            return 0;
        }
    }
    if (rp != NULL) {
        if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_parse(rp, &adaptor_sig162[33], 33)) {
            return 0;
        }
    }
    if (sp != NULL) {
        if (!rustsecp256k1zkp_v0_8_0_scalar_set_b32_seckey(sp, &adaptor_sig162[66])) {
            return 0;
        }
    }
    if (dleq_proof_e != NULL) {
        rustsecp256k1zkp_v0_8_0_scalar_set_b32(dleq_proof_e, &adaptor_sig162[98], NULL);
    }
    if (dleq_proof_s != NULL) {
        int overflow;
        rustsecp256k1zkp_v0_8_0_scalar_set_b32(dleq_proof_s, &adaptor_sig162[130], &overflow);
        if (overflow) {
            return 0;
        }
    }
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/non")||SHA256("ECDSAadaptor/non"). */
static void rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor_sha256_tagged(rustsecp256k1zkp_v0_8_0_sha256 *sha) {
    rustsecp256k1zkp_v0_8_0_sha256_initialize(sha);
    sha->s[0] = 0x791dae43ul;
    sha->s[1] = 0xe52d3b44ul;
    sha->s[2] = 0x37f9edeaul;
    sha->s[3] = 0x9bfd2ab1ul;
    sha->s[4] = 0xcfb0f44dul;
    sha->s[5] = 0xccf1d880ul;
    sha->s[6] = 0xd18f2c13ul;
    sha->s[7] = 0xa37b9024ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/aux")||SHA256("ECDSAadaptor/aux"). */
static void rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor_sha256_tagged_aux(rustsecp256k1zkp_v0_8_0_sha256 *sha) {
    rustsecp256k1zkp_v0_8_0_sha256_initialize(sha);
    sha->s[0] = 0xd14c7bd9ul;
    sha->s[1] = 0x095d35e6ul;
    sha->s[2] = 0xb8490a88ul;
    sha->s[3] = 0xfb00ef74ul;
    sha->s[4] = 0x0baa488ful;
    sha->s[5] = 0x69366693ul;
    sha->s[6] = 0x1c81c5baul;
    sha->s[7] = 0xc33b296aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_ecdsa_adaptor to derive the nonce using a tagged hash function. */
static const unsigned char ecdsa_adaptor_algo[16] = "ECDSAadaptor/non";

/* Modified BIP-340 nonce function */
static int nonce_function_ecdsa_adaptor(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *pk33, const unsigned char *algo, size_t algolen, void *data) {
    rustsecp256k1zkp_v0_8_0_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor_sha256_tagged_aux(&sha);
        rustsecp256k1zkp_v0_8_0_sha256_write(&sha, data, 32);
        rustsecp256k1zkp_v0_8_0_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithims. An optimized tagging implementation is used if the default
     * tag is provided. */
    if (algolen == sizeof(ecdsa_adaptor_algo)
            && rustsecp256k1zkp_v0_8_0_memcmp_var(algo, ecdsa_adaptor_algo, algolen) == 0) {
        rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor_sha256_tagged(&sha);
    } else if (algolen == sizeof(dleq_algo)
            && rustsecp256k1zkp_v0_8_0_memcmp_var(algo, dleq_algo, algolen) == 0) {
        rustsecp256k1zkp_v0_8_0_nonce_function_dleq_sha256_tagged(&sha);
    } else {
        rustsecp256k1zkp_v0_8_0_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash (masked-)key||pk||msg using the tagged hash as per BIP-340 */
    if (data != NULL) {
        rustsecp256k1zkp_v0_8_0_sha256_write(&sha, masked_key, 32);
    } else {
        rustsecp256k1zkp_v0_8_0_sha256_write(&sha, key32, 32);
    }
    rustsecp256k1zkp_v0_8_0_sha256_write(&sha, pk33, 33);
    rustsecp256k1zkp_v0_8_0_sha256_write(&sha, msg32, 32);
    rustsecp256k1zkp_v0_8_0_sha256_finalize(&sha, nonce32);
    return 1;
}

const rustsecp256k1zkp_v0_8_0_nonce_function_hardened_ecdsa_adaptor rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor = nonce_function_ecdsa_adaptor;

int rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_encrypt(const rustsecp256k1zkp_v0_8_0_context* ctx, unsigned char *adaptor_sig162, unsigned char *seckey32, const rustsecp256k1zkp_v0_8_0_pubkey *enckey, const unsigned char *msg32, rustsecp256k1zkp_v0_8_0_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    rustsecp256k1zkp_v0_8_0_scalar k;
    rustsecp256k1zkp_v0_8_0_gej rj, rpj;
    rustsecp256k1zkp_v0_8_0_ge r, rp;
    rustsecp256k1zkp_v0_8_0_ge enckey_ge;
    rustsecp256k1zkp_v0_8_0_scalar dleq_proof_s;
    rustsecp256k1zkp_v0_8_0_scalar dleq_proof_e;
    rustsecp256k1zkp_v0_8_0_scalar sk;
    rustsecp256k1zkp_v0_8_0_scalar msg;
    rustsecp256k1zkp_v0_8_0_scalar sp;
    rustsecp256k1zkp_v0_8_0_scalar sigr;
    rustsecp256k1zkp_v0_8_0_scalar n;
    unsigned char nonce32[32] = { 0 };
    unsigned char buf33[33];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_8_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(seckey32 != NULL);
    ARG_CHECK(enckey != NULL);
    ARG_CHECK(msg32 != NULL);

    rustsecp256k1zkp_v0_8_0_scalar_clear(&dleq_proof_e);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&dleq_proof_s);

    if (noncefp == NULL) {
        noncefp = rustsecp256k1zkp_v0_8_0_nonce_function_ecdsa_adaptor;
    }

    ret &= rustsecp256k1zkp_v0_8_0_pubkey_load(ctx, &enckey_ge, enckey);
    ret &= rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(&enckey_ge, buf33, &size, 1);
    ret &= !!noncefp(nonce32, msg32, seckey32, buf33, ecdsa_adaptor_algo, sizeof(ecdsa_adaptor_algo), ndata);
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(&k, nonce32, NULL);
    ret &= !rustsecp256k1zkp_v0_8_0_scalar_is_zero(&k);
    rustsecp256k1zkp_v0_8_0_scalar_cmov(&k, &rustsecp256k1zkp_v0_8_0_scalar_one, !ret);

    /* R' := k*G */
    rustsecp256k1zkp_v0_8_0_ecmult_gen(&ctx->ecmult_gen_ctx, &rpj, &k);
    rustsecp256k1zkp_v0_8_0_ge_set_gej(&rp, &rpj);
    /* R = k*Y; */
    rustsecp256k1zkp_v0_8_0_ecmult_const(&rj, &enckey_ge, &k, 256);
    rustsecp256k1zkp_v0_8_0_ge_set_gej(&r, &rj);
    /* We declassify the non-secret values rp and r to allow using them
     * as branch points. */
    rustsecp256k1zkp_v0_8_0_declassify(ctx, &rp, sizeof(rp));
    rustsecp256k1zkp_v0_8_0_declassify(ctx, &r, sizeof(r));

    /* dleq_proof = DLEQ_prove(k, (R', Y, R)) */
    ret &= rustsecp256k1zkp_v0_8_0_dleq_prove(ctx, &dleq_proof_s, &dleq_proof_e, &k, &enckey_ge, &rp, &r, noncefp, ndata);

    ret &= rustsecp256k1zkp_v0_8_0_scalar_set_b32_seckey(&sk, seckey32);
    rustsecp256k1zkp_v0_8_0_scalar_cmov(&sk, &rustsecp256k1zkp_v0_8_0_scalar_one, !ret);
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(&msg, msg32, NULL);
    rustsecp256k1zkp_v0_8_0_fe_normalize(&r.x);
    rustsecp256k1zkp_v0_8_0_fe_get_b32(buf33, &r.x);
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(&sigr, buf33, NULL);
    ret &= !rustsecp256k1zkp_v0_8_0_scalar_is_zero(&sigr);
    /* s' = k⁻¹(m + R.x * x) */
    rustsecp256k1zkp_v0_8_0_scalar_mul(&n, &sigr, &sk);
    rustsecp256k1zkp_v0_8_0_scalar_add(&n, &n, &msg);
    rustsecp256k1zkp_v0_8_0_scalar_inverse(&sp, &k);
    rustsecp256k1zkp_v0_8_0_scalar_mul(&sp, &sp, &n);
    ret &= !rustsecp256k1zkp_v0_8_0_scalar_is_zero(&sp);

    /* return (R, R', s', dleq_proof) */
    ret &= rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_sig_serialize(adaptor_sig162, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s);

    rustsecp256k1zkp_v0_8_0_memczero(adaptor_sig162, 162, !ret);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&n);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&k);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&sk);

    return ret;
}

int rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_verify(const rustsecp256k1zkp_v0_8_0_context* ctx, const unsigned char *adaptor_sig162, const rustsecp256k1zkp_v0_8_0_pubkey *pubkey, const unsigned char *msg32, const rustsecp256k1zkp_v0_8_0_pubkey *enckey) {
    rustsecp256k1zkp_v0_8_0_scalar dleq_proof_s, dleq_proof_e;
    rustsecp256k1zkp_v0_8_0_scalar msg;
    rustsecp256k1zkp_v0_8_0_ge pubkey_ge;
    rustsecp256k1zkp_v0_8_0_ge r, rp;
    rustsecp256k1zkp_v0_8_0_scalar sp;
    rustsecp256k1zkp_v0_8_0_scalar sigr;
    rustsecp256k1zkp_v0_8_0_ge enckey_ge;
    rustsecp256k1zkp_v0_8_0_gej derived_rp;
    rustsecp256k1zkp_v0_8_0_scalar sn, u1, u2;
    rustsecp256k1zkp_v0_8_0_gej pubkeyj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(enckey != NULL);

    if (!rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig162)) {
        return 0;
    }
    if (!rustsecp256k1zkp_v0_8_0_pubkey_load(ctx, &enckey_ge, enckey)) {
        return 0;
    }
    /* DLEQ_verify((R', Y, R), dleq_proof) */
    if(!rustsecp256k1zkp_v0_8_0_dleq_verify(&dleq_proof_s, &dleq_proof_e, &rp, &enckey_ge, &r)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(&msg, msg32, NULL);
    if (!rustsecp256k1zkp_v0_8_0_pubkey_load(ctx, &pubkey_ge, pubkey)) {
        return 0;
    }

    /* return R' == s'⁻¹(m * G + R.x * X) */
    rustsecp256k1zkp_v0_8_0_scalar_inverse_var(&sn, &sp);
    rustsecp256k1zkp_v0_8_0_scalar_mul(&u1, &sn, &msg);
    rustsecp256k1zkp_v0_8_0_scalar_mul(&u2, &sn, &sigr);
    rustsecp256k1zkp_v0_8_0_gej_set_ge(&pubkeyj, &pubkey_ge);
    rustsecp256k1zkp_v0_8_0_ecmult(&derived_rp, &pubkeyj, &u2, &u1);
    if (rustsecp256k1zkp_v0_8_0_gej_is_infinity(&derived_rp)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_gej_neg(&derived_rp, &derived_rp);
    rustsecp256k1zkp_v0_8_0_gej_add_ge_var(&derived_rp, &derived_rp, &rp, NULL);
    return rustsecp256k1zkp_v0_8_0_gej_is_infinity(&derived_rp);
}

int rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_decrypt(const rustsecp256k1zkp_v0_8_0_context* ctx, rustsecp256k1zkp_v0_8_0_ecdsa_signature *sig, const unsigned char *deckey32, const unsigned char *adaptor_sig162) {
    rustsecp256k1zkp_v0_8_0_scalar deckey;
    rustsecp256k1zkp_v0_8_0_scalar sp;
    rustsecp256k1zkp_v0_8_0_scalar s;
    rustsecp256k1zkp_v0_8_0_scalar sigr;
    int overflow;
    int high;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(deckey32 != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);

    rustsecp256k1zkp_v0_8_0_scalar_clear(&sp);
    rustsecp256k1zkp_v0_8_0_scalar_set_b32(&deckey, deckey32, &overflow);
    ret &= !overflow;
    ret &= rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, &sp, NULL, NULL, adaptor_sig162);
    ret &= !rustsecp256k1zkp_v0_8_0_scalar_is_zero(&deckey);
    rustsecp256k1zkp_v0_8_0_scalar_inverse(&s, &deckey);
    /* s = s' * y⁻¹ */
    rustsecp256k1zkp_v0_8_0_scalar_mul(&s, &s, &sp);
    high = rustsecp256k1zkp_v0_8_0_scalar_is_high(&s);
    rustsecp256k1zkp_v0_8_0_scalar_cond_negate(&s, high);
    rustsecp256k1zkp_v0_8_0_ecdsa_signature_save(sig, &sigr, &s);

    rustsecp256k1zkp_v0_8_0_memczero(&sig->data[0], 64, !ret);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&deckey);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&sp);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&s);

    return ret;
}

int rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_recover(const rustsecp256k1zkp_v0_8_0_context* ctx, unsigned char *deckey32, const rustsecp256k1zkp_v0_8_0_ecdsa_signature *sig, const unsigned char *adaptor_sig162, const rustsecp256k1zkp_v0_8_0_pubkey *enckey) {
    rustsecp256k1zkp_v0_8_0_scalar sp, adaptor_sigr;
    rustsecp256k1zkp_v0_8_0_scalar s, r;
    rustsecp256k1zkp_v0_8_0_scalar deckey;
    rustsecp256k1zkp_v0_8_0_ge enckey_expected_ge;
    rustsecp256k1zkp_v0_8_0_gej enckey_expected_gej;
    unsigned char enckey33[33];
    unsigned char enckey_expected33[33];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1zkp_v0_8_0_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(deckey32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(enckey != NULL);

    if (!rustsecp256k1zkp_v0_8_0_ecdsa_adaptor_sig_deserialize(NULL, &adaptor_sigr, NULL, &sp, NULL, NULL, adaptor_sig162)) {
        return 0;
    }
    rustsecp256k1zkp_v0_8_0_ecdsa_signature_load(ctx, &r, &s, sig);
    /* Check that we're not looking at some unrelated signature */
    ret &= rustsecp256k1zkp_v0_8_0_scalar_eq(&adaptor_sigr, &r);
    /* y = s⁻¹ * s' */
    ret &= !rustsecp256k1zkp_v0_8_0_scalar_is_zero(&s);
    rustsecp256k1zkp_v0_8_0_scalar_inverse(&deckey, &s);
    rustsecp256k1zkp_v0_8_0_scalar_mul(&deckey, &deckey, &sp);

    /* Deal with ECDSA malleability */
    rustsecp256k1zkp_v0_8_0_ecmult_gen(&ctx->ecmult_gen_ctx, &enckey_expected_gej, &deckey);
    rustsecp256k1zkp_v0_8_0_ge_set_gej(&enckey_expected_ge, &enckey_expected_gej);
    /* We declassify non-secret enckey_expected_ge to allow using it as a
     * branch point. */
    rustsecp256k1zkp_v0_8_0_declassify(ctx, &enckey_expected_ge, sizeof(enckey_expected_ge));
    if (!rustsecp256k1zkp_v0_8_0_eckey_pubkey_serialize(&enckey_expected_ge, enckey_expected33, &size, SECP256K1_EC_COMPRESSED)) {
        /* Unreachable from tests (and other VERIFY builds) and therefore this
         * branch should be ignored in test coverage analysis.
         *
         * Proof:
         *     eckey_pubkey_serialize fails <=> deckey = 0
         *     deckey = 0 <=> s^-1 = 0 or sp = 0
         *     case 1: s^-1 = 0 impossible by the definition of multiplicative
         *             inverse and because the scalar_inverse implementation
         *             VERIFY_CHECKs that the inputs are valid scalars.
         *     case 2: sp = 0 impossible because ecdsa_adaptor_sig_deserialize would have already failed
         */
        return 0;
    }
    if (!rustsecp256k1zkp_v0_8_0_ec_pubkey_serialize(ctx, enckey33, &size, enckey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    if (rustsecp256k1zkp_v0_8_0_memcmp_var(&enckey_expected33[1], &enckey33[1], 32) != 0) {
        return 0;
    }
    if (enckey_expected33[0] != enckey33[0]) {
        /* try Y_implied == -Y */
        rustsecp256k1zkp_v0_8_0_scalar_negate(&deckey, &deckey);
    }
    rustsecp256k1zkp_v0_8_0_scalar_get_b32(deckey32, &deckey);

    rustsecp256k1zkp_v0_8_0_scalar_clear(&deckey);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&sp);
    rustsecp256k1zkp_v0_8_0_scalar_clear(&s);

    return ret;
}

#endif
