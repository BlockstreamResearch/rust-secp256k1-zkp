/**********************************************************************
 * Copyright (c) 2018 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/**
 * This file demonstrates how to use the MuSig module to create a multisignature.
 * Additionally, see the documentation in include/rustsecp256k1zkp_v0_4_0_musig.h.
 */

#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>

struct signer_secrets_t {
    rustsecp256k1zkp_v0_4_0_keypair keypair;
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce;
};

struct signer_t {
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pubkey;
    rustsecp256k1zkp_v0_4_0_musig_pubnonce pubnonce;
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig;
};

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 3
 /* Create a key pair and store it in seckey and pubkey */
int create_keypair(const rustsecp256k1zkp_v0_4_0_context* ctx, struct signer_secrets_t *signer_secrets, struct signer_t *signer) {
    int ret;
    unsigned char seckey[32];
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL) {
        return 0;
    }
    do {
        if(!fread(seckey, sizeof(seckey), 1, frand)) {
             fclose(frand);
             return 0;
         }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!rustsecp256k1zkp_v0_4_0_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    ret = rustsecp256k1zkp_v0_4_0_keypair_create(ctx, &signer_secrets->keypair, seckey);
    ret &= rustsecp256k1zkp_v0_4_0_keypair_xonly_pub(ctx, &signer->pubkey, NULL, &signer_secrets->keypair);

    return ret;
}

/* Sign a message hash with the given key pairs and store the result in sig */
int sign(const rustsecp256k1zkp_v0_4_0_context* ctx, struct signer_secrets_t *signer_secrets, struct signer_t *signer, const unsigned char* msg32, unsigned char *sig64) {
    int i;
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pubkeys[N_SIGNERS];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonces[N_SIGNERS];
    rustsecp256k1zkp_v0_4_0_musig_aggnonce agg_pubnonce;
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *partial_sigs[N_SIGNERS];
    /* The same for all signers */
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache cache;
    rustsecp256k1zkp_v0_4_0_musig_session session;

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char seckey[32];
        unsigned char session_id[32];
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of rustsecp256k1zkp_v0_4_0_musig_nonce_gen. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);
        if (!rustsecp256k1zkp_v0_4_0_keypair_sec(ctx, seckey, &signer_secrets[i].keypair)) {
            return 0;
        }
        /* Initialize session and create secret nonce for signing and public
         * nonce to send to the other signers. */
        if (!rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &signer_secrets[i].secnonce, &signer[i].pubnonce, session_id, seckey, msg32, NULL, NULL)) {
            return 0;
        }
        pubkeys[i] = &signer[i].pubkey;
        pubnonces[i] = &signer[i].pubnonce;
    }
    /* Communication round 1: Exchange nonces */
    for (i = 0; i < N_SIGNERS; i++) {
        rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk;

        /* Create aggregate pubkey, aggregate nonce and initialize signer data */
        if (!rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, NULL, &agg_pk, &cache, pubkeys, N_SIGNERS)) {
            return 0;
        }
        if(!rustsecp256k1zkp_v0_4_0_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, N_SIGNERS)) {
            return 0;
        }
        if(!rustsecp256k1zkp_v0_4_0_musig_nonce_process(ctx, &session, &agg_pubnonce, msg32, &cache, NULL)) {
            return 0;
        }
        /* partial_sign will clear the secnonce by setting it 0. That's because
         * you must _never_ reuse the secnonce (or use the same session_id to
         * create a secnonce). If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &signer[i].partial_sig, &signer_secrets[i].secnonce, &signer_secrets[i].keypair, &cache, &session)) {
            return 0;
        }
        partial_sigs[i] = &signer[i].partial_sig;
    }
    /* Communication round 2: Exchange partial signatures */
    for (i = 0; i < N_SIGNERS; i++) {
        /* To check whether signing was successful, it suffices to either verify
         * the aggregate signature with the aggregate public key using
         * rustsecp256k1zkp_v0_4_0_schnorrsig_verify, or verify all partial signatures of all
         * signers individually. Verifying the aggregate signature is cheaper but
         * verifying the individual partial signatures has the advantage that it
         * can be used to determine which of the partial signatures are invalid
         * (if any), i.e., which of the partial signatures cause the aggregate
         * signature to be invalid and thus the protocol run to fail. It's also
         * fine to first verify the aggregate sig, and only verify the individual
         * sigs if it does not work.
         */
        if (!rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &signer[i].partial_sig, &signer[i].pubnonce, &signer[i].pubkey, &cache, &session)) {
            return 0;
        }
    }
    return rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(ctx, sig64, &session, partial_sigs, N_SIGNERS);
}

 int main(void) {
    rustsecp256k1zkp_v0_4_0_context* ctx;
    int i;
    struct signer_secrets_t signer_secrets[N_SIGNERS];
    struct signer_t signers[N_SIGNERS];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pubkeys_ptr[N_SIGNERS];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg!";
    unsigned char sig[64];

    /* Create a context for signing and verification */
    ctx = rustsecp256k1zkp_v0_4_0_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    printf("Creating key pairs......");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!create_keypair(ctx, &signer_secrets[i], &signers[i])) {
            printf("FAILED\n");
            return 1;
        }
        pubkeys_ptr[i] = &signers[i].pubkey;
    }
    printf("ok\n");
    printf("Combining public keys...");
    if (!rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, NULL, &agg_pk, NULL, pubkeys_ptr, N_SIGNERS)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Signing message.........");
    if (!sign(ctx, signer_secrets, signers, msg, sig)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying signature.....");
    if (!rustsecp256k1zkp_v0_4_0_schnorrsig_verify(ctx, sig, msg, 32, &agg_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    rustsecp256k1zkp_v0_4_0_context_destroy(ctx);
    return 0;
}
