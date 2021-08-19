/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

static int create_keypair_and_pk(rustsecp256k1zkp_v0_4_0_keypair *keypair, rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk, const unsigned char *sk) {
    int ret;
    rustsecp256k1zkp_v0_4_0_keypair keypair_tmp;
    ret = rustsecp256k1zkp_v0_4_0_keypair_create(ctx, &keypair_tmp, sk);
    ret &= rustsecp256k1zkp_v0_4_0_keypair_xonly_pub(ctx, pk, NULL, &keypair_tmp);
    if (keypair != NULL) {
        *keypair = keypair_tmp;
    }
    return ret;
}

/* Just a simple (non-adaptor, non-tweaked) 2-of-2 MuSig aggregate, sign, verify
 * test. */
void musig_simple_test(rustsecp256k1zkp_v0_4_0_scratch_space *scratch) {
    unsigned char sk[2][32];
    rustsecp256k1zkp_v0_4_0_keypair keypair[2];
    rustsecp256k1zkp_v0_4_0_musig_pubnonce pubnonce[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_aggnonce aggnonce;
    unsigned char msg[32];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk;
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache;
    unsigned char session_id[2][32];
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce[2];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk[2];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig[2];
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *partial_sig_ptr[2];
    unsigned char final_sig[64];
    rustsecp256k1zkp_v0_4_0_musig_session session;
    int i;

    rustsecp256k1zkp_v0_4_0_testrand256(msg);
    for (i = 0; i < 2; i++) {
        rustsecp256k1zkp_v0_4_0_testrand256(session_id[i]);
        rustsecp256k1zkp_v0_4_0_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }

    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce[0], &pubnonce[0], session_id[0], sk[0], NULL, NULL, NULL) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce[1], &pubnonce[1], session_id[1], sk[1], NULL, NULL, NULL) == 1);


    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(ctx, &session, &aggnonce, msg, &keyagg_cache, NULL) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig[0], &secnonce[0], &keypair[0], &keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig[1], &secnonce[1], &keypair[1], &keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &partial_sig[1], &pubnonce[1], &pk[1], &keyagg_cache, &session) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), &agg_pk) == 1);
}

void pubnonce_summing_to_inf(rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce) {
    rustsecp256k1zkp_v0_4_0_ge ge[2];
    int i;
    rustsecp256k1zkp_v0_4_0_gej summed_nonces[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce_ptr[2];

    ge[0] = rustsecp256k1zkp_v0_4_0_ge_const_g;
    ge[1] = rustsecp256k1zkp_v0_4_0_ge_const_g;

    for (i = 0; i < 2; i++) {
        rustsecp256k1zkp_v0_4_0_musig_pubnonce_save(&pubnonce[i], ge);
        pubnonce_ptr[i] = &pubnonce[i];
        rustsecp256k1zkp_v0_4_0_ge_neg(&ge[0], &ge[0]);
        rustsecp256k1zkp_v0_4_0_ge_neg(&ge[1], &ge[1]);
    }

    rustsecp256k1zkp_v0_4_0_musig_sum_nonces(ctx, summed_nonces, pubnonce_ptr, 2);
    rustsecp256k1zkp_v0_4_0_gej_is_infinity(&summed_nonces[0]);
    rustsecp256k1zkp_v0_4_0_gej_is_infinity(&summed_nonces[1]);
}

void musig_api_tests(rustsecp256k1zkp_v0_4_0_scratch_space *scratch) {
    rustsecp256k1zkp_v0_4_0_scratch_space *scratch_small;
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig[2];
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *partial_sig_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_partial_sig invalid_partial_sig;
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *invalid_partial_sig_ptr[2];
    unsigned char final_sig[64];
    unsigned char pre_sig[64];
    unsigned char buf[32];
    unsigned char sk[2][32];
    rustsecp256k1zkp_v0_4_0_keypair keypair[2];
    rustsecp256k1zkp_v0_4_0_keypair invalid_keypair;
    unsigned char max64[64];
    unsigned char zeros68[68] = { 0 };
    unsigned char session_id[2][32];
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce[2];
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce_tmp;
    rustsecp256k1zkp_v0_4_0_musig_secnonce invalid_secnonce;
    rustsecp256k1zkp_v0_4_0_musig_pubnonce pubnonce[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce_ptr[2];
    unsigned char pubnonce_ser[66];
    rustsecp256k1zkp_v0_4_0_musig_pubnonce inf_pubnonce[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *inf_pubnonce_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_pubnonce invalid_pubnonce;
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *invalid_pubnonce_ptr[1];
    rustsecp256k1zkp_v0_4_0_musig_aggnonce aggnonce;
    unsigned char aggnonce_ser[66];
    unsigned char msg[32];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk;
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache;
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache invalid_keyagg_cache;
    rustsecp256k1zkp_v0_4_0_musig_session session;
    rustsecp256k1zkp_v0_4_0_musig_session invalid_session;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk[2];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk_ptr[2];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey invalid_pk;
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *invalid_pk_ptr2[2];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *invalid_pk_ptr3[3];
    unsigned char tweak[32];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    rustsecp256k1zkp_v0_4_0_pubkey adaptor;
    int i;

    /** setup **/
    rustsecp256k1zkp_v0_4_0_context *none = rustsecp256k1zkp_v0_4_0_context_create(SECP256K1_CONTEXT_NONE);
    rustsecp256k1zkp_v0_4_0_context *sign = rustsecp256k1zkp_v0_4_0_context_create(SECP256K1_CONTEXT_SIGN);
    rustsecp256k1zkp_v0_4_0_context *vrfy = rustsecp256k1zkp_v0_4_0_context_create(SECP256K1_CONTEXT_VERIFY);
    int ecount;

    rustsecp256k1zkp_v0_4_0_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    rustsecp256k1zkp_v0_4_0_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    rustsecp256k1zkp_v0_4_0_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    rustsecp256k1zkp_v0_4_0_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    rustsecp256k1zkp_v0_4_0_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    rustsecp256k1zkp_v0_4_0_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);

    memset(max64, 0xff, sizeof(max64));
    memset(&invalid_keypair, 0, sizeof(invalid_keypair));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_secnonce, 0, sizeof(invalid_secnonce));
    memset(&invalid_partial_sig, 0, sizeof(invalid_partial_sig));
    pubnonce_summing_to_inf(inf_pubnonce);
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&invalid_keyagg_cache, 0, sizeof(invalid_keyagg_cache));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_session, 0, sizeof(invalid_session));

    rustsecp256k1zkp_v0_4_0_testrand256(sec_adaptor);
    rustsecp256k1zkp_v0_4_0_testrand256(msg);
    rustsecp256k1zkp_v0_4_0_testrand256(tweak);
    CHECK(rustsecp256k1zkp_v0_4_0_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        invalid_pk_ptr2[i] = &invalid_pk;
        invalid_pk_ptr3[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        inf_pubnonce_ptr[i] = &inf_pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        invalid_partial_sig_ptr[i] = &partial_sig[i];
        rustsecp256k1zkp_v0_4_0_testrand256(session_id[i]);
        rustsecp256k1zkp_v0_4_0_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    invalid_pubnonce_ptr[0] = &invalid_pubnonce;
    invalid_partial_sig_ptr[0] = &invalid_partial_sig;
    /* invalid_pk_ptr3 has two valid, one invalid pk, which is important to test
     * musig_pubkey_agg */
    invalid_pk_ptr3[2] = &invalid_pk;

    /** main test body **/

    /* Key aggregation */
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(none, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(sign, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(ecount == 2);
    /* pubkey_agg does not require a scratch space */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, NULL, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(ecount == 2);
    /* A small scratch space works too, but will result in using an ineffecient algorithm */
    scratch_small = rustsecp256k1zkp_v0_4_0_scratch_space_create(ctx, 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch_small, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    rustsecp256k1zkp_v0_4_0_scratch_space_destroy(ctx, scratch_small);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, NULL, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, NULL, pk_ptr, 2) == 1);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, NULL, 2) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp(&agg_pk, zeros68, sizeof(agg_pk)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, invalid_pk_ptr2, 2) == 0);
    CHECK(ecount == 4);
    CHECK(memcmp(&agg_pk, zeros68, sizeof(agg_pk)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, invalid_pk_ptr3, 3) == 0);
    CHECK(ecount == 5);
    CHECK(memcmp(&agg_pk, zeros68, sizeof(agg_pk)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 0) == 0);
    CHECK(ecount == 6);
    CHECK(memcmp(&agg_pk, zeros68, sizeof(agg_pk)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, NULL, 0) == 0);
    CHECK(ecount == 7);
    CHECK(memcmp(&agg_pk, zeros68, sizeof(agg_pk)) == 0);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);

    /** Tweaking */
    ecount = 0;
    {
        rustsecp256k1zkp_v0_4_0_pubkey tmp_output_pk;
        rustsecp256k1zkp_v0_4_0_musig_keyagg_cache tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(ctx, &tmp_output_pk, tweak, &tmp_keyagg_cache) == 1);
        /* Reset keyagg_cache */
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(none, &tmp_output_pk, tweak, &tmp_keyagg_cache) == 0);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
        CHECK(ecount == 1);
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(sign, &tmp_output_pk, tweak, &tmp_keyagg_cache) == 0);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
        CHECK(ecount == 2);
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, tweak, &tmp_keyagg_cache) == 1);
        CHECK(ecount == 2);
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, NULL, tweak, &tmp_keyagg_cache) == 1);
        CHECK(ecount == 2);
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, NULL, &tmp_keyagg_cache) == 0);
        CHECK(ecount == 3);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, max64, &tmp_keyagg_cache) == 0);
        CHECK(ecount == 3);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
        tmp_keyagg_cache = keyagg_cache;
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, tweak, NULL) == 0);
        CHECK(ecount == 4);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
        tmp_keyagg_cache = keyagg_cache;
        /* Uninitialized keyagg_cache */
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, tweak, &invalid_keyagg_cache) == 0);
        CHECK(ecount == 5);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
        /* Using the same keyagg_cache twice does not work */
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, tweak, &tmp_keyagg_cache) == 1);
        CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(vrfy, &tmp_output_pk, tweak, &tmp_keyagg_cache) == 0);
        CHECK(ecount == 6);
        CHECK(memcmp(&tmp_output_pk, zeros68, sizeof(tmp_output_pk)) == 0);
    }

    /** Session creation **/
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(none, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(vrfy, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 1);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, NULL, &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], NULL, session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 4);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], NULL, sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 5);
    CHECK(memcmp(&secnonce[0], zeros68, sizeof(secnonce[0])) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, msg, &keyagg_cache, max64) == 1);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], NULL, &keyagg_cache, max64) == 1);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, NULL, max64) == 1);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &invalid_keyagg_cache, max64) == 0);
    CHECK(ecount == 6);
    CHECK(memcmp(&secnonce[0], zeros68, sizeof(secnonce[0])) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, NULL) == 1);
    CHECK(ecount == 6);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], NULL, NULL, NULL) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(sign, &secnonce[1], &pubnonce[1], session_id[1], sk[1], NULL, NULL, NULL) == 1);

    /** Serialize and parse public nonces **/
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_serialize(none, pubnonce_ser, &pubnonce[0]) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_serialize(none, NULL, &pubnonce[0]) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_serialize(none, pubnonce_ser, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp(zeros68, pubnonce_ser, sizeof(pubnonce_ser)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_serialize(none, pubnonce_ser, &invalid_pubnonce) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp(zeros68, pubnonce_ser, sizeof(pubnonce_ser)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_serialize(none, pubnonce_ser, &pubnonce[0]) == 1);

    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_parse(none, &pubnonce[0], pubnonce_ser) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_parse(none, NULL, pubnonce_ser) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_parse(none, &pubnonce[0], NULL) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_parse(none, &pubnonce[0], zeros68) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubnonce_parse(none, &pubnonce[0], pubnonce_ser) == 1);

    /** Receive nonces and aggregate**/
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(none, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(none, NULL, pubnonce_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(none, &aggnonce, NULL, 2) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(none, &aggnonce, pubnonce_ptr, 0) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(none, &aggnonce, invalid_pubnonce_ptr, 1) == 0);
    CHECK(ecount == 4);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(none, &aggnonce, inf_pubnonce_ptr, 2) == 0);
    CHECK(ecount == 4);

    /** Serialize and parse aggregate nonces **/
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_serialize(none, aggnonce_ser, &aggnonce) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_serialize(none, NULL, &aggnonce) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_serialize(none, aggnonce_ser, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp(zeros68, aggnonce_ser, sizeof(aggnonce_ser)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_serialize(none, aggnonce_ser, (rustsecp256k1zkp_v0_4_0_musig_aggnonce*) &invalid_pubnonce) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp(zeros68, aggnonce_ser, sizeof(aggnonce_ser)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_serialize(none, aggnonce_ser, &aggnonce) == 1);

    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_parse(none, &aggnonce, aggnonce_ser) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_parse(none, NULL, aggnonce_ser) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_parse(none, &aggnonce, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_parse(none, &aggnonce, zeros68) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_parse(none, &aggnonce, aggnonce_ser) == 1);

    /** Process nonces **/
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(none, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(sign, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, NULL, &aggnonce, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, NULL, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 4);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, (rustsecp256k1zkp_v0_4_0_musig_aggnonce*) &invalid_pubnonce, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, &aggnonce, NULL, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 6);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, &aggnonce, msg, NULL, &adaptor) == 0);
    CHECK(ecount == 7);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, &aggnonce, msg, &invalid_keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 8);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, &aggnonce, msg, &keyagg_cache, NULL) == 1);
    CHECK(ecount == 8);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, &aggnonce, msg, &keyagg_cache, (rustsecp256k1zkp_v0_4_0_pubkey *)&invalid_pk) == 0);
    CHECK(ecount == 9);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(vrfy, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 1);

    ecount = 0;
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, &session) == 1);
    /* The session_id is set to 0 and subsequent signing attempts fail */
    CHECK(memcmp(&secnonce_tmp, zeros68, sizeof(secnonce_tmp)) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 1);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, NULL, &secnonce_tmp, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 2);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], NULL, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &invalid_secnonce, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 4);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, NULL, &keyagg_cache, &session) == 0);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &invalid_keypair, &keyagg_cache, &session) == 0);
    CHECK(ecount == 6);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], NULL, &session) == 0);
    CHECK(ecount == 7);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &invalid_keyagg_cache, &session) == 0);
    CHECK(ecount == 8);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, NULL) == 0);
    CHECK(ecount == 9);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, &invalid_session) == 0);
    CHECK(ecount == 10);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[0], &secnonce[0], &keypair[0], &keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(none, &partial_sig[1], &secnonce[1], &keypair[1], &keyagg_cache, &session) == 1);

    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_serialize(none, buf, &partial_sig[0]) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_serialize(none, buf, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_parse(none, &partial_sig[0], buf) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_parse(none, NULL, buf) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_parse(none, &partial_sig[0], max64) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 4);

    /** Partial signature verification */
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(none, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(sign, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, NULL, &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &invalid_partial_sig, &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 4);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], NULL, &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &invalid_pubnonce, &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 6);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], NULL, &keyagg_cache, &session) == 0);
    CHECK(ecount == 7);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &invalid_pk, &keyagg_cache, &session) == 0);
    CHECK(ecount == 8);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], NULL, &session) == 0);
    CHECK(ecount == 9);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &invalid_keyagg_cache, &session) == 0);
    CHECK(ecount == 10);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, NULL) == 0);
    CHECK(ecount == 11);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &invalid_session) == 0);
    CHECK(ecount == 12);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(vrfy, &partial_sig[1], &pubnonce[1], &pk[1], &keyagg_cache, &session) == 1);

    /** Sign aggregation and verification */
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, NULL, &session, partial_sig_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, NULL, partial_sig_ptr, 2) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, &invalid_session, partial_sig_ptr, 2) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, &session, NULL, 2) == 0);
    CHECK(ecount == 4);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, &session, invalid_partial_sig_ptr, 2) == 0);
    CHECK(ecount == 5);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 0) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 2) == 1);

    /** Adaptor signature verification */
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(none, &nonce_parity, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(none, NULL, &session) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(none, &nonce_parity, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(none, &nonce_parity, &invalid_session) == 0);
    CHECK(ecount == 3);

    ecount = 0;
    {
        unsigned char tmp_sig[64];
        memcpy(tmp_sig, pre_sig, sizeof(tmp_sig));
        CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(none, tmp_sig, sec_adaptor, nonce_parity) == 1);
        CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(none, NULL, sec_adaptor, 0) == 0);
        CHECK(ecount == 1);
        CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(none, max64, sec_adaptor, 0) == 0);
        CHECK(ecount == 1);
        CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(none, tmp_sig, NULL, 0) == 0);
        CHECK(ecount == 2);
        CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(none, tmp_sig, max64, nonce_parity) == 0);
        CHECK(ecount == 2);
    }
    memcpy(final_sig, pre_sig, sizeof(final_sig));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(none, final_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_schnorrsig_verify(vrfy, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    /** Secret adaptor can be extracted from signature */
    ecount = 0;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, nonce_parity) == 1);
    CHECK(memcmp(sec_adaptor, sec_adaptor1, 32) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, NULL, final_sig, pre_sig, 0) == 0);
    CHECK(ecount == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, sec_adaptor1, NULL, pre_sig, 0) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, sec_adaptor1, max64, pre_sig, 0) == 0);
    CHECK(ecount == 2);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, sec_adaptor1, final_sig, NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, sec_adaptor1, final_sig, max64, 0) == 0);
    CHECK(ecount == 3);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, 1) == 1);

    /** cleanup **/
    rustsecp256k1zkp_v0_4_0_context_destroy(none);
    rustsecp256k1zkp_v0_4_0_context_destroy(sign);
    rustsecp256k1zkp_v0_4_0_context_destroy(vrfy);
}

void musig_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    rustsecp256k1zkp_v0_4_0_scalar k1[2], k2[2];

    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k1, args[0], args[1], args[2], args[3], args[4]);
    rustsecp256k1zkp_v0_4_0_testrand_flip(args[n_flip], n_bytes);
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k2, args[0], args[1], args[2], args[3], args[4]);
    CHECK(rustsecp256k1zkp_v0_4_0_scalar_eq(&k1[0], &k2[0]) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_scalar_eq(&k1[1], &k2[1]) == 0);
}

void musig_nonce_null(unsigned char **args, size_t n_flip) {
    rustsecp256k1zkp_v0_4_0_scalar k1[2], k2[2];
    unsigned char *args_tmp;

    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k1, args[0], args[1], args[2], args[3], args[4]);
    args_tmp = args[n_flip];
    args[n_flip] = NULL;
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k2, args[0], args[1], args[2], args[3], args[4]);
    CHECK(rustsecp256k1zkp_v0_4_0_scalar_eq(&k1[0], &k2[0]) == 0);
    CHECK(rustsecp256k1zkp_v0_4_0_scalar_eq(&k1[1], &k2[1]) == 0);
    args[n_flip] = args_tmp;
}

void musig_nonce_test(void) {
    unsigned char *args[5];
    unsigned char session_id[32];
    unsigned char sk[32];
    unsigned char msg[32];
    unsigned char agg_pk[32];
    unsigned char extra_input[32];
    int i, j;
    rustsecp256k1zkp_v0_4_0_scalar k[5][2];

    rustsecp256k1zkp_v0_4_0_rfc6979_hmac_sha256_generate(&rustsecp256k1zkp_v0_4_0_test_rng, session_id, sizeof(session_id));
    rustsecp256k1zkp_v0_4_0_rfc6979_hmac_sha256_generate(&rustsecp256k1zkp_v0_4_0_test_rng, sk, sizeof(sk));
    rustsecp256k1zkp_v0_4_0_rfc6979_hmac_sha256_generate(&rustsecp256k1zkp_v0_4_0_test_rng, msg, sizeof(msg));
    rustsecp256k1zkp_v0_4_0_rfc6979_hmac_sha256_generate(&rustsecp256k1zkp_v0_4_0_test_rng, agg_pk, sizeof(agg_pk));
    rustsecp256k1zkp_v0_4_0_rfc6979_hmac_sha256_generate(&rustsecp256k1zkp_v0_4_0_test_rng, extra_input, sizeof(extra_input));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = session_id;
    args[1] = sk;
    args[2] = msg;
    args[3] = agg_pk;
    args[4] = extra_input;
    for (i = 0; i < count; i++) {
        musig_nonce_bitflip(args, 0, sizeof(session_id));
        musig_nonce_bitflip(args, 1, sizeof(sk));
        musig_nonce_bitflip(args, 2, sizeof(msg));
        musig_nonce_bitflip(args, 3, sizeof(agg_pk));
        musig_nonce_bitflip(args, 4, sizeof(extra_input));
    }
    /* Check that if any argument is NULL, a different nonce is produced than if
     * any other argument is NULL. */
    memcpy(sk, session_id, sizeof(sk));
    memcpy(msg, session_id, sizeof(msg));
    memcpy(agg_pk, session_id, sizeof(agg_pk));
    memcpy(extra_input, session_id, sizeof(extra_input));
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k[0], args[0], args[1], args[2], args[3], args[4]);
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k[1], args[0], NULL, args[2], args[3], args[4]);
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k[2], args[0], args[1], NULL, args[3], args[4]);
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k[3], args[0], args[1], args[2], NULL, args[4]);
    rustsecp256k1zkp_v0_4_0_nonce_function_musig(k[4], args[0], args[1], args[2], args[3], NULL);
    for (i = 0; i < 4; i++) {
        for (j = i+1; j < 5; j++) {
            CHECK(rustsecp256k1zkp_v0_4_0_scalar_eq(&k[i][0], &k[j][0]) == 0);
            CHECK(rustsecp256k1zkp_v0_4_0_scalar_eq(&k[i][1], &k[j][1]) == 0);
        }
    }
}

void scriptless_atomic_swap(rustsecp256k1zkp_v0_4_0_scratch_space *scratch) {
    /* Throughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    unsigned char final_sig_a[64];
    unsigned char pre_sig_b[64];
    unsigned char final_sig_b[64];
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig_a[2];
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *partial_sig_a_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig_b[2];
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *partial_sig_b_ptr[2];
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    rustsecp256k1zkp_v0_4_0_pubkey pub_adaptor;
    unsigned char sk_a[2][32];
    unsigned char sk_b[2][32];
    rustsecp256k1zkp_v0_4_0_keypair keypair_a[2];
    rustsecp256k1zkp_v0_4_0_keypair keypair_b[2];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk_a[2];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk_a_ptr[2];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk_b[2];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk_b_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache_a;
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache_b;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk_a;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk_b;
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce_a[2];
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce_b[2];
    rustsecp256k1zkp_v0_4_0_musig_pubnonce pubnonce_a[2];
    rustsecp256k1zkp_v0_4_0_musig_pubnonce pubnonce_b[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce_ptr_a[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce_ptr_b[2];
    rustsecp256k1zkp_v0_4_0_musig_aggnonce aggnonce_a;
    rustsecp256k1zkp_v0_4_0_musig_aggnonce aggnonce_b;
    rustsecp256k1zkp_v0_4_0_musig_session session_a, session_b;
    int nonce_parity_a;
    int nonce_parity_b;
    unsigned char seed_a[2][32] = { "a0", "a1" };
    unsigned char seed_b[2][32] = { "b0", "b1" };
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";
    int i;

    /* Step 1: key setup */
    for (i = 0; i < 2; i++) {
        pk_a_ptr[i] = &pk_a[i];
        pk_b_ptr[i] = &pk_b[i];
        pubnonce_ptr_a[i] = &pubnonce_a[i];
        pubnonce_ptr_b[i] = &pubnonce_b[i];
        partial_sig_a_ptr[i] = &partial_sig_a[i];
        partial_sig_b_ptr[i] = &partial_sig_b[i];

        rustsecp256k1zkp_v0_4_0_testrand256(sk_a[i]);
        rustsecp256k1zkp_v0_4_0_testrand256(sk_b[i]);
        CHECK(create_keypair_and_pk(&keypair_a[i], &pk_a[i], sk_a[i]));
        CHECK(create_keypair_and_pk(&keypair_b[i], &pk_b[i], sk_b[i]));
    }
    rustsecp256k1zkp_v0_4_0_testrand256(sec_adaptor);
    CHECK(rustsecp256k1zkp_v0_4_0_ec_pubkey_create(ctx, &pub_adaptor, sec_adaptor));

    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, scratch, &agg_pk_a, &keyagg_cache_a, pk_a_ptr, 2));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, scratch, &agg_pk_b, &keyagg_cache_b, pk_b_ptr, 2));

    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce_a[0], &pubnonce_a[0], seed_a[0], sk_a[0], NULL, NULL, NULL));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce_a[1], &pubnonce_a[1], seed_a[1], sk_a[1], NULL, NULL, NULL));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce_b[0], &pubnonce_b[0], seed_b[0], sk_b[0], NULL, NULL, NULL));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce_b[1], &pubnonce_b[1], seed_b[1], sk_b[1], NULL, NULL, NULL));

    /* Step 2: Exchange nonces */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(ctx, &aggnonce_a, pubnonce_ptr_a, 2));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(ctx, &session_a, &aggnonce_a, msg32_a, &keyagg_cache_a, &pub_adaptor));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(ctx, &nonce_parity_a, &session_a));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(ctx, &aggnonce_b, pubnonce_ptr_b, 2));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(ctx, &session_b, &aggnonce_b, msg32_b, &keyagg_cache_b, &pub_adaptor));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(ctx, &nonce_parity_b, &session_b));

    /* Step 3: Signer 0 produces partial signatures for both chains. */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig_a[0], &secnonce_a[0], &keypair_a[0], &keyagg_cache_a, &session_a));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig_b[0], &secnonce_b[0], &keypair_b[0], &keyagg_cache_b, &session_b));

    /* Step 4: Signer 1 receives partial signatures, verifies them and creates a
     * partial signature to send B-coins to signer 0. */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &partial_sig_a[0], &pubnonce_a[0], &pk_a[0], &keyagg_cache_a, &session_a) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &partial_sig_b[0], &pubnonce_b[0], &pk_b[0], &keyagg_cache_b, &session_b) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig_b[1], &secnonce_b[1], &keypair_b[1], &keyagg_cache_b, &session_b));

    /* Step 5: Signer 0 aggregates its own partial signature with the partial
     * signature from signer 1 and adapts it. This results in a complete
     * signature which is broadcasted by signer 0 to take B-coins. */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(ctx, pre_sig_b, &session_b, partial_sig_b_ptr, 2) == 1);
    memcpy(final_sig_b, pre_sig_b, sizeof(final_sig_b));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(ctx, final_sig_b, sec_adaptor, nonce_parity_b));
    CHECK(rustsecp256k1zkp_v0_4_0_schnorrsig_verify(ctx, final_sig_b, msg32_b, sizeof(msg32_b), &agg_pk_b) == 1);

    /* Step 6: Signer 1 signs, extracts adaptor from the published signature,
     * and adapts the signature to take A-coins. */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig_a[1], &secnonce_a[1], &keypair_a[1], &keyagg_cache_a, &session_a));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(ctx, final_sig_a, &session_a, partial_sig_a_ptr, 2) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_extract_adaptor(ctx, sec_adaptor_extracted, final_sig_b, pre_sig_b, nonce_parity_b) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(rustsecp256k1zkp_v0_4_0_musig_adapt(ctx, final_sig_a, sec_adaptor_extracted, nonce_parity_a));
    CHECK(rustsecp256k1zkp_v0_4_0_schnorrsig_verify(ctx, final_sig_a, msg32_a, sizeof(msg32_a), &agg_pk_a) == 1);
}

void sha256_tag_test_internal(rustsecp256k1zkp_v0_4_0_sha256 *sha_tagged, unsigned char *tag, size_t taglen) {
    rustsecp256k1zkp_v0_4_0_sha256 sha;
    unsigned char buf[32];
    unsigned char buf2[32];
    size_t i;

    rustsecp256k1zkp_v0_4_0_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_4_0_sha256_write(&sha, tag, taglen);
    rustsecp256k1zkp_v0_4_0_sha256_finalize(&sha, buf);
    /* buf = SHA256("KeyAgg coefficient") */

    rustsecp256k1zkp_v0_4_0_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_4_0_sha256_write(&sha, buf, 32);
    rustsecp256k1zkp_v0_4_0_sha256_write(&sha, buf, 32);
    /* Is buffer fully consumed? */
    CHECK((sha.bytes & 0x3F) == 0);

    /* Compare with tagged SHA */
    for (i = 0; i < 8; i++) {
        CHECK(sha_tagged->s[i] == sha.s[i]);
    }
    rustsecp256k1zkp_v0_4_0_sha256_write(&sha, buf, 32);
    rustsecp256k1zkp_v0_4_0_sha256_write(sha_tagged, buf, 32);
    rustsecp256k1zkp_v0_4_0_sha256_finalize(&sha, buf);
    rustsecp256k1zkp_v0_4_0_sha256_finalize(sha_tagged, buf2);
    CHECK(memcmp(buf, buf2, 32) == 0);
}

/* Checks that the initialized tagged hashes initialized have the expected
 * state. */
void sha256_tag_test(void) {
    rustsecp256k1zkp_v0_4_0_sha256 sha_tagged;
    {
        char tag[11] = "KeyAgg list";
        rustsecp256k1zkp_v0_4_0_musig_keyagglist_sha256(&sha_tagged);
        sha256_tag_test_internal(&sha_tagged, (unsigned char*)tag, sizeof(tag));
    }
    {
        char tag[18] = "KeyAgg coefficient";
        rustsecp256k1zkp_v0_4_0_musig_keyaggcoef_sha256(&sha_tagged);
        sha256_tag_test_internal(&sha_tagged, (unsigned char*)tag, sizeof(tag));
    }
}

/* Attempts to create a signature for the aggregate public key using given secret
 * keys and keyagg_cache. */
void musig_tweak_test_helper(const rustsecp256k1zkp_v0_4_0_xonly_pubkey* agg_pk, const unsigned char *sk0, const unsigned char *sk1, rustsecp256k1zkp_v0_4_0_musig_keyagg_cache *keyagg_cache) {
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk[2];
    unsigned char session_id[2][32];
    unsigned char msg[32];
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce[2];
    rustsecp256k1zkp_v0_4_0_musig_pubnonce pubnonce[2];
    const rustsecp256k1zkp_v0_4_0_musig_pubnonce *pubnonce_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_aggnonce aggnonce;
    rustsecp256k1zkp_v0_4_0_keypair keypair[2];
    rustsecp256k1zkp_v0_4_0_musig_session session;
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig[2];
    const rustsecp256k1zkp_v0_4_0_musig_partial_sig *partial_sig_ptr[2];
    unsigned char final_sig[64];
    int i;

    for (i = 0; i < 2; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        rustsecp256k1zkp_v0_4_0_testrand256(session_id[i]);
    }
    CHECK(create_keypair_and_pk(&keypair[0], &pk[0], sk0) == 1);
    CHECK(create_keypair_and_pk(&keypair[1], &pk[1], sk1) == 1);
    rustsecp256k1zkp_v0_4_0_testrand256(msg);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce[0], &pubnonce[0], session_id[0], sk0, NULL, NULL, NULL) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_gen(ctx, &secnonce[1], &pubnonce[1], session_id[1], sk1, NULL, NULL, NULL) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptr, 2));
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(ctx, &session, &aggnonce, msg, keyagg_cache, NULL) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig[0], &secnonce[0], &keypair[0], keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig[1], &secnonce[1], &keypair[1], keyagg_cache, &session) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &partial_sig[0], &pubnonce[0], &pk[0], keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_verify(ctx, &partial_sig[1], &pubnonce[1], &pk[1], keyagg_cache, &session) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 2));
    CHECK(rustsecp256k1zkp_v0_4_0_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), agg_pk) == 1);
}

/* In this test we create a aggregate public key P and a commitment Q = P +
 * hash(P, contract)*G. Then we test that we can sign for both public keys. In
 * order to sign for Q we use the tweak32 argument of partial_sig_agg. */
void musig_tweak_test(rustsecp256k1zkp_v0_4_0_scratch_space *scratch) {
    unsigned char sk[2][32];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk[2];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk_ptr[2];
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache_P;
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache_Q;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey P;
    unsigned char P_serialized[32];
    rustsecp256k1zkp_v0_4_0_pubkey Q;
    int Q_parity;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey Q_xonly;
    unsigned char Q_serialized[32];
    rustsecp256k1zkp_v0_4_0_sha256 sha;
    unsigned char contract[32];
    unsigned char ec_commit_tweak[32];
    int i;

    /* Setup */

    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];

        rustsecp256k1zkp_v0_4_0_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(NULL, &pk[i], sk[i]) == 1);
    }
    rustsecp256k1zkp_v0_4_0_testrand256(contract);

    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, scratch, &P, &keyagg_cache_P, pk_ptr, 2) == 1);

    CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_serialize(ctx, P_serialized, &P) == 1);
    rustsecp256k1zkp_v0_4_0_sha256_initialize(&sha);
    rustsecp256k1zkp_v0_4_0_sha256_write(&sha, P_serialized, 32);
    rustsecp256k1zkp_v0_4_0_sha256_write(&sha, contract, 32);
    rustsecp256k1zkp_v0_4_0_sha256_finalize(&sha, ec_commit_tweak);
    keyagg_cache_Q = keyagg_cache_P;
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_tweak_add(ctx, &Q, ec_commit_tweak, &keyagg_cache_Q) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_from_pubkey(ctx, &Q_xonly, &Q_parity, &Q));
    CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_serialize(ctx, Q_serialized, &Q_xonly));
    /* Check that musig_pubkey_tweak_add produces same result as
     * xonly_pubkey_tweak_add. */
    CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_tweak_add_check(ctx, Q_serialized, Q_parity, &P, ec_commit_tweak) == 1);

    /* Test signing for P */
    musig_tweak_test_helper(&P, sk[0], sk[1], &keyagg_cache_P);
    /* Test signing for Q */
    musig_tweak_test_helper(&Q_xonly, sk[0], sk[1], &keyagg_cache_Q);
}

void musig_test_vectors_keyagg_helper(const unsigned char **pk_ser, int n_pks, const unsigned char *agg_pk_expected, int has_second_pk, int second_pk_idx) {
    rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk = malloc(n_pks * sizeof(*pk));
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey **pk_ptr = malloc(n_pks * sizeof(*pk_ptr));
    rustsecp256k1zkp_v0_4_0_keyagg_cache_internal cache_i;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk;
    unsigned char agg_pk_ser[32];
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache;
    int i;

    for (i = 0; i < n_pks; i++) {
        CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_parse(ctx, &pk[i], pk_ser[i]));
        pk_ptr[i] = &pk[i];
    }

    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, NULL, &agg_pk, &keyagg_cache, pk_ptr, n_pks) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_keyagg_cache_load(ctx, &cache_i, &keyagg_cache));
    CHECK(rustsecp256k1zkp_v0_4_0_fe_is_zero(&cache_i.second_pk_x) == !has_second_pk);
    if (!rustsecp256k1zkp_v0_4_0_fe_is_zero(&cache_i.second_pk_x)) {
        rustsecp256k1zkp_v0_4_0_ge pk_pt;
        CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_load(ctx, &pk_pt, &pk[second_pk_idx]));
        CHECK(rustsecp256k1zkp_v0_4_0_fe_equal_var(&pk_pt.x, &cache_i.second_pk_x));
    }
    CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_serialize(ctx, agg_pk_ser, &agg_pk));
    /* TODO: remove when test vectors are not expected to change anymore */
    /* int k, l; */
    /* printf("const unsigned char agg_pk_expected[32] = {\n"); */
    /* for (k = 0; k < 4; k++) { */
    /*     printf("    "); */
    /*     for (l = 0; l < 8; l++) { */
    /*         printf("0x%02X, ", agg_pk_ser[k*8+l]); */
    /*     } */
    /*     printf("\n"); */
    /* } */
    /* printf("};\n"); */
    CHECK(rustsecp256k1zkp_v0_4_0_memcmp_var(agg_pk_ser, agg_pk_expected, sizeof(agg_pk_ser)) == 0);
    free(pk);
    free(pk_ptr);
}

/* Test vector public keys */
const unsigned char vec_pk[3][32] = {
    /* X1 */
    {
        0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
        0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
        0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
        0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9
    },
    /* X2 */
    {
        0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
        0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
        0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
        0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59
    },
    /* X3 */
    {
        0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18,
        0x15, 0xC2, 0xF2, 0x4B, 0x4D, 0x80, 0xA8, 0xE3,
        0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7,
        0xAD, 0x33, 0x83, 0x68, 0xD0, 0x38, 0xCA, 0x66
    }
};

void musig_test_vectors_keyagg(void) {
    size_t i;
    const unsigned char *pk[4];
    const unsigned char agg_pk_expected[4][32] = {
        { /* 0 */
            0xE5, 0x83, 0x01, 0x40, 0x51, 0x21, 0x95, 0xD7,
            0x4C, 0x83, 0x07, 0xE3, 0x96, 0x37, 0xCB, 0xE5,
            0xFB, 0x73, 0x0E, 0xBE, 0xAB, 0x80, 0xEC, 0x51,
            0x4C, 0xF8, 0x8A, 0x87, 0x7C, 0xEE, 0xEE, 0x0B,
        },
        { /* 1 */
            0xD7, 0x0C, 0xD6, 0x9A, 0x26, 0x47, 0xF7, 0x39,
            0x09, 0x73, 0xDF, 0x48, 0xCB, 0xFA, 0x2C, 0xCC,
            0x40, 0x7B, 0x8B, 0x2D, 0x60, 0xB0, 0x8C, 0x5F,
            0x16, 0x41, 0x18, 0x5C, 0x79, 0x98, 0xA2, 0x90,
        },
        { /* 2 */
            0x81, 0xA8, 0xB0, 0x93, 0x91, 0x2C, 0x9E, 0x48,
            0x14, 0x08, 0xD0, 0x97, 0x76, 0xCE, 0xFB, 0x48,
            0xAE, 0xB8, 0xB6, 0x54, 0x81, 0xB6, 0xBA, 0xAF,
            0xB3, 0xC5, 0x81, 0x01, 0x06, 0x71, 0x7B, 0xEB,
        },
        { /* 3 */
            0x2E, 0xB1, 0x88, 0x51, 0x88, 0x7E, 0x7B, 0xDC,
            0x5E, 0x83, 0x0E, 0x89, 0xB1, 0x9D, 0xDB, 0xC2,
            0x80, 0x78, 0xF1, 0xFA, 0x88, 0xAA, 0xD0, 0xAD,
            0x01, 0xCA, 0x06, 0xFE, 0x4F, 0x80, 0x21, 0x0B,
        },
    };

    for (i = 0; i < sizeof(agg_pk_expected)/sizeof(agg_pk_expected[0]); i++) {
        size_t n_pks;
        int has_second_pk;
        int second_pk_idx;
        switch (i) {
            case 0:
                /* [X1, X2, X3] */
                n_pks = 3;
                pk[0] = vec_pk[0];
                pk[1] = vec_pk[1];
                pk[2] = vec_pk[2];
                has_second_pk = 1;
                second_pk_idx = 1;
                break;
            case 1:
                /* [X3, X2, X1] */
                n_pks = 3;
                pk[2] = vec_pk[0];
                pk[1] = vec_pk[1];
                pk[0] = vec_pk[2];
                has_second_pk = 1;
                second_pk_idx = 1;
                break;
            case 2:
                /* [X1, X1, X1] */
                n_pks = 3;
                pk[0] = vec_pk[0];
                pk[1] = vec_pk[0];
                pk[2] = vec_pk[0];
                has_second_pk = 0;
                second_pk_idx = 0; /* unchecked */
                break;
            case 3:
                /* [X1, X1, X2, X2] */
                n_pks = 4;
                pk[0] = vec_pk[0];
                pk[1] = vec_pk[0];
                pk[2] = vec_pk[1];
                pk[3] = vec_pk[1];
                has_second_pk = 1;
                second_pk_idx = 2; /* second_pk_idx = 3 is equally valid */
                break;
            default:
                CHECK(0);
        }
        musig_test_vectors_keyagg_helper(pk, n_pks, agg_pk_expected[i], has_second_pk, second_pk_idx);
    }
}
void musig_test_vectors_sign_helper(rustsecp256k1zkp_v0_4_0_musig_keyagg_cache *keyagg_cache, int *fin_nonce_parity, unsigned char *sig, const unsigned char state[2][32], const unsigned char *agg_pubnonce_ser, const unsigned char *sk, const unsigned char *msg, const unsigned char **pk_ser, int signer_pos) {
    rustsecp256k1zkp_v0_4_0_keypair signer_keypair;
    rustsecp256k1zkp_v0_4_0_musig_secnonce secnonce;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk[3];
    const rustsecp256k1zkp_v0_4_0_xonly_pubkey *pk_ptr[3];
    rustsecp256k1zkp_v0_4_0_xonly_pubkey agg_pk;
    rustsecp256k1zkp_v0_4_0_musig_session session;
    rustsecp256k1zkp_v0_4_0_musig_aggnonce agg_pubnonce;
    rustsecp256k1zkp_v0_4_0_musig_partial_sig partial_sig;
    int i;

    CHECK(create_keypair_and_pk(&signer_keypair, &pk[signer_pos], sk));
    for (i = 0; i < 3; i++) {
        if (i != signer_pos) {
            int offset = i < signer_pos ? 0 : -1;
            CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_parse(ctx, &pk[i], pk_ser[i + offset]));
        }
        pk_ptr[i] = &pk[i];
    }
    CHECK(rustsecp256k1zkp_v0_4_0_musig_pubkey_agg(ctx, NULL, &agg_pk, keyagg_cache, pk_ptr, 3) == 1);
    memcpy(&secnonce.data[0], rustsecp256k1zkp_v0_4_0_musig_secnonce_magic, 4);
    memcpy(&secnonce.data[4], state, sizeof(secnonce.data) - 4);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_aggnonce_parse(ctx, &agg_pubnonce, agg_pubnonce_ser) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_process(ctx, &session, &agg_pubnonce, msg, keyagg_cache, NULL) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_partial_sign(ctx, &partial_sig, &secnonce, &signer_keypair, keyagg_cache, &session) == 1);
    CHECK(rustsecp256k1zkp_v0_4_0_musig_nonce_parity(ctx, fin_nonce_parity, &session));
    memcpy(sig, &partial_sig.data[4], 32);
}

int musig_test_pk_parity(const rustsecp256k1zkp_v0_4_0_musig_keyagg_cache *keyagg_cache) {
    rustsecp256k1zkp_v0_4_0_keyagg_cache_internal cache_i;
    CHECK(rustsecp256k1zkp_v0_4_0_keyagg_cache_load(ctx, &cache_i, keyagg_cache));
    return rustsecp256k1zkp_v0_4_0_fe_is_odd(&cache_i.pk.y);
}

int musig_test_is_second_pk(const rustsecp256k1zkp_v0_4_0_musig_keyagg_cache *keyagg_cache, const unsigned char *sk) {
    rustsecp256k1zkp_v0_4_0_ge pkp;
    rustsecp256k1zkp_v0_4_0_xonly_pubkey pk;
    rustsecp256k1zkp_v0_4_0_keyagg_cache_internal cache_i;
    CHECK(create_keypair_and_pk(NULL, &pk, sk));
    CHECK(rustsecp256k1zkp_v0_4_0_xonly_pubkey_load(ctx, &pkp, &pk));
    CHECK(rustsecp256k1zkp_v0_4_0_keyagg_cache_load(ctx, &cache_i, keyagg_cache));
    return rustsecp256k1zkp_v0_4_0_fe_equal_var(&cache_i.second_pk_x, &pkp.x);
}

/* TODO: Add test vectors for failed signing */
void musig_test_vectors_sign(void) {
    unsigned char sig[32];
    rustsecp256k1zkp_v0_4_0_musig_keyagg_cache keyagg_cache;
    int fin_nonce_parity;
    /* The state corresponds to the two scalars that constitute the secret
     * nonce. */
    const unsigned char state[2][32] = {
        {
            0x50, 0x8B, 0x81, 0xA6, 0x11, 0xF1, 0x00, 0xA6,
            0xB2, 0xB6, 0xB2, 0x96, 0x56, 0x59, 0x08, 0x98,
            0xAF, 0x48, 0x8B, 0xCF, 0x2E, 0x1F, 0x55, 0xCF,
            0x22, 0xE5, 0xCF, 0xB8, 0x44, 0x21, 0xFE, 0x61,
        },
        {
            0xFA, 0x27, 0xFD, 0x49, 0xB1, 0xD5, 0x00, 0x85,
            0xB4, 0x81, 0x28, 0x5E, 0x1C, 0xA2, 0x05, 0xD5,
            0x5C, 0x82, 0xCC, 0x1B, 0x31, 0xFF, 0x5C, 0xD5,
            0x4A, 0x48, 0x98, 0x29, 0x35, 0x59, 0x01, 0xF7,
        }
    };
    /* The nonces are already aggregated */
    const unsigned char agg_pubnonce[66] = {
        0x02,
        0x84, 0x65, 0xFC, 0xF0, 0xBB, 0xDB, 0xCF, 0x44,
        0x3A, 0xAB, 0xCC, 0xE5, 0x33, 0xD4, 0x2B, 0x4B,
        0x5A, 0x10, 0x96, 0x6A, 0xC0, 0x9A, 0x49, 0x65,
        0x5E, 0x8C, 0x42, 0xDA, 0xAB, 0x8F, 0xCD, 0x61,
        0x03,
        0x74, 0x96, 0xA3, 0xCC, 0x86, 0x92, 0x6D, 0x45,
        0x2C, 0xAF, 0xCF, 0xD5, 0x5D, 0x25, 0x97, 0x2C,
        0xA1, 0x67, 0x5D, 0x54, 0x93, 0x10, 0xDE, 0x29,
        0x6B, 0xFF, 0x42, 0xF7, 0x2E, 0xEE, 0xA8, 0xC9,
    };
    const unsigned char sk[32] = {
        0x7F, 0xB9, 0xE0, 0xE6, 0x87, 0xAD, 0xA1, 0xEE,
        0xBF, 0x7E, 0xCF, 0xE2, 0xF2, 0x1E, 0x73, 0xEB,
        0xDB, 0x51, 0xA7, 0xD4, 0x50, 0x94, 0x8D, 0xFE,
        0x8D, 0x76, 0xD7, 0xF2, 0xD1, 0x00, 0x76, 0x71,
    };
    const unsigned char msg[32] = {
        0xF7, 0x54, 0x66, 0xD0, 0x86, 0x77, 0x0E, 0x68,
        0x99, 0x64, 0x66, 0x42, 0x19, 0x26, 0x6F, 0xE5,
        0xED, 0x21, 0x5C, 0x92, 0xAE, 0x20, 0xBA, 0xB5,
        0xC9, 0xD7, 0x9A, 0xDD, 0xDD, 0xF3, 0xC0, 0xCF,
    };
    const unsigned char *pk[2] = { vec_pk[0], vec_pk[1] };

    {
        const unsigned char sig_expected[32] = {
            0x00, 0xB6, 0x9D, 0x89, 0xCD, 0x3A, 0x54, 0xF3,
            0x9F, 0x2D, 0x2D, 0xDC, 0x5B, 0xE1, 0x90, 0x5E,
            0x08, 0xD2, 0x9E, 0x26, 0x6A, 0xD3, 0xA0, 0x59,
            0x92, 0x05, 0xF9, 0xF7, 0x91, 0x45, 0xDC, 0xF9,
        };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, state, agg_pubnonce, sk, msg, pk, 0);
        /* TODO: remove when test vectors are not expected to change anymore */
        /* int k, l; */
        /* printf("const unsigned char sig_expected[32] = {\n"); */
        /* for (k = 0; k < 4; k++) { */
        /*     printf("    "); */
        /*     for (l = 0; l < 8; l++) { */
        /*         printf("0x%02X, ", sig[k*8+l]); */
        /*     } */
        /*     printf("\n"); */
        /* } */
        /* printf("};\n"); */

        /* This is a test where the combined public key point has an _odd_ y
         * coordinate, the signer _is not_ the second pubkey in the list and the
         * nonce parity is 1. */
        CHECK(musig_test_pk_parity(&keyagg_cache) == 1);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 1);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
        const unsigned char sig_expected[32] = {
            0x7C, 0x45, 0xDD, 0xB6, 0x7D, 0x3D, 0x7C, 0x3D,
            0xE8, 0x82, 0x22, 0xFC, 0xF6, 0x62, 0x0D, 0xCE,
            0xBE, 0x92, 0x3D, 0x3B, 0x02, 0xF0, 0xAE, 0xC4,
            0x66, 0xEC, 0xBC, 0xA3, 0x01, 0x3A, 0x7C, 0xCB,
        };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, state, agg_pubnonce, sk, msg, pk, 1);

       /* This is a test where the aggregate public key point has an _even_ y
        * coordinate, the signer _is_ the second pubkey in the list and the
        * nonce parity is 0. */
        CHECK(musig_test_pk_parity(&keyagg_cache) == 0);
        CHECK(musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 0);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
}

void run_musig_tests(void) {
    int i;
    rustsecp256k1zkp_v0_4_0_scratch_space *scratch = rustsecp256k1zkp_v0_4_0_scratch_space_create(ctx, 1024 * 1024);

    for (i = 0; i < count; i++) {
        musig_simple_test(scratch);
    }
    musig_api_tests(scratch);
    musig_nonce_test();
    for (i = 0; i < count; i++) {
        /* Run multiple times to ensure that pk and nonce have different y
         * parities */
        scriptless_atomic_swap(scratch);
        musig_tweak_test(scratch);
    }
    sha256_tag_test();
    musig_test_vectors_keyagg();
    musig_test_vectors_sign();

    rustsecp256k1zkp_v0_4_0_scratch_space_destroy(ctx, scratch);
}

#endif
