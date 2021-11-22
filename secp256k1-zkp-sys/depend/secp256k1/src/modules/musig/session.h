/**********************************************************************
 * Copyright (c) 2021 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_SESSION_
#define _SECP256K1_MODULE_MUSIG_SESSION_

typedef struct {
    int fin_nonce_parity;
    const unsigned char *fin_nonce;
    rustsecp256k1zkp_v0_4_0_scalar noncecoef;
    rustsecp256k1zkp_v0_4_0_scalar challenge;
    rustsecp256k1zkp_v0_4_0_scalar s_part;
} rustsecp256k1zkp_v0_4_0_musig_session_internal;

static int rustsecp256k1zkp_v0_4_0_musig_session_load(const rustsecp256k1zkp_v0_4_0_context* ctx, rustsecp256k1zkp_v0_4_0_musig_session_internal *session_i, const rustsecp256k1zkp_v0_4_0_musig_session *session);

#endif
