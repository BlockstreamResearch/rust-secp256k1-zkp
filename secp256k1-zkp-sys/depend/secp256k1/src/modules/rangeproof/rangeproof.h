/**********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_RANGEPROOF_H_
#define _SECP256K1_RANGEPROOF_H_

#include "../../scalar.h"
#include "../../group.h"
#include "../../ecmult.h"
#include "../../ecmult_gen.h"

static int rustsecp256k1zkp_v0_8_0_rangeproof_verify_impl(const rustsecp256k1zkp_v0_8_0_ecmult_gen_context* ecmult_gen_ctx,
 unsigned char *blindout, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
 uint64_t *min_value, uint64_t *max_value, const rustsecp256k1zkp_v0_8_0_ge *commit, const unsigned char *proof, size_t plen,
 const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1zkp_v0_8_0_ge* genp);

#endif
