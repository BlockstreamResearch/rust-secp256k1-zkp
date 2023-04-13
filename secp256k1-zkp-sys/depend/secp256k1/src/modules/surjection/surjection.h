/**********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SURJECTION_H_
#define _SECP256K1_SURJECTION_H_

#include "../../group.h"
#include "../../scalar.h"

SECP256K1_INLINE static int rustsecp256k1zkp_v0_8_0_surjection_genmessage(unsigned char *msg32, rustsecp256k1zkp_v0_8_0_ge *ephemeral_input_tags, size_t n_input_tags, rustsecp256k1zkp_v0_8_0_ge *ephemeral_output_tag);

SECP256K1_INLINE static int rustsecp256k1zkp_v0_8_0_surjection_genrand(rustsecp256k1zkp_v0_8_0_scalar *s, size_t ns, const rustsecp256k1zkp_v0_8_0_scalar *blinding_key);

SECP256K1_INLINE static int rustsecp256k1zkp_v0_8_0_surjection_compute_public_keys(rustsecp256k1zkp_v0_8_0_gej *pubkeys, size_t n_pubkeys, const rustsecp256k1zkp_v0_8_0_ge *input_tags, size_t n_input_tags, const unsigned char *used_tags, const rustsecp256k1zkp_v0_8_0_ge *output_tag, size_t input_index, size_t *ring_input_index);

#endif
