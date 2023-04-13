/**********************************************************************
 * Copyright (c) 2020 The libsecp256k1-zkp Developers                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECCOMMIT_H
#define SECP256K1_ECCOMMIT_H

/** Helper function to add a 32-byte value to a scalar */
static int rustsecp256k1zkp_v0_8_0_ec_seckey_tweak_add_helper(rustsecp256k1zkp_v0_8_0_scalar *sec, const unsigned char *tweak);
/** Helper function to add a 32-byte value, times G, to an EC point */
static int rustsecp256k1zkp_v0_8_0_ec_pubkey_tweak_add_helper(const rustsecp256k1zkp_v0_8_0_ecmult_context* ecmult_ctx, rustsecp256k1zkp_v0_8_0_ge *p, const unsigned char *tweak);

/** Serializes elem as a 33 byte array. This is non-constant time with respect to
 *  whether pubp is the point at infinity. Thus, you may need to declassify
 *  pubp->infinity before calling this function. */
static int rustsecp256k1zkp_v0_8_0_ec_commit_pubkey_serialize_const(rustsecp256k1zkp_v0_8_0_ge *pubp, unsigned char *buf33);
/** Compute an ec commitment tweak as hash(pubkey, data). */
static int rustsecp256k1zkp_v0_8_0_ec_commit_tweak(unsigned char *tweak32, rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size);
/** Compute an ec commitment as pubkey + hash(pubkey, data)*G. */
static int rustsecp256k1zkp_v0_8_0_ec_commit(const rustsecp256k1zkp_v0_8_0_ecmult_context* ecmult_ctx, rustsecp256k1zkp_v0_8_0_ge* commitp, const rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size);
/** Compute a secret key commitment as seckey + hash(pubkey, data). */
static int rustsecp256k1zkp_v0_8_0_ec_commit_seckey(const rustsecp256k1zkp_v0_8_0_ecmult_gen_context* ecmult_gen_ctx, rustsecp256k1zkp_v0_8_0_scalar* seckey, rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size);
/** Verify an ec commitment as pubkey + hash(pubkey, data)*G ?= commitment. */
static int rustsecp256k1zkp_v0_8_0_ec_commit_verify(const rustsecp256k1zkp_v0_8_0_ecmult_context* ecmult_ctx, const rustsecp256k1zkp_v0_8_0_ge* commitp, const rustsecp256k1zkp_v0_8_0_ge* pubp, rustsecp256k1zkp_v0_8_0_sha256* sha, const unsigned char *data, size_t data_size);

#endif /* SECP256K1_ECCOMMIT_H */
