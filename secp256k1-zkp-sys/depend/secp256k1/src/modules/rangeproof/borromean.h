/**********************************************************************
 * Copyright (c) 2014, 2015 Gregory Maxwell                          *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef SECP256K1_BORROMEAN_H
#define SECP256K1_BORROMEAN_H

#include "../../scalar.h"
#include "../../field.h"
#include "../../group.h"
#include "../../ecmult.h"
#include "../../ecmult_gen.h"

static int rustsecp256k1zkp_v0_10_0_borromean_verify(rustsecp256k1zkp_v0_10_0_scalar *evalues, const unsigned char *e0, const rustsecp256k1zkp_v0_10_0_scalar *s,
 const rustsecp256k1zkp_v0_10_0_gej *pubs, const size_t *rsizes, size_t nrings, const unsigned char *m, size_t mlen);

static int rustsecp256k1zkp_v0_10_0_borromean_sign(const rustsecp256k1zkp_v0_10_0_ecmult_gen_context *ecmult_gen_ctx,
 unsigned char *e0, rustsecp256k1zkp_v0_10_0_scalar *s, const rustsecp256k1zkp_v0_10_0_gej *pubs, const rustsecp256k1zkp_v0_10_0_scalar *k, const rustsecp256k1zkp_v0_10_0_scalar *sec,
 const size_t *rsizes, const size_t *secidx, size_t nrings, const unsigned char *m, size_t mlen);

#endif
