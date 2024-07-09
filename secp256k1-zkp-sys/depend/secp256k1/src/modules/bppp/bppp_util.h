/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BPPP_UTIL_H
#define SECP256K1_MODULE_BPPP_UTIL_H

#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../eckey.h"

/* Outputs a pair of points, amortizing the parity byte between them
 * Assumes both points' coordinates have been normalized.
 */
static void rustsecp256k1zkp_v0_10_0_bppp_serialize_points(unsigned char *output, rustsecp256k1zkp_v0_10_0_ge *lpt, rustsecp256k1zkp_v0_10_0_ge *rpt) {
    unsigned char tmp[33];
    rustsecp256k1zkp_v0_10_0_ge_serialize_ext(tmp, lpt);
    output[0] = (tmp[0] & 1) << 1;
    memcpy(&output[1], &tmp[1], 32);
    rustsecp256k1zkp_v0_10_0_ge_serialize_ext(tmp, rpt);
    output[0] |= (tmp[0] & 1);
    memcpy(&output[33], &tmp[1], 32);
}

static int rustsecp256k1zkp_v0_10_0_bppp_parse_one_of_points(rustsecp256k1zkp_v0_10_0_ge *pt, const unsigned char *in65, int idx) {
    unsigned char tmp[33] = { 0 };
    if (in65[0] > 3) {
        return 0;
    }
    /* Check if the input array encodes the point at infinity */
    if ((rustsecp256k1zkp_v0_10_0_memcmp_var(tmp, &in65[1 + 32*idx], 32)) != 0) {
        tmp[0] = 2 | ((in65[0] & (2 - idx)) >> (1 - idx));
        memcpy(&tmp[1], &in65[1 + 32*idx], 32);
    } else {
        /* If we're parsing the point at infinity, enforce that the sign bit is
         * 0. */
        if ((in65[0] & (2 - idx)) != 0) {
            return 0;
        }
    }
    return rustsecp256k1zkp_v0_10_0_ge_parse_ext(pt, tmp);
}

/* Outputs a serialized point in compressed form. Returns 0 at point at infinity.
*/
static int rustsecp256k1zkp_v0_10_0_bppp_serialize_pt(unsigned char *output, rustsecp256k1zkp_v0_10_0_ge *lpt) {
    size_t size;
    return rustsecp256k1zkp_v0_10_0_eckey_pubkey_serialize(lpt, output, &size, 1 /*compressed*/);
}

/* little-endian encodes a uint64 */
static void rustsecp256k1zkp_v0_10_0_bppp_le64(unsigned char *output, const uint64_t n) {
    output[0] = n;
    output[1] = n >> 8;
    output[2] = n >> 16;
    output[3] = n >> 24;
    output[4] = n >> 32;
    output[5] = n >> 40;
    output[6] = n >> 48;
    output[7] = n >> 56;
}

/* Check if n is power of two*/
static int rustsecp256k1zkp_v0_10_0_is_power_of_two(size_t n) {
    return n > 0 && (n & (n - 1)) == 0;
}

/* Compute the log2 of n. n must NOT be 0. If n is not a power of two, it
 * returns the largest `k` such that 2^k <= n. Assumes 0 < n < 2^64. In
 * Bulletproofs, this is bounded by len of input vectors which can be safely
 * assumed to be less than 2^64.
*/
static size_t rustsecp256k1zkp_v0_10_0_bppp_log2(size_t n) {
    return 64 - 1 - rustsecp256k1zkp_v0_10_0_clz64_var((uint64_t)n);
}

#endif
