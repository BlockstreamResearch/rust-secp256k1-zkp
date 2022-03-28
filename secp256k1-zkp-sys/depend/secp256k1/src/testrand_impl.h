/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille, Gregory Maxwell              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_TESTRAND_IMPL_H
#define SECP256K1_TESTRAND_IMPL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "testrand.h"
#include "hash.h"

static uint64_t rustsecp256k1zkp_v0_6_0_test_state[4];
static uint64_t rustsecp256k1zkp_v0_6_0_test_rng_integer;
static int rustsecp256k1zkp_v0_6_0_test_rng_integer_bits_left = 0;

SECP256K1_INLINE static void rustsecp256k1zkp_v0_6_0_testrand_seed(const unsigned char *seed16) {
    static const unsigned char PREFIX[19] = "secp256k1 test init";
    unsigned char out32[32];
    rustsecp256k1zkp_v0_6_0_sha256 hash;
    int i;

    /* Use SHA256(PREFIX || seed16) as initial state. */
    rustsecp256k1zkp_v0_6_0_sha256_initialize(&hash);
    rustsecp256k1zkp_v0_6_0_sha256_write(&hash, PREFIX, sizeof(PREFIX));
    rustsecp256k1zkp_v0_6_0_sha256_write(&hash, seed16, 16);
    rustsecp256k1zkp_v0_6_0_sha256_finalize(&hash, out32);
    for (i = 0; i < 4; ++i) {
        uint64_t s = 0;
        int j;
        for (j = 0; j < 8; ++j) s = (s << 8) | out32[8*i + j];
        rustsecp256k1zkp_v0_6_0_test_state[i] = s;
    }
    rustsecp256k1zkp_v0_6_0_test_rng_integer_bits_left = 0;
}

SECP256K1_INLINE static uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

SECP256K1_INLINE static uint64_t rustsecp256k1zkp_v0_6_0_testrand64(void) {
    /* Test-only Xoshiro256++ RNG. See https://prng.di.unimi.it/ */
    const uint64_t result = rotl(rustsecp256k1zkp_v0_6_0_test_state[0] + rustsecp256k1zkp_v0_6_0_test_state[3], 23) + rustsecp256k1zkp_v0_6_0_test_state[0];
    const uint64_t t = rustsecp256k1zkp_v0_6_0_test_state[1] << 17;
    rustsecp256k1zkp_v0_6_0_test_state[2] ^= rustsecp256k1zkp_v0_6_0_test_state[0];
    rustsecp256k1zkp_v0_6_0_test_state[3] ^= rustsecp256k1zkp_v0_6_0_test_state[1];
    rustsecp256k1zkp_v0_6_0_test_state[1] ^= rustsecp256k1zkp_v0_6_0_test_state[2];
    rustsecp256k1zkp_v0_6_0_test_state[0] ^= rustsecp256k1zkp_v0_6_0_test_state[3];
    rustsecp256k1zkp_v0_6_0_test_state[2] ^= t;
    rustsecp256k1zkp_v0_6_0_test_state[3] = rotl(rustsecp256k1zkp_v0_6_0_test_state[3], 45);
    return result;
}

SECP256K1_INLINE static uint64_t rustsecp256k1zkp_v0_6_0_testrand_bits(int bits) {
    uint64_t ret;
    if (rustsecp256k1zkp_v0_6_0_test_rng_integer_bits_left < bits) {
        rustsecp256k1zkp_v0_6_0_test_rng_integer = rustsecp256k1zkp_v0_6_0_testrand64();
        rustsecp256k1zkp_v0_6_0_test_rng_integer_bits_left = 64;
    }
    ret = rustsecp256k1zkp_v0_6_0_test_rng_integer;
    rustsecp256k1zkp_v0_6_0_test_rng_integer >>= bits;
    rustsecp256k1zkp_v0_6_0_test_rng_integer_bits_left -= bits;
    ret &= ((~((uint64_t)0)) >> (64 - bits));
    return ret;
}

SECP256K1_INLINE static uint32_t rustsecp256k1zkp_v0_6_0_testrand32(void) {
    return rustsecp256k1zkp_v0_6_0_testrand_bits(32);
}

static uint32_t rustsecp256k1zkp_v0_6_0_testrand_int(uint32_t range) {
    /* We want a uniform integer between 0 and range-1, inclusive.
     * B is the smallest number such that range <= 2**B.
     * two mechanisms implemented here:
     * - generate B bits numbers until one below range is found, and return it
     * - find the largest multiple M of range that is <= 2**(B+A), generate B+A
     *   bits numbers until one below M is found, and return it modulo range
     * The second mechanism consumes A more bits of entropy in every iteration,
     * but may need fewer iterations due to M being closer to 2**(B+A) then
     * range is to 2**B. The array below (indexed by B) contains a 0 when the
     * first mechanism is to be used, and the number A otherwise.
     */
    static const int addbits[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 0};
    uint32_t trange, mult;
    int bits = 0;
    if (range <= 1) {
        return 0;
    }
    trange = range - 1;
    while (trange > 0) {
        trange >>= 1;
        bits++;
    }
    if (addbits[bits]) {
        bits = bits + addbits[bits];
        mult = ((~((uint32_t)0)) >> (32 - bits)) / range;
        trange = range * mult;
    } else {
        trange = range;
        mult = 1;
    }
    while(1) {
        uint32_t x = rustsecp256k1zkp_v0_6_0_testrand_bits(bits);
        if (x < trange) {
            return (mult == 1) ? x : (x % range);
        }
    }
}

static void rustsecp256k1zkp_v0_6_0_testrand256(unsigned char *b32) {
    int i;
    for (i = 0; i < 4; ++i) {
        uint64_t val = rustsecp256k1zkp_v0_6_0_testrand64();
        b32[0] = val;
        b32[1] = val >> 8;
        b32[2] = val >> 16;
        b32[3] = val >> 24;
        b32[4] = val >> 32;
        b32[5] = val >> 40;
        b32[6] = val >> 48;
        b32[7] = val >> 56;
        b32 += 8;
    }
}

static void rustsecp256k1zkp_v0_6_0_testrand_bytes_test(unsigned char *bytes, size_t len) {
    size_t bits = 0;
    memset(bytes, 0, len);
    while (bits < len * 8) {
        int now;
        uint32_t val;
        now = 1 + (rustsecp256k1zkp_v0_6_0_testrand_bits(6) * rustsecp256k1zkp_v0_6_0_testrand_bits(5) + 16) / 31;
        val = rustsecp256k1zkp_v0_6_0_testrand_bits(1);
        while (now > 0 && bits < len * 8) {
            bytes[bits / 8] |= val << (bits % 8);
            now--;
            bits++;
        }
    }
}

static void rustsecp256k1zkp_v0_6_0_testrand256_test(unsigned char *b32) {
    rustsecp256k1zkp_v0_6_0_testrand_bytes_test(b32, 32);
}

SECP256K1_INLINE static int64_t rustsecp256k1zkp_v0_6_0_testrandi64(uint64_t min, uint64_t max) {
    uint64_t range;
    uint64_t r;
    uint64_t clz;
    VERIFY_CHECK(max >= min);
    if (max == min) {
        return min;
    }
    range = max - min;
    clz = rustsecp256k1zkp_v0_6_0_clz64_var(range);
    do {
        r = ((uint64_t)rustsecp256k1zkp_v0_6_0_testrand32() << 32) | rustsecp256k1zkp_v0_6_0_testrand32();
        r >>= clz;
    } while (r > range);
    return min + (int64_t)r;
}

static void rustsecp256k1zkp_v0_6_0_testrand_flip(unsigned char *b, size_t len) {
    b[rustsecp256k1zkp_v0_6_0_testrand_int(len)] ^= (1 << rustsecp256k1zkp_v0_6_0_testrand_bits(3));
}

static void rustsecp256k1zkp_v0_6_0_testrand_init(const char* hexseed) {
    unsigned char seed16[16] = {0};
    if (hexseed && strlen(hexseed) != 0) {
        int pos = 0;
        while (pos < 16 && hexseed[0] != 0 && hexseed[1] != 0) {
            unsigned short sh;
            if ((sscanf(hexseed, "%2hx", &sh)) == 1) {
                seed16[pos] = sh;
            } else {
                break;
            }
            hexseed += 2;
            pos++;
        }
    } else {
        FILE *frand = fopen("/dev/urandom", "rb");
        if ((frand == NULL) || fread(&seed16, 1, sizeof(seed16), frand) != sizeof(seed16)) {
            uint64_t t = time(NULL) * (uint64_t)1337;
            fprintf(stderr, "WARNING: could not read 16 bytes from /dev/urandom; falling back to insecure PRNG\n");
            seed16[0] ^= t;
            seed16[1] ^= t >> 8;
            seed16[2] ^= t >> 16;
            seed16[3] ^= t >> 24;
            seed16[4] ^= t >> 32;
            seed16[5] ^= t >> 40;
            seed16[6] ^= t >> 48;
            seed16[7] ^= t >> 56;
        }
        if (frand) {
            fclose(frand);
        }
    }

    printf("random seed = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", seed16[0], seed16[1], seed16[2], seed16[3], seed16[4], seed16[5], seed16[6], seed16[7], seed16[8], seed16[9], seed16[10], seed16[11], seed16[12], seed16[13], seed16[14], seed16[15]);
    rustsecp256k1zkp_v0_6_0_testrand_seed(seed16);
}

static void rustsecp256k1zkp_v0_6_0_testrand_finish(void) {
    unsigned char run32[32];
    rustsecp256k1zkp_v0_6_0_testrand256(run32);
    printf("random run = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", run32[0], run32[1], run32[2], run32[3], run32[4], run32[5], run32[6], run32[7], run32[8], run32[9], run32[10], run32[11], run32[12], run32[13], run32[14], run32[15]);
}

#endif /* SECP256K1_TESTRAND_IMPL_H */
