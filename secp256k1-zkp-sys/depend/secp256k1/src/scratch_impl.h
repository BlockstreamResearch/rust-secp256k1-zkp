/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SCRATCH_IMPL_H_
#define _SECP256K1_SCRATCH_IMPL_H_

#include "util.h"
#include "scratch.h"

static rustsecp256k1zkp_v0_1_0_scratch* rustsecp256k1zkp_v0_1_0_scratch_create(const rustsecp256k1zkp_v0_1_0_callback* error_callback, size_t size) {
    const size_t base_alloc = ROUND_TO_ALIGN(sizeof(rustsecp256k1zkp_v0_1_0_scratch));
    void *alloc = checked_malloc(error_callback, base_alloc + size);
    rustsecp256k1zkp_v0_1_0_scratch* ret = (rustsecp256k1zkp_v0_1_0_scratch *)alloc;
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        memcpy(ret->magic, "scratch", 8);
        ret->data = (void *) ((char *) alloc + base_alloc);
        ret->max_size = size;
    }
    return ret;
}

static void rustsecp256k1zkp_v0_1_0_scratch_destroy(const rustsecp256k1zkp_v0_1_0_callback* error_callback, rustsecp256k1zkp_v0_1_0_scratch* scratch) {
    if (scratch != NULL) {
        VERIFY_CHECK(scratch->alloc_size == 0); /* all checkpoints should be applied */
        if (rustsecp256k1zkp_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
            rustsecp256k1zkp_v0_1_0_callback_call(error_callback, "invalid scratch space");
            return;
        }
        memset(scratch->magic, 0, sizeof(scratch->magic));
        free(scratch);
    }
}

static size_t rustsecp256k1zkp_v0_1_0_scratch_checkpoint(const rustsecp256k1zkp_v0_1_0_callback* error_callback, const rustsecp256k1zkp_v0_1_0_scratch* scratch) {
    if (rustsecp256k1zkp_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1zkp_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    return scratch->alloc_size;
}

static void rustsecp256k1zkp_v0_1_0_scratch_apply_checkpoint(const rustsecp256k1zkp_v0_1_0_callback* error_callback, rustsecp256k1zkp_v0_1_0_scratch* scratch, size_t checkpoint) {
    if (rustsecp256k1zkp_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1zkp_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return;
    }
    if (checkpoint > scratch->alloc_size) {
        rustsecp256k1zkp_v0_1_0_callback_call(error_callback, "invalid checkpoint");
        return;
    }
    scratch->alloc_size = checkpoint;
}

static size_t rustsecp256k1zkp_v0_1_0_scratch_max_allocation(const rustsecp256k1zkp_v0_1_0_callback* error_callback, const rustsecp256k1zkp_v0_1_0_scratch* scratch, size_t objects) {
    if (rustsecp256k1zkp_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1zkp_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    /* Ensure that multiplication will not wrap around */
    if (ALIGNMENT > 1 && objects > SIZE_MAX/(ALIGNMENT - 1)) {
        return 0;
    }
    if (scratch->max_size - scratch->alloc_size <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - scratch->alloc_size - objects * (ALIGNMENT - 1);
}

static void *rustsecp256k1zkp_v0_1_0_scratch_alloc(const rustsecp256k1zkp_v0_1_0_callback* error_callback, rustsecp256k1zkp_v0_1_0_scratch* scratch, size_t size) {
    void *ret;
    size_t rounded_size;

    rounded_size = ROUND_TO_ALIGN(size);
    /* Check that rounding did not wrap around */
    if (rounded_size < size) {
        return NULL;
    }
    size = rounded_size;

    if (rustsecp256k1zkp_v0_1_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1zkp_v0_1_0_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (size > scratch->max_size - scratch->alloc_size) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->data + scratch->alloc_size);
    memset(ret, 0, size);
    scratch->alloc_size += size;

    return ret;
}

#endif
