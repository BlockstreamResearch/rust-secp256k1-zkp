#ifndef _SECP256K1_BPPP_
# define _SECP256K1_BPPP_

#include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/** Opaque structure representing a large number of NUMS generators */
typedef struct rustsecp256k1zkp_v0_8_0_bppp_generators rustsecp256k1zkp_v0_8_0_bppp_generators;

/** Allocates and initializes a list of NUMS generators.
 *  Returns a list of generators, or calls the error callback if the allocation fails.
 *  Args:          ctx: pointer to a context object
 *                   n: number of NUMS generators to produce.
 *
 * TODO: In a followup range-proof PR, this is would still require 16 + 8 = 24 NUMS
 * points. We will later use G = H0(required for compatibility with pedersen_commitment DS)
 * in a separate commit to make review easier.
 */
SECP256K1_API rustsecp256k1zkp_v0_8_0_bppp_generators *rustsecp256k1zkp_v0_8_0_bppp_generators_create(
    const rustsecp256k1zkp_v0_8_0_context* ctx,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Allocates a list of generators from a static array
 *  Returns a list of generators or NULL in case of failure.
 *  Args:      ctx: pointer to a context object
 *  In:       data: data that came from `rustsecp256k1zkp_v0_8_0_bppp_generators_serialize`
 *        data_len: the length of the `data` buffer
 */
SECP256K1_API rustsecp256k1zkp_v0_8_0_bppp_generators* rustsecp256k1zkp_v0_8_0_bppp_generators_parse(
    const rustsecp256k1zkp_v0_8_0_context* ctx,
    const unsigned char* data,
    size_t data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serializes a list of generators to an array
 *  Returns 1 on success, 0 if the provided array was not large enough
 *  Args:        ctx: pointer to a context object
 *               gen: pointer to the generator set to be serialized
 *  Out:        data: pointer to buffer into which the generators will be serialized
 *  In/Out: data_len: the length of the `data` buffer. Should be at least
 *                    k = 33 * num_gens. Will be set to k on successful return
 *
 * TODO: For ease of review, this setting G = H0 is not included in this commit. We will
 * add it in the follow-up rangeproof PR.
 */
SECP256K1_API int rustsecp256k1zkp_v0_8_0_bppp_generators_serialize(
    const rustsecp256k1zkp_v0_8_0_context* ctx,
    const rustsecp256k1zkp_v0_8_0_bppp_generators* gen,
    unsigned char* data,
    size_t *data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Destroys a list of NUMS generators, freeing allocated memory
 *  Args:   ctx: pointer to a context object
 *          gen: pointer to the generator set to be destroyed
 *               (can be NULL, in which case this function is a no-op)
 */
SECP256K1_API void rustsecp256k1zkp_v0_8_0_bppp_generators_destroy(
    const rustsecp256k1zkp_v0_8_0_context* ctx,
    rustsecp256k1zkp_v0_8_0_bppp_generators* gen
) SECP256K1_ARG_NONNULL(1);

# ifdef __cplusplus
}
# endif

#endif
