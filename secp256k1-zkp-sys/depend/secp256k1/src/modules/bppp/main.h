#ifndef SECP256K1_MODULE_BPPP_MAIN_H
#define SECP256K1_MODULE_BPPP_MAIN_H

/* this type must be completed before any of the modules/bppp includes */
struct rustsecp256k1zkp_v0_8_0_bppp_generators {
    size_t n;
    /* n total generators; includes both G_i and H_i */
    /* For BP++, the generators are G_i from [0..(n - 8)] and the last 8 values
    are generators are for H_i */
    rustsecp256k1zkp_v0_8_0_ge* gens;
};

#endif
