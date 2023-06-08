![Continuous integration](https://github.com/ElementsProject/rust-secp256k1-zkp/workflows/Continuous%20integration/badge.svg)

# rust-secp256k1-zkp

`rust-secp256k1-zkp` is a wrapper around [libsecp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp) that also
re-exports all bindings from [`rust-secp256k1`](https://github.com/rust-bitcoin/rust-secp256k1).
As such, all of its types - `SecretKey`, `Context`, etc - are interoperable with the ones defined in `rust-secp256k1`.

In addition to everything from `rust-secp256k1`, this library adds type-safe Rust bindings for the following modules:

- generators
- range proofs
- pedersen commitments
- adaptor signatures

# Contributing

Contributions to this library are welcome. A few guidelines:

- Any breaking changes must have an accompanied entry in CHANGELOG.md
- No new dependencies, please.
- No crypto should be implemented in Rust, with the possible exception of hash functions. Cryptographic contributions should be directed upstream to libsecp256k1.
- This library should always compile with any combination of features on **Rust 1.41.1**.

