# rust-secp256k1-zkp

**Experimental. Do not use in production. Seriously.**

rust-secp256k1-zkp is a wrapper around [libsecp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp/), a fork of [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
For bindings to `libsecp256k1` see [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/).

This repository is devided into the `secp256k1-zkp-sys` crate and `secp256k1-zkp` crate.
The former is `no_std` and therefore provides only low-level bindings while the latter provides more high-level abstractions.

Modules currently supported:

* `schnorrsig` which allows creating and (batch-) verifying bip-schnorr compatible signatures

### Documentation

- [secp256k1-zkp](https://docs.rs/secp256k1-zkp/)
- [secp256k1-zkp-sys](https://docs.rs/secp256k1-zkp-sys/)

### Contributing

Contributions to this library are welcome. A few guidelines:

* No new dependencies, please.
* This library should always compile with any combination of features on **Rust 1.22**.
* Please use `rustfmt`.
