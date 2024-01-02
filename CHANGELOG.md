# 0.10.0 - 2024-01-02

- update `secp256k1` to 0.28.0
- update `secp256k1-sys` to 0.9.0
- update `hashes` to 0.13.0
- rename `bitcoin_hashes` feature to `hashes`
- bump MSRV to 1.56.1

# 0.9.2 - 2023-07-18

- Impl `Ord` for `RangeProof`, `SurjectionProof` and `PedersenCommitment`

# 0.9.1 - 2023-06-09

- Add `Hash` derive to `Tweak`

# 0.9.0 - 2023-06-08

- Rename `use-serde` to `serde` and `use-rand` to `rand`
- Remove unused `unstable` feature
- Add `PartialOrd`, `Ord` and `Hash` back to `Tweak`

# 0.8.0 - 2023-04-13

- Increment MSRV to 1.48.0
- Increment `secp256k1` dependency to 0.27.0
- Update upstream to 1d256089004a19bdbead7c5676e52c8e07b09fce

# 0.7.0 - 2022-09-27

- Increment MSRV to 1.41.1 and edition to 2018
- ffi: fix signature of whitelist_sign
- Update secp256k1 to 0.24.0 and update deprecated functions
- Fix RangeProof and SurjectionProof from_str

# 0.6.0 - 2022-03-28

- Update secp256k1 to 0.22.1
- Updates upstream to 725d895fc54cf82da1c2a9c69048656405da556d
- Comment out WASM build

# 0.5.0 - 2021-10-22

- Encrypt ECDSA adaptor signatures in release builds. Previously encryption returned just zero bytes.
- Add support for "whitelist" ring signatures of libsecp256k1-zkp.
- Rename `secp256k1_zkp::bitcoin_hashes` module to `secp256k1_zkp::hashes`.
- Rename feature `hashes` to `bitcoin_hashes` to align with `rust-secp256k1`.
- Implement `serde::{Serialize, Deserialize}` for `EcdsaAdaptorSignature`.

# 0.4.0 - 2021-05-04

- Changed several zkp APIs to use `Tweak` type instead of `SecretKey` type to allow modelling of zero tweaks.
- Introduce `Generator::new_unblinded` and `PedersenCommitment::new_unblinded` APIs

# 0.3.0 - 2021-04-19

- Add ECDSA adaptor signatures

# 0.2.1 - 2021-04-13

- Fix bug in Pedersen Commitment deserialization.

# 0.2.0 - 2021-01-06

- Completely replaced with https://github.com/comit-network/rust-secp256k1-zkp/ which has
  bindings for generators, pedersen commitments and range proofs

# 0.1.0 - 2019-06-03

- Initial release with bindings to Schnorr signatures
