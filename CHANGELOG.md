# Unreleased

- Rename `secp256k1_zkp::bitcoin_hashes` module to `secp256k1_zkp::hashes`.

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
