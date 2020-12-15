# secp256k1-zkp-sys

This crate provides Rust definitions for the FFI structures and methods.

## Vendoring

The default build process is to build using the vendored libsecp256k1-zkp sources in
the depend folder. These sources are prefixed with a special
rust-secp256k1-zkp-sys-specific prefix `rustsecp256k1zkp_v1_2_3_`.

This prefix ensures that no symbol collision can happen:

- when a Rust project has two different versions of rust-secp256k1-zkp in its
  depepdency tree, or
- when rust-secp256k1-zkp is used for building a static library in a context where
  existing libsecp256k1-zkp symbols are already linked.

To update the vendored sources, use the `vendor-libsecp.sh` script:

```
$ ./vendor-libsecp.sh depend <version-code> <rev>
```

- Where `<version-code>` is the secp256k1-zkp-sys version number underscored: `0_1_2`.
- Where `<rev>` is the git revision of libsecp256k1-zkp to checkout.

## Linking to external symbols

For the more exotic use cases, this crate can be used with existing libsecp256k1-zkp
symbols by using the `external-symbols` feature. How to setup rustc to link
against those existing symbols is left as an exercise to the reader.
