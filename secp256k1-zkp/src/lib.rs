// secp256k1-zkp bindings
// Written in 2019 by
//   Jonas Nick
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Secp256k1-zkp
//! Rust bindings for the secp256k1-zkp library.

#![crate_type = "rlib"]
#![crate_type = "dylib"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]
#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[cfg(any(test, feature = "rand"))]
pub extern crate rand;
#[cfg(test)]
extern crate secp256k1_zkp_dev;

pub extern crate secp256k1;
pub extern crate secp256k1_zkp_sys;

extern crate core;

pub mod schnorrsig;
