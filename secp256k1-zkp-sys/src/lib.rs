// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
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
//! # secp256k1-zkp-sys FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#[cfg(any(test, feature = "std"))]
extern crate core;
#[macro_use]
extern crate secp256k1_sys;
pub use secp256k1_sys::*;

mod error_callbacks;
mod zkp;

pub use zkp::*;
