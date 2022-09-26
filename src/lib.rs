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

//! # Secp256k1-zkp
//!
//! Rust bindings for libsecp256k1-zkp, a fork of Pieter Wuille's secp256k1 library.
//!
//! This library re-exports everything from `secp256k1` and adds bindings for the following modules:
//!
//! - generators
//! - range proofs
//! - pedersen commitments
//!
//! As such, it can be used as a drop-in replacement for `secp256k1`. All types are interoperable
//! (as long as you are dependening on the correct version) which means [`SecretKey`]s and the [`Context`]
//! are interoperable.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

#[macro_use]
pub extern crate secp256k1_zkp_sys;
pub use secp256k1_zkp_sys as ffi;

extern crate secp256k1;

#[cfg(feature = "bitcoin_hashes")]
pub use secp256k1::hashes;
#[cfg(any(test, feature = "std"))]
extern crate core;
#[cfg(any(test, feature = "rand"))]
pub extern crate rand;
#[cfg(any(test))]
extern crate rand_core;
#[cfg(feature = "serde")]
pub extern crate serde;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;
#[cfg(all(test, feature = "unstable"))]
extern crate test;
#[cfg(all(test, target_arch = "wasm32"))]
#[macro_use]
extern crate wasm_bindgen_test;

use core::{fmt, str};

pub use secp256k1::constants;
pub use secp256k1::ecdh;
pub use secp256k1::ecdsa;
pub use secp256k1::schnorr;

pub use crate::{PublicKey, SecretKey};

pub use secp256k1::*;

#[cfg(feature = "serde")]
mod serde_util;
mod zkp;
pub use crate::zkp::*;

pub use secp256k1::Error as UpstreamError;

/// An ECDSA error
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Calling through to `secp256k1` resulted in an error.
    Upstream(UpstreamError),
    /// Failed to produce a surjection proof because of an internal error within `libsecp256k1-zkp`
    CannotProveSurjection,
    /// Given bytes don't represent a valid surjection proof
    InvalidSurjectionProof,
    /// Given bytes don't represent a valid pedersen commitment
    InvalidPedersenCommitment,
    /// Failed to produce a range proof because of an internal error within `libsecp256k1-zkp`
    CannotMakeRangeProof,
    /// Given range proof does not prove that the commitment is within a range
    InvalidRangeProof,
    /// Bad generator
    InvalidGenerator,
    /// Tweak must of len 32
    InvalidTweakLength,
    /// Tweak must be less than secp curve order
    TweakOutOfBounds,
    /// Given bytes don't represent a valid adaptor signature
    InvalidEcdsaAdaptorSignature,
    /// Failed to decrypt an adaptor signature because of an internal error within `libsecp256k1-zkp`
    CannotDecryptAdaptorSignature,
    /// Failed to recover an adaptor secret from an adaptor signature because of an internal error within `libsecp256k1-zkp`
    CannotRecoverAdaptorSecret,
    /// Given adaptor signature is not valid for the provided combination of public key, encryption key and message
    CannotVerifyAdaptorSignature,
    /// Given bytes don't represent a valid whitelist signature
    InvalidWhitelistSignature,
    /// Invalid PAK list
    InvalidPakList,
    /// Couldn't create whitelist signature with the given data.
    CannotCreateWhitelistSignature,
    /// The given whitelist signature doesn't correctly prove inclusion in the whitelist.
    InvalidWhitelistProof,
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let str = match *self {
            Error::CannotProveSurjection => "failed to prove surjection",
            Error::InvalidSurjectionProof => "malformed surjection proof",
            Error::InvalidPedersenCommitment => "malformed pedersen commitment",
            Error::CannotMakeRangeProof => "failed to generate range proof",
            Error::InvalidRangeProof => "failed to verify range proof",
            Error::InvalidGenerator => "malformed generator",
            Error::InvalidEcdsaAdaptorSignature => "malformed ecdsa adaptor signature",
            Error::CannotDecryptAdaptorSignature => "failed to decrypt adaptor signature",
            Error::CannotRecoverAdaptorSecret => "failed to recover adaptor secret",
            Error::CannotVerifyAdaptorSignature => "failed to verify adaptor signature",
            Error::Upstream(inner) => return write!(f, "{}", inner),
            Error::InvalidTweakLength => "Tweak must of size 32",
            Error::TweakOutOfBounds => "Tweak must be less than secp curve order",
            Error::InvalidWhitelistSignature => "malformed whitelist signature",
            Error::InvalidPakList => "invalid PAK list",
            Error::CannotCreateWhitelistSignature => {
                "cannot create whitelist signature with the given data"
            }
            Error::InvalidWhitelistProof => {
                "given whitelist signature doesn't correctly prove inclusion in the whitelist"
            }
        };

        f.write_str(str)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<UpstreamError> for Error {
    fn from(e: UpstreamError) -> Self {
        Error::Upstream(e)
    }
}

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}
