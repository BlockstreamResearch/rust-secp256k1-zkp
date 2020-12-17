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
//! ## Examples
//!
//! ```rust
//! # #[cfg(all(feature="use-rand", feature="hashes"))] {
//! use secp256k1_zkp::rand::rngs::OsRng;
//! use secp256k1_zkp::{Secp256k1, Message};
//! use secp256k1_zkp::bitcoin_hashes::sha256;
//!
//! let secp = Secp256k1::new();
//! let mut rng = OsRng::new().expect("OsRng");
//! let (secret_key, public_key) = secp.generate_keypair(&mut rng);
//! let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());
//!
//! let sig = secp.sign(&message, &secret_key);
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! The above code requires `rust-secp256k1` to be compiled with the `rand` and `bitcoin_hashes`
//! feature enabled, to get access to [`generate_keypair`](struct.Secp256k1.html#method.generate_keypair)
//! Alternately, keys and messages can be parsed from slices, like
//!
//! ```rust
//! use self::secp256k1_zkp::{Secp256k1, Message, SecretKey, PublicKey};
//!
//! let secp = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
//! let public_key = PublicKey::from_secret_key(&secp, &secret_key);
//! // This is unsafe unless the supplied byte slice is the output of a cryptographic hash function.
//! // See the above example for how to use this library together with bitcoin_hashes.
//! let message = Message::from_slice(&[0xab; 32]).expect("32 bytes");
//!
//! let sig = secp.sign(&message, &secret_key);
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! ```
//!
//! Users who only want to verify signatures can use a cheaper context, like so:
//!
//! ```rust
//! use secp256k1_zkp::{Secp256k1, Message, Signature, PublicKey};
//!
//! let secp = Secp256k1::verification_only();
//!
//! let public_key = PublicKey::from_slice(&[
//!     0x02,
//!     0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55,
//!     0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8,
//!     0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c,
//!     0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
//! ]).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
//!
//! let message = Message::from_slice(&[
//!     0xaa, 0xdf, 0x7d, 0xe7, 0x82, 0x03, 0x4f, 0xbe,
//!     0x3d, 0x3d, 0xb2, 0xcb, 0x13, 0xc0, 0xcd, 0x91,
//!     0xbf, 0x41, 0xcb, 0x08, 0xfa, 0xc7, 0xbd, 0x61,
//!     0xd5, 0x44, 0x53, 0xcf, 0x6e, 0x82, 0xb4, 0x50,
//! ]).expect("messages must be 32 bytes and are expected to be hashes");
//!
//! let sig = Signature::from_compact(&[
//!     0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a,
//!     0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c, 0x39, 0x7a,
//!     0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94,
//!     0x0b, 0x55, 0x86, 0x82, 0x3d, 0xfd, 0x02, 0xae,
//!     0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb,
//!     0xae, 0xfd, 0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc,
//!     0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
//!     0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
//! ]).expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes");
//!
//! assert!(secp.verify(&message, &sig, &public_key).is_ok());
//! ```
//!
//! Observe that the same code using, say [`signing_only`](struct.Secp256k1.html#method.signing_only)
//! to generate a context would simply not compile.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

pub extern crate secp256k1_zkp_sys;
pub use secp256k1_zkp_sys as ffi;

extern crate secp256k1;

#[cfg(feature = "hashes")]
pub extern crate bitcoin_hashes;
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
pub use secp256k1::key;
#[cfg(feature = "recovery")]
pub use secp256k1::recovery;
pub use secp256k1::schnorrsig;

pub use key::{PublicKey, SecretKey};

pub use secp256k1::*;

mod zkp;
pub use zkp::*;

pub use secp256k1::Error as UpstreamError;

/// An ECDSA error
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
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
            Error::Upstream(inner) => return write!(f, "{}", inner),
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
