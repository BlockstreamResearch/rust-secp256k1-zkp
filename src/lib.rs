// SPDX-License-Identifier: CC0-1.0

//! Rust bindings for Pieter Wuille's secp256k1 library, which is used for
//! fast and accurate manipulation of ECDSA and Schnorr signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!
//! To minimize dependencies, some functions are feature-gated. To generate
//! random keys or to re-randomize a context object, compile with the
//! `rand` and `std` features. If you are willing to use these features, we
//! have enabled an additional defense-in-depth sidechannel protection for
//! our context objects, which re-blinds certain operations on secret key
//! data. To de/serialize objects with serde, compile with "serde".
//! **Important**: `serde` encoding is **not** the same as consensus
//! encoding!
//!
//! Where possible, the bindings use the Rust type system to ensure that
//! API usage errors are impossible. For example, the library uses context
//! objects that contain precomputation tables which are created on object
//! construction. Since this is a slow operation (10+ milliseconds, vs ~50
//! microseconds for typical crypto operations, on a 2.70 Ghz i7-6820HQ)
//! the tables are optional, giving a performance boost for users who only
//! care about signing, only care about verification, or only care about
//! parsing. In the upstream library, if you attempt to sign a message using
//! a context that does not support this, it will trigger an assertion
//! failure and terminate the program. In `rust-secp256k1`, this is caught
//! at compile-time; in fact, it is impossible to compile code that will
//! trigger any assertion failures in the upstream library.
//!
//! ```rust
//! # #[cfg(all(feature = "rand", feature = "hashes", feature = "std"))] {
//! use secp256k1::rand;
//! use secp256k1::{Secp256k1, Message};
//! use secp256k1::hashes::{sha256, Hash};
//!
//! let secp = Secp256k1::new();
//! let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());
//! let digest = sha256::Hash::hash("Hello World!".as_bytes());
//! let message = Message::from_digest(digest.to_byte_array());
//!
//! let sig = secp.sign_ecdsa(message, &secret_key);
//! assert!(secp.verify_ecdsa(message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! If the "global-context" feature is enabled you have access to an alternate API.
//!
//! ```rust
//! # #[cfg(all(feature = "global-context", feature = "hashes", feature = "rand", feature = "std"))] {
//! use secp256k1::{rand, generate_keypair, Message};
//! use secp256k1::hashes::{sha256, Hash};
//!
//! let (secret_key, public_key) = generate_keypair(&mut rand::rng());
//! let digest = sha256::Hash::hash("Hello World!".as_bytes());
//! let message = Message::from_digest(digest.to_byte_array());
//!
//! let sig = secret_key.sign_ecdsa(message);
//! assert!(sig.verify(message, &public_key).is_ok());
//! # }
//! ```
//!
//! The above code requires `rust-secp256k1` to be compiled with the `rand`, `hashes`, and `std`
//! feature enabled, to get access to [`generate_keypair`](struct.Secp256k1.html#method.generate_keypair)
//! Alternately, keys and messages can be parsed from slices, like
//!
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
//! # fn compute_hash(_: &[u8]) -> [u8; 32] { [0xab; 32] }
//!
//! let secp = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
//! let public_key = PublicKey::from_secret_key(&secp, &secret_key);
//! // If the supplied byte slice was *not* the output of a cryptographic hash function this would
//! // be cryptographically broken. It has been trivially used in the past to execute attacks.
//! let message = Message::from_digest(compute_hash(b"CSW is not Satoshi"));
//!
//! let sig = secp.sign_ecdsa(message, &secret_key);
//! assert!(secp.verify_ecdsa(message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Users who only want to verify signatures can use a cheaper context, like so:
//!
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! use secp256k1::{Secp256k1, Message, ecdsa, PublicKey};
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
//! let message = Message::from_digest([
//!     0xaa, 0xdf, 0x7d, 0xe7, 0x82, 0x03, 0x4f, 0xbe,
//!     0x3d, 0x3d, 0xb2, 0xcb, 0x13, 0xc0, 0xcd, 0x91,
//!     0xbf, 0x41, 0xcb, 0x08, 0xfa, 0xc7, 0xbd, 0x61,
//!     0xd5, 0x44, 0x53, 0xcf, 0x6e, 0x82, 0xb4, 0x50,
//! ]);
//!
//! let sig = ecdsa::Signature::from_compact(&[
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
//! # #[cfg(not(secp256k1_fuzz))]
//! assert!(secp.verify_ecdsa(message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Observe that the same code using, say [`signing_only`](struct.Secp256k1.html#method.signing_only)
//! to generate a context would simply not compile.
//!
//! ## Crate features/optional dependencies
//!
//! This crate provides the following opt-in Cargo features:
//!
//! * `std` - use standard Rust library, enabled by default.
//! * `alloc` - use the `alloc` standard Rust library to provide heap allocations.
//! * `rand` - use `rand` library to provide random generator (e.g. to generate keys).
//! * `hashes` - use the `hashes` library.
//! * `recovery` - enable functions that can compute the public key from signature.
//! * `lowmemory` - optimize the library for low-memory environments.
//! * `global-context` - enable use of global secp256k1 context (implies `std`).
//! * `serde` - implements serialization and deserialization for types in this crate using `serde`.
//!   **Important**: `serde` encoding is **not** the same as consensus encoding!
//!

// Coding conventions
#![deny(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![warn(
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations
)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate core;
#[cfg(bench)]
extern crate test;

#[cfg(feature = "hashes")]
pub extern crate hashes;

#[macro_use]
mod macros;
mod context;
mod ffi_convert;

pub use secp256k1::constants;
pub use secp256k1::ecdh;
pub use secp256k1::ecdsa;
pub use secp256k1::ellswift;
pub use secp256k1::scalar;
pub use secp256k1::schnorr;
mod zkp;
pub use crate::zkp::*;
#[cfg(feature = "serde")]
mod serde_util;

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::{fmt, mem, str};

#[cfg(all(feature = "global-context", feature = "std"))]
pub use context::global::{self, SECP256K1};
#[cfg(feature = "rand")]
pub extern crate rand;
pub extern crate secp256k1_zkp_sys;
pub use secp256k1_zkp_sys as ffi;
#[cfg(feature = "serde")]
pub extern crate serde;

#[cfg(feature = "alloc")]
pub use crate::context::{All, SignOnly, VerifyOnly};
pub use crate::context::{
    AllPreallocated, Context, PreallocatedContext, SignOnlyPreallocated, Signing, Verification,
    VerifyOnlyPreallocated,
};
use crate::ffi::types::AlignedType;
use crate::ffi::CPtr;
pub use secp256k1::{
    InvalidParityValue, Keypair, Parity, PublicKey, Scalar, SecretKey, XOnlyPublicKey,
};

use ffi_convert::ConvertFromUpstream;

/// Trait describing something that promises to be a 32-byte uniformly random number.
///
/// In particular, anything implementing this trait must have neglibile probability
/// of being zero, overflowing the group order, or equalling any specific value.
///
/// Since version 0.29 this has been deprecated; users should instead implement
/// `Into<Message>` for types that satisfy these properties.
#[deprecated(
    since = "0.29.0",
    note = "Please see v0.29.0 rust-secp256k1/CHANGELOG.md for suggestion"
)]
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

/// A (hashed) message input to an ECDSA signature.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);
impl_pretty_debug!(Message);

impl Message {
    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
    /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
    /// the result of signing isn't a
    /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
    #[inline]
    #[deprecated(since = "0.28.0", note = "use from_digest instead")]
    pub fn from_slice(digest: &[u8]) -> Result<Message, Error> {
        #[allow(deprecated)]
        Message::from_digest_slice(digest)
    }

    /// Creates a [`Message`] from a `digest`.
    ///
    /// The `digest` array has to be a cryptographically secure hash of the actual message that's
    /// going to be signed. Otherwise the result of signing isn't a [secure signature].
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    pub fn from_digest(digest: [u8; 32]) -> Message {
        Message(digest)
    }

    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// The slice has to be 32 bytes long and be a cryptographically secure hash of the actual
    /// message that's going to be signed. Otherwise the result of signing isn't a [secure
    /// signature].
    ///
    /// This method is deprecated. It's best to use [`Message::from_digest`] directly with an
    /// array. If your hash engine doesn't return an array for some reason use `.try_into()` on its
    /// output.
    ///
    /// # Errors
    ///
    /// If `digest` is not exactly 32 bytes long.
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    #[deprecated(since = "0.30.0", note = "use from_digest instead")]
    pub fn from_digest_slice(digest: &[u8]) -> Result<Message, Error> {
        Ok(Message::from_digest(
            digest.try_into().map_err(|_| Error::InvalidMessage)?,
        ))
    }
}

#[allow(deprecated)]
impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths.
    fn from(t: T) -> Message {
        Message(t.into_32())
    }
}

impl fmt::LowerHex for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

/// The main error type for this library.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub enum Error {
    /// Bad sized message ("messages" are actually fixed-sized digests [`constants::MESSAGE_SIZE`]).
    InvalidMessage,
    /// Bad secret key.
    InvalidSecretKey,
    /// Didn't pass enough memory to context creation with preallocated memory.
    NotEnoughMemory,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Self::InvalidMessage => f.write_str("message was not 32 bytes (do you need to hash?)"),
            Self::InvalidSecretKey => f.write_str("malformed or out-of-range secret key"),
            Self::NotEnoughMemory => f.write_str("not enough memory allocated"),
            Self::CannotProveSurjection => f.write_str("failed to prove surjection"),
            Self::InvalidSurjectionProof => f.write_str("malformed surjection proof"),
            Self::InvalidPedersenCommitment => f.write_str("malformed pedersen commitment"),
            Self::CannotMakeRangeProof => f.write_str("failed to generate range proof"),
            Self::InvalidRangeProof => f.write_str("failed to verify range proof"),
            Self::InvalidGenerator => f.write_str("malformed generator"),
            Self::InvalidEcdsaAdaptorSignature => f.write_str("malformed ecdsa adaptor signature"),
            Self::CannotDecryptAdaptorSignature => {
                f.write_str("failed to decrypt adaptor signature")
            }
            Self::CannotRecoverAdaptorSecret => f.write_str("failed to recover adaptor secret"),
            Self::CannotVerifyAdaptorSignature => f.write_str("failed to verify adaptor signature"),
            Self::InvalidTweakLength => f.write_str("Tweak must of size 32"),
            Self::TweakOutOfBounds => f.write_str("Tweak must be less than secp curve order"),
            Self::InvalidWhitelistSignature => f.write_str("malformed whitelist signature"),
            Self::InvalidPakList => f.write_str("invalid PAK list"),
            Self::CannotCreateWhitelistSignature => {
                f.write_str("cannot create whitelist signature with the given data")
            }
            Self::InvalidWhitelistProof => f.write_str(
                "given whitelist signature doesn't correctly prove inclusion in the whitelist",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidMessage => None,
            Self::InvalidSecretKey => None,
            Self::NotEnoughMemory => None,
            Self::CannotProveSurjection => None,
            Self::InvalidSurjectionProof => None,
            Self::InvalidPedersenCommitment => None,
            Self::CannotMakeRangeProof => None,
            Self::InvalidRangeProof => None,
            Self::InvalidGenerator => None,
            Self::InvalidTweakLength => None,
            Self::TweakOutOfBounds => None,
            Self::InvalidEcdsaAdaptorSignature => None,
            Self::CannotDecryptAdaptorSignature => None,
            Self::CannotRecoverAdaptorSecret => None,
            Self::CannotVerifyAdaptorSignature => None,
            Self::InvalidWhitelistSignature => None,
            Self::InvalidPakList => None,
            Self::CannotCreateWhitelistSignature => None,
            Self::InvalidWhitelistProof => None,
        }
    }
}

/// The secp256k1 engine, used to execute all signature operations.
pub struct Secp256k1<C: Context> {
    ctx: NonNull<ffi::Context>,
    phantom: PhantomData<C>,
}

// The underlying secp context does not contain any references to memory it does not own.
unsafe impl<C: Context> Send for Secp256k1<C> {}
// The API does not permit any mutation of `Secp256k1` objects except through `&mut` references.
unsafe impl<C: Context> Sync for Secp256k1<C> {}

impl<C: Context> PartialEq for Secp256k1<C> {
    fn eq(&self, _other: &Secp256k1<C>) -> bool {
        true
    }
}

impl<C: Context> Eq for Secp256k1<C> {}

impl<C: Context> Drop for Secp256k1<C> {
    fn drop(&mut self) {
        unsafe {
            let size = ffi::secp256k1_context_preallocated_clone_size(self.ctx.as_ptr());
            ffi::secp256k1_context_preallocated_destroy(self.ctx);

            C::deallocate(self.ctx.as_ptr().cast::<u8>(), size);
        }
    }
}

impl<C: Context> fmt::Debug for Secp256k1<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context {:?}, {}>", self.ctx, C::DESCRIPTION)
    }
}

impl<C: Context> Secp256k1<C> {
    /// Getter for the raw pointer to the underlying secp256k1 context. This
    /// shouldn't be needed with normal usage of the library. It enables
    /// extending the Secp256k1 with more cryptographic algorithms outside of
    /// this crate.
    pub fn ctx(&self) -> NonNull<ffi::Context> {
        self.ctx
    }

    /// Returns the required memory for a preallocated context buffer in a generic manner(sign/verify/all).
    pub fn preallocate_size_gen() -> usize {
        let word_size = mem::size_of::<AlignedType>();
        let bytes = unsafe { ffi::secp256k1_context_preallocated_size(C::FLAGS) };

        bytes.div_ceil(word_size)
    }

    /// (Re)randomizes the Secp256k1 context for extra sidechannel resistance.
    ///
    /// Requires compilation with "rand" feature. See comment by Gregory Maxwell in
    /// [libsecp256k1](https://github.com/bitcoin-core/secp256k1/commit/d2275795ff22a6f4738869f5528fbbb61738aa48).
    #[cfg(feature = "rand")]
    pub fn randomize<R: rand::Rng + ?Sized>(&mut self, rng: &mut R) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        self.seeded_randomize(&seed);
    }

    /// (Re)randomizes the Secp256k1 context for extra sidechannel resistance given 32 bytes of
    /// cryptographically-secure random data;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell.
    pub fn seeded_randomize(&mut self, seed: &[u8; 32]) {
        unsafe {
            let err = ffi::secp256k1_context_randomize(self.ctx, seed.as_c_ptr());
            // This function cannot fail; it has an error return for future-proofing.
            // We do not expose this error since it is impossible to hit, and we have
            // precedent for not exposing impossible errors (for example in
            // `PublicKey::from_secret_key` where it is impossible to create an invalid
            // secret key through the API.)
            // However, if this DOES fail, the result is potentially weaker side-channel
            // resistance, which is deadly and undetectable, so we take out the entire
            // thread to be on the safe side.
            assert_eq!(err, 1);
        }
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

#[cfg(test)]
mod test_util {
    pub struct KeyPairStream {
        ctx: secp256k1::Secp256k1<secp256k1::All>,
        sk: secp256k1::SecretKey,
        pk: secp256k1::PublicKey,
    }

    impl KeyPairStream {
        /// Generates a new iterator which produces an indefinite stream of distinct
        /// keypairs for use with testing.
        pub fn new() -> Self {
            let ctx = secp256k1::Secp256k1::new();
            let sk = secp256k1::SecretKey::from_byte_array([100; 32]).unwrap();
            let pk = secp256k1::PublicKey::from_secret_key(&ctx, &sk);
            KeyPairStream { sk, pk, ctx }
        }
    }

    impl Iterator for KeyPairStream {
        type Item = (secp256k1::SecretKey, secp256k1::PublicKey);

        fn next(&mut self) -> Option<Self::Item> {
            let offs = secp256k1::Scalar::from_be_bytes([50; 32]).unwrap();

            let ret = (self.sk, self.pk);
            self.sk = self.sk.add_tweak(&offs).expect("will not cancel");
            self.pk = self
                .pk
                .add_exp_tweak(&self.ctx, &offs)
                .expect("will not cancel");
            Some(ret)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "std")]
    // In rustc 1.72 this Clippy lint was pulled out of clippy and into rustc, and
    // was made deny-by-default, breaking compilation of this test. Aside from this
    // breaking change, which there is no point in bugging, the rename was done so
    // clumsily that you need four separate "allow"s to disable this wrong lint.
    #[allow(unknown_lints)]
    #[allow(renamed_and_removed_lints)]
    #[allow(undropped_manually_drops)]
    #[allow(clippy::unknown_manually_drops)]
    fn test_raw_ctx() {
        use std::mem::{forget, ManuallyDrop};

        let ctx_full = Secp256k1::new();
        let ctx_sign = Secp256k1::signing_only();
        let ctx_vrfy = Secp256k1::verification_only();

        let full = unsafe { Secp256k1::from_raw_all(ctx_full.ctx) };
        let sign = unsafe { Secp256k1::from_raw_signing_only(ctx_sign.ctx) };
        let mut vrfy = unsafe { Secp256k1::from_raw_verification_only(ctx_vrfy.ctx) };

        let keyset = whitelist_test_util::KeySet::new(10);

        // Try signing
        assert_eq!(
            whitelist_test_util::whitelist_prove(&sign, &keyset, 0),
            whitelist_test_util::whitelist_prove(&full, &keyset, 0),
        );
        let sig = whitelist_test_util::whitelist_prove(&sign, &keyset, 0).unwrap();

        // Try verifying
        assert!(whitelist_test_util::whitelist_verify(&vrfy, &keyset, &sig).is_ok());
        assert!(whitelist_test_util::whitelist_verify(&full, &keyset, &sig).is_ok());

        // The following drop will have no effect; in fact, they will trigger a compiler
        // error because manually dropping a `ManuallyDrop` is almost certainly incorrect.
        // If you want to drop the inner object you should called `ManuallyDrop::drop`.
        drop(full);
        // This will actually drop the context, though it will leave `full` accessible and
        // in an invalid state. However, this is almost certainly what you want to do.
        drop(ctx_full);
        unsafe {
            // Need to compute the allocation size, and need to do so *before* dropping
            // anything.
            let sz = ffi::secp256k1_context_preallocated_clone_size(ctx_sign.ctx.as_ptr());
            // We can alternately drop the `ManuallyDrop` by unwrapping it and then letting
            // it be dropped. This is actually a safe function, but it will destruct the
            // underlying context without deallocating it...
            ManuallyDrop::into_inner(sign);
            // ...leaving us holding the bag to deallocate the context's memory without
            // double-calling `secp256k1_context_destroy`, which cannot be done safely.
            SignOnly::deallocate(ctx_sign.ctx.as_ptr() as *mut u8, sz);
            forget(ctx_sign);
        }

        unsafe {
            // Finally, we can call `ManuallyDrop::drop`, which has the same effect, but
            let sz = ffi::secp256k1_context_preallocated_clone_size(ctx_vrfy.ctx.as_ptr());
            // leaves the `ManuallyDrop` itself accessible. This is marked unsafe.
            ManuallyDrop::drop(&mut vrfy);
            VerifyOnly::deallocate(ctx_vrfy.ctx.as_ptr() as *mut u8, sz);
            forget(ctx_vrfy);
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_preallocation() {
        use crate::ffi::types::AlignedType;

        let mut buf_ful = vec![AlignedType::zeroed(); Secp256k1::preallocate_size()];
        let mut buf_sign = vec![AlignedType::zeroed(); Secp256k1::preallocate_signing_size()];
        let mut buf_vfy = vec![AlignedType::zeroed(); Secp256k1::preallocate_verification_size()];

        let full = Secp256k1::preallocated_new(&mut buf_ful).unwrap();
        let sign = Secp256k1::preallocated_signing_only(&mut buf_sign).unwrap();
        let vrfy = Secp256k1::preallocated_verification_only(&mut buf_vfy).unwrap();

        //        drop(buf_vfy); // The buffer can't get dropped before the context.
        //        println!("{:?}", buf_ful[5]); // Can't even read the data thanks to the borrow checker.

        let keyset = whitelist_test_util::KeySet::new(10);
        // Try signing
        assert_eq!(
            whitelist_test_util::whitelist_prove(&sign, &keyset, 0),
            whitelist_test_util::whitelist_prove(&full, &keyset, 0),
        );
        let sig = whitelist_test_util::whitelist_prove(&sign, &keyset, 0).unwrap();

        // Try verifying
        assert!(whitelist_test_util::whitelist_verify(&vrfy, &keyset, &sig).is_ok());
        assert!(whitelist_test_util::whitelist_verify(&full, &keyset, &sig).is_ok());
    }

    #[test]
    #[cfg(feature = "std")]
    fn capabilities() {
        let sign = Secp256k1::signing_only();
        let vrfy = Secp256k1::verification_only();
        let full = Secp256k1::new();

        let keyset = whitelist_test_util::KeySet::new(10);

        // Try signing
        assert_eq!(
            whitelist_test_util::whitelist_prove(&sign, &keyset, 0),
            whitelist_test_util::whitelist_prove(&full, &keyset, 0),
        );
        let sig = whitelist_test_util::whitelist_prove(&sign, &keyset, 0).unwrap();

        // Try verifying
        assert!(whitelist_test_util::whitelist_verify(&vrfy, &keyset, &sig).is_ok());
        assert!(whitelist_test_util::whitelist_verify(&full, &keyset, &sig).is_ok());
    }

    #[cfg(feature = "global-context")]
    #[test]
    fn test_global_context() {
        use crate::SECP256K1;
        let keyset = whitelist_test_util::KeySet::new(10);
        let sig = whitelist_test_util::whitelist_prove(SECP256K1, &keyset, 0).unwrap();
        assert!(whitelist_test_util::whitelist_verify(SECP256K1, &keyset, &sig).is_ok());
    }
}
