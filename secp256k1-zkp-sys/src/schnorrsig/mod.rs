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

//! # Schnorrsig
//! Support for bip-schnorr compliant signatures
//!

mod ffi;

use core::{fmt, ptr, str};

use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{self, Message, Secp256k1, Signing, Verification};

use super::{from_hex, ScratchSpace};

/// A Schnorrsig error. This does not implement `std:error::Error` because it's not available with
/// `no_std`.
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Signature failed verification
    IncorrectSignature,
    /// Malformed signature
    InvalidSignature,
    /// Batch verification arguments don't have same size
    ArgumentLength,
    /// Too many signatures for batch verification
    TooManySignatures,
}

impl Error {
    /// Convert error into string
    pub fn as_str(&self) -> &str {
        match *self {
            Error::IncorrectSignature => "secp schnorrisg: signature failed verification",
            Error::InvalidSignature => "secp schnorrsig: malformed signature",
            Error::ArgumentLength => {
                "secp schnorrsig: batch verification arguments don't have same size"
            }
            Error::TooManySignatures => "secp schnorrsig: too many signatures for verification",
        }
    }
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.as_str())
    }
}

/// A Schnorr signature
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Signature(ffi::SchnorrSignature);
impl Signature {
    #[inline]
    /// Converts a byte slice to a signature
    pub fn parse(data: &[u8]) -> Result<Signature, Error> {
        if data.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let mut ret = unsafe { ffi::SchnorrSignature::blank() };
        unsafe {
            if ffi::secp256k1_zkp_schnorrsig_parse(
                secp256k1::ffi::secp256k1_context_no_precomp,
                &mut ret,
                data.as_ptr(),
            ) == 1
            {
                Ok(Signature(ret))
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize(&self) -> [u8; 64] {
        let mut ret = [0; 64];
        unsafe {
            let err = ffi::secp256k1_zkp_schnorrsig_serialize(
                secp256k1::ffi::secp256k1_context_no_precomp,
                ret.as_mut_ptr(),
                self.as_ptr(),
            );
            debug_assert!(err == 1);
        }
        ret
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SchnorrSignature {
        &self.0 as *const _
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::SchnorrSignature {
        &mut self.0 as *mut _
    }
}

/// Creates a new signature from a FFI signature
impl From<ffi::SchnorrSignature> for Signature {
    #[inline]
    fn from(sig: ffi::SchnorrSignature) -> Signature {
        Signature(sig)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = self.serialize();
        for ch in &v[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0; 64];
        if s.len() != 64 * 2 {
            return Err(Error::InvalidSignature);
        }
        match from_hex(s, &mut res) {
            Ok(x) => Signature::parse(&res[0..x]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for Signature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.serialize())
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Signature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use serde::de::Error;

        let sl: &[u8] = ::serde::Deserialize::deserialize(d)?;
        Signature::parse(sl).map_err(D::Error::custom)
    }
}

/// Schnorrsig signing trait
pub trait Sign {
    /// Creates a Schnorr signature as defined by BIP-schnorr from a message and a secret key.
    fn schnorrsig_sign(&self, msg: &Message, sk: &SecretKey) -> Signature;
}

/// Schnorrsig verification trait
pub trait Verify {
    /// Verifies a Schnorr signature `sig` for `msg` using the public key `pubkey` as defined by
    /// BIP-schnorr.
    fn schnorrsig_verify(
        &self,
        msg: &Message,
        sig: &Signature,
        pk: &PublicKey,
    ) -> Result<(), Error>;
    /// Takes slices of pointers to messages, Schnorr signatures and public keys and verifies them
    /// all at once. That's faster than if they would have been verified one by one. Returns an
    /// Error if a single Signature fails verification.
    fn schnorrsig_verify_batch(
        &self,
        scratch_space: &ScratchSpace,
        msgs: &[*const Message],
        sigs: &[*const Signature],
        pks: &[*const PublicKey],
    ) -> Result<(), Error>;
}

impl<C: Signing> Sign for Secp256k1<C> {
    fn schnorrsig_sign(&self, msg: &Message, sk: &SecretKey) -> Signature {
        let mut ret = unsafe { ffi::SchnorrSignature::blank() };
        unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid signature from a valid `Message` and `SecretKey`
            assert_eq!(
                ffi::secp256k1_zkp_schnorrsig_sign(
                    *self.ctx(),
                    &mut ret,
                    ptr::null_mut(),
                    msg.as_ptr(),
                    sk.as_ptr(),
                    secp256k1::ffi::secp256k1_nonce_function_rfc6979,
                    ptr::null_mut()
                ),
                1
            );
        }
        Signature::from(ret)
    }
}

impl<C: Verification> Verify for Secp256k1<C> {
    #[inline]
    fn schnorrsig_verify(
        &self,
        msg: &Message,
        sig: &Signature,
        pk: &PublicKey,
    ) -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_zkp_schnorrsig_verify(
                *self.ctx(),
                sig.as_ptr(),
                msg.as_ptr(),
                pk.as_ptr(),
            ) == 0
            {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        }
    }

    fn schnorrsig_verify_batch(
        &self,
        scratch_space: &ScratchSpace,
        msgs: &[*const Message],
        sigs: &[*const Signature],
        pks: &[*const PublicKey],
    ) -> Result<(), Error> {
        if msgs.len() != sigs.len() || msgs.len() != pks.len() {
            return Err(Error::ArgumentLength);
        }
        if sigs.len() >= 1 << 31 {
            return Err(Error::TooManySignatures);
        }
        unsafe {
            let result = ffi::secp256k1_zkp_schnorrsig_verify_batch(
                *self.ctx(),
                scratch_space.scratch_space(),
                sigs.as_ptr() as *const *const ffi::SchnorrSignature,
                msgs.as_ptr() as *const *const u8,
                pks.as_ptr() as *const *const secp256k1::ffi::PublicKey,
                sigs.len(),
            );
            if result == 0 {
                Err(Error::IncorrectSignature)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ScratchSpace, Sign, Signature, Verify};
    use core::str::FromStr;
    use rand::{thread_rng, RngCore};
    use secp256k1::{Message, Secp256k1};
    use secp256k1_zkp_dev::GenerateKeypair;

    #[test]
    fn serialization_roundtrip() {
        let ser_sig = [
            0x78, 0x7A, 0x84, 0x8E, 0x71, 0x04, 0x3D, 0x28, 0x0C, 0x50, 0x47, 0x0E, 0x8E, 0x15,
            0x32, 0xB2, 0xDD, 0x5D, 0x20, 0xEE, 0x91, 0x2A, 0x45, 0xDB, 0xDD, 0x2B, 0xD1, 0xDF,
            0xBF, 0x18, 0x7E, 0xF6, 0x70, 0x31, 0xA9, 0x88, 0x31, 0x85, 0x9D, 0xC3, 0x4D, 0xFF,
            0xEE, 0xDD, 0xA8, 0x68, 0x31, 0x84, 0x2C, 0xCD, 0x00, 0x79, 0xE1, 0xF9, 0x2A, 0xF1,
            0x77, 0xF7, 0xF2, 0x2C, 0xC1, 0xDC, 0xED, 0x05,
        ];
        let sig = Signature::parse(&ser_sig).unwrap();
        let ser_sig2 = Signature::serialize(&sig);
        assert_eq!(ser_sig.to_vec(), ser_sig2.to_vec());

        // Parsing sig where first 32 bytes are not X-coordinate on the curve
        let ser_sig = [
            0x4A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A, 0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD,
            0x1D, 0xCB, 0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7, 0x0A, 0x74, 0xF8, 0x22,
            0x04, 0x29, 0xBA, 0x1D, 0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99, 0xB8, 0xF2,
            0x66, 0x91, 0x22, 0x81, 0xF8, 0x36, 0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
            0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD,
        ];
        // Shouldn't return error right now
        let sig = Signature::parse(&ser_sig).unwrap();
        // Parsing wrong number of bytes results in Error
        assert_eq!(Signature::parse(&[]), Err(Error::InvalidSignature));

        let hex_sig = format!("{}", sig);
        assert_eq!(sig, Signature::from_str(&hex_sig).unwrap());
        let hex_sig = "";
        assert_eq!(Signature::from_str(&hex_sig), Err(Error::InvalidSignature));
        let hex_sig = "x";
        assert_eq!(Signature::from_str(&hex_sig), Err(Error::InvalidSignature));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_signature_serde() {
        use secp256k1::SecretKey;
        use serde_test::{assert_tokens, Token};

        let s = Secp256k1::new();

        let msg = Message::from_slice(&[1; 32]).unwrap();
        let sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let sig = s.schnorrsig_sign(&msg, &sk);
        static SIG_BYTES: [u8; 64] = [
            0x9D, 0x0B, 0xAD, 0x57, 0x67, 0x19, 0xD3, 0x2A, 0xE7, 0x6B, 0xED, 0xB3, 0x4C, 0x77,
            0x48, 0x66, 0x67, 0x3C, 0xBD, 0xE3, 0xF4, 0xE1, 0x29, 0x51, 0x55, 0x5C, 0x94, 0x08,
            0xE6, 0xCE, 0x77, 0x4B, 0xA2, 0x9B, 0x2E, 0x41, 0x74, 0x30, 0x82, 0x17, 0x1E, 0x35,
            0xD5, 0x63, 0xC9, 0x9D, 0x0F, 0xCE, 0xB6, 0xC4, 0x0B, 0x9A, 0xC2, 0x80, 0x77, 0x33,
            0x59, 0xE7, 0xB5, 0x6C, 0x09, 0x41, 0x8D, 0x6D,
        ];
        assert_tokens(&sig, &[Token::BorrowedBytes(&SIG_BYTES[..])]);
    }

    #[test]
    fn sign_and_verify() {
        let s = Secp256k1::new();
        let scratch_space = ScratchSpace::new(&s, 8192);

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng());
            let sig = s.schnorrsig_sign(&msg, &sk);
            assert_eq!(s.schnorrsig_verify(&msg, &sig, &pk), Ok(()));

            let msgptr = &msg as *const _;
            let sigptr = &sig as *const _;
            let pkptr = &pk as *const _;
            assert_eq!(
                s.schnorrsig_verify_batch(&scratch_space, &[msgptr], &[sigptr], &[pkptr]),
                Ok(())
            );

            // Verifying signature under different public key should fail
            let (_, pk) = s.generate_keypair(&mut thread_rng());
            let pkptr = &pk as *const _;
            assert_eq!(
                s.schnorrsig_verify(&msg, &sig, &pk),
                Err(Error::IncorrectSignature)
            );
            assert_eq!(
                s.schnorrsig_verify_batch(&scratch_space, &[msgptr], &[sigptr], &[pkptr]),
                Err(Error::IncorrectSignature)
            );
        }
    }

    #[test]
    fn batch_verify() {
        const N: usize = 100;
        let s = Secp256k1::new();
        let scratch_space = ScratchSpace::new(&s, 8192);

        // Test empty input
        assert_eq!(
            s.schnorrsig_verify_batch(&scratch_space, &[], &[], &[]),
            Ok(())
        );

        // Test that batch verification succeeds with N signatures
        let mut msgs = vec![];
        let mut pks = vec![];
        let mut sigs = vec![];
        for _ in 0..N {
            let mut msg = [0; 32];
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng());
            let sig = s.schnorrsig_sign(&msg, &sk);
            msgs.push(&msg as *const _);
            pks.push(&pk as *const _);
            sigs.push(&sig as *const _);
        }
        assert_eq!(
            s.schnorrsig_verify_batch(&scratch_space, &msgs, &sigs, &pks),
            Ok(())
        );

        // Test that changing a single message makes batch verification fail
        for i in 0..N {
            let mut msgs_tmp = msgs.clone();
            let mut msg = [0; 32];
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();
            msgs_tmp[i] = &msg as *const _;
            assert_eq!(
                s.schnorrsig_verify_batch(&scratch_space, &msgs_tmp, &sigs, &pks),
                Err(Error::IncorrectSignature)
            );
        }
    }
}
