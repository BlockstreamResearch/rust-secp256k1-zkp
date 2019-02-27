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

use std::{error, fmt};

use secp256k1::key::PublicKey;
use secp256k1::{Message, Secp256k1, Verification};

use secp256k1_zkp_sys::schnorrsig as schnorrsig_sys;

pub use secp256k1_zkp_sys::schnorrsig::Error as SysError;
pub use secp256k1_zkp_sys::schnorrsig::Sign;
pub use secp256k1_zkp_sys::ScratchSpace;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
/// A schnorrsig error
pub enum Error {
    /// Error from the underlying secp256k_zkp_sys library.
    SysError(schnorrsig_sys::Error),
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        None
    }

    fn description(&self) -> &str {
        match *self {
            Error::SysError(ref e) => e.as_str(),
        }
    }
}

impl From<schnorrsig_sys::Error> for Error {
    fn from(err: schnorrsig_sys::Error) -> Self {
        Error::SysError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::SysError(e) => f.write_str(e.as_str()),
        }
    }
}

type Signature = schnorrsig_sys::Signature;

/// Schnorrsig verification trait
pub trait Verify {
    /// Verifies a Schnorr signature as defined by BIP-schnorr
    fn schnorrsig_verify(
        &self,
        msg: &Message,
        sig: &Signature,
        pk: &PublicKey,
    ) -> Result<(), Error>;

    /// Takes slices of messages, Schnorr signatures and public keys and verifies them all at once.
    /// That's faster than if they would have been verified one by one. Returns an Error if a
    /// single Signature fails verification. If the scratch space is not provided, this function
    /// will create a scratch space on its own of size 8192 bytes.
    fn schnorrsig_verify_batch(
        &self,
        scratch_space: Option<ScratchSpace>,
        msgs: &[Message],
        sigs: &[Signature],
        pks: &[PublicKey],
    ) -> Result<(), Error>;
}

impl<C: Verification> Verify for Secp256k1<C> {
    fn schnorrsig_verify(
        &self,
        msg: &Message,
        sig: &Signature,
        pk: &PublicKey,
    ) -> Result<(), Error> {
        schnorrsig_sys::Verify::schnorrsig_verify(self, msg, sig, pk).map_err(|e| e.into())
    }
    fn schnorrsig_verify_batch(
        &self,
        scratch_space: Option<ScratchSpace>,
        msgs: &[Message],
        sigs: &[Signature],
        pks: &[PublicKey],
    ) -> Result<(), Error> {
        if msgs.len() != sigs.len() || msgs.len() != pks.len() {
            return Err(schnorrsig_sys::Error::ArgumentLength.into());
        }
        let scratch_space = scratch_space.unwrap_or(ScratchSpace::new(self, 8192));
        let n = msgs.len();
        let mut msgptrs = Vec::with_capacity(n);
        let mut sigptrs = Vec::with_capacity(n);
        let mut pkptrs = Vec::with_capacity(n);
        for i in 0..n {
            msgptrs.push(msgs[i].as_ptr() as *const _);
            sigptrs.push(&sigs[i] as *const _);
            pkptrs.push(pks[i].as_ptr() as *const _);
        }
        schnorrsig_sys::Verify::schnorrsig_verify_batch(
            self,
            &scratch_space,
            &msgptrs[..],
            &sigptrs[..],
            &pkptrs[..],
        )
        .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Sign, Signature, SysError, Verify};
    use rand::{thread_rng, RngCore};
    use secp256k1::{Message, Secp256k1};
    use secp256k1_zkp_dev::GenerateKeypair;

    #[test]
    fn sign_and_verify() {
        let s = Secp256k1::new();

        let mut msg = [0; 32];
        for _ in 0..100 {
            thread_rng().fill_bytes(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut thread_rng());
            let sig = s.schnorrsig_sign(&msg, &sk);
            Signature::serialize(&sig);
            assert_eq!(s.schnorrsig_verify(&msg, &sig, &pk), Ok(()));
            assert_eq!(
                s.schnorrsig_verify_batch(None, &[msg], &[sig], &[pk]),
                Ok(())
            );
            assert_eq!(
                s.schnorrsig_verify_batch(None, &[msg], &[], &[pk]),
                Err(SysError::ArgumentLength.into())
            );
        }
    }
}
