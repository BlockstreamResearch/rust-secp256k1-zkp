//! Bindings for Schnorr based adaptor signatures in secp256k1-zkp.

use crate::ffi::{self, CPtr, SCHNORR_ADAPTOR_PRESIGNATURE_LENGTH};
#[cfg(feature = "rand-std")]
use crate::rand::thread_rng;
#[cfg(feature = "actual-rand")]
use crate::rand::{CryptoRng, Rng};
use crate::{PublicKey, Secp256k1, SecretKey, Keypair, XOnlyPublicKey};
use crate::constants::{SECRET_KEY_SIZE,SCHNORR_SIGNATURE_SIZE};
use crate::schnorr::Signature as SchnorrSignature;
use crate::{Message, Signing};
use crate::{from_hex, Error};
use core::{fmt, ptr, str};

/// Represents an adaptor signature
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub struct SchnorrAdaptorPreSignature(ffi::SchnorrAdaptorPreSignature);

impl fmt::LowerHex for SchnorrAdaptorPreSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.as_ref().iter() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for SchnorrAdaptorPreSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for SchnorrAdaptorPreSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<SchnorrAdaptorPreSignature, Error> {
        let mut res = [0; SCHNORR_ADAPTOR_PRESIGNATURE_LENGTH];
        match from_hex(s, &mut res) {
            Ok(SCHNORR_ADAPTOR_PRESIGNATURE_LENGTH) => {
                SchnorrAdaptorPreSignature::from_slice(&res[0..SCHNORR_ADAPTOR_PRESIGNATURE_LENGTH])
            }
            _ => Err(Error::InvalidSchnorrAdaptorPreSignature),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for SchnorrAdaptorPreSignature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(self.0.as_ref())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for SchnorrAdaptorPreSignature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                SchnorrAdaptorPreSignature::from_slice,
            ))
        }
    }
}

impl CPtr for SchnorrAdaptorPreSignature {
    type Target = ffi::SchnorrAdaptorPreSignature;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl AsRef<[u8]> for SchnorrAdaptorPreSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SchnorrAdaptorPreSignature {
    /// Creates an [`SchnorrAdaptorPreSignature`] directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<SchnorrAdaptorPreSignature, Error> {
        match data.len() {
            SCHNORR_ADAPTOR_PRESIGNATURE_LENGTH => {
                let mut ret = [0; SCHNORR_ADAPTOR_PRESIGNATURE_LENGTH];
                ret[..].copy_from_slice(data);
                unsafe {
                    Ok(SchnorrAdaptorPreSignature(
                        ffi::SchnorrAdaptorPreSignature::from_array_unchecked(ret),
                    ))
                }
            }
            _ => Err(Error::InvalidSchnorrAdaptorPreSignature),
        }
    }

    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SchnorrAdaptorPreSignature {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::SchnorrAdaptorPreSignature {
        &mut self.0
    }
}

impl SchnorrAdaptorPreSignature {
    /// Creates a Schnorr adaptor pre-signature. The auxiliary randomness is
    /// generated using the ThreadRng random number generator.
    /// Requires compilation with "rand-std" feature.
    #[cfg(feature = "rand-std")]
    pub fn presign<C: Signing>(
        secp: &Secp256k1<C>,
        msg: &Message,
        keypair: &Keypair,
        adaptor: &PublicKey,
    ) -> SchnorrAdaptorPreSignature {
        let mut rng = thread_rng();
        SchnorrAdaptorPreSignature::presign_with_rng(secp, msg, keypair, adaptor, &mut rng)
    }

    /// Creates an adaptor signature along with a proof to verify the adaptor signature,
    /// This function derives a nonce using a similar process as described in BIP-340.
    /// The nonce derivation process is strengthened against side channel
    /// attacks by providing auxiliary randomness using the provided random number generator.
    /// Requires compilation with "rand" feature.
    #[cfg(feature = "actual-rand")]
    pub fn presign_with_rng<C: Signing, R: Rng + CryptoRng>(
        secp: &Secp256k1<C>,
        msg: &Message,
        keypair: &Keypair,
        adaptor: &PublicKey,
        rng: &mut R,
    ) -> SchnorrAdaptorPreSignature {
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        SchnorrAdaptorPreSignature::presign_with_aux_rand(secp, msg, keypair, adaptor, &aux)
    }

    /// Creates a Schnorr adaptor pre-signature without using any auxiliary
    /// random data. Note that using this function is still considered safe.
    pub fn presign_no_aux_rand<C: Signing>(
        secp: &Secp256k1<C>,
        msg: &Message,
        keypair: &Keypair,
        adaptor: &PublicKey,
    ) -> SchnorrAdaptorPreSignature {
        let mut pre_sig = ffi::SchnorrAdaptorPreSignature::new();

        let res = unsafe {
            ffi::secp256k1_schnorr_adaptor_presign(
                secp.ctx().as_ptr(),
                &mut pre_sig,
                msg.as_c_ptr(),
                keypair.as_c_ptr(),
                adaptor.as_c_ptr(),
                ptr::null_mut(),
            )
        };
        debug_assert_eq!(res, 1);

        SchnorrAdaptorPreSignature(pre_sig)
    }

    /// Creates a Schnorr adaptor pre-signature given an auxiliary random
    /// data. Note that using this function is still considered safe.
    pub fn presign_with_aux_rand<C: Signing>(
        secp: &Secp256k1<C>,
        msg: &Message,
        keypair: &Keypair,
        adaptor: &PublicKey,
        aux_rand: &[u8; 32],
    ) -> SchnorrAdaptorPreSignature {
        let mut pre_sig = ffi::SchnorrAdaptorPreSignature::new();

        let res = unsafe {
            ffi::secp256k1_schnorr_adaptor_presign(
                secp.ctx().as_ptr(),
                &mut pre_sig,
                msg.as_c_ptr(),
                keypair.as_c_ptr(),
                adaptor.as_c_ptr(),
                aux_rand.as_c_ptr() as *const ffi::types::c_uchar,
            )
        };
        debug_assert_eq!(res, 1);

        SchnorrAdaptorPreSignature(pre_sig)
    }

    /// Extracts the adaptor point from a Schnorr adaptor pre-signature.
    pub fn extract_adaptor(&self, msg: &Message, pubkey: &XOnlyPublicKey) -> Result<PublicKey, Error> {
        unsafe {
            let mut adaptor = ffi::PublicKey::new();
            let res = ffi::secp256k1_schnorr_adaptor_extract(
                ffi::secp256k1_context_no_precomp,
                &mut adaptor,
                self.as_c_ptr(),
                msg.as_c_ptr(),
                pubkey.as_c_ptr(),
            );

            if res != 1 {
                return Err(Error::CannotExtractAdaptorPoint);
            }

            Ok(adaptor.into())
        }
    }

    /// Adapts the Schnorr adaptor pre-signature to produce a BIP-340 Schnorr signature
    pub fn adapt(&self, sec_adaptor: &SecretKey) -> Result<SchnorrSignature, Error> {
        let mut sig = [0u8; SCHNORR_SIGNATURE_SIZE];

        let res = unsafe {
            ffi::secp256k1_schnorr_adaptor_adapt(
                ffi::secp256k1_context_no_precomp,
                sig.as_mut_c_ptr(),
                self.as_c_ptr(),
                sec_adaptor.as_c_ptr(),
            )
        };

        if res != 1 {
            return Err(Error::CannotAdaptPreSignature);
        }

        Ok(SchnorrSignature::from_slice(&sig)?)
    }

    /// Extract a secret adaptor from Schnorr adaptor pre-signature and BIP340 Schnorr signature
    pub fn extract_secadaptor(&self, sig: &SchnorrSignature) -> Result<SecretKey, Error> {
        let mut sec_adaptor = [0u8; SECRET_KEY_SIZE];

        let res = unsafe {
            ffi::secp256k1_schnorr_adaptor_extract_sec(
                ffi::secp256k1_context_no_precomp,
                sec_adaptor.as_mut_c_ptr(),
                self.as_c_ptr(),
                sig.as_c_ptr(),
            )
        };

        if res != 1 {
            return Err(Error::CannotExtractSecretAdaptor);
        }

        Ok(SecretKey::from_slice(&sec_adaptor)?)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rand-std")]
    fn test_schnorr_adaptor_correctness() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        let msg:[u8; 32] = rng.gen();
        let msg = Message::from_digest(msg);

        let keypair = Keypair::new(&secp, &mut rng);
        let (pubkey, _parity) = keypair.x_only_public_key();

        let (secret_adaptor, adaptor) = secp.generate_keypair(&mut rng);

        let pre_sig = SchnorrAdaptorPreSignature::presign(&secp, &msg, &keypair, &adaptor);

        let extracted_adaptor = pre_sig.extract_adaptor(&msg, &pubkey).unwrap();
        assert_eq!(adaptor, extracted_adaptor);

        let sig = pre_sig.adapt(&secret_adaptor).unwrap();
        let res = secp.verify_schnorr(&sig, &msg, &pubkey);
        assert_eq!(res, Ok(()));

        let extracted_secadaptor = pre_sig.extract_secadaptor(&sig).unwrap();
        assert_eq!(secret_adaptor, extracted_secadaptor);
    }
}
