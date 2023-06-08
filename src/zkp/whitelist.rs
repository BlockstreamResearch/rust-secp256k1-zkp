//! Bindings for the "whitelist" ring signature implementation in secp256k1-zkp.
//!
//! This implementation is used for Liquid PAK list inclusion proofs.

#[cfg(feature = "std")]
use std::{fmt, str};

use crate::ffi::CPtr;
#[cfg(feature = "std")]
use crate::from_hex;
use crate::{ffi, Error, PublicKey, Secp256k1, SecretKey, Signing, Verification};

/// A whitelist ring signature.
#[derive(Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct WhitelistSignature(ffi::WhitelistSignature);

impl WhitelistSignature {
    /// Number of keys in the whitelist.
    pub fn n_keys(&self) -> usize {
        self.0.n_keys
    }

    /// Serialize to bytes.
    #[cfg(feature = "std")]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0; 33 + 32 * self.n_keys()];

        let mut out_len = buf.len();
        let ret = unsafe {
            ffi::secp256k1_whitelist_signature_serialize(
                ffi::secp256k1_context_no_precomp,
                buf.as_mut_ptr(),
                &mut out_len,
                &self.0,
            )
        };
        assert_eq!(ret, 1, "failed to serialize whitelist signature");
        assert_eq!(
            out_len,
            buf.len(),
            "whitelist serialized to unexpected length"
        );

        buf
    }

    /// Parse a whitelist ring signature from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut sig = ffi::WhitelistSignature::default();

        let ret = unsafe {
            ffi::secp256k1_whitelist_signature_parse(
                ffi::secp256k1_context_no_precomp,
                &mut sig,
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        if ret != 1 {
            return Err(Error::InvalidWhitelistSignature);
        }

        Ok(WhitelistSignature(sig))
    }

    /// Create a new whitelist ring signature for the given PAK list and whitelist key.
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        online_keys: &[PublicKey],
        offline_keys: &[PublicKey],
        whitelist_key: &PublicKey,
        online_secret_key: &SecretKey,
        summed_secret_key: &SecretKey,
        key_index: usize,
    ) -> Result<WhitelistSignature, Error> {
        if online_keys.len() != offline_keys.len() {
            return Err(Error::InvalidPakList);
        }
        let n_keys = online_keys.len();

        let mut sig = ffi::WhitelistSignature::default();
        let ret = unsafe {
            ffi::secp256k1_whitelist_sign(
                secp.ctx().as_ptr(),
                &mut sig,
                // These two casts are legit because PublicKey has repr(transparent).
                online_keys.as_c_ptr() as *const ffi::PublicKey,
                offline_keys.as_c_ptr() as *const ffi::PublicKey,
                n_keys,
                whitelist_key.as_c_ptr(),
                online_secret_key.as_c_ptr(),
                summed_secret_key.as_c_ptr(),
                key_index,
            )
        };
        if ret != 1 {
            return Err(Error::CannotCreateWhitelistSignature);
        }

        Ok(WhitelistSignature(sig))
    }

    /// Verify the given whitelist signature against the PAK list and whitelist key.
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        online_keys: &[PublicKey],
        offline_keys: &[PublicKey],
        whitelist_key: &PublicKey,
    ) -> Result<(), Error> {
        if online_keys.len() != offline_keys.len() {
            return Err(Error::InvalidPakList);
        }
        let n_keys = online_keys.len();

        let ret = unsafe {
            ffi::secp256k1_whitelist_verify(
                secp.ctx().as_ptr(),
                &self.0,
                // These two casts are legit because PublicKey has repr(transparent).
                online_keys.as_c_ptr() as *const ffi::PublicKey,
                offline_keys.as_c_ptr() as *const ffi::PublicKey,
                n_keys,
                whitelist_key.as_c_ptr(),
            )
        };
        if ret != 1 {
            return Err(Error::InvalidWhitelistProof);
        }

        Ok(())
    }

    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::WhitelistSignature {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::WhitelistSignature {
        &mut self.0
    }
}

#[cfg(feature = "std")]
impl fmt::LowerHex for WhitelistSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.serialize().iter() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl fmt::Display for WhitelistSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for WhitelistSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl str::FromStr for WhitelistSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<WhitelistSignature, Error> {
        let mut buf = vec![0; s.len() / 2];
        from_hex(s, &mut buf).map_err(|_| Error::InvalidWhitelistSignature)?;
        WhitelistSignature::from_slice(&buf)
    }
}

#[cfg(all(feature = "serde", feature = "std"))]
impl ::serde::Serialize for WhitelistSignature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(all(feature = "serde", feature = "std"))]
impl<'de> ::serde::Deserialize<'de> for WhitelistSignature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                WhitelistSignature::from_slice,
            ))
        }
    }
}

impl CPtr for WhitelistSignature {
    type Target = ffi::WhitelistSignature;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

#[cfg(all(test, feature = "global-context"))]
mod tests {
    use super::*;
    use crate::SECP256K1;
    use rand::thread_rng;

    fn test_whitelist_proof_roundtrip(n_keys: usize) {
        let mut rng = thread_rng();
        let (keys_online, pak_online) = (0..n_keys)
            .map(|_| SECP256K1.generate_keypair(&mut rng))
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let (keys_offline, pak_offline) = (0..n_keys)
            .map(|_| SECP256K1.generate_keypair(&mut rng))
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let (whitelist_sk, whitelist_pk) = SECP256K1.generate_keypair(&mut rng);

        for our_idx in vec![0, n_keys / 2, n_keys - 1].into_iter() {
            // sign

            let summed_key = keys_offline[our_idx]
                .clone()
                .add_tweak(&whitelist_sk.into())
                .unwrap();

            let signature = WhitelistSignature::new(
                SECP256K1,
                &pak_online,
                &pak_offline,
                &whitelist_pk,
                &keys_online[our_idx],
                &summed_key,
                our_idx,
            )
            .unwrap();
            assert_eq!(n_keys, signature.n_keys());

            // verify

            signature
                .verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk)
                .unwrap();

            // round trip

            let encoded = signature.serialize();
            let decoded = WhitelistSignature::from_slice(&encoded).unwrap();
            assert_eq!(n_keys, decoded.n_keys());
            assert_eq!(signature, decoded);
            decoded
                .verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk)
                .unwrap();
        }
    }

    #[test]
    fn test_whitelist_proof_roundtrip_n1() {
        test_whitelist_proof_roundtrip(1);
    }

    #[test]
    fn test_whitelist_proof_roundtrip_n50() {
        test_whitelist_proof_roundtrip(50);
    }

    #[test]
    fn test_whitelist_proof_roundtrip_n255() {
        test_whitelist_proof_roundtrip(255);
    }

    #[test]
    fn test_whitelist_proof_invalid() {
        let n_keys = 255;

        let mut rng = thread_rng();
        let (keys_online, pak_online) = (0..n_keys)
            .map(|_| SECP256K1.generate_keypair(&mut rng))
            .unzip::<_, _, Vec<_>, Vec<_>>();
        let (keys_offline, pak_offline) = (0..n_keys)
            .map(|_| SECP256K1.generate_keypair(&mut rng))
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let (whitelist_sk, whitelist_pk) = SECP256K1.generate_keypair(&mut rng);

        let our_idx = 100;
        let summed_key = keys_offline[our_idx]
            .clone()
            .add_tweak(&whitelist_sk.into())
            .unwrap();

        {
            // wrong pak
            let offline = pak_offline[1..].to_vec();
            assert_eq!(
                Err(Error::InvalidPakList),
                WhitelistSignature::new(
                    SECP256K1,
                    &pak_online,
                    &offline, // wrong pak
                    &whitelist_pk,
                    &keys_online[our_idx],
                    &summed_key,
                    our_idx,
                )
            );
        }

        let correct_signature = WhitelistSignature::new(
            SECP256K1,
            &pak_online,
            &pak_offline,
            &whitelist_pk,
            &keys_online[our_idx],
            &summed_key,
            our_idx,
        )
        .unwrap();

        {
            // wrong n_keys
            let sig = unsafe {
                let sig = correct_signature.clone();
                let ptr = sig.as_c_ptr() as *mut ffi::WhitelistSignature;
                (*ptr).n_keys -= 1;
                sig
            };
            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                sig.verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk,)
            );
        }

        {
            // wrong pak
            let offline = pak_offline[1..].to_vec();
            assert_eq!(
                Err(Error::InvalidPakList),
                correct_signature.verify(SECP256K1, &pak_online, &offline, &whitelist_pk,)
            );
        }

        {
            // verify for online pubkey
            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                correct_signature.verify(
                    SECP256K1,
                    &pak_online,
                    &pak_offline,
                    &pak_online[our_idx],
                )
            );
        }

        {
            // verify for offline pubkey
            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                correct_signature.verify(
                    SECP256K1,
                    &pak_online,
                    &pak_offline,
                    &pak_offline[our_idx],
                )
            );
        }

        {
            // incorrectly serialized with byte added
            let mut encoded = correct_signature.serialize();
            encoded.push(42);
            assert_eq!(
                Err(Error::InvalidWhitelistSignature),
                WhitelistSignature::from_slice(&encoded),
            );
        }

        {
            // incorrectly serialized with byte changed
            let mut encoded = correct_signature.serialize();
            let len = encoded.len();
            encoded[len - 1] = encoded[len - 1] ^ 0x01;
            let decoded = WhitelistSignature::from_slice(&encoded).unwrap();
            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                decoded.verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk,)
            );
        }

        {
            // offline key instead of summed
            let sig = WhitelistSignature::new(
                SECP256K1,
                &pak_online,
                &pak_offline,
                &whitelist_pk,
                &keys_online[our_idx],
                &keys_offline[our_idx], // actual offline key, not summed
                our_idx,
            )
            .unwrap();

            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                sig.verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk,)
            );
            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                sig.verify(SECP256K1, &pak_online, &pak_offline, &pak_offline[our_idx],)
            );
        }

        {
            // whitelist key instead of summed
            let sig = WhitelistSignature::new(
                SECP256K1,
                &pak_online,
                &pak_offline,
                &whitelist_pk,
                &keys_online[our_idx],
                &whitelist_sk, // whitelist key, not summed
                our_idx,
            )
            .unwrap();

            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                sig.verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk,)
            );
        }

        assert_eq!(
            Ok(()),
            correct_signature.verify(SECP256K1, &pak_online, &pak_offline, &whitelist_pk,)
        );
    }
}
