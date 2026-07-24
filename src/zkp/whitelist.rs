//! Bindings for the "whitelist" ring signature implementation in secp256k1-zkp.
//!
//! This implementation is used for Liquid PAK list inclusion proofs.

#[cfg(feature = "std")]
use std::{fmt, str};

use crate::ffi::CPtr;
#[cfg(feature = "std")]
use crate::from_hex;
use crate::ConvertFromUpstream as _;
use crate::{ffi, Error, Secp256k1, Signing, Verification};

use secp256k1::{PublicKey, SecretKey};

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
                online_keys.to_zkp_ffi(),
                offline_keys.to_zkp_ffi(),
                n_keys,
                whitelist_key.to_zkp_ffi(),
                online_secret_key.as_ref().as_ptr(),
                summed_secret_key.as_ref().as_ptr(),
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
                online_keys.to_zkp_ffi(),
                offline_keys.to_zkp_ffi(),
                n_keys,
                whitelist_key.to_zkp_ffi(),
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
        for ch in &self.serialize() {
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
        from_hex(s, &mut buf).map_err(|()| Error::InvalidWhitelistSignature)?;
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

#[cfg(test)]
/// Test utilities related to creating and verifying whitelist proofs.
pub mod whitelist_test_util {
    use crate::test_util::KeyPairStream;
    use crate::{Secp256k1, Signing, Verification};

    use secp256k1::{PublicKey, SecretKey};

    use super::WhitelistSignature;

    /// All the keys that are needed to generate a whitelist proof.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct KeySet {
        /// Online secret keys.
        pub keys_online: Vec<SecretKey>,
        /// Online public keys.
        pub pak_online: Vec<PublicKey>,
        /// Offline secret keys.
        pub keys_offline: Vec<SecretKey>,
        /// Offline public keys.
        pub pak_offline: Vec<PublicKey>,
        /// Secret key of the address we're going to whitelist.
        pub whitelist_sk: SecretKey,
        /// Public key of the address we're going to whitelist.
        pub whitelist_pk: PublicKey,
    }

    impl KeySet {
        /// Generates a list of keypairs that can be used with a whitelist test.
        pub fn new(n_keys: usize) -> Self {
            let iter = &mut KeyPairStream::new();
            let (keys_online, pak_online) = iter.take(n_keys).unzip();
            let (keys_offline, pak_offline) = iter.take(n_keys).unzip();
            let (whitelist_sk, whitelist_pk) = iter.next().unwrap();
            Self {
                keys_online,
                pak_online,
                keys_offline,
                pak_offline,
                whitelist_sk,
                whitelist_pk,
            }
        }
    }

    /// Generates a valid test whitelist proof, given a set of keypairs.
    ///
    /// # Panics
    ///
    /// Panics if `our_idx` is out of range for the key set.
    pub fn whitelist_prove<C: Signing>(
        ctx: &Secp256k1<C>,
        key_set: &KeySet,
        our_idx: usize,
    ) -> Result<WhitelistSignature, crate::Error> {
        let summed_key = key_set.keys_offline[our_idx]
            .add_tweak(&key_set.whitelist_sk.into())
            .unwrap();

        WhitelistSignature::new(
            ctx,
            &key_set.pak_online,
            &key_set.pak_offline,
            &key_set.whitelist_pk,
            &key_set.keys_online[our_idx],
            &summed_key,
            our_idx,
        )
    }

    /// Validates a whitelist proof, given a set of keypairs.
    pub fn whitelist_verify<C: Verification>(
        ctx: &Secp256k1<C>,
        key_set: &KeySet,
        signature: &WhitelistSignature,
    ) -> Result<(), crate::Error> {
        signature.verify(
            ctx,
            &key_set.pak_online,
            &key_set.pak_offline,
            &key_set.whitelist_pk,
        )
    }
}

#[cfg(test)]
#[cfg(feature = "global-context")]
mod tests {
    use super::*;
    use crate::SECP256K1;

    use super::whitelist_test_util as test_util;

    fn test_whitelist_proof_roundtrip(n_keys: usize) {
        let keyset = test_util::KeySet::new(n_keys);

        for our_idx in vec![0, n_keys / 2, n_keys - 1].into_iter() {
            // sign
            let signature = test_util::whitelist_prove(SECP256K1, &keyset, our_idx).unwrap();
            assert_eq!(n_keys, signature.n_keys());

            // verify
            test_util::whitelist_verify(SECP256K1, &keyset, &signature).unwrap();

            // round trip
            let encoded = signature.serialize();
            let decoded = WhitelistSignature::from_slice(&encoded).unwrap();
            assert_eq!(n_keys, decoded.n_keys());
            assert_eq!(signature, decoded);
            test_util::whitelist_verify(SECP256K1, &keyset, &decoded).unwrap();
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
        let our_idx = 100;
        let original_keyset = test_util::KeySet::new(n_keys);

        // Missing an offline public key.
        let keyset = test_util::KeySet {
            pak_offline: original_keyset.pak_offline[1..].to_vec(),
            ..original_keyset.clone()
        };
        assert_eq!(
            Err(Error::InvalidPakList),
            test_util::whitelist_prove(SECP256K1, &keyset, our_idx),
        );
        // Missing a full offline keypair.
        let keyset = test_util::KeySet {
            keys_offline: keyset.keys_offline[1..].to_vec(),
            ..keyset
        };
        assert_eq!(
            Err(Error::InvalidPakList),
            test_util::whitelist_prove(SECP256K1, &keyset, our_idx),
        );

        let correct_signature =
            test_util::whitelist_prove(SECP256K1, &original_keyset, our_idx).unwrap();

        // validate with wrong n_keys
        let mut wrong_n_keys = correct_signature.clone();
        wrong_n_keys.0.n_keys -= 1;
        assert_eq!(
            Err(Error::InvalidWhitelistProof),
            test_util::whitelist_verify(SECP256K1, &original_keyset, &wrong_n_keys),
        );

        // wrong pak
        assert_eq!(
            Err(Error::InvalidPakList),
            test_util::whitelist_verify(SECP256K1, &keyset, &correct_signature),
        );

        // wrong pubkey
        let keyset = test_util::KeySet {
            whitelist_pk: original_keyset.pak_online[our_idx],
            ..original_keyset.clone()
        };
        assert_eq!(
            Err(Error::InvalidWhitelistProof),
            test_util::whitelist_verify(SECP256K1, &keyset, &correct_signature),
        );
        let keyset = test_util::KeySet {
            whitelist_pk: original_keyset.pak_offline[our_idx],
            ..original_keyset.clone()
        };
        assert_eq!(
            Err(Error::InvalidWhitelistProof),
            test_util::whitelist_verify(SECP256K1, &keyset, &correct_signature),
        );

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
            encoded[len - 1] ^= 0x01;
            let decoded = WhitelistSignature::from_slice(&encoded).unwrap();
            assert_eq!(
                Err(Error::InvalidWhitelistProof),
                test_util::whitelist_verify(SECP256K1, &original_keyset, &decoded),
            );
        }

        let ks = original_keyset.clone();
        // offline key instead of summed
        let sig = WhitelistSignature::new(
            SECP256K1,
            &ks.pak_online,
            &ks.pak_offline,
            &ks.whitelist_pk,
            &ks.keys_online[our_idx],
            &ks.keys_offline[our_idx], // actual offline key, not summed
            our_idx,
        )
        .unwrap();

        assert_eq!(
            Err(Error::InvalidWhitelistProof),
            sig.verify(SECP256K1, &ks.pak_online, &ks.pak_offline, &ks.whitelist_pk)
        );
        assert_eq!(
            Err(Error::InvalidWhitelistProof),
            sig.verify(
                SECP256K1,
                &ks.pak_online,
                &ks.pak_offline,
                &ks.pak_offline[our_idx]
            )
        );

        // whitelist key instead of summed
        let sig = WhitelistSignature::new(
            SECP256K1,
            &ks.pak_online,
            &ks.pak_offline,
            &ks.whitelist_pk,
            &ks.keys_online[our_idx],
            &ks.whitelist_sk, // whitelist key, not summed
            our_idx,
        )
        .unwrap();

        assert_eq!(
            Err(Error::InvalidWhitelistProof),
            sig.verify(SECP256K1, &ks.pak_online, &ks.pak_offline, &ks.whitelist_pk)
        );

        assert_eq!(
            Ok(()),
            correct_signature.verify(SECP256K1, &ks.pak_online, &ks.pak_offline, &ks.whitelist_pk)
        );
    }
}
