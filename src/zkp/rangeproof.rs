use ffi::CPtr;

use crate::ffi::RANGEPROOF_MAX_LENGTH;
use crate::from_hex;
use crate::Error;
use crate::Generator;
use crate::PedersenCommitment;
use crate::Verification;
use crate::{ffi, Secp256k1, SecretKey, Signing, Tweak};
use std::ops::Range;
use std::str;

/// Represents a range proof.
///
/// TODO: Store rangeproof info
#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct RangeProof {
    inner: ffi::RangeProof,
}

impl RangeProof {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Parse from byte slice.
    ///
    /// TODO: Rename to parse (and other similar functions)
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut exp = 0;
        let mut mantissa = 0;
        let mut min_value = 0;
        let mut max_value = 0;

        let ret = unsafe {
            ffi::secp256k1_rangeproof_info(
                ffi::secp256k1_context_no_precomp,
                &mut exp,
                &mut mantissa,
                &mut min_value,
                &mut max_value,
                bytes.as_ptr(),
                bytes.len(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidRangeProof);
        }

        Ok(RangeProof {
            inner: ffi::RangeProof::new(bytes),
        })
    }

    /// Get length.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if it's empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Prove that `commitment` hides a value within a range, with the lower bound set to `min_value`.
    #[allow(clippy::too_many_arguments)]
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        min_value: u64,
        commitment: PedersenCommitment,
        value: u64,
        commitment_blinding: Tweak,
        message: &[u8],
        additional_commitment: &[u8],
        sk: SecretKey,
        exp: i32,
        min_bits: u8,
        additional_generator: Generator,
    ) -> Result<RangeProof, Error> {
        let mut proof = [0u8; RANGEPROOF_MAX_LENGTH];
        let mut proof_length = RANGEPROOF_MAX_LENGTH;

        let ret = unsafe {
            ffi::secp256k1_rangeproof_sign(
                secp.ctx().as_ptr(),
                proof.as_mut_ptr(),
                &mut proof_length,
                min_value,
                commitment.as_inner(),
                commitment_blinding.as_c_ptr(),
                sk.as_c_ptr(),
                exp,
                min_bits as i32,
                value,
                message.as_ptr(),
                message.len(),
                additional_commitment.as_ptr(),
                additional_commitment.len(),
                additional_generator.as_inner(),
            )
        };

        if ret == 0 {
            return Err(Error::CannotMakeRangeProof);
        }

        Ok(RangeProof {
            inner: ffi::RangeProof::new(&proof[..proof_length]),
        })
    }

    /// Verify that the committed value is within a range.
    ///
    /// If the verification is successful, return the actual range of possible values.
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        commitment: PedersenCommitment,
        additional_commitment: &[u8],
        additional_generator: Generator,
    ) -> Result<Range<u64>, Error> {
        let mut min_value = 0u64;
        let mut max_value = 0u64;

        let ret = unsafe {
            ffi::secp256k1_rangeproof_verify(
                secp.ctx().as_ptr(),
                &mut min_value,
                &mut max_value,
                commitment.as_inner(),
                self.inner.as_ptr(),
                self.inner.len(),
                additional_commitment.as_ptr(),
                additional_commitment.len(),
                additional_generator.as_inner(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidRangeProof);
        }

        Ok(Range {
            start: min_value,
            end: max_value + 1,
        })
    }

    /// Verify a range proof proof and rewind the proof to recover information sent by its author.
    pub fn rewind<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        commitment: PedersenCommitment,
        sk: SecretKey,
        additional_commitment: &[u8],
        additional_generator: Generator,
    ) -> Result<(Opening, Range<u64>), Error> {
        let mut min_value = 0u64;
        let mut max_value = 0u64;

        let mut blinding_factor = [0u8; 32];
        let mut value = 0u64;
        let mut message = [0u8; 4096];
        let mut message_length = 4096usize;

        let ret = unsafe {
            ffi::secp256k1_rangeproof_rewind(
                secp.ctx().as_ptr(),
                blinding_factor.as_mut_ptr(),
                &mut value,
                message.as_mut_ptr(),
                &mut message_length,
                sk.as_c_ptr(),
                &mut min_value,
                &mut max_value,
                commitment.as_inner(),
                self.inner.as_ptr(),
                self.inner.len(),
                additional_commitment.as_ptr(),
                additional_commitment.len(),
                additional_generator.as_inner(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidRangeProof);
        }

        let opening = Opening {
            value,
            blinding_factor: Tweak::from_slice(&blinding_factor)?,
            message: message[..message_length].into(),
        };

        let range = Range {
            start: min_value,
            end: max_value + 1,
        };

        Ok((opening, range))
    }
}

#[cfg(feature = "hashes")]
impl ::core::fmt::Display for RangeProof {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        use internals::hex::display::DisplayHex;

        write!(f, "{:x}", &self.serialize().as_slice().as_hex())
    }
}

impl str::FromStr for RangeProof {
    type Err = Error;
    fn from_str(s: &str) -> Result<RangeProof, Error> {
        let mut res = vec![0u8; s.len() / 2];
        match from_hex(s, &mut res) {
            Ok(_) => RangeProof::from_slice(&res),
            _ => Err(Error::InvalidRangeProof),
        }
    }
}

#[cfg(all(feature = "serde", feature = "hashes"))]
impl ::serde::Serialize for RangeProof {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(all(feature = "serde", feature = "hashes"))]
impl<'de> ::serde::Deserialize<'de> for RangeProof {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<RangeProof, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                RangeProof::from_slice,
            ))
        }
    }
}

/// The result of rewinding a range proof.
///
/// Rewinding a range proof reveals ("opens") the stored information and allows us to access information the prover embedded in the proof.
pub struct Opening {
    /// The value that the prover originally committed to in the Pedersen commitment.
    pub value: u64,
    /// The blinding factor that was used to create the Pedersen commitment of above value.
    pub blinding_factor: Tweak,
    /// The message that was embedded by the prover.
    pub message: Box<[u8]>,
}

#[cfg(all(test, feature = "global-context"))] // use global context for convenience
mod tests {
    use super::*;
    use crate::{CommitmentSecrets, Tag, SECP256K1};
    use rand::thread_rng;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn create_and_verify_range_proof() {
        let value = 1_000;
        let commitment_secrets = CommitmentSecrets::random(value);
        let tag = Tag::random();
        let commitment = commitment_secrets.commit(tag);

        let message = b"foo";
        let additional_commitment = b"bar";

        let sk = SecretKey::new(&mut thread_rng());
        let additional_generator =
            Generator::new_blinded(SECP256K1, tag, commitment_secrets.generator_blinding_factor);

        let proof = RangeProof::new(
            SECP256K1,
            1,
            commitment,
            value,
            commitment_secrets.value_blinding_factor,
            message,
            additional_commitment,
            sk,
            0,
            52,
            additional_generator,
        )
        .unwrap();

        proof
            .verify(
                SECP256K1,
                commitment,
                additional_commitment,
                additional_generator,
            )
            .unwrap();

        #[cfg(feature = "hashes")]
        {
            use std::str::FromStr;
            use std::string::ToString;
            let proof_str = proof.to_string();
            assert_eq!(proof, RangeProof::from_str(&proof_str).unwrap());
        }
    }

    #[test]
    fn rewind_range_proof() {
        let value = 1_000;
        let commitment_secrets = CommitmentSecrets::random(value);
        let tag = Tag::random();
        let commitment = commitment_secrets.commit(tag);

        let message = b"foo";
        let additional_commitment = b"bar";

        let sk = SecretKey::new(&mut thread_rng());
        let additional_generator =
            Generator::new_blinded(SECP256K1, tag, commitment_secrets.generator_blinding_factor);

        let proof = RangeProof::new(
            SECP256K1,
            1,
            commitment,
            value,
            commitment_secrets.value_blinding_factor,
            message,
            additional_commitment,
            sk,
            0,
            52,
            additional_generator,
        )
        .unwrap();

        let (opening, _range) = proof
            .rewind(
                SECP256K1,
                commitment,
                sk,
                additional_commitment,
                additional_generator,
            )
            .unwrap();

        assert_eq!(opening.value, commitment_secrets.value);
        assert_eq!(
            opening.blinding_factor,
            commitment_secrets.value_blinding_factor
        );

        assert!(opening.message.starts_with(message));
        assert!(opening
            .message
            .ends_with(&vec![0; opening.message.len() - message.len()]));
    }
}
