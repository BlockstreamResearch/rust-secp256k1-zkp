use ffi::CPtr;

use crate::ffi::RANGEPROOF_MAX_LENGTH;
use crate::from_hex;
use crate::Generator;
use crate::PedersenCommitment;
use crate::{ffi, Tweak};

use secp256k1::SecretKey;

use core::{fmt, ops, str};

/// Rangeproof failed to validate.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct InvalidRangeProofError;

impl fmt::Display for InvalidRangeProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self = *self;
        f.write_str("invalid rangeproof")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidRangeProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self = *self;
        None
    }
}

/// Value did not lie in the range implied by a [`RangeProofInfo`].
#[derive(Clone, PartialEq, Eq, Debug)]
enum InvalidValueErrorInner {
    /// The rangeproof was for an exact value, and this is not that value.
    Exact,
    Minimum,
    Exponent,
    Mantissa,
}

/// Value did not lie in the range implied by a [`RangeProofInfo`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InvalidValueError {
    inner: InvalidValueErrorInner,
    value: u64,
    info: RangeProofInfo,
}

impl fmt::Display for InvalidValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InvalidValueErrorInner as Inn;
        match (&self.inner, &self.info) {
            (Inn::Exact, RangeProofInfo::Exact(target)) => {
                write!(f, "value {} cannot be proven exactly equal to {}", self.value, target)
            },
            (Inn::Exact, RangeProofInfo::Range { .. }) => unreachable!(),
            (_, RangeProofInfo::Exact(_)) => unreachable!(),
            (Inn::Minimum, RangeProofInfo::Range { minimum, .. }) => {
                write!(f, "value {} is below minimum {}", self.value, minimum)
            },
            (Inn::Exponent, RangeProofInfo::Range { minimum, exponent, .. }) => {
                write!(f, "value {} is not {} plus a multiple of 10^{}", self.value, minimum, exponent)
            },
            (Inn::Mantissa, RangeProofInfo::Range { minimum, exponent, mantissa }) => {
                write!(f, "value {} is {} plus x*10^{} where x >= 2^{}", self.value, minimum, exponent, mantissa)
            },
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidValueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { inner: _, value: _, info: _ } = *self;
        None
    }
}

/// Error constructing a [`RangeProofInfoError`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RangeProofInfoError {
    /// The base-10 exponent would have unconditionally put the range outside of `[0, 2^64)`.
    ExponentTooHigh(usize),
    /// The mantissa (bit width) would have unconditionally put the range outside of `[0, 2^64)`.
    MantissaTooHigh(usize),
    /// The rangeproof parameters, while individually sensible, together put the range
    /// outside of `[0, 2^64)`.
    RangeWillBeTruncated {
        /// The rangeproof parameters, reduced to put the final range within `[0, 2^64)`.
        truncated_info: RangeProofInfo,
    },
}

impl fmt::Display for RangeProofInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ExponentTooHigh(exp) => write!(
                f,
                "exponent {exp} exceeds maximum {}",
                RangeProofInfo::MAX_EXPONENT,
            ),
            Self::MantissaTooHigh(exp) => write!(
                f,
                "mantissa {exp} exceeds maximum {}",
                RangeProofInfo::MAX_MANTISSA,
            ),
            Self::RangeWillBeTruncated { .. } => {
                f.write_str("rangeproof settings imply a maximum value in excess of u64::MAX")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RangeProofInfoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::ExponentTooHigh(_) => None,
            Self::MantissaTooHigh(_) => None,
            Self::RangeWillBeTruncated { .. } => None,
        }
    }
}

/// Information about the range proven by a rangeproof.
///
/// This can be constructed directly with arbitrary values, but in this case [`RangeProof::new`]
/// may return an error. To avoid this, use [`RangeProofInfo::new_range`] to first validate the
/// parameters.
#[derive(Copy, Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub enum RangeProofInfo {
    /// The rangeproof proves that the commitment is to an exact (public) value.
    Exact(u64),
    /// The rangeproof proves that the commitment is to a number within a range.
    Range {
        /// The minimum value of the range. For privacy reasons, this should almost always be 0 or
        /// 1 (whichever is the least value allowed by consensus rules).
        minimum: u64,
        /// The least power of 10 that the value (with `minimum` subtracted) might be a multiple of.
        ///
        /// For privacy reasons this should basically always be set to zero. If this is set greater
        /// than 18, proving will fail.
        exponent: u8,
        /// The number of bits wide the range is. Also known as `min_bits` in some APIs.
        ///
        /// In general, given a valid rangeproof, the values the committed value might take are
        /// `minimum + 10^exponent * i` where `i` ranges from 0 up to `2^mantissa - 1`.
        ///
        /// For privacy reasons, this should be at least 52 for Bitcoin amounts, and 64 for other
        /// assets. The size of the resulting proof is directly proportional to this value so
        /// there is a privacy vs cost tradeoff.
        ///
        /// If this is set greater than 64, proving will fail.
        mantissa: u8,
    },
}

impl RangeProofInfo {
    /// The maximum allowable value for the `exponent` field of a [`RangeProofInfo`].
    pub const MAX_EXPONENT: u8 = 18;

    /// The maximum allowable value for the `mantissa` field of a [`RangeProofInfo`].
    pub const MAX_MANTISSA: u8 = 64;

    /// Constructs a [`RangeProofInfo`] for an exact value.
    ///
    /// Equivalent to [`Self::Exact`] but provided for symmetry with [`Self::new_range`].
    #[inline]
    pub const fn new_exact(value: u64) -> Self {
        Self::Exact(value)
    }

    /// Constructs a [`RangeProofInfo`]
    pub fn new_range(
        minimum: u64,
        exponent: usize,
        mantissa: usize,
    ) -> Result<Self, RangeProofInfoError> {
        let exponent =
            u8::try_from(exponent).map_err(|_| RangeProofInfoError::ExponentTooHigh(exponent))?;
        let mantissa =
            u8::try_from(mantissa).map_err(|_| RangeProofInfoError::MantissaTooHigh(mantissa))?;

        if exponent > Self::MAX_EXPONENT {
            return Err(RangeProofInfoError::ExponentTooHigh(usize::from(exponent)));
        }
        if mantissa > Self::MAX_MANTISSA {
            return Err(RangeProofInfoError::MantissaTooHigh(usize::from(mantissa)));
        }

        let ret = Self::Range {
            minimum,
            exponent,
            mantissa,
        };
        // Check that the maximum value is representable as a u64.
        if mantissa == 64 {
            return if minimum == 0 && exponent == 0 {
                Ok(ret)
            } else {
                let ret = Self::Range { minimum: 0, exponent: 0, mantissa: 64 };
                Err(RangeProofInfoError::RangeWillBeTruncated { truncated_info: ret })
            };
        }
        debug_assert!(mantissa < 64);
        minimum.checked_add(
            10u64.pow(u32::from(exponent))
                .checked_mul(if mantissa == 64 { u64::MAX } else { (1u64 << mantissa) - 1 })
                .ok_or(RangeProofInfoError::RangeWillBeTruncated { truncated_info: ret })?
            ).ok_or(RangeProofInfoError::RangeWillBeTruncated { truncated_info: ret })?;

        Ok(ret)
    }

    /// Constructs a [`RangeProofInfo`] from the raw values returned from rust-secp-zkp.
    ///
    /// # Panics
    ///
    /// Panics if `exponent` is negative but not equal to -1, or if `max_value` does not match
    /// the computed maximum value, or if any of the inputs are out of range.
    fn new_from_raw_data(exponent: i32, mantissa: i32, min_value: u64, max_value: u64) -> Self {
        let exponent = match u8::try_from(exponent) {
            Ok(exp) => exp,
            Err(_) => {
                assert_eq!(exponent, -1);
                assert_eq!(mantissa, 0);
                assert_eq!(min_value, max_value);
                return Self::Exact(min_value);
            }
        };
        let mantissa =
            u8::try_from(mantissa).expect("mantissa is encoded in 6 bits and fits in u8");

        let ret = Self::new_range(min_value, usize::from(exponent), usize::from(mantissa))
            .expect("data extracted from a passing rangeproof must be valid");
        assert_eq!(ret.maximum_value(), Some(max_value));
        ret
    }

    /// The minimum value allowed by a proof with this [`RangeProofInfo`].
    #[inline]
    pub fn minimum_value(&self) -> u64 {
        match *self {
            Self::Exact(n) => n,
            Self::Range { minimum, .. } => minimum,
        }
    }

    /// The (base-10) exponent of the proof, or -1 for exact proofs.
    ///
    /// This value is intended to be used by the C API. For Rust use it is better to just match
    /// directly on the [`RangeProofInfo`] and handle both cases separately.
    #[inline]
    pub fn raw_exponent(&self) -> i32 {
        match *self {
            Self::Exact(_) => -1,
            Self::Range { exponent, .. } => i32::from(exponent),
        }
    }

    /// The (base-2) mantissa of the proof.
    #[inline]
    pub fn mantissa(&self) -> u8 {
        match *self {
            Self::Exact(_) => 0,
            Self::Range { mantissa, .. } => mantissa,
        }
    }

    /// The maximum value allowed by a proof with this [`RangeProofInfo`].
    ///
    /// # Returns
    ///
    /// Returns `None` if the maximum value would exceed `u64::MAX`.
    pub fn maximum_value(&self) -> Option<u64> {
        match *self {
            Self::Exact(n) => Some(n),
            Self::Range {
                minimum,
                mantissa,
                exponent,
            } => {
                let bin_range = if mantissa == 64 {
                    u64::MAX
                } else {
                    2u64.checked_pow(u32::from(mantissa))? - 1
                };
                let dec_range = bin_range.checked_mul(10u64.checked_pow(u32::from(exponent))?)?;
                minimum.checked_add(dec_range)
            }
        }
    }

    /// The range of possible values that the proven value may have.
    ///
    /// # Return
    ///
    /// Returns `None` if there is no maximum value (see [`Self::maximum_value`]) or if the
    /// `exponent` field is nonzero.
    #[inline]
    pub fn to_range(&self) -> Option<ops::RangeInclusive<u64>> {
        if let Self::Range { exponent, .. } = self {
            if *exponent > 0 {
                // If there is a nonzero exponent, the possible values differ by 10, 100, etc.,
                // rather than 1, so a range is misleading.
                return None;
            }
        }
        // For a zero exponent, we have a range iff we have a maximum value.
        self.maximum_value().map(|max| self.minimum_value()..=max)
    }

    /// Whether a given number lies within the range of the [`RangeProofInfo`].
    ///
    /// Will fail if the value is too large or small, or if the `exponent` value of the
    /// rangeproof info is positive and the value is not a multiple of the appropriate
    /// power of 10.
    #[inline]
    pub fn is_valid_for(&self, value: u64) -> Result<(), InvalidValueError> {
        let err = |inner| Err(InvalidValueError { inner, value, info: *self });
        match *self {
            Self::Exact(target) if value == target => Ok(()),
            Self::Exact(_) => err(InvalidValueErrorInner::Exact),
            Self::Range { minimum, exponent, mantissa } => {
                if value < minimum {
                    return err(InvalidValueErrorInner::Minimum);
                }
                let mut value_reduced = value - minimum;

                let pow = 10u64.pow(u32::from(exponent));
                if value_reduced % pow != 0 {
                    return err(InvalidValueErrorInner::Exponent);
                }
                value_reduced /= pow;

                if mantissa == 64 || value_reduced < 1 << mantissa {
                    Ok(())
                } else {
                    err(InvalidValueErrorInner::Mantissa)
                }
            }
        }
    }
}

/// Represents a range proof.
#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct RangeProof {
    inner: Box<[u8]>,
    info: RangeProofInfo,
}

impl RangeProof {
    /// Directly access the bytes of the rangeproof.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Directly access the bytes of the rangeproof.
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.to_vec()
    }

    /// Obtains the metadata of the rangeproof.
    ///
    /// This information is available from any rangeproof that parses successfully, but it should
    /// **not** be trusted unless the rangeproof has been verified with [`Self::verify`].
    pub fn info(&self) -> &RangeProofInfo {
        &self.info
    }

    /// Parse from byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidRangeProofError> {
        let mut exponent = 0;
        let mut mantissa = 0;
        let mut min_value = 0;
        let mut max_value = 0;

        let ret = unsafe {
            ffi::secp256k1_rangeproof_info(
                ffi::secp256k1_context_static,
                &mut exponent,
                &mut mantissa,
                &mut min_value,
                &mut max_value,
                bytes.as_ptr(),
                bytes.len(),
            )
        };

        if ret == 0 {
            return Err(InvalidRangeProofError);
        }

        Ok(RangeProof {
            inner: Box::from(bytes),
            info: RangeProofInfo::new_from_raw_data(exponent, mantissa, min_value, max_value),
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
    ///
    /// `value` and `commitment_blinding` reprsenet the secret opening and should be kept private.
    /// `nonce` is used to seed the RNG used to generate the proof. It MUST be unique and secret
    /// (i.e. it should contain at least 128 bits of entropy). Anybody who learns this nonce will
    /// be able to decode the amount and blinding factor from the rangeproof, as well as any
    /// embedded message.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        info: RangeProofInfo,
        commitment: PedersenCommitment,
        value: u64,
        commitment_blinding: Tweak,
        message: &[u8],
        additional_commitment: &[u8],
        nonce: SecretKey,
        additional_generator: Generator,
    ) -> Result<Self, InvalidValueError> {
        info.is_valid_for(value)?;

        let mut proof = [0u8; RANGEPROOF_MAX_LENGTH];
        let mut proof_length = RANGEPROOF_MAX_LENGTH;

        let ret = crate::context::with_raw_global_context(
            |ctx| unsafe {
                ffi::secp256k1_rangeproof_sign(
                    ctx.as_ptr(),
                    proof.as_mut_ptr(),
                    &mut proof_length,
                    info.minimum_value(),
                    commitment.as_inner(),
                    commitment_blinding.as_c_ptr(),
                    nonce.as_secret_bytes().as_ptr(),
                    info.raw_exponent(),
                    i32::from(info.mantissa()),
                    value,
                    message.as_ptr(),
                    message.len(),
                    additional_commitment.as_ptr(),
                    additional_commitment.len(),
                    additional_generator.as_inner(),
                )
            },
            Some(nonce.as_secret_bytes()),
        );
        assert_eq!(ret, 1, "rangeproof parameters should be validated by Rust type constructors");

        Ok(RangeProof {
            inner: Box::from(&proof[..proof_length]),
            info,
        })
    }

    /// Verify that the committed value is within a range.
    ///
    /// If the verification is successful, return the actual range of possible values.
    pub fn verify(
        &self,
        commitment: PedersenCommitment,
        additional_commitment: &[u8],
        additional_generator: Generator,
    ) -> Result<RangeProofInfo, InvalidRangeProofError> {
        let mut min_value = 0u64;
        let mut max_value = 0u64;

        let ret = crate::context::with_raw_global_context(
            |ctx| unsafe {
                ffi::secp256k1_rangeproof_verify(
                    ctx.as_ptr(),
                    &mut min_value,
                    &mut max_value,
                    commitment.as_inner(),
                    self.inner.as_ptr(),
                    self.inner.len(),
                    additional_commitment.as_ptr(),
                    additional_commitment.len(),
                    additional_generator.as_inner(),
                )
            },
            None,
        );

        if ret == 0 {
            return Err(InvalidRangeProofError);
        }

        assert_eq!(min_value, self.info.minimum_value());
        assert_eq!(Some(max_value), self.info.maximum_value());

        Ok(self.info)
    }

    /// Verify a range proof proof and rewind the proof to recover information sent by its author.
    pub fn rewind(
        &self,
        commitment: PedersenCommitment,
        nonce: SecretKey,
        additional_commitment: &[u8],
        additional_generator: Generator,
    ) -> Result<(Opening, RangeProofInfo), InvalidRangeProofError> {
        let mut min_value = 0u64;
        let mut max_value = 0u64;

        let mut blinding_factor = [0u8; 32];
        let mut value = 0u64;
        let mut message = [0u8; 4096];
        let mut message_length = 4096usize;

        let ret = crate::context::with_raw_global_context(
            |ctx| unsafe {
                ffi::secp256k1_rangeproof_rewind(
                    ctx.as_ptr(),
                    blinding_factor.as_mut_ptr(),
                    &mut value,
                    message.as_mut_ptr(),
                    &mut message_length,
                    nonce.as_secret_bytes().as_ptr(),
                    &mut min_value,
                    &mut max_value,
                    commitment.as_inner(),
                    self.inner.as_ptr(),
                    self.inner.len(),
                    additional_commitment.as_ptr(),
                    additional_commitment.len(),
                    additional_generator.as_inner(),
                )
            },
            Some(nonce.as_secret_bytes()),
        );

        if ret == 0 {
            return Err(InvalidRangeProofError);
        }

        // libsecp256k1 will validate that the opening is valid, i.e. it matches the proven
        // commitment. So we don't need to check this, or whether it's in-range for self.info,
        // or whatever.
        let opening = Opening {
            value,
            blinding_factor: Tweak::from_byte_array(blinding_factor)
                .expect("libsecp256k1zkp validates this tweak"),
            message: message[..message_length].into(),
        };

        Ok((opening, self.info))
    }
}

#[cfg(feature = "hashes")]
impl ::core::fmt::Display for RangeProof {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        use internals::hex::display::DisplayHex;

        write!(f, "{:x}", &self.as_slice().as_hex())
    }
}

impl str::FromStr for RangeProof {
    type Err = InvalidRangeProofError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = vec![0u8; s.len() / 2];
        match from_hex(s, &mut res) {
            Ok(_) => RangeProof::from_slice(&res),
            _ => Err(InvalidRangeProofError),
        }
    }
}

#[cfg(all(feature = "serde", feature = "hashes"))]
impl ::serde::Serialize for RangeProof {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&self)
        } else {
            s.serialize_bytes(&self.as_slice())
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
#[derive(Debug)]
pub struct Opening {
    /// The value that the prover originally committed to in the Pedersen commitment.
    pub value: u64,
    /// The blinding factor that was used to create the Pedersen commitment of above value.
    pub blinding_factor: Tweak,
    /// The message that was embedded by the prover.
    pub message: Box<[u8]>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parsing_full_width_header_does_not_panic() {
        // from_slice checks the header, not the cryptographic proof.
        // Either Ok or Err is acceptable here; panicking is not.
        let mut bytes = [0u8; 65];
        bytes[..2].copy_from_slice(&[0x40, 0x3f]);
        let _ = RangeProof::from_slice(&bytes);
    }

    #[test]
    fn constructor_rejects_multiplicative_overflow() {
        assert!(matches!(
            RangeProofInfo::new_range(0, 18, 5),
            Err(RangeProofInfoError::RangeWillBeTruncated { .. })
        ));
    }

    #[test]
    fn constructor_accepts_representable_upper_boundary() {
        let info = RangeProofInfo::new_range(u64::MAX - 1, 0, 1).unwrap();
        assert_eq!(info.maximum_value(), Some(u64::MAX));
    }

    #[test]
    fn parsing_upper_boundary_header_does_not_panic() {
        let mut bytes = [0u8; 65];
        bytes[..2].copy_from_slice(&[0x60, 0x00]);
        bytes[2..10].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
        let _ = RangeProof::from_slice(&bytes);
    }

    #[test]
    fn full_width_maximum_is_representable() {
        let info = RangeProofInfo::new_range(0, 0, 64).unwrap();
        assert_eq!(info.maximum_value(), Some(u64::MAX));
        assert_eq!(info.to_range(), Some(0..=u64::MAX));
    }
}

#[cfg(all(test, feature = "rand"))]
mod rand_tests {
    use super::*;

    use crate::{CommitmentSecrets, Tag};
    use crate::rand::rng;

    #[test]
    fn create_and_verify_range_proof() {
        let value = 1_000;
        let commitment_secrets = CommitmentSecrets::random(value);
        let tag = Tag::random();
        let commitment = commitment_secrets.commit(tag);

        let message = b"foo";
        let additional_commitment = b"bar";

        let nonce = SecretKey::new(&mut rng());
        let additional_generator =
            Generator::new_blinded(tag, commitment_secrets.generator_blinding_factor);

        let info = RangeProofInfo::new_range(1, 0, 52).unwrap();
        let proof = RangeProof::new(
            info,
            commitment,
            value,
            commitment_secrets.value_blinding_factor,
            message,
            additional_commitment,
            nonce,
            additional_generator,
        )
        .unwrap();

        let extracted_info = proof
            .verify(
                commitment,
                additional_commitment,
                additional_generator,
            )
            .unwrap();
        assert_eq!(info, extracted_info);

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

        let nonce = SecretKey::new(&mut rng());
        let additional_generator =
            Generator::new_blinded(tag, commitment_secrets.generator_blinding_factor);

        let info = RangeProofInfo::new_range(1, 0, 52).unwrap();
        let proof = RangeProof::new(
            info,
            commitment,
            value,
            commitment_secrets.value_blinding_factor,
            message,
            additional_commitment,
            nonce,
            additional_generator,
        )
        .unwrap();

        let (opening, _range) = proof
            .rewind(
                commitment,
                nonce,
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
    
    fn make_proof(
        info: RangeProofInfo,
        value: u64,
    ) -> Result<(RangeProof, PedersenCommitment, Generator), InvalidValueError> {
        let generator = Generator::new_unblinded(Tag::from_byte_array([7; 32]));
        let blind = Tweak::from_byte_array([1; 32]).unwrap();
        let commitment = PedersenCommitment::new(value, blind, generator);
        let nonce = SecretKey::new(&mut crate::rand::rng());
        let proof = RangeProof::new(
            info,
            commitment,
            value,
            blind,
            &[],
            &[],
            nonce,
            generator,
        )?;
        Ok((proof, commitment, generator))
    }

    #[test]
    fn ordinary_52_bit_proof_roundtrips() {
        let info = RangeProofInfo::new_range(1, 0, 52).unwrap();
        let (proof, commitment, generator) = make_proof(info, 1000).unwrap();
        assert_eq!(
            proof.verify(commitment, &[], generator),
            Ok(info)
        );
        assert_eq!(proof, RangeProof::from_slice(proof.as_slice()).unwrap());
    }

    #[test]
    fn generated_full_width_proof_verifies() {
        let info = RangeProofInfo::new_range(0, 0, 64).unwrap();
        let (proof, commitment, generator) = make_proof(info, 1000).unwrap();
        assert_eq!(
            proof.verify(commitment, &[], generator),
            Ok(info)
        );
    }

    #[test]
    fn info_value_mismatch_exact() {
        let info = RangeProofInfo::new_exact(1000);
        assert!(matches!(
            make_proof(info, 1001),
            Err(InvalidValueError { value: 1001, inner: InvalidValueErrorInner::Exact, .. }),
        ));
    }

    #[test]
    fn info_value_mismatch_minimum() {
        let value = 999;
        let info = RangeProofInfo::new_range(1000, 0, 32).unwrap();
        assert_eq!(
            make_proof(info, value),
            Err(InvalidValueError { info, value, inner: InvalidValueErrorInner::Minimum }),
        );
    }

    #[test]
    fn info_value_mismatch_exponent() {
        let value = 1001;
        let info = RangeProofInfo::new_range(0, 1, 8).unwrap();
        assert_eq!(
            make_proof(info, value),
            Err(InvalidValueError { info, value, inner: InvalidValueErrorInner::Exponent }),
        );
    }

    #[test]
    fn info_value_mismatch_mantissa() {
        let value = 1257;
        let info = RangeProofInfo::new_range(1000, 0, 8).unwrap();
        assert_eq!(
            make_proof(info, value),
            Err(InvalidValueError { info, value, inner: InvalidValueErrorInner::Mantissa }),
        );
    }

    #[test]
    fn explicit_truncation_opt_in_produces_a_usable_proof() {
        let info = match RangeProofInfo::new_range(1, 0, 64) {
            Err(RangeProofInfoError::RangeWillBeTruncated { truncated_info }) => truncated_info,
            other => panic!("expected the truncation escape hatch, got {:?}", other),
        };
        let (proof, commitment, generator) = make_proof(info, 1000).unwrap();
        proof.verify(commitment, &[], generator).unwrap();
    }
}
