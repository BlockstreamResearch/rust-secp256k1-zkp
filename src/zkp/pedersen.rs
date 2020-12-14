use core::{fmt, slice, str};
use ffi;
use {from_hex, key::ONE_KEY, Error, Generator, Secp256k1, SecretKey, Signing};

/// Represents a commitment to a single u64 value.
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct PedersenCommitment(ffi::PedersenCommitment);

impl PedersenCommitment {
    /// Serialize a pedersen commitment.
    ///
    /// The format of this serialization is stable and platform-independent.
    pub fn serialize(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];

        let ret = unsafe {
            ffi::secp256k1_pedersen_commitment_serialize(
                ffi::secp256k1_context_no_precomp,
                bytes.as_mut_ptr(),
                &self.0,
            )
        };
        assert_eq!(ret, 1, "failed to serialize pedersen commitment");

        bytes
    }

    /// Parse a pedersen commitment from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut commitment = ffi::PedersenCommitment::default();

        let ret = unsafe {
            ffi::secp256k1_pedersen_commitment_parse(
                ffi::secp256k1_context_no_precomp,
                &mut commitment,
                bytes.as_ptr(),
            )
        };

        if ret != 1 {
            return Err(Error::InvalidPedersenCommitment);
        }

        Ok(PedersenCommitment(commitment))
    }

    /// Create a new [`PedersenCommitment`] that commits to the given value with a certain blinding factor and generator.
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        blinding_factor: SecretKey,
        generator: Generator,
    ) -> Self {
        let mut commitment = ffi::PedersenCommitment::default();

        let ret = unsafe {
            ffi::secp256k1_pedersen_commit(
                *secp.ctx(),
                &mut commitment,
                blinding_factor.as_ptr(),
                value,
                generator.as_inner(),
            )
        };
        assert_eq!(
            ret, 1,
            "failed to create pedersen commitment, likely a bad blinding factor"
        );

        PedersenCommitment(commitment)
    }

    pub(crate) fn as_inner(&self) -> &ffi::PedersenCommitment {
        &self.0
    }
}

/// Represents all secret data involved in making a [`PedersenCommitment`] where one of the generators is blinded.
///
/// A Pedersen commitment of the form `P = vT' + r'G` can be expressed as `vT + (vr + r')G` if `T' = T + rG` with:
/// - `v` = `value`
/// - `T` being a public key generated from a [`Tag`]
/// - `r` = `generator_blinding_factor`
/// - `r'` = `value_blinding_factor`
#[derive(Debug)]
pub struct CommitmentSecrets {
    /// The value that is committed to.
    pub value: u64,
    /// The blinding factor used when committing to the value.
    pub value_blinding_factor: SecretKey,
    /// The blinding factor used when producing the [`Generator`] that is necessary to commit to the value.
    pub generator_blinding_factor: SecretKey,
}

impl CommitmentSecrets {
    /// Constructor.
    pub fn new(
        value: u64,
        value_blinding_factor: SecretKey,
        generator_blinding_factor: SecretKey,
    ) -> Self {
        CommitmentSecrets {
            value,
            value_blinding_factor,
            generator_blinding_factor,
        }
    }
}

/// Compute a blinding factor such that the sum of all blinding factors in both sets is equal.
pub fn compute_adaptive_blinding_factor<C: Signing>(
    secp: &Secp256k1<C>,
    value: u64,
    generator_blinding_factor: SecretKey,
    set_a: &[CommitmentSecrets],
    set_b: &[CommitmentSecrets],
) -> SecretKey {
    let value_blinding_factor_placeholder = ONE_KEY; // this placeholder will be filled with the generated blinding factor

    let (mut values, mut secrets) = set_a
        .iter()
        .chain(set_b.iter())
        .map(|c| {
            (
                c.value,
                (c.value_blinding_factor, c.generator_blinding_factor),
            )
        })
        .unzip::<_, _, Vec<_>, Vec<_>>();
    values.push(value);
    secrets.push((value_blinding_factor_placeholder, generator_blinding_factor));

    let (vbf, gbf) = secrets
        .iter_mut()
        .map(|(s_v, s_g)| (s_v.as_mut_ptr(), s_g.as_ptr()))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    let ret = unsafe {
        ffi::secp256k1_pedersen_blind_generator_blind_sum(
            *secp.ctx(),
            values.as_ptr(),
            gbf.as_ptr(),
            vbf.as_ptr(),
            set_a.len() + set_b.len() + 1,
            set_a.len(),
        )
    };
    assert_eq!(1, ret, "failed to compute blinding factor");

    let last = vbf.last().expect("this vector is never empty");
    let slice = unsafe { slice::from_raw_parts(*last, 32) };
    SecretKey::from_slice(slice).expect("data is always a valid secret key")
}

/// Verifies that the sum of the committed values within the commitments of both sets is equal.
#[must_use]
pub fn verify_commitments_sum_to_equal<C: Signing>(
    secp: &Secp256k1<C>,
    a: &[PedersenCommitment],
    b: &[PedersenCommitment],
) -> bool {
    let a = a.iter().map(|c| &c.0).collect::<Vec<_>>();
    let b = b.iter().map(|c| &c.0).collect::<Vec<_>>();

    let ret = unsafe {
        ffi::secp256k1_pedersen_verify_tally(*secp.ctx(), a.as_ptr(), a.len(), b.as_ptr(), b.len())
    };

    ret == 1
}

impl fmt::LowerHex for PedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for PedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for PedersenCommitment {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mut res = [0; 64];
        match from_hex(s, &mut res) {
            Ok(64) => Self::from_slice(&res[0..64]),
            _ => Err(Error::InvalidPedersenCommitment),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for PedersenCommitment {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for PedersenCommitment {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = PedersenCommitment;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = str::from_utf8(v) {
                        str::FromStr::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    str::FromStr::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = PedersenCommitment;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    PedersenCommitment::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(all(test, feature = "global-context"))]
mod tests {
    use super::*;
    use rand::thread_rng;
    use {Tag, SECP256K1};

    impl CommitmentSecrets {
        pub fn random(value: u64) -> Self {
            Self {
                value,
                value_blinding_factor: SecretKey::new(&mut thread_rng()),
                generator_blinding_factor: SecretKey::new(&mut thread_rng()),
            }
        }

        pub fn commit(&self, tag: Tag) -> PedersenCommitment {
            let generator = Generator::new_blinded(SECP256K1, tag, self.generator_blinding_factor);

            PedersenCommitment::new(SECP256K1, self.value, self.value_blinding_factor, generator)
        }
    }

    #[test]
    fn test_serialize_and_parse_pedersen_commitment() {
        let commitment = CommitmentSecrets::random(1000).commit(Tag::random());

        let bytes = commitment.serialize();
        let got = PedersenCommitment::from_slice(&bytes).unwrap();

        assert_eq!(got, commitment);
    }

    #[test]
    fn test_equal_sum_of_commitments() {
        let tag_1 = Tag::random();
        let tag_2 = Tag::random();

        let secrets_1 = CommitmentSecrets::random(1000);
        let commitment_1 = secrets_1.commit(tag_1);
        let secrets_2 = CommitmentSecrets::random(1000);
        let commitment_2 = secrets_2.commit(tag_2);

        let secrets_3 = CommitmentSecrets::random(1000);
        let commitment_3 = secrets_3.commit(tag_1);

        let tbf_4 = SecretKey::new(&mut thread_rng());
        let blinded_tag_4 = Generator::new_blinded(SECP256K1, tag_2, tbf_4);
        let vbf_4 = compute_adaptive_blinding_factor(
            SECP256K1,
            1000,
            tbf_4,
            &[secrets_1, secrets_2],
            &[secrets_3],
        );
        let commitment_4 = PedersenCommitment::new(SECP256K1, 1000, vbf_4, blinded_tag_4);

        let commitment_sums_are_equal = verify_commitments_sum_to_equal(
            SECP256K1,
            &[commitment_1, commitment_2],
            &[commitment_3, commitment_4],
        );

        assert!(commitment_sums_are_equal);
    }

    // TODO: Test prefix of serialization
}
