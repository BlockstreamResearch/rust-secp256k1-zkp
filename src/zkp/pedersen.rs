use ffi::CPtr;

use crate::ffi;
use crate::{from_hex, Error, Generator, Secp256k1, Signing, Tweak, ZERO_TWEAK};
use core::{fmt, slice, str};

/// Represents a commitment to a single u64 value.
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
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

    /// Create a new [`PedersenCommitment`] that commits to the given value with
    /// a certain blinding factor and generator.
    /// Use the [PedersenCommitment::new_unblinded] for creating a commitment
    /// using zero blinding factor.
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        blinding_factor: Tweak,
        generator: Generator,
    ) -> Self {
        let mut commitment = ffi::PedersenCommitment::default();

        let ret = unsafe {
            ffi::secp256k1_pedersen_commit(
                secp.ctx().as_ptr(),
                &mut commitment,
                blinding_factor.as_c_ptr(),
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

    /// Create a new [`PedersenCommitment`] that commits to the given value
    /// with a zero blinding factor and the [`Generator`].
    pub fn new_unblinded<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        generator: Generator,
    ) -> Self {
        PedersenCommitment::new(secp, value, ZERO_TWEAK, generator)
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
    pub value_blinding_factor: Tweak,
    /// The blinding factor used when producing the [`Generator`] that is necessary to commit to the value.
    pub generator_blinding_factor: Tweak,
}

impl CommitmentSecrets {
    /// Constructor.
    pub fn new(value: u64, value_blinding_factor: Tweak, generator_blinding_factor: Tweak) -> Self {
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
    generator_blinding_factor: Tweak,
    set_a: &[CommitmentSecrets],
    set_b: &[CommitmentSecrets],
) -> Tweak {
    let value_blinding_factor_placeholder = ZERO_TWEAK; // this placeholder will be filled with the generated blinding factor

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
        .map(|(s_v, s_g)| (s_v.as_mut_c_ptr(), s_g.as_c_ptr()))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    let ret = unsafe {
        ffi::secp256k1_pedersen_blind_generator_blind_sum(
            secp.ctx().as_ptr(),
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
    Tweak::from_slice(slice).expect("data is always 32 bytes")
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
        ffi::secp256k1_pedersen_verify_tally(
            secp.ctx().as_ptr(),
            a.as_ptr(),
            a.len(),
            b.as_ptr(),
            b.len(),
        )
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
        let mut res = [0; 33];
        match from_hex(s, &mut res) {
            Ok(33) => Self::from_slice(&res[0..33]),
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
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                PedersenCommitment::from_slice,
            ))
        }
    }
}

#[cfg(all(test, feature = "global-context"))]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{Tag, SECP256K1};
    use rand::thread_rng;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    impl CommitmentSecrets {
        pub fn random(value: u64) -> Self {
            Self {
                value,
                value_blinding_factor: Tweak::new(&mut thread_rng()),
                generator_blinding_factor: Tweak::new(&mut thread_rng()),
            }
        }

        pub fn commit(&self, tag: Tag) -> PedersenCommitment {
            let generator = Generator::new_blinded(SECP256K1, tag, self.generator_blinding_factor);

            PedersenCommitment::new(SECP256K1, self.value, self.value_blinding_factor, generator)
        }
    }

    #[test]
    fn test_unblinded_pedersen_commitments() {
        let tag = Tag::random();
        let unblinded_gen = Generator::new_unblinded(SECP256K1, tag);
        let one_comm = PedersenCommitment::new_unblinded(SECP256K1, 1, unblinded_gen); // 1*G
        let two_comm = PedersenCommitment::new_unblinded(SECP256K1, 2, unblinded_gen); // 2*G
        let three_comm = PedersenCommitment::new_unblinded(SECP256K1, 3, unblinded_gen); // 3*G
        let six_comm = PedersenCommitment::new_unblinded(SECP256K1, 6, unblinded_gen); // 6*G

        let commitment_sums_are_equal = verify_commitments_sum_to_equal(
            SECP256K1,
            &[one_comm, two_comm, three_comm],
            &[six_comm],
        );

        assert!(commitment_sums_are_equal);
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

        let tbf_4 = Tweak::new(&mut thread_rng());
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

    #[test]
    fn test_pedersen_from_str() {
        let commitment = CommitmentSecrets::random(1000).commit(Tag::random());

        let string = commitment.to_string();
        let from_str = PedersenCommitment::from_str(&string);

        assert_eq!(Ok(commitment), from_str)
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_pedersen_de_serialization() {
        use serde_test::Configure;
        use serde_test::{assert_tokens, Token};

        let commitment = PedersenCommitment::from_slice(&[
            9, 7, 166, 63, 171, 227, 228, 157, 87, 19, 233, 218, 252, 171, 254, 202, 228, 138, 19,
            124, 26, 29, 131, 42, 33, 212, 151, 151, 89, 0, 135, 201, 254,
        ])
        .unwrap();

        assert_tokens(
            &commitment.readable(),
            &[Token::Str(
                "0907a63fabe3e49d5713e9dafcabfecae48a137c1a1d832a21d49797590087c9fe",
            )],
        );

        assert_tokens(
            &commitment.compact(),
            &[Token::Bytes(&[
                9, 7, 166, 63, 171, 227, 228, 157, 87, 19, 233, 218, 252, 171, 254, 202, 228, 138,
                19, 124, 26, 29, 131, 42, 33, 212, 151, 151, 89, 0, 135, 201, 254,
            ])],
        );
    }

    // TODO: Test prefix of serialization
}
