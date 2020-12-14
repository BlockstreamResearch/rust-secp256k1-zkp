use core::mem;
use core::mem::size_of;
use ffi;
use Verification;
use {Error, Generator, Secp256k1};

/// Represents a surjection proof.
#[derive(Debug, PartialEq)]
pub struct SurjectionProof {
    inner: ffi::SurjectionProof,
}

#[cfg(feature = "rand")]
mod with_rand {
    use super::*;
    use rand::Rng;
    use {SecretKey, Signing, Tag};

    impl SurjectionProof {
        /// Prove that a given tag - when blinded - is contained within another set of blinded tags.
        ///
        /// Mathematically, we are proving that there exists a surjective mapping between the domain and codomain of tags.
        /// Blinding a tag produces a [`Generator`]. As such, to create this proof we need to provide the `[Generator]`s and the respective blinding factors that were used to create them.
        pub fn new<C: Signing, R: Rng>(
            secp: &Secp256k1<C>,
            rng: &mut R,
            codomain_tag: Tag,
            codomain_blinding_factor: SecretKey,
            domain: &[(Generator, Tag, SecretKey)],
        ) -> Result<SurjectionProof, Error> {
            let mut proof = ffi::SurjectionProof::new();

            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);

            let mut domain_index = 0;
            let max_iteration = 100;

            let mut domain_blinded_tags = Vec::with_capacity(domain.len());
            let mut domain_tags = Vec::with_capacity(domain.len());
            let mut domain_blinding_factors = Vec::with_capacity(domain.len());

            for (blinded_tag, tag, bf) in domain {
                domain_blinded_tags.push(*blinded_tag.as_inner());
                domain_tags.push(tag.into_inner());
                domain_blinding_factors.push(*bf);
            }

            let ret = unsafe {
                ffi::secp256k1_surjectionproof_initialize(
                    *secp.ctx(),
                    &mut proof,
                    &mut domain_index,
                    domain_tags.as_ptr(),
                    domain.len(),
                    domain.len().min(3),
                    codomain_tag.as_inner(),
                    max_iteration,
                    seed.as_ptr(),
                )
            };

            if ret == 0 {
                return Err(Error::CannotProveSurjection);
            }

            let codomain_blinded_tag =
                Generator::new_blinded(secp, codomain_tag, codomain_blinding_factor);

            let ret = unsafe {
                ffi::secp256k1_surjectionproof_generate(
                    *secp.ctx(),
                    &mut proof,
                    domain_blinded_tags.as_ptr(),
                    domain.len(),
                    codomain_blinded_tag.as_inner(),
                    domain_index,
                    domain
                        .get(domain_index)
                        .ok_or(Error::CannotProveSurjection)?
                        .2
                        .as_ptr(), // TODO: Return dedicated error here?
                    codomain_blinding_factor.as_ptr(),
                )
            };

            if ret == 0 {
                return Err(Error::CannotProveSurjection);
            }

            Ok(SurjectionProof { inner: proof })
        }
    }
}

impl SurjectionProof {
    /// Creates a surjection proof from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut proof = ffi::SurjectionProof::new();

        let ret = unsafe {
            ffi::secp256k1_surjectionproof_parse(
                ffi::secp256k1_context_no_precomp,
                &mut proof,
                bytes.as_ptr(),
                bytes.len(),
            )
        };

        if ret != 1 {
            return Err(Error::InvalidSurjectionProof);
        }

        Ok(SurjectionProof { inner: proof })
    }

    /// Serializes a surjection proof.
    ///
    /// The format of this serialization is stable and platform-independent.
    pub fn serialize(&self) -> Vec<u8> {
        let mut size = unsafe {
            ffi::secp256k1_surjectionproof_serialized_size(
                ffi::secp256k1_context_no_precomp,
                &self.inner,
            )
        };

        let mut bytes = vec![0u8; size];

        let ret = unsafe {
            ffi::secp256k1_surjectionproof_serialize(
                ffi::secp256k1_context_no_precomp,
                bytes.as_mut_ptr(),
                &mut size,
                &self.inner,
            )
        };
        assert_eq!(ret, 1, "failed to serialize surjection proof"); // This is safe as long as we correctly computed the size of the proof upfront using `secp256k1_surjectionproof_serialized_size`.

        bytes
    }

    /// Verify a surjection proof.
    #[must_use]
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        codomain: Generator,
        domain: &[Generator],
    ) -> bool {
        // Safety: Generator and ffi::PublicKey are the same size and layout.
        let domain_blinded_tags = unsafe {
            debug_assert_eq!(size_of::<Generator>(), size_of::<ffi::PublicKey>());

            mem::transmute::<_, &[ffi::PublicKey]>(domain)
        };

        let ret = unsafe {
            ffi::secp256k1_surjectionproof_verify(
                *secp.ctx(),
                &self.inner,
                domain_blinded_tags.as_ptr(),
                domain_blinded_tags.len(),
                codomain.as_inner(),
            )
        };

        ret == 1
    }
}

#[cfg(all(test, feature = "global-context"))] // use global context for convenience
mod tests {
    use super::*;
    use rand::thread_rng;
    use {SecretKey, Tag, SECP256K1};

    #[test]
    fn test_create_and_verify_surjection_proof() {
        // create three random tags
        let (domain_tag_1, domain_blinded_tag_1, domain_bf_1) = random_blinded_tag();
        let (domain_tag_2, domain_blinded_tag_2, domain_bf_2) = random_blinded_tag();
        let (domain_tag_3, domain_blinded_tag_3, domain_bf_3) = random_blinded_tag();

        // pick the first one as the codomain
        let codomain_tag_1 = domain_tag_1;
        let (codomain_blinded_tag_1, codomain_bf_1) = blind_tag(codomain_tag_1);

        let proof = SurjectionProof::new(
            SECP256K1,
            &mut thread_rng(),
            codomain_tag_1,
            codomain_bf_1,
            &[
                (domain_blinded_tag_1, domain_tag_1, domain_bf_1),
                (domain_blinded_tag_2, domain_tag_2, domain_bf_2),
                (domain_blinded_tag_3, domain_tag_3, domain_bf_3),
            ],
        )
        .unwrap();

        assert!(proof.verify(
            SECP256K1,
            codomain_blinded_tag_1,
            &[
                domain_blinded_tag_1,
                domain_blinded_tag_2,
                domain_blinded_tag_3
            ],
        ))
    }

    #[test]
    fn test_serialize_and_parse_surjection_proof() {
        let (domain_tag_1, domain_blinded_tag_1, domain_bf_1) = random_blinded_tag();
        let codomain_tag_1 = domain_tag_1;
        let (_, codomain_bf_1) = blind_tag(codomain_tag_1);

        let proof = SurjectionProof::new(
            SECP256K1,
            &mut thread_rng(),
            codomain_tag_1,
            codomain_bf_1,
            &[(domain_blinded_tag_1, domain_tag_1, domain_bf_1)],
        )
        .unwrap();
        let bytes = proof.serialize();
        let parsed = SurjectionProof::from_slice(&bytes).unwrap();

        assert_eq!(parsed, proof)
    }

    fn random_blinded_tag() -> (Tag, Generator, SecretKey) {
        let tag = Tag::random();

        let (blinded_tag, bf) = blind_tag(tag);

        (tag, blinded_tag, bf)
    }

    fn blind_tag(tag: Tag) -> (Generator, SecretKey) {
        let bf = SecretKey::new(&mut thread_rng());
        let blinded_tag = Generator::new_blinded(SECP256K1, tag, bf);

        (blinded_tag, bf)
    }
}
