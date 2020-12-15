use core::{fmt, hash};

use {types::*, Context, PublicKey};

/// Rangeproof maximum length
pub const RANGEPROOF_MAX_LENGTH: size_t = 5134;

extern "C" {
    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_pedersen_commitment_parse"
    )]
    // Parse a 33-byte commitment into 64 byte internal commitment object
    pub fn secp256k1_pedersen_commitment_parse(
        cx: *const Context,
        commit: *mut PedersenCommitment,
        input: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_pedersen_commitment_serialize"
    )]
    // Serialize a 64-byte commit object into a 33 byte serialized byte sequence
    pub fn secp256k1_pedersen_commitment_serialize(
        cx: *const Context,
        output: *mut c_uchar,
        commit: *const PedersenCommitment,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_pedersen_commit"
    )]
    // Generates a pedersen commitment: *commit = blind * G + value * G2.
    // The commitment is 33 bytes, the blinding factor is 32 bytes.
    pub fn secp256k1_pedersen_commit(
        ctx: *const Context,
        commit: *mut PedersenCommitment,
        blind: *const c_uchar,
        value: u64,
        value_gen: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_pedersen_blind_generator_blind_sum"
    )]
    /// Sets the final Pedersen blinding factor correctly when the generators themselves
    ///  have blinding factors.
    ///
    /// Consider a generator of the form A' = A + rG, where A is the "real" generator
    /// but A' is the generator provided to verifiers. Then a Pedersen commitment
    /// P = vA' + r'G really has the form vA + (vr + r')G. To get all these (vr + r')
    /// to sum to zero for multiple commitments, we take three arrays consisting of
    /// the `v`s, `r`s, and `r'`s, respectively called `value`s, `generator_blind`s
    /// and `blinding_factor`s, and sum them.
    ///
    /// The function then subtracts the sum of all (vr + r') from the last element
    /// of the `blinding_factor` array, setting the total sum to zero.
    ///
    /// Returns 1: Blinding factor successfully computed.
    ///         0: Error. A blinding_factor or generator_blind are larger than the group
    ///            order (probability for random 32 byte number < 2^-127). Retry with
    ///            different values.
    ///
    /// In:                 ctx: pointer to a context object
    ///                   value: array of asset values, `v` in the above paragraph.
    ///                          May not be NULL unless `n_total` is 0.
    ///         generator_blind: array of asset blinding factors, `r` in the above paragraph
    ///                          May not be NULL unless `n_total` is 0.
    ///                 n_total: Total size of the above arrays
    ///                n_inputs: How many of the initial array elements represent commitments that
    ///                          will be negated in the final sum
    /// In/Out: blinding_factor: array of commitment blinding factors, `r'` in the above paragraph
    ///                          May not be NULL unless `n_total` is 0.
    ///                          the last value will be modified to get the total sum to zero.
    pub fn secp256k1_pedersen_blind_generator_blind_sum(
        ctx: *const Context,
        value: *const u64,
        generator_blind: *const *const c_uchar,
        blinding_factor: *const *mut c_uchar,
        n_total: size_t,
        n_inputs: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_pedersen_verify_tally"
    )]
    // Takes two list of 64-byte commitments and sums the first set and
    // subtracts the second and verifies that they sum to 0.
    pub fn secp256k1_pedersen_verify_tally(
        ctx: *const Context,
        commits: *const &PedersenCommitment,
        pcnt: size_t,
        ncommits: *const &PedersenCommitment,
        ncnt: size_t,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_rangeproof_info"
    )]
    pub fn secp256k1_rangeproof_info(
        ctx: *const Context,
        exp: *mut c_int,
        mantissa: *mut c_int,
        min_value: *mut u64,
        max_value: *mut u64,
        proof: *const c_uchar,
        plen: size_t,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_rangeproof_rewind"
    )]
    pub fn secp256k1_rangeproof_rewind(
        ctx: *const Context,
        blind_out: *mut c_uchar,
        value_out: *mut u64,
        message_out: *mut c_uchar,
        outlen: *mut size_t,
        nonce: *const c_uchar,
        min_value: *mut u64,
        max_value: *mut u64,
        commit: *const PedersenCommitment,
        proof: *const c_uchar,
        plen: size_t,
        extra_commit: *const c_uchar,
        extra_commit_len: size_t,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_rangeproof_verify"
    )]
    pub fn secp256k1_rangeproof_verify(
        ctx: *const Context,
        min_value: &mut u64,
        max_value: &mut u64,
        commit: *const PedersenCommitment,
        proof: *const c_uchar,
        plen: size_t,
        extra_commit: *const c_uchar,
        extra_commit_len: size_t,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg(feature = "std")]
    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_rangeproof_sign"
    )]
    pub fn secp256k1_rangeproof_sign(
        ctx: *const Context,
        proof: *mut c_uchar,
        plen: *mut size_t,
        min_value: u64,
        commit: *const PedersenCommitment,
        blind: *const c_uchar,
        nonce: *const c_uchar,
        exp: c_int,
        min_bits: c_int,
        value: u64,
        message: *const c_uchar,
        msg_len: size_t,
        extra_commit: *const c_uchar,
        extra_commit_len: size_t,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_surjectionproof_initialize"
    )]
    pub fn secp256k1_surjectionproof_initialize(
        ctx: *const Context,
        proof: *mut SurjectionProof,
        input_index: *mut size_t,
        fixed_input_tags: *const Tag,
        n_input_tags: size_t,
        n_input_tags_to_use: size_t,
        fixed_output_tag: *const Tag,
        n_max_iterations: size_t,
        random_seed32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_surjectionproof_serialize"
    )]
    pub fn secp256k1_surjectionproof_serialize(
        ctx: *const Context,
        output: *mut c_uchar,
        outputlen: *mut size_t,
        proof: *const SurjectionProof,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_surjectionproof_serialized_size"
    )]
    pub fn secp256k1_surjectionproof_serialized_size(
        ctx: *const Context,
        proof: *const SurjectionProof,
    ) -> size_t;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_surjectionproof_parse"
    )]
    pub fn secp256k1_surjectionproof_parse(
        ctx: *const Context,
        proof: *mut SurjectionProof,
        input_bytes: *const c_uchar,
        input_len: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_surjectionproof_generate"
    )]
    pub fn secp256k1_surjectionproof_generate(
        ctx: *const Context,
        proof: *mut SurjectionProof,
        ephemeral_input_tags: *const PublicKey,
        n_ephemeral_input_tags: size_t,
        ephemeral_output_tag: *const PublicKey,
        input_index: size_t,
        input_blinding_key: *const c_uchar,
        output_blinding_key: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_surjectionproof_verify"
    )]
    pub fn secp256k1_surjectionproof_verify(
        ctx: *const Context,
        proof: *const SurjectionProof,
        ephemeral_input_tags: *const PublicKey,
        n_ephemeral_input_tags: size_t,
        ephemeral_output_tag: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_generator_generate_blinded"
    )]
    pub fn secp256k1_generator_generate_blinded(
        ctx: *const Context,
        gen: *mut PublicKey,
        key32: *const c_uchar,
        blind32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_generator_serialize"
    )]
    pub fn secp256k1_generator_serialize(
        ctx: *const Context,
        output: *mut c_uchar,
        gen: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(feature = "external-symbols"),
        link_name = "rustsecp256k1zkp_v0_1_0_generator_parse"
    )]
    pub fn secp256k1_generator_parse(
        ctx: *const Context,
        output: *mut PublicKey,
        bytes: *const c_uchar,
    ) -> c_int;
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SurjectionProof {
    #[doc = " Total number of input asset tags"]
    pub n_inputs: size_t,
    #[doc = " Bitmap of which input tags are used in the surjection proof"]
    pub used_inputs: [c_uchar; 32usize],
    #[doc = " Borromean signature: e0, scalars"]
    pub data: [c_uchar; 8224usize],
}

impl fmt::Debug for SurjectionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slice = &self.data[..];

        f.debug_struct("SurjectionProof")
            .field("n_inputs", &self.n_inputs)
            .field("used_inputs", &self.used_inputs)
            .field("data", &slice)
            .finish()
    }
}

impl PartialEq for SurjectionProof {
    fn eq(&self, other: &Self) -> bool {
        self.n_inputs == other.n_inputs
            && self.used_inputs == other.used_inputs
            && &self.data[..] == &other.data[..]
    }
}

impl SurjectionProof {
    pub fn new() -> Self {
        Self {
            n_inputs: 0,
            used_inputs: [0u8; 32],
            data: [0u8; 8224],
        }
    }
}

#[cfg(feature = "std")]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RangeProof(Box<[c_uchar]>);

#[cfg(feature = "std")]
impl RangeProof {
    pub fn new(bytes: &[u8]) -> Self {
        RangeProof(bytes.into())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_ptr(&self) -> *const c_uchar {
        self.0.as_ptr()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[repr(C)]
#[derive(Hash)]
pub struct Tag([c_uchar; 32]);
impl_array_newtype!(Tag, c_uchar, 32);
impl_raw_debug!(Tag);

impl Tag {
    pub fn new() -> Self {
        Tag([0; 32])
    }
}

impl Default for Tag {
    fn default() -> Self {
        Tag::new()
    }
}

impl From<[u8; 32]> for Tag {
    fn from(bytes: [u8; 32]) -> Self {
        Tag(bytes)
    }
}

impl From<Tag> for [u8; 32] {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

// TODO: Replace this with ffi::PublicKey?
#[repr(C)]
pub struct PedersenCommitment([c_uchar; 64]);
impl_array_newtype!(PedersenCommitment, c_uchar, 64);
impl_raw_debug!(PedersenCommitment);

impl PedersenCommitment {
    pub fn new() -> Self {
        PedersenCommitment([0; 64])
    }
}

impl Default for PedersenCommitment {
    fn default() -> Self {
        PedersenCommitment::new()
    }
}

impl hash::Hash for PedersenCommitment {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}
