use crate::{impl_array_newtype, impl_raw_debug};
use core::hash::{self, Hash};
use {types::*, Context, Keypair, PublicKey, XOnlyPublicKey};

pub const MUSIG_KEYAGG_CACHE_LENGTH: size_t = 197;
pub const MUSIG_SECNONCE_LENGTH: size_t = 132;
pub const MUSIG_PUBNONCE_LENGTH: size_t = 132;
pub const MUSIG_AGGNONCE_LENGTH: size_t = 132;
pub const MUSIG_SESSION_LENGTH: size_t = 133;
pub const MUSIG_PART_SIG_LENGTH: size_t = 36;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MusigKeyaggCache([c_uchar; MUSIG_KEYAGG_CACHE_LENGTH]);
impl_array_newtype!(MusigKeyaggCache, c_uchar, MUSIG_KEYAGG_CACHE_LENGTH);
impl_raw_debug!(MusigKeyaggCache);

impl MusigKeyaggCache {
    /// Create a new (zeroed) MuSig keyagg cache usable for the FFI interface
    pub fn new() -> Self {
        MusigKeyaggCache([0; MUSIG_KEYAGG_CACHE_LENGTH])
    }
}

impl Default for MusigKeyaggCache {
    fn default() -> Self {
        MusigKeyaggCache::new()
    }
}

impl PartialEq for MusigKeyaggCache {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for MusigKeyaggCache {}

impl Hash for MusigKeyaggCache {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// Implements neither `Copy` nor `Clone`, and exposes no way to read its bytes.
#[repr(C)]
pub struct MusigSecNonce([c_uchar; MUSIG_SECNONCE_LENGTH]);

impl MusigSecNonce {
    /// Create a new (zeroed) MuSig secret nonce usable for the FFI interface
    pub fn new() -> Self {
        MusigSecNonce([0; MUSIG_SECNONCE_LENGTH])
    }

    /// Return a mutable pointer to the underlying bytes, for the parent crate's zeroizing `Drop`
    pub fn as_mut_bytes_ptr(&mut self) -> *mut c_uchar {
        self.0.as_mut_ptr()
    }
}

impl Default for MusigSecNonce {
    fn default() -> Self {
        MusigSecNonce::new()
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MusigPubNonce([c_uchar; MUSIG_PUBNONCE_LENGTH]);
impl_array_newtype!(MusigPubNonce, c_uchar, MUSIG_PUBNONCE_LENGTH);
impl_raw_debug!(MusigPubNonce);

impl MusigPubNonce {
    /// Create a new (zeroed) MuSig public nonce usable for the FFI interface
    pub fn new() -> Self {
        MusigPubNonce([0; MUSIG_PUBNONCE_LENGTH])
    }
}

impl Default for MusigPubNonce {
    fn default() -> Self {
        MusigPubNonce::new()
    }
}

impl PartialEq for MusigPubNonce {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for MusigPubNonce {}

impl Hash for MusigPubNonce {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MusigAggNonce([c_uchar; MUSIG_AGGNONCE_LENGTH]);
impl_array_newtype!(MusigAggNonce, c_uchar, MUSIG_AGGNONCE_LENGTH);
impl_raw_debug!(MusigAggNonce);

impl MusigAggNonce {
    /// Create a new (zeroed) MuSig aggregate nonce usable for the FFI interface
    pub fn new() -> Self {
        MusigAggNonce([0; MUSIG_AGGNONCE_LENGTH])
    }
}

impl Default for MusigAggNonce {
    fn default() -> Self {
        MusigAggNonce::new()
    }
}

impl PartialEq for MusigAggNonce {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for MusigAggNonce {}

impl Hash for MusigAggNonce {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MusigSession([c_uchar; MUSIG_SESSION_LENGTH]);
impl_array_newtype!(MusigSession, c_uchar, MUSIG_SESSION_LENGTH);
impl_raw_debug!(MusigSession);

impl MusigSession {
    /// Create a new (zeroed) MuSig session usable for the FFI interface
    pub fn new() -> Self {
        MusigSession([0; MUSIG_SESSION_LENGTH])
    }
}

impl Default for MusigSession {
    fn default() -> Self {
        MusigSession::new()
    }
}

impl PartialEq for MusigSession {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for MusigSession {}

impl Hash for MusigSession {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MusigPartialSignature([c_uchar; MUSIG_PART_SIG_LENGTH]);
impl_array_newtype!(MusigPartialSignature, c_uchar, MUSIG_PART_SIG_LENGTH);
impl_raw_debug!(MusigPartialSignature);

impl MusigPartialSignature {
    /// Create a new (zeroed) MuSig partial signature usable for the FFI interface
    pub fn new() -> Self {
        MusigPartialSignature([0; MUSIG_PART_SIG_LENGTH])
    }
}

impl Default for MusigPartialSignature {
    fn default() -> Self {
        MusigPartialSignature::new()
    }
}

impl PartialEq for MusigPartialSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for MusigPartialSignature {}

impl Hash for MusigPartialSignature {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

extern "C" {
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_pubkey_sort"
    )]
    // Sorts (in place) an array of pointers to public keys into a canonical
    // order, so that MuSig key aggregation is independent of input order.
    pub fn secp256k1_ec_pubkey_sort(
        ctx: *const Context,
        pubkeys: *mut *const PublicKey,
        n_pubkeys: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_pubnonce_parse"
    )]
    pub fn secp256k1_musig_pubnonce_parse(
        ctx: *const Context,
        nonce: *mut MusigPubNonce,
        in66: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_pubnonce_serialize"
    )]
    pub fn secp256k1_musig_pubnonce_serialize(
        ctx: *const Context,
        out66: *mut c_uchar,
        nonce: *const MusigPubNonce,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_aggnonce_parse"
    )]
    pub fn secp256k1_musig_aggnonce_parse(
        ctx: *const Context,
        nonce: *mut MusigAggNonce,
        in66: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_aggnonce_serialize"
    )]
    pub fn secp256k1_musig_aggnonce_serialize(
        ctx: *const Context,
        out66: *mut c_uchar,
        nonce: *const MusigAggNonce,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_partial_sig_parse"
    )]
    pub fn secp256k1_musig_partial_sig_parse(
        ctx: *const Context,
        sig: *mut MusigPartialSignature,
        in32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_partial_sig_serialize"
    )]
    pub fn secp256k1_musig_partial_sig_serialize(
        ctx: *const Context,
        out32: *mut c_uchar,
        sig: *const MusigPartialSignature,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_pubkey_agg"
    )]
    pub fn secp256k1_musig_pubkey_agg(
        ctx: *const Context,
        agg_pk: *mut XOnlyPublicKey,
        keyagg_cache: *mut MusigKeyaggCache,
        pubkeys: *const *const PublicKey,
        n_pubkeys: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_pubkey_get"
    )]
    pub fn secp256k1_musig_pubkey_get(
        ctx: *const Context,
        agg_pk: *mut PublicKey,
        keyagg_cache: *const MusigKeyaggCache,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_pubkey_ec_tweak_add"
    )]
    pub fn secp256k1_musig_pubkey_ec_tweak_add(
        ctx: *const Context,
        output_pubkey: *mut PublicKey,
        keyagg_cache: *mut MusigKeyaggCache,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_pubkey_xonly_tweak_add"
    )]
    pub fn secp256k1_musig_pubkey_xonly_tweak_add(
        ctx: *const Context,
        output_pubkey: *mut PublicKey,
        keyagg_cache: *mut MusigKeyaggCache,
        tweak32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_nonce_gen"
    )]
    pub fn secp256k1_musig_nonce_gen(
        ctx: *const Context,
        secnonce: *mut MusigSecNonce,
        pubnonce: *mut MusigPubNonce,
        session_secrand32: *mut c_uchar,
        seckey: *const c_uchar,
        pubkey: *const PublicKey,
        msg32: *const c_uchar,
        keyagg_cache: *const MusigKeyaggCache,
        extra_input32: *const c_uchar,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_nonce_agg"
    )]
    pub fn secp256k1_musig_nonce_agg(
        ctx: *const Context,
        aggnonce: *mut MusigAggNonce,
        pubnonces: *const *const MusigPubNonce,
        n_pubnonces: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_nonce_process"
    )]
    pub fn secp256k1_musig_nonce_process(
        ctx: *const Context,
        session: *mut MusigSession,
        aggnonce: *const MusigAggNonce,
        msg32: *const c_uchar,
        keyagg_cache: *const MusigKeyaggCache,
        adaptor: *const PublicKey,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_partial_sign"
    )]
    pub fn secp256k1_musig_partial_sign(
        ctx: *const Context,
        partial_sig: *mut MusigPartialSignature,
        secnonce: *mut MusigSecNonce,
        keypair: *const Keypair,
        keyagg_cache: *const MusigKeyaggCache,
        session: *const MusigSession,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_partial_sig_verify"
    )]
    pub fn secp256k1_musig_partial_sig_verify(
        ctx: *const Context,
        partial_sig: *const MusigPartialSignature,
        pubnonce: *const MusigPubNonce,
        pubkey: *const PublicKey,
        keyagg_cache: *const MusigKeyaggCache,
        session: *const MusigSession,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_partial_sig_agg"
    )]
    pub fn secp256k1_musig_partial_sig_agg(
        ctx: *const Context,
        sig64: *mut c_uchar,
        session: *const MusigSession,
        partial_sigs: *const *const MusigPartialSignature,
        n_sigs: size_t,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_nonce_parity"
    )]
    pub fn secp256k1_musig_nonce_parity(
        ctx: *const Context,
        nonce_parity: *mut c_int,
        session: *const MusigSession,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_adapt"
    )]
    pub fn secp256k1_musig_adapt(
        ctx: *const Context,
        sig64: *mut c_uchar,
        pre_sig64: *const c_uchar,
        sec_adaptor32: *const c_uchar,
        nonce_parity: c_int,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_musig_extract_adaptor"
    )]
    pub fn secp256k1_musig_extract_adaptor(
        ctx: *const Context,
        sec_adaptor32: *mut c_uchar,
        sig64: *const c_uchar,
        pre_sig64: *const c_uchar,
        nonce_parity: c_int,
    ) -> c_int;
}
