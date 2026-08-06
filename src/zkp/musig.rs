//! # MuSig2
//! Bindings for the MuSig2 multi-signature scheme (BIP 327).
//!
//! Covers public-key aggregation, the two-round nonce exchange, partial signing and
//! aggregation, plain/x-only tweaking, and adaptor signatures.

use crate::ffi::{self, CPtr};
#[cfg(feature = "rand")]
use crate::rand::{CryptoRng, Rng};
use crate::schnorr::Signature;
use crate::{
    from_hex, Error, Keypair, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification,
    XOnlyPublicKey,
};
use core::sync::atomic::{compiler_fence, Ordering};
use core::{fmt, ptr, str};

/// The length of a serialized MuSig public or aggregate nonce.
pub const NONCE_SERIALIZED_SIZE: usize = 66;
/// The length of a serialized MuSig partial signature.
pub const PARTIAL_SIGNATURE_SERIALIZED_SIZE: usize = 32;

/// Cached state produced by aggregating a set of public keys.
///
/// Required for signing, verifying partial signatures and observing a signing session.
#[derive(Copy, Clone, Debug)]
pub struct KeyAggCache {
    cache: ffi::MusigKeyaggCache,
    agg_pk: XOnlyPublicKey,
}

impl KeyAggCache {
    /// Aggregates the given public keys and caches the result.
    ///
    /// The order of `pubkeys` matters; different orders produce different aggregate keys. Sort
    /// the keys first (see [`ffi::secp256k1_ec_pubkey_sort`]) for an order-independent result.
    /// Fails if the set is empty.
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        pubkeys: &[&PublicKey],
    ) -> Result<KeyAggCache, Error> {
        if pubkeys.is_empty() {
            return Err(Error::CannotAggregateMusigPubkeys);
        }

        let pubkey_ptrs: Vec<*const ffi::PublicKey> =
            pubkeys.iter().map(|pk| pk.as_c_ptr()).collect();

        let mut cache = ffi::MusigKeyaggCache::new();
        let mut agg_pk = unsafe { ffi::XOnlyPublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_musig_pubkey_agg(
                secp.ctx().as_ptr(),
                &mut agg_pk,
                &mut cache,
                pubkey_ptrs.as_ptr(),
                pubkey_ptrs.len(),
            )
        };

        if ret == 0 {
            return Err(Error::CannotAggregateMusigPubkeys);
        }

        Ok(KeyAggCache {
            cache,
            agg_pk: XOnlyPublicKey::from(agg_pk),
        })
    }

    /// Returns the aggregate x-only public key that the final signature verifies against.
    pub fn agg_pk(&self) -> XOnlyPublicKey {
        self.agg_pk
    }

    /// Returns the aggregate public key in full (non-x-only) form, e.g. for plain tweaking.
    pub fn agg_pk_full<C: Verification>(&self, secp: &Secp256k1<C>) -> PublicKey {
        let mut pk = unsafe { ffi::PublicKey::new() };

        let ret =
            unsafe { ffi::secp256k1_musig_pubkey_get(secp.ctx().as_ptr(), &mut pk, &self.cache) };
        debug_assert_eq!(ret, 1);

        PublicKey::from(pk)
    }

    /// Applies plain "EC" tweaking to the cached aggregate key.
    ///
    /// Required if you want to *sign* for the tweaked key. Returns the tweaked public key. Fails
    /// if `tweak32` is zero, out of range, or the negated aggregate secret key.
    pub fn pubkey_ec_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak32: &[u8; 32],
    ) -> Result<PublicKey, Error> {
        let mut out = unsafe { ffi::PublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_musig_pubkey_ec_tweak_add(
                secp.ctx().as_ptr(),
                &mut out,
                &mut self.cache,
                tweak32.as_ptr(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidMusigTweak);
        }

        // The tweak updates the aggregate key held in the cache, so refresh `agg_pk` to match.
        let output = PublicKey::from(out);
        self.agg_pk = XOnlyPublicKey::from(output);
        Ok(output)
    }

    /// Applies x-only tweaking to the cached aggregate key.
    ///
    /// Required if you want to *sign* for the tweaked key. Returns the tweaked public key. Fails
    /// if `tweak32` is zero, out of range, or the negated aggregate secret key.
    pub fn pubkey_xonly_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak32: &[u8; 32],
    ) -> Result<PublicKey, Error> {
        let mut out = unsafe { ffi::PublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_musig_pubkey_xonly_tweak_add(
                secp.ctx().as_ptr(),
                &mut out,
                &mut self.cache,
                tweak32.as_ptr(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidMusigTweak);
        }

        // The tweak updates the aggregate key held in the cache, so refresh `agg_pk` to match.
        let output = PublicKey::from(out);
        self.agg_pk = XOnlyPublicKey::from(output);
        Ok(output)
    }
}

/// A signer's secret nonce for a single MuSig signing session.
///
/// Consumed by value in [`Session::partial_sign`]; not `Copy`, `Clone` or serializable.
pub struct SecretNonce(ffi::MusigSecNonce);

impl fmt::Debug for SecretNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SecretNonce(<secret>)")
    }
}

impl Drop for SecretNonce {
    fn drop(&mut self) {
        // Zero the secret nonce on drop. `write_volatile` plus a compiler fence keeps the
        // writes from being optimized away.
        let ptr = self.0.as_mut_bytes_ptr();
        for i in 0..ffi::MUSIG_SECNONCE_LENGTH {
            unsafe {
                ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// A signer's public nonce, shared with the other signers.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicNonce(ffi::MusigPubNonce);

impl PublicNonce {
    /// Serialize the public nonce to 66 bytes.
    #[inline]
    pub fn serialize(&self) -> [u8; NONCE_SERIALIZED_SIZE] {
        let mut data = [0u8; NONCE_SERIALIZED_SIZE];

        let ret = unsafe {
            ffi::secp256k1_musig_pubnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                &self.0,
            )
        };
        debug_assert_eq!(ret, 1);

        data
    }

    /// Parse a public nonce from a 66-byte slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicNonce, Error> {
        if data.len() != NONCE_SERIALIZED_SIZE {
            return Err(Error::InvalidMusigNonce);
        }

        let mut nonce = ffi::MusigPubNonce::new();
        let ret = unsafe {
            ffi::secp256k1_musig_pubnonce_parse(
                ffi::secp256k1_context_no_precomp,
                &mut nonce,
                data.as_ptr(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidMusigNonce);
        }

        Ok(PublicNonce(nonce))
    }
}

impl fmt::LowerHex for PublicNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for PublicNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for PublicNonce {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicNonce, Error> {
        let mut res = [0u8; NONCE_SERIALIZED_SIZE];
        match from_hex(s, &mut res) {
            Ok(NONCE_SERIALIZED_SIZE) => PublicNonce::from_slice(&res[0..NONCE_SERIALIZED_SIZE]),
            _ => Err(Error::InvalidMusigNonce),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for PublicNonce {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for PublicNonce {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                PublicNonce::from_slice,
            ))
        }
    }
}

/// The aggregate of all signers' public nonces for a session.
///
/// May be computed by an untrusted party; an incorrect aggregate only invalidates the final
/// signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AggregatedNonce(ffi::MusigAggNonce);

impl AggregatedNonce {
    /// Aggregates the given public nonces into a single nonce. Fails if `nonces` is empty.
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        nonces: &[&PublicNonce],
    ) -> Result<AggregatedNonce, Error> {
        if nonces.is_empty() {
            return Err(Error::CannotAggregateMusigNonces);
        }

        let nonce_ptrs: Vec<*const ffi::MusigPubNonce> =
            nonces.iter().map(|n| &n.0 as *const _).collect();

        let mut agg = ffi::MusigAggNonce::new();
        let ret = unsafe {
            ffi::secp256k1_musig_nonce_agg(
                secp.ctx().as_ptr(),
                &mut agg,
                nonce_ptrs.as_ptr(),
                nonce_ptrs.len(),
            )
        };

        if ret == 0 {
            return Err(Error::CannotAggregateMusigNonces);
        }

        Ok(AggregatedNonce(agg))
    }

    /// Serialize the aggregate nonce to 66 bytes.
    #[inline]
    pub fn serialize(&self) -> [u8; NONCE_SERIALIZED_SIZE] {
        let mut data = [0u8; NONCE_SERIALIZED_SIZE];

        let ret = unsafe {
            ffi::secp256k1_musig_aggnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                &self.0,
            )
        };
        debug_assert_eq!(ret, 1);

        data
    }

    /// Parse an aggregate nonce from a 66-byte slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<AggregatedNonce, Error> {
        if data.len() != NONCE_SERIALIZED_SIZE {
            return Err(Error::InvalidMusigNonce);
        }

        let mut nonce = ffi::MusigAggNonce::new();
        let ret = unsafe {
            ffi::secp256k1_musig_aggnonce_parse(
                ffi::secp256k1_context_no_precomp,
                &mut nonce,
                data.as_ptr(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidMusigNonce);
        }

        Ok(AggregatedNonce(nonce))
    }
}

impl fmt::LowerHex for AggregatedNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for AggregatedNonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for AggregatedNonce {
    type Err = Error;
    fn from_str(s: &str) -> Result<AggregatedNonce, Error> {
        let mut res = [0u8; NONCE_SERIALIZED_SIZE];
        match from_hex(s, &mut res) {
            Ok(NONCE_SERIALIZED_SIZE) => {
                AggregatedNonce::from_slice(&res[0..NONCE_SERIALIZED_SIZE])
            }
            _ => Err(Error::InvalidMusigNonce),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for AggregatedNonce {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for AggregatedNonce {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                AggregatedNonce::from_slice,
            ))
        }
    }
}

/// A single signer's partial signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PartialSignature(ffi::MusigPartialSignature);

impl PartialSignature {
    /// Serialize the partial signature to 32 bytes.
    #[inline]
    pub fn serialize(&self) -> [u8; PARTIAL_SIGNATURE_SERIALIZED_SIZE] {
        let mut data = [0u8; PARTIAL_SIGNATURE_SERIALIZED_SIZE];

        let ret = unsafe {
            ffi::secp256k1_musig_partial_sig_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                &self.0,
            )
        };
        debug_assert_eq!(ret, 1);

        data
    }

    /// Parse a partial signature from a 32-byte slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PartialSignature, Error> {
        if data.len() != PARTIAL_SIGNATURE_SERIALIZED_SIZE {
            return Err(Error::InvalidMusigPartialSignature);
        }

        let mut sig = ffi::MusigPartialSignature::new();
        let ret = unsafe {
            ffi::secp256k1_musig_partial_sig_parse(
                ffi::secp256k1_context_no_precomp,
                &mut sig,
                data.as_ptr(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidMusigPartialSignature);
        }

        Ok(PartialSignature(sig))
    }
}

impl fmt::LowerHex for PartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for PartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for PartialSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<PartialSignature, Error> {
        let mut res = [0u8; PARTIAL_SIGNATURE_SERIALIZED_SIZE];
        match from_hex(s, &mut res) {
            Ok(PARTIAL_SIGNATURE_SERIALIZED_SIZE) => {
                PartialSignature::from_slice(&res[0..PARTIAL_SIGNATURE_SERIALIZED_SIZE])
            }
            _ => Err(Error::InvalidMusigPartialSignature),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for PartialSignature {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for PartialSignature {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                PartialSignature::from_slice,
            ))
        }
    }
}

/// A MuSig signing session, created from the aggregate nonce and the message.
///
/// Not secret; it can be shared with observers. Required to produce and verify partial
/// signatures and to aggregate them into the final signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Session(ffi::MusigSession);

impl Session {
    /// Processes the aggregate nonce into a signing session for `msg`.
    ///
    /// Fails if the arguments are invalid.
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        key_agg_cache: &KeyAggCache,
        agg_nonce: AggregatedNonce,
        msg: Message,
    ) -> Result<Session, Error> {
        Session::process(secp, key_agg_cache, agg_nonce, msg, ptr::null())
    }

    /// Like [`Session::new`], but binds the session to an `adaptor` point for an
    /// adaptor-signature protocol.
    ///
    /// With an adaptor, [`Session::partial_sig_agg`] produces a *pre-signature* that is not a
    /// valid Schnorr signature until it is completed with [`Session::adapt`] and the secret
    /// adaptor. Fails if the arguments are invalid.
    pub fn with_adaptor<C: Verification>(
        secp: &Secp256k1<C>,
        key_agg_cache: &KeyAggCache,
        agg_nonce: AggregatedNonce,
        msg: Message,
        adaptor: &PublicKey,
    ) -> Result<Session, Error> {
        Session::process(secp, key_agg_cache, agg_nonce, msg, adaptor.as_c_ptr())
    }

    fn process<C: Verification>(
        secp: &Secp256k1<C>,
        key_agg_cache: &KeyAggCache,
        agg_nonce: AggregatedNonce,
        msg: Message,
        adaptor: *const ffi::PublicKey,
    ) -> Result<Session, Error> {
        let mut session = ffi::MusigSession::new();

        let ret = unsafe {
            ffi::secp256k1_musig_nonce_process(
                secp.ctx().as_ptr(),
                &mut session,
                &agg_nonce.0,
                msg.as_c_ptr(),
                &key_agg_cache.cache,
                adaptor,
            )
        };

        if ret == 0 {
            return Err(Error::CannotProcessMusigNonce);
        }

        Ok(Session(session))
    }

    /// Produces this signer's partial signature.
    ///
    /// The `secnonce` must have been generated for `keypair`; a mismatch aborts the process
    /// (rather than returning an error), consistent with this crate's handling of misuse in the
    /// underlying library.
    pub fn partial_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        mut secnonce: SecretNonce,
        keypair: &Keypair,
        key_agg_cache: &KeyAggCache,
    ) -> PartialSignature {
        let mut partial_sig = ffi::MusigPartialSignature::new();

        let ret = unsafe {
            ffi::secp256k1_musig_partial_sign(
                secp.ctx().as_ptr(),
                &mut partial_sig,
                &mut secnonce.0,
                keypair.as_c_ptr(),
                &key_agg_cache.cache,
                &self.0,
            )
        };
        debug_assert_eq!(ret, 1);

        PartialSignature(partial_sig)
    }

    /// Verifies a single signer's partial signature.
    ///
    /// Not required for security (an invalid partial signature makes the aggregate invalid too),
    /// but it lets you identify which signer produced a bad signature and guards against faulty or
    /// adversarial computation. Returns `true` iff the partial signature is valid.
    pub fn partial_verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        key_agg_cache: &KeyAggCache,
        partial_sig: &PartialSignature,
        pubnonce: &PublicNonce,
        pubkey: &PublicKey,
    ) -> bool {
        let ret = unsafe {
            ffi::secp256k1_musig_partial_sig_verify(
                secp.ctx().as_ptr(),
                &partial_sig.0,
                &pubnonce.0,
                pubkey.as_c_ptr(),
                &key_agg_cache.cache,
                &self.0,
            )
        };

        ret == 1
    }

    /// Aggregates partial signatures into a complete BIP-340 Schnorr signature.
    ///
    /// Success does not imply the signature is valid; verify it against [`KeyAggCache::agg_pk`]
    /// with `verify_schnorr`. Fails if `partial_sigs` is empty. For a session created with
    /// [`Session::with_adaptor`], this returns a pre-signature to complete with [`Session::adapt`].
    pub fn partial_sig_agg(&self, partial_sigs: &[&PartialSignature]) -> Result<Signature, Error> {
        if partial_sigs.is_empty() {
            return Err(Error::CannotAggregateMusigPartialSignatures);
        }

        let sig_ptrs: Vec<*const ffi::MusigPartialSignature> =
            partial_sigs.iter().map(|s| &s.0 as *const _).collect();

        let mut sig = [0u8; 64];
        let ret = unsafe {
            ffi::secp256k1_musig_partial_sig_agg(
                ffi::secp256k1_context_no_precomp,
                sig.as_mut_ptr(),
                &self.0,
                sig_ptrs.as_ptr(),
                sig_ptrs.len(),
            )
        };

        if ret == 0 {
            return Err(Error::CannotAggregateMusigPartialSignatures);
        }

        Ok(Signature::from_byte_array(sig))
    }

    /// Completes a pre-signature into a valid Schnorr signature using the secret adaptor.
    ///
    /// `pre_sig` is the output of [`Session::partial_sig_agg`] for a session created with
    /// [`Session::with_adaptor`], and `sec_adaptor` is the secret whose public counterpart was
    /// passed to `with_adaptor`.
    pub fn adapt(&self, pre_sig: &Signature, sec_adaptor: &SecretKey) -> Signature {
        let mut sig = [0u8; 64];

        let ret = unsafe {
            ffi::secp256k1_musig_adapt(
                ffi::secp256k1_context_no_precomp,
                sig.as_mut_ptr(),
                pre_sig.as_byte_array().as_ptr(),
                sec_adaptor.as_c_ptr(),
                self.nonce_parity(),
            )
        };
        debug_assert_eq!(ret, 1);

        Signature::from_byte_array(sig)
    }

    /// Extracts the secret adaptor from a completed signature and the pre-signature it was
    /// completed from.
    ///
    /// This is the "reveal" step of an adaptor-signature protocol: given the final `sig` (e.g.
    /// observed on-chain) and the `pre_sig`, recover the secret. Fails if the arguments are
    /// grossly invalid; note that mismatched signatures yield a nonsensical result rather than an
    /// error, so verify all inputs beforehand.
    pub fn extract_adaptor(
        &self,
        sig: &Signature,
        pre_sig: &Signature,
    ) -> Result<SecretKey, Error> {
        let mut sec_adaptor = [0u8; 32];

        let ret = unsafe {
            ffi::secp256k1_musig_extract_adaptor(
                ffi::secp256k1_context_no_precomp,
                sec_adaptor.as_mut_ptr(),
                sig.as_byte_array().as_ptr(),
                pre_sig.as_byte_array().as_ptr(),
                self.nonce_parity(),
            )
        };

        if ret == 0 {
            return Err(Error::CannotRecoverAdaptorSecret);
        }

        SecretKey::from_byte_array(sec_adaptor).map_err(|_| Error::CannotRecoverAdaptorSecret)
    }

    /// Parity of the aggregate nonce, required to complete or extract an adaptor signature.
    fn nonce_parity(&self) -> i32 {
        let mut parity = 0i32;

        let ret = unsafe {
            ffi::secp256k1_musig_nonce_parity(
                ffi::secp256k1_context_no_precomp,
                &mut parity,
                &self.0,
            )
        };
        debug_assert_eq!(ret, 1);

        parity
    }
}

/// Generates a new nonce pair for a signing session, drawing session randomness from `rng`.
///
/// This is the recommended way to create a nonce: it pulls a fresh, uniformly-random session
/// value from the CSPRNG so callers never handle it directly.
///
/// The optional arguments (`key_agg_cache`, `seckey`, `msg`, `extra_rand`) are folded into the
/// nonce derivation for extra misuse-resistance when they are already known; passing `None` is
/// safe. `pubkey` is the public key of the signer creating the nonce.
#[cfg(feature = "rand")]
pub fn new_nonce_pair<C: Signing, R: Rng + CryptoRng>(
    secp: &Secp256k1<C>,
    rng: &mut R,
    key_agg_cache: Option<&KeyAggCache>,
    seckey: Option<&SecretKey>,
    pubkey: &PublicKey,
    msg: Option<&Message>,
    extra_rand: Option<&[u8; 32]>,
) -> (SecretNonce, PublicNonce) {
    let session_secrand = crate::random_32_bytes(rng);
    new_nonce_pair_with_secrand(
        secp,
        session_secrand,
        key_agg_cache,
        seckey,
        pubkey,
        msg,
        extra_rand,
    )
    .expect("CSPRNG returned an all-zero session secret; the RNG is broken")
}

/// Generates a new nonce pair from caller-supplied session randomness.
///
/// `session_secrand32` must be uniformly random. Unless you have a specific reason to control it
/// (e.g. a deterministic HSM setup), prefer [`new_nonce_pair`]. The supplied array is consumed by
/// value and cleared by the underlying library.
///
/// Fails with [`Error::CannotGenerateMusigNonce`] if `session_secrand32` is all zeros, the one
/// input the underlying library rejects.
pub fn new_nonce_pair_with_secrand<C: Signing>(
    secp: &Secp256k1<C>,
    mut session_secrand32: [u8; 32],
    key_agg_cache: Option<&KeyAggCache>,
    seckey: Option<&SecretKey>,
    pubkey: &PublicKey,
    msg: Option<&Message>,
    extra_rand: Option<&[u8; 32]>,
) -> Result<(SecretNonce, PublicNonce), Error> {
    let mut secnonce = SecretNonce(ffi::MusigSecNonce::new());
    let mut pubnonce = ffi::MusigPubNonce::new();

    let seckey_ptr = seckey.map(|s| s.as_c_ptr()).unwrap_or(ptr::null());
    let cache_ptr = key_agg_cache
        .map(|c| &c.cache as *const ffi::MusigKeyaggCache)
        .unwrap_or(ptr::null());
    let msg_ptr = msg.map(|m| m.as_c_ptr()).unwrap_or(ptr::null());
    let extra_ptr = extra_rand.map(|e| e.as_ptr()).unwrap_or(ptr::null());

    let ret = unsafe {
        ffi::secp256k1_musig_nonce_gen(
            secp.ctx().as_ptr(),
            &mut secnonce.0,
            &mut pubnonce,
            session_secrand32.as_mut_ptr(),
            seckey_ptr,
            pubkey.as_c_ptr(),
            msg_ptr,
            cache_ptr,
            extra_ptr,
        )
    };

    if ret == 0 {
        return Err(Error::CannotGenerateMusigNonce);
    }

    Ok((secnonce, PublicNonce(pubnonce)))
}

/// Sorts `pubkeys` into the canonical order used for order-independent key aggregation.
///
/// Call this before [`KeyAggCache::new`] when there is no natural signer order, so that the
/// aggregate key does not depend on the order in which the keys are provided.
pub fn sort_pubkeys<C: Verification>(secp: &Secp256k1<C>, pubkeys: &mut [PublicKey]) {
    let original: Vec<*const ffi::PublicKey> = pubkeys.iter().map(|pk| pk.as_c_ptr()).collect();
    let mut sorted = original.clone();

    let ret = unsafe {
        ffi::secp256k1_ec_pubkey_sort(secp.ctx().as_ptr(), sorted.as_mut_ptr(), sorted.len())
    };
    debug_assert_eq!(ret, 1);

    // `sorted` is a permutation of `original`; map it back to a permutation of `pubkeys`.
    let permuted: Vec<PublicKey> = sorted
        .iter()
        .map(|&p| {
            pubkeys[original
                .iter()
                .position(|&o| o == p)
                .expect("pointer from this slice")]
        })
        .collect();
    pubkeys.copy_from_slice(&permuted);
}

// These tests exercise the real MuSig implementation end to end, so they are disabled under
// `rust_secp_fuzz` where the core key/signature operations are mocked.
#[cfg(all(test, not(rust_secp_fuzz), feature = "global-context"))]
mod tests {
    use super::*;
    use crate::rand::rng;
    use crate::{Keypair, Message, SECP256K1};

    #[test]
    fn test_musig_2_of_2_roundtrip() {
        let mut rng = rng();

        // Two signers.
        let (sk1, pk1) = SECP256K1.generate_keypair(&mut rng);
        let (sk2, pk2) = SECP256K1.generate_keypair(&mut rng);
        let kp1 = Keypair::from_secret_key(SECP256K1, &sk1);
        let kp2 = Keypair::from_secret_key(SECP256K1, &sk2);

        // Aggregate the public keys.
        let cache = KeyAggCache::new(SECP256K1, &[&pk1, &pk2]).unwrap();

        let msg_bytes = [0xab; 32];
        let msg = Message::from_digest(msg_bytes);

        // Each signer produces a fresh nonce pair.
        let (secnonce1, pubnonce1) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk1),
            &pk1,
            Some(&msg),
            None,
        );
        let (secnonce2, pubnonce2) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk2),
            &pk2,
            Some(&msg),
            None,
        );

        // Aggregate the public nonces and open a session.
        let agg_nonce = AggregatedNonce::new(SECP256K1, &[&pubnonce1, &pubnonce2]).unwrap();
        let session = Session::new(SECP256K1, &cache, agg_nonce, msg).unwrap();

        // Each signer produces (and we verify) a partial signature.
        let psig1 = session.partial_sign(SECP256K1, secnonce1, &kp1, &cache);
        let psig2 = session.partial_sign(SECP256K1, secnonce2, &kp2, &cache);
        assert!(session.partial_verify(SECP256K1, &cache, &psig1, &pubnonce1, &pk1));
        assert!(session.partial_verify(SECP256K1, &cache, &psig2, &pubnonce2, &pk2));
        // A partial signature does not verify against the wrong signer's nonce/key.
        assert!(!session.partial_verify(SECP256K1, &cache, &psig1, &pubnonce2, &pk2));

        // Aggregate into a Schnorr signature that verifies under the aggregate key.
        let sig = session.partial_sig_agg(&[&psig1, &psig2]).unwrap();
        SECP256K1
            .verify_schnorr(&sig, &msg_bytes, &cache.agg_pk())
            .expect("aggregate MuSig signature must verify against the aggregate key");
    }

    #[test]
    fn test_musig_serialization_roundtrip() {
        let mut rng = rng();

        let (sk, pk) = SECP256K1.generate_keypair(&mut rng);
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
        let cache = KeyAggCache::new(SECP256K1, &[&pk]).unwrap();
        let msg = Message::from_digest([0x11; 32]);

        let (secnonce, pubnonce) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk),
            &pk,
            None,
            None,
        );

        // Public nonce round-trips.
        let pubnonce_bytes = pubnonce.serialize();
        assert_eq!(pubnonce_bytes.len(), NONCE_SERIALIZED_SIZE);
        assert_eq!(pubnonce, PublicNonce::from_slice(&pubnonce_bytes).unwrap());

        // Aggregate nonce round-trips.
        let agg_nonce = AggregatedNonce::new(SECP256K1, &[&pubnonce]).unwrap();
        let agg_bytes = agg_nonce.serialize();
        assert_eq!(agg_nonce, AggregatedNonce::from_slice(&agg_bytes).unwrap());

        // Partial signature round-trips.
        let session = Session::new(SECP256K1, &cache, agg_nonce, msg).unwrap();
        let psig = session.partial_sign(SECP256K1, secnonce, &kp, &cache);
        let psig_bytes = psig.serialize();
        assert_eq!(psig_bytes.len(), PARTIAL_SIGNATURE_SERIALIZED_SIZE);
        assert_eq!(psig, PartialSignature::from_slice(&psig_bytes).unwrap());

        // Display / FromStr (hex) round-trips.
        assert_eq!(
            pubnonce,
            pubnonce.to_string().parse::<PublicNonce>().unwrap()
        );
        assert_eq!(
            agg_nonce,
            agg_nonce.to_string().parse::<AggregatedNonce>().unwrap()
        );
        assert_eq!(psig, psig.to_string().parse::<PartialSignature>().unwrap());

        // Wrong-length inputs are rejected instead of aborting.
        assert!(PublicNonce::from_slice(&[0u8; 10]).is_err());
        assert!(AggregatedNonce::from_slice(&[0u8; 10]).is_err());
        assert!(PartialSignature::from_slice(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_musig_key_order_matters_but_agg_is_deterministic() {
        let mut rng = rng();
        let (_sk1, pk1) = SECP256K1.generate_keypair(&mut rng);
        let (_sk2, pk2) = SECP256K1.generate_keypair(&mut rng);

        let cache_a = KeyAggCache::new(SECP256K1, &[&pk1, &pk2]).unwrap();
        let cache_b = KeyAggCache::new(SECP256K1, &[&pk1, &pk2]).unwrap();
        let cache_rev = KeyAggCache::new(SECP256K1, &[&pk2, &pk1]).unwrap();

        // Same order -> same aggregate key; different order -> (generally) different key.
        assert_eq!(cache_a.agg_pk(), cache_b.agg_pk());
        assert_ne!(cache_a.agg_pk(), cache_rev.agg_pk());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_musig_serde_tokens() {
        use serde_test::{assert_tokens, Configure, Token};

        const NONCE_HEX: &str = "033f1b220aae8b87da496154ca3ac1964033281bf3ac14098a60e3f7d5e580cb7002ead5bd6c06b8eb52d65d5e0a670155b9c74f442bba08ac079d0bd986b3274d76";
        const NONCE_BYTES: [u8; NONCE_SERIALIZED_SIZE] = [
            3, 63, 27, 34, 10, 174, 139, 135, 218, 73, 97, 84, 202, 58, 193, 150, 64, 51, 40, 27,
            243, 172, 20, 9, 138, 96, 227, 247, 213, 229, 128, 203, 112, 2, 234, 213, 189, 108, 6,
            184, 235, 82, 214, 93, 94, 10, 103, 1, 85, 185, 199, 79, 68, 43, 186, 8, 172, 7, 157,
            11, 217, 134, 179, 39, 77, 118,
        ];
        const PARTIAL_HEX: &str =
            "61f0672b8bbb8c3c76aebbccdb9f658f4c938f82899ff770789517df7707badb";
        const PARTIAL_BYTES: [u8; PARTIAL_SIGNATURE_SERIALIZED_SIZE] = [
            97, 240, 103, 43, 139, 187, 140, 60, 118, 174, 187, 204, 219, 159, 101, 143, 76, 147,
            143, 130, 137, 159, 247, 112, 120, 149, 23, 223, 119, 7, 186, 219,
        ];

        let pubnonce = PublicNonce::from_slice(&NONCE_BYTES).unwrap();
        assert_tokens(&pubnonce.readable(), &[Token::Str(NONCE_HEX)]);
        assert_tokens(&pubnonce.compact(), &[Token::Bytes(&NONCE_BYTES)]);

        let agg_nonce = AggregatedNonce::from_slice(&NONCE_BYTES).unwrap();
        assert_tokens(&agg_nonce.readable(), &[Token::Str(NONCE_HEX)]);
        assert_tokens(&agg_nonce.compact(), &[Token::Bytes(&NONCE_BYTES)]);

        let partial = PartialSignature::from_slice(&PARTIAL_BYTES).unwrap();
        assert_tokens(&partial.readable(), &[Token::Str(PARTIAL_HEX)]);
        assert_tokens(&partial.compact(), &[Token::Bytes(&PARTIAL_BYTES)]);
    }

    #[test]
    fn test_musig_tweak_keeps_agg_pk_in_sync() {
        let mut rng = rng();
        let (sk1, pk1) = SECP256K1.generate_keypair(&mut rng);
        let (sk2, pk2) = SECP256K1.generate_keypair(&mut rng);
        let kp1 = Keypair::from_secret_key(SECP256K1, &sk1);
        let kp2 = Keypair::from_secret_key(SECP256K1, &sk2);
        let mut cache = KeyAggCache::new(SECP256K1, &[&pk1, &pk2]).unwrap();

        cache.pubkey_ec_tweak_add(SECP256K1, &[0x01; 32]).unwrap();
        let tweaked = cache
            .pubkey_xonly_tweak_add(SECP256K1, &[0x02; 32])
            .unwrap();

        assert_eq!(cache.agg_pk(), XOnlyPublicKey::from(tweaked));
        assert_eq!(
            cache.agg_pk(),
            XOnlyPublicKey::from(cache.agg_pk_full(SECP256K1))
        );

        let msg_bytes = [0x33; 32];
        let msg = Message::from_digest(msg_bytes);
        let (sn1, pn1) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk1),
            &pk1,
            Some(&msg),
            None,
        );
        let (sn2, pn2) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk2),
            &pk2,
            Some(&msg),
            None,
        );
        let agg_nonce = AggregatedNonce::new(SECP256K1, &[&pn1, &pn2]).unwrap();
        let session = Session::new(SECP256K1, &cache, agg_nonce, msg).unwrap();
        let ps1 = session.partial_sign(SECP256K1, sn1, &kp1, &cache);
        let ps2 = session.partial_sign(SECP256K1, sn2, &kp2, &cache);
        let sig = session.partial_sig_agg(&[&ps1, &ps2]).unwrap();
        SECP256K1
            .verify_schnorr(&sig, &msg_bytes, &cache.agg_pk())
            .expect("signature for the tweaked key must verify against agg_pk()");
    }

    #[test]
    fn test_musig_nonce_gen_rejects_zero_secrand() {
        let mut rng = rng();
        let (sk, pk) = SECP256K1.generate_keypair(&mut rng);

        let res =
            new_nonce_pair_with_secrand(SECP256K1, [0u8; 32], None, Some(&sk), &pk, None, None);
        assert!(matches!(res, Err(Error::CannotGenerateMusigNonce)));

        assert!(new_nonce_pair_with_secrand(
            SECP256K1,
            [0x07u8; 32],
            None,
            Some(&sk),
            &pk,
            None,
            None,
        )
        .is_ok());
    }

    #[test]
    fn test_musig_empty_inputs_rejected() {
        let mut rng = rng();
        let (sk, pk) = SECP256K1.generate_keypair(&mut rng);
        let cache = KeyAggCache::new(SECP256K1, &[&pk]).unwrap();
        let msg = Message::from_digest([0x55; 32]);

        assert!(KeyAggCache::new(SECP256K1, &[]).is_err());
        assert!(AggregatedNonce::new(SECP256K1, &[]).is_err());

        let (_secnonce, pubnonce) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk),
            &pk,
            Some(&msg),
            None,
        );
        let agg_nonce = AggregatedNonce::new(SECP256K1, &[&pubnonce]).unwrap();
        let session = Session::new(SECP256K1, &cache, agg_nonce, msg).unwrap();

        assert!(session.partial_sig_agg(&[]).is_err());
    }

    #[test]
    fn test_musig_adaptor_roundtrip() {
        let mut rng = rng();

        let (sk1, pk1) = SECP256K1.generate_keypair(&mut rng);
        let (sk2, pk2) = SECP256K1.generate_keypair(&mut rng);
        let kp1 = Keypair::from_secret_key(SECP256K1, &sk1);
        let kp2 = Keypair::from_secret_key(SECP256K1, &sk2);
        let cache = KeyAggCache::new(SECP256K1, &[&pk1, &pk2]).unwrap();

        // The adaptor: a secret and its public point.
        let (adaptor_secret, adaptor_point) = SECP256K1.generate_keypair(&mut rng);

        let msg_bytes = [0xcd; 32];
        let msg = Message::from_digest(msg_bytes);

        let (secnonce1, pubnonce1) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk1),
            &pk1,
            Some(&msg),
            None,
        );
        let (secnonce2, pubnonce2) = new_nonce_pair(
            SECP256K1,
            &mut rng,
            Some(&cache),
            Some(&sk2),
            &pk2,
            Some(&msg),
            None,
        );
        let agg_nonce = AggregatedNonce::new(SECP256K1, &[&pubnonce1, &pubnonce2]).unwrap();

        // Adaptor session: the aggregate is a pre-signature, not a valid signature.
        let session =
            Session::with_adaptor(SECP256K1, &cache, agg_nonce, msg, &adaptor_point).unwrap();
        let psig1 = session.partial_sign(SECP256K1, secnonce1, &kp1, &cache);
        let psig2 = session.partial_sign(SECP256K1, secnonce2, &kp2, &cache);
        let pre_sig = session.partial_sig_agg(&[&psig1, &psig2]).unwrap();
        assert!(SECP256K1
            .verify_schnorr(&pre_sig, &msg_bytes, &cache.agg_pk())
            .is_err());

        // Completing with the secret yields a valid signature.
        let sig = session.adapt(&pre_sig, &adaptor_secret);
        SECP256K1
            .verify_schnorr(&sig, &msg_bytes, &cache.agg_pk())
            .expect("adapted signature must verify");

        // Given both signatures, the secret adaptor can be recovered.
        let recovered = session.extract_adaptor(&sig, &pre_sig).unwrap();
        assert_eq!(recovered, adaptor_secret);
    }
}
