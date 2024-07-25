//! This module implements high-level Rust bindings for a Schnorr-based
//! multi-signature scheme called MuSig2 [paper](https://eprint.iacr.org/2020/1261).
//! It is compatible with bip-schnorr.
//!
//! The module also supports adaptor signatures as described in
//! [scriptless-scripts repo](https://github.com/ElementsProject/scriptless-scripts)
//!
//! The documentation in this module is for reference and may not be sufficient
//! for advanced use-cases. A full description of the C API usage along with security considerations
//! can be found in [C-musig.md](secp256k1-sys/depend/secp256k1/src/modules/musig/musig.md).
use core::fmt;
use {core, std};

use crate::ffi::{self, CPtr};
use crate::ZERO_TWEAK;
use crate::{schnorr, Keypair, XOnlyPublicKey};
use crate::{Message, PublicKey, Secp256k1, SecretKey, Tweak};
use crate::{Signing, Verification};
use secp256k1::Parity;

#[cfg(feature = "actual-rand")]
use rand::{CryptoRng, RngCore};
use secp256k1_zkp_sys::MUSIG_SECNONCE_LEN;

///  Cached data related to a key aggregation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MusigKeyAggCache(ffi::MusigKeyAggCache, XOnlyPublicKey);

/// Session Id for a MuSig session.
///
/// # NOTE:
///
/// Each call to this nonce generation APIs must have a UNIQUE session_id. This must NOT BE
/// REUSED in subsequent calls to nonce generation APIs such as [`MusigKeyAggCache::nonce_gen`]
/// or [`new_musig_nonce_pair`].
pub struct MusigSessionId([u8; 32]);

impl MusigSessionId {
    /// Creates a new [`MusigSessionId`] with thread local random bytes
    #[cfg(feature = "rand-std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand-std")))]
    pub fn random() -> Self {
        MusigSessionId::new(&mut rand::thread_rng())
    }

    /// Creates a new [`MusigSessionId`] with random bytes from the given rng
    #[cfg(feature = "actual-rand")]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);
        MusigSessionId(session_id)
    }

    /// Creates a new [`MusigSessionId`] with the given bytes.
    ///
    /// Special care must be taken that the bytes are unique for each call to
    /// [`MusigKeyAggCache::nonce_gen`] or [`new_musig_nonce_pair`]. The simplest
    /// recommendation is to use a random 32-byte value. Refer to upstream libsecp256k1-zkp
    /// documentation for more details.
    ///
    /// In rand-std environment, [`MusigSessionId::random`] can be used to generate a random
    /// session id using thread rng.
    pub fn assume_unique_per_nonce_gen(inner: [u8; 32]) -> Self {
        MusigSessionId(inner)
    }

    /// Obtains the inner bytes of the [`MusigSessionId`].
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Obtains a reference to the inner bytes of the [`MusigSessionId`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl CPtr for MusigKeyAggCache {
    type Target = ffi::MusigKeyAggCache;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigKeyAggCache {
    /// Creates a new [`MusigKeyAggCache`] by supplying a list of PublicKeys used in the session.
    ///
    /// Computes a combined public key and the hash of the given public keys.
    ///
    /// Different orders of `pubkeys` result in different `agg_pk`s.
    /// The pubkeys can be sorted lexicographically before combining with which
    /// ensures the same resulting `agg_pk` for the same multiset of pubkeys.
    /// This is useful to do before aggregating pubkeys, such that the order of pubkeys
    /// does not affect the combined public key.
    ///
    /// # Returns
    ///
    ///  A [`MusigKeyAggCache`] the can be used [`MusigKeyAggCache::nonce_gen`] and [`MusigSession::new`].
    ///
    /// # Args:
    ///
    /// * `secp` - Secp256k1 context object initialized for verification
    /// * `pubkeys` - Input array of public keys to combine. The order is important; a
    /// different order will result in a different combined public key
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    /// #
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// let _agg_pk = key_agg_cache.agg_pk();
    /// # }
    /// ```
    pub fn new<C: Verification>(secp: &Secp256k1<C>, pubkeys: &[PublicKey]) -> Self {
        let cx = secp.ctx().as_ptr();
        let pubkey_ptrs = pubkeys.iter().map(|k| k.as_c_ptr()).collect::<Vec<_>>();
        let mut key_agg_cache = ffi::MusigKeyAggCache::new();

        unsafe {
            let mut agg_pk = XOnlyPublicKey::from(ffi::XOnlyPublicKey::new());
            if ffi::secp256k1_musig_pubkey_agg(
                cx,
                // Pass null ptr as scratch space
                core::ptr::null_mut(),
                agg_pk.as_mut_c_ptr(),
                &mut key_agg_cache,
                pubkey_ptrs.as_ptr(),
                pubkey_ptrs.len(),
            ) == 0
            {
                // Returns 0 only if the keys are malformed that never happens in safe rust type system.
                unreachable!("Invalid XOnlyPublicKey in input pubkeys")
            } else {
                MusigKeyAggCache(key_agg_cache, agg_pk)
            }
        }
    }

    /// Obtains the aggregate public key for this [`MusigKeyAggCache`]
    pub fn agg_pk(&self) -> XOnlyPublicKey {
        self.1
    }

    /// Obtains the aggregate public key for this [`MusigKeyAggCache`] as a full [`PublicKey`].
    ///
    /// This is only useful if you need the non-xonly public key, in particular for
    /// plain (non-xonly) tweaking or batch-verifying multiple key aggregations
    /// (not supported yet).
    pub fn agg_pk_full(&self) -> PublicKey {
        unsafe {
            let mut pk = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_get(
                ffi::secp256k1_context_no_precomp,
                pk.as_mut_c_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Returns 0 only if the keys are malformed that never happens in safe rust type system.
                unreachable!("All the arguments are valid")
            } else {
                pk
            }
        }
    }

    /// Apply ordinary "EC" tweaking to a public key in a [`MusigKeyAggCache`].
    ///
    /// This is done by adding the generator multiplied with `tweak32` to it. Returns the tweaked [`PublicKey`].
    /// This is useful for deriving child keys from an aggregate public key via BIP32.
    /// This function is required if you want to _sign_ for a tweaked aggregate key.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for verification
    /// * `tweak`: tweak of type [`SecretKey`] with which to tweak the aggregated key
    ///
    /// # Errors:
    ///
    /// If resulting public key would be invalid (only when the tweak is the negation of the corresponding
    /// secret key). For uniformly random 32-byte arrays(for example, in BIP 32 derivation) the chance of
    /// being invalid is negligible (around 1 in 2^128).
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    /// #
    /// let mut key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    ///
    /// let tweak = SecretKey::from_slice(b"Insecure tweak, Don't use this!!").unwrap(); // tweak could be from BIP32
    /// let _tweaked_key = key_agg_cache.pubkey_ec_tweak_add(&secp, tweak).unwrap();
    /// # }
    /// ```
    pub fn pubkey_ec_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: SecretKey,
    ) -> Result<PublicKey, MusigTweakErr> {
        let cx = secp.ctx().as_ptr();
        unsafe {
            let mut out = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_ec_tweak_add(
                cx,
                out.as_mut_c_ptr(),
                self.as_mut_ptr(),
                tweak.as_c_ptr(),
            ) == 0
            {
                Err(MusigTweakErr::InvalidTweak)
            } else {
                Ok(out)
            }
        }
    }

    /// Apply "x-only" tweaking to a public key in a [`MusigKeyAggCache`].
    ///
    /// This is done by adding the generator multiplied with `tweak32` to it. Returns the tweaked [`XOnlyPublicKey`].
    /// This is useful in creating taproot outputs.
    /// This function is required if you want to _sign_ for a tweaked aggregate key.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for verification
    /// * `tweak`: tweak of type [`SecretKey`] with which to tweak the aggregated key
    ///
    /// # Errors:
    ///
    /// If resulting public key would be invalid (only when the tweak is the negation of the corresponding
    /// secret key). For uniformly random 32-byte arrays(for example, in BIP341 taproot tweaks) the chance of
    /// being invalid is negligible (around 1 in 2^128)
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// let mut key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    ///
    /// let tweak = SecretKey::from_slice(b"Insecure tweak, Don't use this!!").unwrap(); // tweak could be from tap
    /// let _x_only_key_tweaked = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak).unwrap();
    /// # }
    /// ```
    pub fn pubkey_xonly_tweak_add<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: SecretKey,
    ) -> Result<PublicKey, MusigTweakErr> {
        let cx = secp.ctx().as_ptr();
        unsafe {
            let mut out = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_xonly_tweak_add(
                cx,
                out.as_mut_c_ptr(),
                self.as_mut_ptr(),
                tweak.as_c_ptr(),
            ) == 0
            {
                Err(MusigTweakErr::InvalidTweak)
            } else {
                Ok(out)
            }
        }
    }

    /// Starts a signing session by generating a nonce
    ///
    /// This function outputs a secret nonce that will be required for signing and a
    /// corresponding public nonce that is intended to be sent to other signers.
    ///
    /// MuSig differs from regular Schnorr signing in that implementers _must_ take
    /// special care to not reuse a nonce. If you cannot provide a `sec_key`, `session_id`
    /// UNIFORMLY RANDOM AND KEPT SECRET (even from other signers).
    /// Refer to libsecp256k1-zkp documentation for additional considerations.
    ///
    /// Musig2 nonces can be precomputed without knowing the aggregate public key, the message to sign.
    /// See the `new_nonce_pair` method that allows generating [`MusigSecNonce`] and [`MusigPubNonce`]
    /// with only the `session_id` field.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// # Returns:
    ///
    /// A pair of ([`MusigSecNonce`], [`MusigPubNonce`]) that can be later used signing and aggregation
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `session_id`: [`MusigSessionId`] Uniform random identifier for this session. Each call to this
    /// function must have a UNIQUE `session_id`.
    /// * `pub_key`: [`PublicKey`] of the signer creating the nonce.
    /// * `msg`: [`Message`] that will be signed later on.
    /// * `extra_rand`: Additional randomness for mis-use resistance
    ///
    /// # Errors:
    ///
    /// * `ZeroSession`: if the `session_id` is supplied is all zeros.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, MusigSessionId, Message};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    /// #
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    /// let session_id = MusigSessionId::new(&mut thread_rng());
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let extra_rand : Option<[u8; 32]> = None;
    /// let (_sec_nonce, _pub_nonce) = key_agg_cache.nonce_gen(&secp, session_id, pub_key1, msg, extra_rand)
    ///     .expect("non zero session id");
    /// # }
    /// ```
    pub fn nonce_gen<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        session_id: MusigSessionId,
        pub_key: PublicKey,
        msg: Message,
        extra_rand: Option<[u8; 32]>,
    ) -> Result<(MusigSecNonce, MusigPubNonce), MusigNonceGenError> {
        // The secret key here is supplied as NULL. This is okay because we supply the
        // public key and the message.
        // This makes a simple API for the user because it does not require them to pass here.
        new_musig_nonce_pair(
            secp,
            session_id,
            Some(&self),
            None,
            pub_key,
            Some(msg),
            extra_rand,
        )
    }

    /// Get a const pointer to the inner MusigKeyAggCache
    pub fn as_ptr(&self) -> *const ffi::MusigKeyAggCache {
        &self.0
    }

    /// Get a mut pointer to the inner MusigKeyAggCache
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigKeyAggCache {
        &mut self.0
    }
}

/// Musig tweaking related errors.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum MusigTweakErr {
    /// Invalid tweak (tweak is the negation of the corresponding secret key).
    InvalidTweak,
}

#[cfg(feature = "std")]
impl std::error::Error for MusigTweakErr {}

impl fmt::Display for MusigTweakErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            MusigTweakErr::InvalidTweak => write!(
                f,
                "Invalid Tweak: This only happens when
                tweak is negation of secret key"
            ),
        }
    }
}

/// Musig Nonce generation errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum MusigNonceGenError {
    /// Supplied a zero session id
    ZeroSession,
}

#[cfg(feature = "std")]
impl std::error::Error for MusigNonceGenError {}

impl fmt::Display for MusigNonceGenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            MusigNonceGenError::ZeroSession => write!(f, "Supplied a zero session id"),
        }
    }
}
/// Low level API for starting a signing session by generating a nonce.
///
/// Use [`MusigKeyAggCache::nonce_gen`] whenever
/// possible. This API provides full flexibility in providing custom nonce generation,
/// but should be use with care.
///
/// This function outputs a secret nonce that will be required for signing and a
/// corresponding public nonce that is intended to be sent to other signers.
///
/// MuSig differs from regular Schnorr signing in that implementers _must_ take
/// special care to not reuse a nonce. If you cannot provide a `sec_key`, `session_id`
/// UNIFORMLY RANDOM AND KEPT SECRET (even from other signers). Refer to libsecp256k1-zkp
/// documentation for additional considerations.
///
/// Musig2 nonces can be precomputed without knowing the aggregate public key, the message to sign.
/// Refer to libsecp256k1-zkp documentation for additional considerations.
///
/// # Arguments:
///
/// * `secp` : [`Secp256k1`] context object initialized for signing
/// * `session_id`: [`MusigSessionId`] Uniform random identifier for this session. Each call to this
/// function must have a UNIQUE `session_id`.
/// * `sec_key`: Optional [`SecretKey`] that we will use to sign to a create partial signature. Provide this
/// for maximal mis-use resistance.
/// * `pub_key`: [`PublicKey`] that we will use to create partial signature. The secnonce
/// output of this function cannot be used to sign for any other public key.
/// * `msg`: Optional [`Message`] that will be signed later on. Provide this for maximal misuse resistance.
/// * `extra_rand`: Additional randomness for mis-use resistance. Provide this for maximal misuse resistance
///
/// Remember that nonce reuse will immediately leak the secret key!
///
/// # Errors:
///
/// * `ZeroSession`: if the `session_id` is supplied is all zeros.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1_zkp::rand::{thread_rng, RngCore};
/// # use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey, new_musig_nonce_pair, MusigSessionId};
/// # let secp = Secp256k1::new();
/// // The session id must be sampled at random. Read documentation for more details.
/// let session_id = MusigSessionId::new(&mut thread_rng());
/// let sk = SecretKey::new(&mut thread_rng());
/// let pk = PublicKey::from_secret_key(&secp, &sk);
///
/// // Supply extra auxillary randomness to prevent misuse(for example, time of day)
/// let extra_rand : Option<[u8; 32]> = None;
///
/// let (_sec_nonce, _pub_nonce) = new_musig_nonce_pair(&secp, session_id, None, Some(sk), pk, None, None)
///     .expect("non zero session id");
/// # }
/// ```
pub fn new_musig_nonce_pair<C: Signing>(
    secp: &Secp256k1<C>,
    session_id: MusigSessionId,
    key_agg_cache: Option<&MusigKeyAggCache>,
    sec_key: Option<SecretKey>,
    pub_key: PublicKey,
    msg: Option<Message>,
    extra_rand: Option<[u8; 32]>,
) -> Result<(MusigSecNonce, MusigPubNonce), MusigNonceGenError> {
    let cx = secp.ctx().as_ptr();
    let extra_ptr = extra_rand
        .as_ref()
        .map(|e| e.as_ptr())
        .unwrap_or(core::ptr::null());
    let sk_ptr = sec_key
        .as_ref()
        .map(|e| e.as_c_ptr())
        .unwrap_or(core::ptr::null());
    let msg_ptr = msg
        .as_ref()
        .map(|ref e| e.as_c_ptr())
        .unwrap_or(core::ptr::null());
    let cache_ptr = key_agg_cache
        .map(|e| e.as_ptr())
        .unwrap_or(core::ptr::null());
    unsafe {
        let mut sec_nonce = MusigSecNonce(ffi::MusigSecNonce::new());
        let mut pub_nonce = MusigPubNonce(ffi::MusigPubNonce::new());
        if ffi::secp256k1_musig_nonce_gen(
            cx,
            sec_nonce.as_mut_ptr(),
            pub_nonce.as_mut_ptr(),
            session_id.as_bytes().as_ptr(),
            sk_ptr,
            pub_key.as_c_ptr(),
            msg_ptr,
            cache_ptr,
            extra_ptr,
        ) == 0
        {
            // Rust type system guarantees that
            // - input secret key is valid
            // - msg is 32 bytes
            // - Key agg cache is valid
            // - extra input is 32 bytes
            // This can only happen when the session id is all zeros
            Err(MusigNonceGenError::ZeroSession)
        } else {
            Ok((sec_nonce, pub_nonce))
        }
    }
}

/// A Musig partial signature.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigPartialSignature(ffi::MusigPartialSignature);

impl CPtr for MusigPartialSignature {
    type Target = ffi::MusigPartialSignature;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigPartialSignature {
    /// Serialize a MuSigPartialSignature.
    ///
    /// # Returns
    ///
    /// 32-byte array
    pub fn serialize(&self) -> [u8; 32] {
        let mut data = [0; 32];
        unsafe {
            if ffi::secp256k1_musig_partial_sig_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails if args are null pointer which is possible in safe rust
                unreachable!("Serialization cannot fail")
            } else {
                data
            }
        }
    }

    /// Deserialize a MusigPartialSignature from bytes.
    ///
    /// # Errors:
    ///
    /// - ArgLenMismatch: If the signature is not 32 bytes
    /// - MalformedArg: If the signature is 32 bytes, but out of curve order
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let mut part_sig = MusigPartialSignature(ffi::MusigPartialSignature::new());
        if data.len() != 32 {
            return Err(ParseError::ArgLenMismatch {
                expected: 32,
                got: data.len(),
            });
        }
        unsafe {
            if ffi::secp256k1_musig_partial_sig_parse(
                ffi::secp256k1_context_no_precomp,
                part_sig.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(part_sig)
            }
        }
    }

    /// Get a const pointer to the inner MusigPartialSignature
    pub fn as_ptr(&self) -> *const ffi::MusigPartialSignature {
        &self.0
    }

    /// Get a mut pointer to the inner MusigPartialSignature
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPartialSignature {
        &mut self.0
    }
}

/// Musig partial signature parsing errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum ParseError {
    /// Length mismatch
    ArgLenMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size.
        got: usize,
    },
    /// Parse Argument is malformed. This might occur if the point is on the secp order,
    /// or if the secp scalar is outside of group order
    MalformedArg,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ParseError::ArgLenMismatch { expected, got } => {
                write!(f, "Argument must be {} bytes, got {}", expected, got)
            }
            ParseError::MalformedArg => write!(f, "Malformed parse argument"),
        }
    }
}

/// Creates a signature from a pre-signature and an adaptor.
///
/// # Arguments:
///
/// * `pre_sig` : [`schnorr::Signature`] to which the adaptor is to be added
/// * `sec_adaptor` : Secret adaptor of [`Tweak`] type to add to pre signature
/// * `nonce_parity`: The [`Parity`] obtained by [`MusigSession::nonce_parity`] for the session
/// used to compute `pre_sig`.
///
/// # Returns:
///
/// The [`schnorr::Signature`] with the adaptor applied.
///
pub fn adapt(
    pre_sig: schnorr::Signature,
    sec_adaptor: Tweak,
    nonce_parity: Parity,
) -> schnorr::Signature {
    unsafe {
        let mut sig = pre_sig;
        if ffi::secp256k1_musig_adapt(
            ffi::secp256k1_context_no_precomp,
            sig.as_mut_c_ptr(),
            pre_sig.as_c_ptr(),
            sec_adaptor.as_c_ptr(),
            nonce_parity.to_i32(),
        ) == 0
        {
            // Only fails when the arguments are invalid which is not possible in safe rust
            unreachable!("Arguments must be valid and well-typed")
        } else {
            schnorr::Signature::from_slice(sig.as_ref())
                .expect("Adapted signatures from pre-sig must be valid schnorr signatures")
        }
    }
}

/// Extracts a secret adaptor from a MuSig.
///
/// Extracts a secret adaptor from a MuSig, given all parties' partial
/// signatures. This function will not fail unless given grossly invalid data; if it
/// is merely given signatures that do not verify, the returned value will be
/// nonsense. It is therefore important that all data be verified at earlier steps of
/// any protocol that uses this function.
///
/// # Arguments:
///
/// * `sig`: the [`schnorr::Signature`] with the adaptor applied.
/// * `pre_sig` : Secret adaptor of [`SecretKey`] type to add to pre signature
/// corresponding to `sig`. This is the aggregation of all [`MusigPartialSignature`] without
/// the adaptor
/// * `nonce_parity`: The [`Parity`] obtained by [`MusigSession::nonce_parity`] for the session
/// used to compute `pre_sig64`.
///
/// # Returns:
///
/// The adaptor secret of [`Tweak`]. The [`Tweak`] type is like [`SecretKey`], but also
/// allows for representing the zero value.
///
/// Example:
///
/// ```rust
/// # # [cfg(any(test, feature = "rand-std"))] {
/// # use secp256k1_zkp::rand::{thread_rng, RngCore};
/// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, MusigSessionId, Message, MusigAggNonce, MusigSession, adapt, extract_adaptor, Tweak};
/// # let secp = Secp256k1::new();
/// # let sk1 = SecretKey::new(&mut thread_rng());
/// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
/// # let sk2 = SecretKey::new(&mut thread_rng());
/// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
///
/// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
/// // The session id must be sampled at random. Read documentation for more details.
///
/// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
///
/// // Provide the current time for mis-use resistance
/// let session_id1 = MusigSessionId::new(&mut thread_rng());
/// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id1, pub_key1, msg, None)
///     .expect("non zero session id");
///
/// // Signer two does the same. Possibly on a different device
/// let session_id2 = MusigSessionId::new(&mut thread_rng());
/// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id2, pub_key2, msg, None)
///     .expect("non zero session id");
///
/// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
///
/// // Tweak with a secret adaptor
/// let adapt_sec = SecretKey::new(&mut thread_rng());
/// let adapt_pub = PublicKey::from_secret_key(&secp, &adapt_sec);
/// let adapt_sec = Tweak::from_slice(adapt_sec.as_ref()).unwrap();
///
/// let session = MusigSession::with_adaptor(
///     &secp,
///     &key_agg_cache,
///     aggnonce,
///     msg,
///     adapt_pub, // adaptor here
/// );
///
/// let partial_sig1 = session.partial_sign(
///     &secp,
///     sec_nonce1,
///     &Keypair::from_secret_key(&secp, &sk1),
///     &key_agg_cache,
/// ).unwrap();
///
/// // Other party creates the other partial signature
/// let partial_sig2 = session.partial_sign(
///     &secp,
///     sec_nonce2,
///     &Keypair::from_secret_key(&secp, &sk2),
///     &key_agg_cache,
/// ).unwrap();
///
/// let nonce_parity = session.nonce_parity();
/// let pre_sig = session.partial_sig_agg(&[partial_sig1, partial_sig2]);
/// // Get the final schnorr signature
/// let schnorr_sig = adapt(pre_sig, adapt_sec, nonce_parity);
///
/// let extracted_sec = extract_adaptor(
///     schnorr_sig,
///     pre_sig,
///     nonce_parity,
/// );
/// assert_eq!(extracted_sec, adapt_sec);
/// # }
/// ```
pub fn extract_adaptor(
    sig: schnorr::Signature,
    pre_sig: schnorr::Signature,
    nonce_parity: Parity,
) -> Tweak {
    unsafe {
        let mut secret = ZERO_TWEAK;
        if ffi::secp256k1_musig_extract_adaptor(
            ffi::secp256k1_context_no_precomp,
            secret.as_mut_c_ptr(),
            sig.as_c_ptr(),
            pre_sig.as_c_ptr(),
            nonce_parity.to_i32(),
        ) == 0
        {
            // Only fails when the arguments are invalid which is not possible in safe rust
            unreachable!("Arguments must be valid and well-typed")
        } else {
            secret
        }
    }
}

/// Musig Secret Nonce.
///
/// This structure MUST NOT be copied or
/// read or written to it directly. A signer who is online throughout the whole
/// process and can keep this structure in memory can use the provided API
/// functions for a safe standard workflow. See
/// <https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/> for
/// more details about the risks associated with serializing or deserializing
/// this structure. There are no serialization and parsing functions (yet).
///
/// Note this deliberately does not implement `Copy` or `Clone`. After creation, the only
/// use of this nonce is [`MusigSession::partial_sign`] API that takes ownership of this
/// and drops it. This is to prevent accidental misuse of this nonce.
///
/// A signer who is online throughout the whole process and can keep this
/// structure in memory can use the provided API functions for a safe standard
/// workflow.
///
/// Signers that pre-computes and saves these nonces are not yet supported. Users
/// who want to serialize this must use unsafe rust to do so.
#[derive(Debug, Eq, PartialEq)]
pub struct MusigSecNonce(ffi::MusigSecNonce);

impl CPtr for MusigSecNonce {
    type Target = ffi::MusigSecNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigSecNonce {
    /// Get a const pointer to the inner MusigKeyAggCache
    pub fn as_ptr(&self) -> *const ffi::MusigSecNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigKeyAggCache
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSecNonce {
        &mut self.0
    }

    /// Function to return a copy of the internal array. See WARNING before using this function.
    ///
    /// # Warning:
    ///  This structure MUST NOT be copied or read or written to directly. A
    ///  signer who is online throughout the whole process and can keep this
    ///  structure in memory can use the provided API functions for a safe standard
    ///  workflow. See
    ///  https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
    ///  more details about the risks associated with serializing or deserializing
    ///  this structure.
    ///
    ///  We repeat, copying this data structure can result in nonce reuse which will
    ///  leak the secret signing key.
    pub fn dangerous_into_bytes(self) -> [u8; MUSIG_SECNONCE_LEN] {
        self.0.dangerous_into_bytes()
    }

    /// Function to create a new MusigKeyAggCoef from a 32 byte array. See WARNING before using this function.
    ///
    /// Refer to [`MusigSecNonce::dangerous_serialize`] for more details.
    pub fn dangerous_from_bytes(array: [u8; MUSIG_SECNONCE_LEN]) -> Self {
        MusigSecNonce(ffi::MusigSecNonce::dangerous_from_bytes(array))
    }
}

/// An individual MuSig public nonce. Not to be confused with [`MusigAggNonce`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigPubNonce(ffi::MusigPubNonce);

impl CPtr for MusigPubNonce {
    type Target = ffi::MusigPubNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigPubNonce {
    /// Serialize a MusigPubNonce
    pub fn serialize(&self) -> [u8; ffi::MUSIG_PUBNONCE_SERIALIZED_LEN] {
        let mut data = [0; ffi::MUSIG_PUBNONCE_SERIALIZED_LEN];
        unsafe {
            if ffi::secp256k1_musig_pubnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails when the arguments are invalid which is not possible in safe rust
                unreachable!("Arguments must be valid and well-typed")
            } else {
                data
            }
        }
    }

    /// Deserialize a MusigPubNonce from a portable byte representation
    ///
    /// # Errors:
    ///
    /// - ArgLenMismatch: If the [`MusigPubNonce`] is not 132 bytes
    /// - MalformedArg: If the [`MusigPubNonce`] is 132 bytes, but out of curve order
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        let mut pubnonce = MusigPubNonce(ffi::MusigPubNonce::new());
        if data.len() != ffi::MUSIG_PUBNONCE_SERIALIZED_LEN {
            return Err(ParseError::ArgLenMismatch {
                expected: ffi::MUSIG_PUBNONCE_SERIALIZED_LEN,
                got: data.len(),
            });
        }
        unsafe {
            if ffi::secp256k1_musig_pubnonce_parse(
                ffi::secp256k1_context_no_precomp,
                pubnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(pubnonce)
            }
        }
    }

    /// Get a const pointer to the inner MusigPubNonce
    pub fn as_ptr(&self) -> *const ffi::MusigPubNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigPubNonce
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigPubNonce {
        &mut self.0
    }
}

/// Musig aggregated nonce computed by aggregating all individual public nonces
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigAggNonce(ffi::MusigAggNonce);

impl CPtr for MusigAggNonce {
    type Target = ffi::MusigAggNonce;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigAggNonce {
    /// Combine received public nonces into a single aggregated nonce
    ///
    /// This is useful to reduce the communication between signers, because instead
    /// of everyone sending nonces to everyone else, there can be one party
    /// receiving all nonces, combining the nonces with this function and then
    /// sending only the combined nonce back to the signers.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, MusigSessionId, Message, MusigAggNonce};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// # let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// let session_id1 = MusigSessionId::new(&mut thread_rng());
    /// let (_sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id1, pub_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same: Possibly on a different device
    /// let session_id2 = MusigSessionId::new(&mut thread_rng());
    /// let (_sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id2, pub_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    /// # }
    /// ```
    pub fn new<C: Signing>(secp: &Secp256k1<C>, nonces: &[MusigPubNonce]) -> Self {
        let mut aggnonce = MusigAggNonce(ffi::MusigAggNonce::new());
        let nonce_ptrs = nonces.iter().map(|n| n.as_ptr()).collect::<Vec<_>>();
        unsafe {
            if ffi::secp256k1_musig_nonce_agg(
                secp.ctx().as_ptr(),
                aggnonce.as_mut_ptr(),
                nonce_ptrs.as_ptr(),
                nonce_ptrs.len(),
            ) == 0
            {
                // This can only crash if the individual nonces are invalid which is not possible is rust.
                // Note that even if aggregate nonce is point at infinity, the musig spec sets it as `G`
                unreachable!("Public key nonces are well-formed and valid in rust typesystem")
            } else {
                aggnonce
            }
        }
    }

    /// Serialize a MusigAggNonce into a 66 bytes array.
    pub fn serialize(&self) -> [u8; ffi::MUSIG_AGGNONCE_SERIALIZED_LEN] {
        let mut data = [0; ffi::MUSIG_AGGNONCE_SERIALIZED_LEN];
        unsafe {
            if ffi::secp256k1_musig_aggnonce_serialize(
                ffi::secp256k1_context_no_precomp,
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Only fails when the arguments are invalid which is not possible in safe rust
                unreachable!("Arguments must be valid and well-typed")
            } else {
                data
            }
        }
    }

    /// Deserialize a MusigAggNonce from byte slice
    ///
    /// # Errors:
    ///
    /// - ArgLenMismatch: If the slice is not 66 bytes
    /// - MalformedArg: If the byte slice is 66 bytes, but the [`MusigAggNonce`] is invalid
    pub fn from_slice(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != ffi::MUSIG_AGGNONCE_SERIALIZED_LEN {
            return Err(ParseError::ArgLenMismatch {
                expected: ffi::MUSIG_AGGNONCE_SERIALIZED_LEN,
                got: data.len(),
            });
        }
        let mut aggnonce = MusigAggNonce(ffi::MusigAggNonce::new());
        unsafe {
            if ffi::secp256k1_musig_aggnonce_parse(
                ffi::secp256k1_context_no_precomp,
                aggnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(ParseError::MalformedArg)
            } else {
                Ok(aggnonce)
            }
        }
    }

    /// Get a const pointer to the inner MusigAggNonce
    pub fn as_ptr(&self) -> *const ffi::MusigAggNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigAggNonce
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigAggNonce {
        &mut self.0
    }
}

/// A musig Singing session.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigSession(ffi::MusigSession);

impl CPtr for MusigSession {
    type Target = ffi::MusigSession;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigSession {
    /// Creates a new musig signing session.
    ///
    /// Takes the public nonces of all signers and computes a session that is
    /// required for signing and verification of partial signatures.
    ///
    /// See [`MusigSession::with_adaptor`] for adaptor signatures.
    ///
    /// # Returns:
    ///
    /// A [`MusigSession`] that can be later used for signing.
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `key_agg_cache`: [`MusigKeyAggCache`] to be used for this session
    /// * `agg_nonce`: [`MusigAggNonce`], the aggregate nonce
    /// * `msg`: [`Message`] that will be signed later on.
    /// * `adaptor`: The adaptor of type [`PublicKey`] if this is signing session is a part of
    /// an adaptor signature protocol.
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, MusigSessionId, Message, MusigAggNonce, MusigSession};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// # let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let session_id1 = MusigSessionId::new(&mut thread_rng());
    /// let extra_rand1 : Option<[u8; 32]> = None;
    /// let (_sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id1, pub_key1, msg, extra_rand1)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same. Possibly on a different device
    /// let session_id2 = MusigSessionId::new(&mut thread_rng());
    /// let extra_rand2 : Option<[u8; 32]> = None;
    /// let (_sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id2, pub_key2, msg, extra_rand2)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    /// );
    /// # }
    /// ```
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        key_agg_cache: &MusigKeyAggCache,
        agg_nonce: MusigAggNonce,
        msg: Message,
    ) -> Self {
        Self::with_optional_adapter(secp, key_agg_cache, agg_nonce, msg, None)
    }

    /// Same as [`MusigSession::new`] but with an adapter.
    ///
    /// The output of partial signature aggregation will be a pre-signature which
    /// is not a valid Schnorr signature. In order to create a valid signature,
    /// the pre-signature and the secret adaptor must be provided to [`adapt`].
    pub fn with_adaptor<C: Signing>(
        secp: &Secp256k1<C>,
        key_agg_cache: &MusigKeyAggCache,
        agg_nonce: MusigAggNonce,
        msg: Message,
        adaptor: PublicKey,
    ) -> Self {
        Self::with_optional_adapter(secp, key_agg_cache, agg_nonce, msg, Some(adaptor))
    }

    /// Internal function to create a new MusigSession with an optional adaptor.
    fn with_optional_adapter<C: Signing>(
        secp: &Secp256k1<C>,
        key_agg_cache: &MusigKeyAggCache,
        agg_nonce: MusigAggNonce,
        msg: Message,
        adaptor: Option<PublicKey>,
    ) -> Self {
        let mut session = MusigSession(ffi::MusigSession::new());
        let adaptor_ptr = match adaptor {
            Some(a) => a.as_c_ptr(),
            None => core::ptr::null(),
        };
        unsafe {
            if ffi::secp256k1_musig_nonce_process(
                secp.ctx().as_ptr(),
                session.as_mut_ptr(),
                agg_nonce.as_ptr(),
                msg.as_c_ptr(),
                key_agg_cache.as_ptr(),
                adaptor_ptr,
            ) == 0
            {
                // Only fails on cryptographically unreachable codes or if the args are invalid.
                // None of which can occur in safe rust.
                unreachable!("Impossible to construct invalid arguments in safe rust.
                    Also reaches here if R1 + R2*b == point at infinity, but only occurs with 1/1^128 probability")
            } else {
                session
            }
        }
    }

    /// Produces a partial signature for a given key pair and secret nonce.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// # Returns:
    ///
    /// A [`MusigPartialSignature`] that can be later be aggregated into a [`schnorr::Signature`]
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `sec_nonce`: [`MusigSecNonce`] to be used for this session that has never
    /// been used before. For mis-use resistance, this API takes a mutable reference
    /// to `sec_nonce` and sets it to zero even if the partial signing fails.
    /// * `key_pair`: The [`Keypair`] to sign the message
    /// * `key_agg_cache`: [`MusigKeyAggCache`] containing the aggregate pubkey used in
    /// the creation of this session
    ///
    /// # Errors:
    ///
    /// - If the provided [`MusigSecNonce`] has already been used for signing
    ///
    pub fn partial_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        mut secnonce: MusigSecNonce,
        keypair: &Keypair,
        key_agg_cache: &MusigKeyAggCache,
    ) -> Result<MusigPartialSignature, MusigSignError> {
        unsafe {
            let mut partial_sig = MusigPartialSignature(ffi::MusigPartialSignature::new());
            if ffi::secp256k1_musig_partial_sign(
                secp.ctx().as_ptr(),
                partial_sig.as_mut_ptr(),
                secnonce.as_mut_ptr(),
                keypair.as_c_ptr(),
                key_agg_cache.as_ptr(),
                self.as_ptr(),
            ) == 0
            {
                // Since the arguments in rust are always session_valid, the only reason
                // this will fail if the nonce was reused.
                Err(MusigSignError::NonceReuse)
            } else {
                Ok(partial_sig)
            }
        }
    }

    /// Checks that an individual partial signature verifies
    ///
    /// This function is essential when using protocols with adaptor signatures.
    /// However, it is not essential for regular MuSig's, in the sense that if any
    /// partial signatures does not verify, the full signature will also not verify, so the
    /// problem will be caught. But this function allows determining the specific party
    /// who produced an invalid signature, so that signing can be restarted without them.
    ///
    /// # Returns:
    ///
    /// true if the partial signature successfully verifies, otherwise returns false
    ///
    /// # Arguments:
    ///
    /// * `secp` : [`Secp256k1`] context object initialized for signing
    /// * `key_agg_cache`: [`MusigKeyAggCache`] containing the aggregate pubkey used in
    /// the creation of this session
    /// * `partial_sig`: [`MusigPartialSignature`] sent by the signer associated with
    /// the given `pub_nonce` and `pubkey`
    /// * `pub_nonce`: The [`MusigPubNonce`] of the signer associated with the `partial_sig`
    /// and `pub_key`
    /// * `pub_key`: The [`XOnlyPublicKey`] of the signer associated with the given
    /// `partial_sig` and `pub_nonce`
    ///
    /// Example:
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, MusigSessionId, Message, MusigAggNonce, MusigSession};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// # let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let session_id1 = MusigSessionId::new(&mut thread_rng());
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id1, pub_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same. Possibly on a different device
    /// let session_id2 = MusigSessionId::new(&mut thread_rng());
    /// let (_sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id2, pub_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    /// );
    ///
    /// let keypair = Keypair::from_secret_key(&secp, &sk1);
    /// let partial_sig1 = session.partial_sign(
    ///     &secp,
    ///     sec_nonce1,
    ///     &keypair,
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// assert!(session.partial_verify(
    ///     &secp,
    ///     &key_agg_cache,
    ///     partial_sig1,
    ///     pub_nonce1,
    ///     pub_key1,
    /// ));
    /// # }
    /// ```
    pub fn partial_verify<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        key_agg_cache: &MusigKeyAggCache,
        partial_sig: MusigPartialSignature,
        pub_nonce: MusigPubNonce,
        pub_key: PublicKey,
    ) -> bool {
        let cx = secp.ctx().as_ptr();
        unsafe {
            ffi::secp256k1_musig_partial_sig_verify(
                cx,
                partial_sig.as_ptr(),
                pub_nonce.as_ptr(),
                pub_key.as_c_ptr(),
                key_agg_cache.as_ptr(),
                self.as_ptr(),
            ) == 1
        }
    }

    /// Aggregate partial signatures for this session into a single [`schnorr::Signature`]
    ///
    /// # Returns:
    ///
    /// A single [`schnorr::Signature`]. Note that this does *NOT* mean that the signature verifies with respect to the
    /// aggregate public key.
    ///
    /// # Arguments:
    ///
    /// * `partial_sigs`: Array of [`MusigPartialSignature`] to be aggregated
    ///
    /// ```rust
    /// # # [cfg(any(test, feature = "rand-std"))] {
    /// # use secp256k1_zkp::rand::{thread_rng, RngCore};
    /// # use secp256k1_zkp::{MusigKeyAggCache, Secp256k1, SecretKey, Keypair, PublicKey, MusigSessionId, Message, MusigAggNonce, MusigSession};
    /// # let secp = Secp256k1::new();
    /// # let sk1 = SecretKey::new(&mut thread_rng());
    /// # let pub_key1 = PublicKey::from_secret_key(&secp, &sk1);
    /// # let sk2 = SecretKey::new(&mut thread_rng());
    /// # let pub_key2 = PublicKey::from_secret_key(&secp, &sk2);
    ///
    /// let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key1, pub_key2]);
    /// // The session id must be sampled at random. Read documentation for more details.
    ///
    /// let msg = Message::from_digest_slice(b"Public Message we want to sign!!").unwrap();
    ///
    /// // Provide the current time for mis-use resistance
    /// let session_id1 = MusigSessionId::new(&mut thread_rng());
    /// let (mut sec_nonce1, pub_nonce1) = key_agg_cache.nonce_gen(&secp, session_id1, pub_key1, msg, None)
    ///     .expect("non zero session id");
    ///
    /// // Signer two does the same. Possibly on a different device
    /// let session_id2 = MusigSessionId::new(&mut thread_rng());
    /// let (mut sec_nonce2, pub_nonce2) = key_agg_cache.nonce_gen(&secp, session_id2, pub_key2, msg, None)
    ///     .expect("non zero session id");
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pub_nonce1, pub_nonce2]);
    ///
    /// let session = MusigSession::new(
    ///     &secp,
    ///     &key_agg_cache,
    ///     aggnonce,
    ///     msg,
    /// );
    ///
    /// let partial_sig1 = session.partial_sign(
    ///     &secp,
    ///     sec_nonce1,
    ///     &Keypair::from_secret_key(&secp, &sk1),
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// // Other party creates the other partial signature
    /// let partial_sig2 = session.partial_sign(
    ///     &secp,
    ///     sec_nonce2,
    ///     &Keypair::from_secret_key(&secp, &sk2),
    ///     &key_agg_cache,
    /// ).unwrap();
    ///
    /// let schnorr_sig = session.partial_sig_agg(&[partial_sig1, partial_sig2]);
    /// let agg_pk = key_agg_cache.agg_pk();
    ///
    /// // Get the final schnorr signature
    /// assert!(secp.verify_schnorr(&schnorr_sig, &msg, &agg_pk).is_ok())
    /// # }
    /// ```
    pub fn partial_sig_agg(&self, partial_sigs: &[MusigPartialSignature]) -> schnorr::Signature {
        let part_sigs = partial_sigs.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        let mut sig = [0u8; 64];
        unsafe {
            if ffi::secp256k1_musig_partial_sig_agg(
                ffi::secp256k1_context_no_precomp,
                sig.as_mut_ptr(),
                self.as_ptr(),
                part_sigs.as_ptr(),
                part_sigs.len(),
            ) == 0
            {
                // All arguments are well-typed partial signatures
                unreachable!("Impossible to construct invalid(not well-typed) partial signatures")
            } else {
                // Resulting signature must be well-typed. Does not mean that will be succeed verification
                schnorr::Signature::from_slice(&sig)
                    .expect("Resulting signature must be well-typed")
            }
        }
    }

    /// Extracts the nonce_parity bit from a session
    ///
    /// This is used for adaptor signatures
    pub fn nonce_parity(&self) -> Parity {
        let mut parity = 0i32;
        unsafe {
            if ffi::secp256k1_musig_nonce_parity(
                ffi::secp256k1_context_no_precomp,
                &mut parity,
                self.as_ptr(),
            ) == 0
            {
                unreachable!("Well-typed and valid arguments to the function")
            } else {
                Parity::from_i32(parity).expect("Parity guaranteed to be binary")
            }
        }
    }

    /// Get a const pointer to the inner MusigSession
    pub fn as_ptr(&self) -> *const ffi::MusigSession {
        &self.0
    }

    /// Get a mut pointer to the inner MusigSession
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSession {
        &mut self.0
    }
}

/// Musig Signing errors
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum MusigSignError {
    /// Musig nonce re-used.
    /// When creating a partial signature, nonce is cleared and set to all zeros.
    /// This error is caused when we create a partial signature with zero nonce.
    // Note: Because of the current borrowing rules around nonce, this should be impossible.
    // Maybe, we can just unwrap this and not have error at all?
    NonceReuse,
}

#[cfg(feature = "std")]
impl std::error::Error for MusigSignError {}

impl fmt::Display for MusigSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            MusigSignError::NonceReuse => write!(f, "Musig signing nonce re-used"),
        }
    }
}

#[cfg(all(test, feature = "global-context"))]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_key_agg_cache() {
        let secp = Secp256k1::new();
        let mut sec_bytes = [0; 32];
        thread_rng().fill_bytes(&mut sec_bytes);
        let sec_key = SecretKey::from_slice(&sec_bytes).unwrap();
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);

        let _key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key, pub_key]);
    }

    #[test]
    fn test_nonce_parsing() {
        let secp = Secp256k1::new();
        let sec_bytes = [1; 32];
        let sec_key = SecretKey::from_slice(&sec_bytes).unwrap();
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);

        let key_agg_cache = MusigKeyAggCache::new(&secp, &[pub_key, pub_key]);
        let msg = Message::from_digest_slice(&[3; 32]).unwrap();
        let session_id = MusigSessionId::assume_unique_per_nonce_gen([1; 32]);
        let (_secnonce, pubnonce) = key_agg_cache
            .nonce_gen(&secp, session_id, pub_key, msg, None)
            .expect("non zero session id");
        let pubnonce_ser = pubnonce.serialize();
        let parsed_pubnonce = MusigPubNonce::from_slice(&pubnonce_ser).unwrap();

        assert_eq!(parsed_pubnonce, pubnonce);
    }
}
