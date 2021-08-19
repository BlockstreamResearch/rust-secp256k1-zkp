///! This module implements high-level Rust bindings for a Schnorr-based
///! multi-signature scheme called MuSig2 (https://eprint.iacr.org/2020/1261).
///! It is compatible with bip-schnorr.
///!
///! Documentation tests and some examples in [examples/musig.rs] show how the library can be used.
///!
///! The module also supports adaptor signatures as described in
///! https://github.com/ElementsProject/scriptless-scripts/pull/24
///!
///! The documentation in this include file is for reference and may not be sufficient
///! for users to begin using the library. A full description of the C API usage can be found
///! in [C-musig.md](secp256k1-sys/depend/secp256k1/src/modules/musig/musig.md), and Rust API
///! usage can be found in [Rust-musig.md](USAGE.md).
use ffi::{self, CPtr};
use schnorrsig;
use Error;
use Signing;
use {Message, PublicKey, Secp256k1, SecretKey};

///  Data structure containing auxiliary data generated in `pubkey_agg` and
///  required for `session_*_init`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MusigPreSession {
    inner: ffi::MusigKeyaggCache,
    agg_pk: schnorrsig::PublicKey,
}

impl CPtr for MusigPreSession {
    type Target = ffi::MusigKeyaggCache;

    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl MusigPreSession {
    /// Create a new MusigPreSession by supplying a list of PublicKeys used in the session
    ///
    /// Computes a combined public key and the hash of the given public keys.
    ///
    /// Different orders of `pubkeys` result in different `agg_pk`s.
    ///
    /// The pubkeys can be sorted before combining with `rustsecp256k1zkp_v0_4_0_xonly_sort` which
    /// ensures the same resulting `agg_pk` for the same multiset of pubkeys.
    /// This is useful to do before pubkey_combine, such that the order of pubkeys
    /// does not affect the combined public key.
    ///
    /// Returns: MusigPreSession if the public keys were successfully combined, Error otherwise
    /// Args:        secp: Secp256k1 context object initialized for verification
    /// Out: pre_session: `MusigPreSession` struct to be used in
    ///                   `MusigPreSession::nonce_process` or `MusigPreSession::pubkey_tweak_add`.
    ///                   `MusigPreSession` also contains the Musig-combined xonly public key
    ///  In:     pubkeys: input array of public keys to combine. The order
    ///                   is important; a different order will result in a different
    ///                   combined public key
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{MusigPreSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key.clone());
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let _pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// ```
    pub fn new<C: Signing>(secp: &Secp256k1<C>, pubkeys: &[schnorrsig::PublicKey]) -> Result<Self, Error> {
        let cx = *secp.ctx();
        let xonly_ptrs = pubkeys
            .iter()
            .map(|k| k.as_ptr())
            .collect::<Vec<_>>();
        let mut keyagg_cache = ffi::MusigKeyaggCache::new();

        unsafe {
            let mut agg_pk = schnorrsig::PublicKey::from(ffi::XOnlyPublicKey::new());
            if ffi::secp256k1_musig_pubkey_agg(
                cx,
                // FIXME: passing null pointer to ScratchSpace uses less efficient algorithm
                // Need scratch_space_{create,destroy} exposed in public C API to safely handle
                // memory
                core::ptr::null_mut(),
                agg_pk.as_mut_ptr(),
                &mut keyagg_cache,
                xonly_ptrs.as_ptr() as *const *const _,
                xonly_ptrs.len(),
            ) == 0
            {
                Err(Error::InvalidMusigPreSession)
            } else {
                Ok(Self {
                    inner: keyagg_cache,
                    agg_pk,
                })
            }
        }
    }

    /// Tweak an x-only public key by adding the generator multiplied with tweak32
    /// to it. The resulting output_pubkey with the given agg_pk and tweak
    /// passes `rustsecp256k1zkp_v0_4_0_xonly_pubkey_tweak_test`.
    ///
    /// This function is only useful before initializing a signing session. If you
    /// are only computing a public key, but not intending to create a signature for
    /// it, you can just use `rustsecp256k1zkp_v0_4_0_xonly_pubkey_tweak_add`. Can only be called
    /// once with a given pre_session.
    ///
    /// Returns: Error if the arguments are invalid or the resulting public key would be
    ///          invalid (only when the tweak is the negation of the corresponding
    ///          secret key). Tweaked PublicKey otherwise.
    /// Args:          secp: Secp256k1 context object initialized for verification
    /// Out: output_pubkey: PublicKey with the result of the tweak
    /// In:        tweak32: const reference to a 32-byte tweak. If the tweak is invalid
    ///                     according to rustsecp256k1zkp_v0_4_0_ec_seckey_verify, this function
    ///                     returns Error. For uniformly random 32-byte arrays the
    ///                     chance of being invalid is negligible (around 1 in
    ///                     2^128)
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{MusigPreSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key.clone());
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let mut pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let _pubkey = pre_session.pubkey_tweak_add(&secp, &[2; 32]).unwrap();
    /// ```
    pub fn pubkey_tweak_add<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: &[u8; 32],
    ) -> Result<PublicKey, Error> {
        let cx = *secp.ctx();
        unsafe {
            let mut out = PublicKey::from(ffi::PublicKey::new());
            if ffi::secp256k1_musig_pubkey_tweak_add(
                cx,
                out.as_mut_ptr(),
                tweak.as_ptr(),
                self.as_mut_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigTweak)
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
    /// special care to not reuse a nonce. This can be ensured by following these rules:
    ///
    /// 1. Always provide a unique session_id32. It is a "number used once".
    /// 2. If you already know the signing key, message or aggregate public key
    ///    cache, they can be optionally provided to derive the nonce and increase
    ///    misuse-resistance. The extra_input32 argument can be used to provide
    ///    additional data that does not repeat in normal scenarios, such as the
    ///    current time.
    /// 3. If you do not provide a seckey, session_id32 _must_ be UNIFORMLY RANDOM.
    ///    If you do provide a seckey, session_id32 can instead be a counter (that
    ///    must never repeat!). However, it is recommended to always choose
    ///    session_id32 uniformly at random. Note that using the same seckey for
    ///    multiple MuSig sessions is fine.
    /// 4. Avoid copying (or serializing) the secnonce. This reduces the possibility
    ///    that it is used more than once for signing.
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigPreSession, PublicKey, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let id = [2; 32];
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let (_sec_nonce, _pub_nonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    /// ```
    pub fn nonce_gen<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        session_id: &[u8; 32],
        seckey: Option<&SecretKey>,
        msg: &Message,
        extra: Option<&[u8; 32]>,
    ) -> Result<(MusigSecNonce, MusigPubNonce), Error> {
        let cx = *secp.ctx();
        let extra_ptr = match extra {
            Some(e) => e.as_ptr(),
            None => core::ptr::null(),
        };
        unsafe {
            let mut sec_nonce = MusigSecNonce(ffi::MusigSecNonce::new());
            let mut pub_nonce = MusigPubNonce(ffi::MusigPubNonce::new());
            let sk_ptr = match seckey {
                Some(s) => s.as_ptr(),
                None => core::ptr::null(),
            };
            if ffi::secp256k1_musig_nonce_gen(
                cx,
                sec_nonce.as_mut_ptr(),
                pub_nonce.as_mut_ptr(),
                session_id.as_ptr(),
                sk_ptr,
                msg.as_ptr(),
                self.as_ptr(),
                extra_ptr,
            ) == 0
            {
                Err(Error::CannotGenMusigNonce)
            } else {
                Ok((sec_nonce, pub_nonce))
            }
        }
    }

    /// Process MusigPreSession nonces to create a session cache and signature template
    /// Takes the public nonces of all signers and computes a session cache that is
    /// required for signing and verification of partial signatures and a signature
    /// template that is required for combining partial signatures.
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, PublicKey, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [1; 32];
    /// let (_secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let _session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    /// ```
    pub fn nonce_process<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        aggnonce: &MusigAggNonce,
        msg: &Message,
        adaptor: Option<&PublicKey>,
    ) -> Result<MusigSession, Error> {
        let mut session = MusigSession(ffi::MusigSession::new());
        let adaptor_ptr = match adaptor {
            Some(a) => a.as_ptr(),
            None => core::ptr::null(),
        };
        unsafe {
            if ffi::secp256k1_musig_nonce_process(
                *secp.ctx(),
                session.as_mut_ptr(),
                aggnonce.as_ptr(),
                msg.as_ptr(),
                self.as_ptr(),
                adaptor_ptr,
            ) == 0
            {
                Err(Error::InvalidMusigPubNonce)
            } else {
                Ok(session)
            }
        }
    }

    /// Get a const reference to the aggregated public key
    pub fn agg_pk(&self) -> &schnorrsig::PublicKey {
        &self.agg_pk
    }

    /// Get a const pointer to the inner MusigPreSession
    pub fn as_ptr(&self) -> *const ffi::MusigKeyaggCache {
        &self.inner
    }

    /// Get a mut pointer to the inner MusigPreSession
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigKeyaggCache {
        &mut self.inner
    }
}

/// Opaque data structure that holds a partial MuSig signature.
///
/// Guaranteed to be 32 bytes in size. Serialized and parsed with
/// [MusigPartialSignature::serialize] and [MusigPartialSignature::parse].
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
    /// Serialize a MuSigPartialSignature or adaptor signature
    ///
    /// Returns: 32-byte array when the signature could be serialized, Error otherwise
    /// Args:    ctx: a Secp256k1 context object
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, PublicKey, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    ///
    /// let partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut secnonce,
    ///     &keypair,
    ///     &pre_session,
    /// ).unwrap();
    ///
    /// let _ser_sig = partial_sig.serialize(&secp).unwrap();
    /// ```
    pub fn serialize<C: Signing>(&self, secp: &Secp256k1<C>) -> Result<[u8; 32], Error> {
        let mut data = [0; 32];
        unsafe {
            if ffi::secp256k1_musig_partial_sig_serialize(
                *secp.ctx(),
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigPartSig)
            } else {
                Ok(data)
            }
        }
    }

    /// Deserialize a MusigPartialSignature from a portable byte representation
    /// Parse and verify a MuSig partial signature.
    ///
    /// After the call, sig will always be initialized. If parsing failed or the
    /// encoded numbers are out of range, signature verification with it is
    /// guaranteed to fail for every message and public key.
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{
    /// #   Message, MusigAggNonce, MusigPartialSignature, MusigPreSession, MusigSession, Secp256k1, SecretKey,
    /// # };
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    ///
    /// let partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut secnonce,
    ///     &keypair,
    ///     &pre_session,
    /// ).unwrap();
    ///
    /// let ser_sig = partial_sig.serialize(&secp).unwrap();
    /// let _parsed_sig = MusigPartialSignature::parse(&secp, &ser_sig).unwrap();
    /// ```
    pub fn parse<C: Signing>(secp: &Secp256k1<C>, data: &[u8]) -> Result<Self, Error> {
        let mut part_sig = MusigPartialSignature(ffi::MusigPartialSignature::new());
        if data.len() != 32 {
            return Err(Error::InvalidMusigPartSig);
        }
        unsafe {
            if ffi::secp256k1_musig_partial_sig_parse(
                *secp.ctx(),
                part_sig.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigPartSig)
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

/// Converts a partial signature to an adaptor signature by adding a given secret adaptor.
///
/// Example:
///
/// ```rust
/// # use secp256k1_zkp::{adapt, Message, MusigAggNonce, MusigPreSession, MusigSession, PublicKey, Secp256k1, SecretKey};
/// # use secp256k1_zkp::schnorrsig;
/// let secp = Secp256k1::new();
/// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
/// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
/// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
/// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
/// let msg = Message::from_slice(&[3; 32]).unwrap();
/// let id = [2; 32];
/// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
///
/// let adapt_bytes = [2; 32];
/// let adapt_sec = SecretKey::from_slice(&adapt_bytes).unwrap();
/// let adapt_pub = PublicKey::from_secret_key(&secp, &adapt_sec);
///
/// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
/// let mut session = pre_session.nonce_process(
///     &secp,
///     &aggnonce,
///     &msg,
///     Some(&adapt_pub),
/// ).unwrap();
///
/// let partial_sig = session.partial_sign(
///     &secp,
///     &mut secnonce,
///     &keypair,
///     &pre_session,
/// ).unwrap();
/// let nonce_parity = session.nonce_parity(&secp).unwrap();
/// let pre_sig = session.partial_sig_agg(&secp, &[partial_sig]).unwrap();
///
/// let _adaptor_sig = adapt(&secp, &pre_sig, &adapt_sec, nonce_parity).unwrap();
/// ```
pub fn adapt<C: Signing>(
    secp: &Secp256k1<C>,
    pre_sig: &schnorrsig::Signature,
    sec_adaptor: &SecretKey,
    nonce_parity: i32,
) -> Result<schnorrsig::Signature, Error> {
    unsafe {
        let mut sig = pre_sig.clone();
        if ffi::secp256k1_musig_adapt(
            *secp.ctx(),
            sig.as_mut_ptr(),
            sec_adaptor.as_ptr(),
            nonce_parity,
        ) == 0
        {
            Err(Error::InvalidMusigPartSig)
        } else {
            Ok(schnorrsig::Signature::from_slice(sig.as_ref())?)
        }
    }
}

/// Extracts a secret adaptor from a MuSig, given all parties' partial
/// signatures. This function will not fail unless given grossly invalid data; if it
/// is merely given signatures that do not verify, the returned value will be
/// nonsense. It is therefore important that all data be verified at earlier steps of
/// any protocol that uses this function.
///
/// Example:
///
/// ```rust
/// # use secp256k1_zkp::{adapt, extract_adaptor};
/// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, PublicKey, Secp256k1, SecretKey};
/// # use secp256k1_zkp::schnorrsig;
/// let secp = Secp256k1::new();
/// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
/// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
/// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
/// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
/// let msg = Message::from_slice(&[3; 32]).unwrap();
///
/// let adapt_bytes = [2; 32];
/// let adapt_sec = SecretKey::from_slice(&adapt_bytes).unwrap();
/// let adapt_pub = PublicKey::from_secret_key(&secp, &adapt_sec);
///
/// let id = [2; 32];
/// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
/// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
///
/// let mut session = pre_session.nonce_process(
///     &secp,
///     &aggnonce,
///     &msg,
///     Some(&adapt_pub),
/// ).unwrap();
///
/// let partial_sig = session.partial_sign(
///     &secp,
///     &mut secnonce,
///     &keypair,
///     &pre_session,
/// ).unwrap();
///
/// let nonce_parity = session.nonce_parity(&secp).unwrap();
/// let pre_sig = session.partial_sig_agg(&secp, &[partial_sig]).unwrap();
/// let adaptor_sig = adapt(&secp, &pre_sig, &adapt_sec, nonce_parity).unwrap();
/// let extracted_sec = extract_adaptor(
///     &secp,
///     &adaptor_sig,
///     &pre_sig,
///     nonce_parity,
/// ).unwrap();
/// assert_eq!(extracted_sec, adapt_sec);
/// ```
pub fn extract_adaptor<C: Signing>(
    secp: &Secp256k1<C>,
    sig: &schnorrsig::Signature,
    pre_sig: &schnorrsig::Signature,
    nonce_parity: i32,
) -> Result<SecretKey, Error> {
    unsafe {
        let mut secret = SecretKey::from_slice([1; 32].as_ref())?;
        if ffi::secp256k1_musig_extract_adaptor(
            *secp.ctx(),
            secret.as_mut_ptr(),
            sig.as_ptr(),
            pre_sig.as_ptr(),
            nonce_parity,
        ) == 0
        {
            Err(Error::InvalidMusigExtract)
        } else {
            Ok(secret)
        }
    }
}

/// Guaranteed to be 64 bytes in size. This structure MUST NOT be copied or
/// read or written to it directly. A signer who is online throughout the whole
/// process and can keep this structure in memory can use the provided API
/// functions for a safe standard workflow. See
/// https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
/// more details about the risks associated with serializing or deserializing
/// this structure. There are no serialization and parsing functions (yet).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    /// Get a const pointer to the inner MusigPreSession
    pub fn as_ptr(&self) -> *const ffi::MusigSecNonce {
        &self.0
    }

    /// Get a mut pointer to the inner MusigPreSession
    pub fn as_mut_ptr(&mut self) -> *mut ffi::MusigSecNonce {
        &mut self.0
    }
}

/// Opaque data structure that holds a MuSig public nonce.
///
/// Guaranteed to be 66 bytes in size. There are no serialization and parsing functions (yet).
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
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigPreSession, MusigPubNonce, PublicKey, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let _pubnonce_ser = pubnonce.serialize(&secp).unwrap();
    /// ```
    pub fn serialize<C: Signing>(&self, secp: &Secp256k1<C>) -> Result<[u8; ffi::MUSIG_PUBNONCE_LEN], Error> {
        let mut data = [0; ffi::MUSIG_PUBNONCE_LEN];
        unsafe {
            if ffi::secp256k1_musig_pubnonce_serialize(
                *secp.ctx(),
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigPubNonce)
            } else {
                Ok(data)
            }
        }
    }

    /// Deserialize a MusigPubNonce from a portable byte representation
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigPreSession, MusigPubNonce, PublicKey, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let pubnonce_ser = pubnonce.serialize(&secp).unwrap();
    /// let parsed_pubnonce = MusigPubNonce::parse(&secp, &pubnonce_ser).unwrap();
    /// assert_eq!(parsed_pubnonce, pubnonce);
    /// ```
    pub fn parse<C: Signing>(secp: &Secp256k1<C>, data: &[u8]) -> Result<Self, Error> {
        let mut pubnonce = MusigPubNonce(ffi::MusigPubNonce::new());
        if data.len() != ffi::MUSIG_PUBNONCE_LEN {
            return Err(Error::InvalidMusigPartSig);
        }
        unsafe {
            if ffi::secp256k1_musig_pubnonce_parse(
                *secp.ctx(),
                pubnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigPubNonce)
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

/// Opaque data structure that holds a MuSig aggregated nonce.
///
/// Guaranteed to be 66 bytes in size. There are no serialization and parsing functions (yet).
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
    /// sending only the combined nonce back to the signers. The pubnonces argument
    /// of [MusigPreSession::nonce_process] then simply becomes an array whose sole
    /// element is this combined nonce.
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigPubNonce, MusigSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    ///
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    /// let _aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// ```
    pub fn new<C: Signing>(secp: &Secp256k1<C>, nonces: &[MusigPubNonce]) -> Result<Self, Error> {
        let mut aggnonce = Self(ffi::MusigAggNonce::new());
        let nonce_ptrs = nonces.iter().map(|n| n.as_ptr()).collect::<Vec<_>>();
        unsafe {
            if ffi::secp256k1_musig_nonce_agg(
                *secp.ctx(),
                aggnonce.as_mut_ptr(),
                nonce_ptrs.as_ptr(),
                nonce_ptrs.len(),
            ) == 0
            {
                Err(Error::InvalidMusigPubNonce)
            } else {
                Ok(aggnonce)
            }
        }
    }

    /// Serialize a MusigAggNonce
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    ///
    /// let _aggnonce_ser = aggnonce.serialize(&secp).unwrap();
    /// ```
    pub fn serialize<C: Signing>(&self, secp: &Secp256k1<C>) -> Result<[u8; ffi::MUSIG_AGGNONCE_LEN], Error> {
        let mut data = [0; ffi::MUSIG_AGGNONCE_LEN];
        unsafe {
            if ffi::secp256k1_musig_aggnonce_serialize(
                *secp.ctx(),
                data.as_mut_ptr(),
                self.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigAggNonce)
            } else {
                Ok(data)
            }
        }
    }

    /// Deserialize a MusigAggNonce from a portable byte representation
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    ///
    /// let aggnonce_ser = aggnonce.serialize(&secp).unwrap();
    /// let parsed_aggnonce = MusigAggNonce::parse(&secp, &aggnonce_ser).unwrap();
    /// assert_eq!(parsed_aggnonce, aggnonce);
    /// ```
    pub fn parse<C: Signing>(secp: &Secp256k1<C>, data: &[u8]) -> Result<Self, Error> {
        if data.len() != ffi::MUSIG_AGGNONCE_LEN {
            return Err(Error::InvalidMusigPartSig);
        }
        let mut aggnonce = Self(ffi::MusigAggNonce::new());
        unsafe {
            if ffi::secp256k1_musig_aggnonce_parse(
                *secp.ctx(),
                aggnonce.as_mut_ptr(),
                data.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigAggNonce)
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

/// Musig session data structure containing the
/// secret and public nonce used in a multi-signature signing session
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
    /// Produces a partial signature
    ///
    /// This function sets the given secnonce to 0 and will abort if given a
    /// secnonce that is 0. This is a best effort attempt to protect against nonce
    /// reuse. However, this is of course easily defeated if the secnonce has been
    /// copied (or serialized).
    ///
    /// Remember that nonce reuse will immediately leak the secret key!
    ///
    /// Returns: Error if the arguments are invalid or the provided secnonce has already
    ///          been used for signing, MusigPartialSignature otherwise
    /// Args:         ctx: pointer to a context object (cannot be NULL)
    /// In/Out:  secnonce: MusigSecNonce struct created in [MusigSession::new]
    /// In:       keypair: Keypair to sign the message with
    ///     session_cache: MusigSessionCache that was created with [MusigPartialSig::nonce_process]
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    ///
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    ///
    /// let _partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut secnonce,
    ///     &keypair,
    ///     &pre_session,
    /// ).unwrap();
    /// ```
    pub fn partial_sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        secnonce: &mut MusigSecNonce,
        keypair: &schnorrsig::KeyPair,
        pre_session: &MusigPreSession,
    ) -> Result<MusigPartialSignature, Error> {
        unsafe {
            let mut partial_sig = MusigPartialSignature(ffi::MusigPartialSignature::new());
            if ffi::secp256k1_musig_partial_sign(
                *secp.ctx(),
                partial_sig.as_mut_ptr(),
                secnonce.as_mut_ptr(),
                keypair.as_ptr(),
                pre_session.as_ptr(),
                self.as_ptr(),
            ) == 0
            {
                Err(Error::InvalidMusigPartSig)
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
    /// Returns: false if the arguments are invalid or the partial signature does not
    ///          verify, true otherwise
    /// Args        secp: Secp256k1 context object, initialized for verification
    /// In:     pubnonce: the 66-byte pubnonce sent by the signer who produced
    ///                   the signature
    ///           pubkey: public key of the signer who produced the signature
    ///      pre_session: MusigPreSession that was output when the
    ///                   combined public key for this session
    ///    session_cache: MusigSessionCache that was created with
    ///                   [MusigPartialSig::nonce_process]
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let mut pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    ///
    /// let partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut secnonce,
    ///     &keypair,
    ///     &pre_session,
    /// ).unwrap();
    ///
    /// assert!(session.partial_verify(
    ///     &secp,
    ///     &partial_sig,
    ///     &pubnonce,
    ///     &pub_key,
    ///     &pre_session,
    /// ));
    /// ```
    pub fn partial_verify<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        partial_sig: &MusigPartialSignature,
        pubnonce: &MusigPubNonce,
        pubkey: &schnorrsig::PublicKey,
        pre_session: &MusigPreSession,
    ) -> bool {
        let cx = *secp.ctx();
        unsafe {
            ffi::secp256k1_musig_partial_sig_verify(
                cx,
                partial_sig.as_ptr(),
                pubnonce.as_ptr(),
                pubkey.as_ptr(),
                pre_session.as_ptr(),
                self.as_ptr(),
            ) == 1
        }
    }

    /// Aggregate partial signatures
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    ///
    /// let partial_sig = session.partial_sign(
    ///     &secp,
    ///     &mut secnonce,
    ///     &keypair,
    ///     &pre_session,
    /// ).unwrap();
    /// let _sig = session.partial_sig_agg(&secp, &[partial_sig]).unwrap();
    /// ```
    pub fn partial_sig_agg<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        partial_sigs: &[MusigPartialSignature],
    ) -> Result<schnorrsig::Signature, Error> {
        let part_sigs = partial_sigs.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        let mut sig = [0u8; 64];
        unsafe {
            if ffi::secp256k1_musig_partial_sig_agg(
                *secp.ctx(),
                sig.as_mut_ptr(),
                self.as_ptr(),
                part_sigs.as_ptr(),
                part_sigs.len(),
            ) == 0
            {
                Err(Error::InvalidMusigPartSig)
            } else {
                Ok(schnorrsig::Signature::from_slice(&sig)?)
            }
        }
    }

    /// Extracts the nonce_parity bit from a session
    ///
    /// This is used for adaptor signatures
    ///
    /// Example:
    ///
    /// ```rust
    /// # use secp256k1_zkp::{Message, MusigAggNonce, MusigPreSession, MusigSession, Secp256k1, SecretKey};
    /// # use secp256k1_zkp::schnorrsig;
    /// let secp = Secp256k1::new();
    /// let sec_key = SecretKey::from_slice([1; 32].as_ref()).unwrap();
    /// let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
    /// let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);
    /// let pre_session = MusigPreSession::new(&secp, &[pub_key]).unwrap();
    /// let msg = Message::from_slice(&[3; 32]).unwrap();
    /// let id = [2; 32];
    /// let (mut secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();
    ///
    /// let aggnonce = MusigAggNonce::new(&secp, &[pubnonce]).unwrap();
    /// let mut session = pre_session.nonce_process(
    ///     &secp,
    ///     &aggnonce,
    ///     &msg,
    ///     None,
    /// ).unwrap();
    ///
    /// let _parity = session.nonce_parity(&secp).unwrap();
    /// ```
    pub fn nonce_parity<C: Signing>(&mut self, secp: &Secp256k1<C>) -> Result<i32, Error> {
        let mut ret = 0i32;
        let cx = *secp.ctx();
        unsafe {
            if ffi::secp256k1_musig_nonce_parity(cx, &mut ret, self.as_mut_ptr()) == 0 {
                Err(Error::InvalidMusigSession)
            } else {
                Ok(ret)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_pre_session() {
        let secp = Secp256k1::new();
        let mut sec_bytes = [0; 32];
        thread_rng().fill_bytes(&mut sec_bytes);
        let sec_key = SecretKey::from_slice(&sec_bytes).unwrap();
        let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
        let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);

        let _pre_session = MusigPreSession::new(&secp, &[pub_key, pub_key]).unwrap();
    }

    #[test]
    fn test_nonce_parsing() {
        let secp = Secp256k1::new();
        let mut sec_bytes = [0; 32];
        thread_rng().fill_bytes(&mut sec_bytes);
        let sec_key = SecretKey::from_slice(&sec_bytes).unwrap();
        let keypair = schnorrsig::KeyPair::from_secret_key(&secp, sec_key);
        let pub_key = schnorrsig::PublicKey::from_keypair(&secp, &keypair);

        let pre_session = MusigPreSession::new(&secp, &[pub_key, pub_key]).unwrap();
        let msg = Message::from_slice(&[3; 32]).unwrap();
        let id = [2; 32];
        let (_secnonce, pubnonce) = pre_session.nonce_gen(&secp, &id, None, &msg, None).unwrap();

        let pubnonce_ser = pubnonce.serialize(&secp).unwrap();
        let parsed_pubnonce = MusigPubNonce::parse(&secp, &pubnonce_ser).unwrap();

        assert_eq!(parsed_pubnonce, pubnonce);
    }
}
