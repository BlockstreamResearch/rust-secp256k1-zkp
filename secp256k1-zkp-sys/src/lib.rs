// SPDX-License-Identifier: CC0-1.0

//! # secp256k1-sys FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut
)]
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(secp256k1_fuzz)]
const THIS_UNUSED_CONSTANT_IS_YOUR_WARNING_THAT_ALL_THE_CRYPTO_IN_THIS_LIB_IS_DISABLED_FOR_FUZZING: usize = 0;

mod macros;
pub mod types;

pub mod zkp;
pub use zkp::*;

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr::NonNull;
use core::{ptr, slice};
use types::size_t;
#[cfg(feature = "alloc")]
use types::ALIGN_TO;

/// Flag for context to enable no precomputation
pub const SECP256K1_START_NONE: c_uint = 1;
/// Flag for context to enable verification precomputation
pub const SECP256K1_START_VERIFY: c_uint = 1 | (1 << 8);
/// Flag for context to enable signing precomputation
pub const SECP256K1_START_SIGN: c_uint = 1 | (1 << 9);
/// Flag for keys to indicate uncompressed serialization format
#[allow(unused_parens)]
pub const SECP256K1_SER_UNCOMPRESSED: c_uint = (1 << 1);
/// Flag for keys to indicate compressed serialization format
pub const SECP256K1_SER_COMPRESSED: c_uint = (1 << 1) | (1 << 8);

/// An opaque Secp256k1 context.
///
/// Currently this object contains a blinding factor used internally to
/// randomize computations to protect against sidechannel attacks. In the
/// past it has contained precomputation tables to speed up crypto operations.
///
/// It should be assumed to be expensive to create and therefore should be
/// reused when possible.
///
/// If you create one of these with `secp256k1_context_create` you must
/// destroy it with `secp256k1_context_destroy`. (Failure to destroy it is
/// a memory leak; destroying it using any other allocator is undefined
/// behavior.)
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Context(c_int);

/// Library-internal representation of a Secp256k1 public key
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(secp256k1_fuzz, derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct PublicKey([c_uchar; 64]);
impl_array_newtype!(PublicKey, c_uchar, 64);
impl_raw_debug!(PublicKey);

impl PublicKey {
    /// Creates an "uninitialized" FFI public key which is zeroed out
    ///
    /// # Safety
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new public key usable for the FFI interface from raw bytes
    ///
    /// # Safety
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        PublicKey(data)
    }

    /// Returns the underlying FFI opaque representation of the public key
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }

    /// Serializes this public key as a byte-encoded pair of values, in compressed form.
    fn serialize(&self) -> [u8; 33] {
        let mut buf = [0u8; 33];
        let mut len = 33;
        unsafe {
            let ret = secp256k1_ec_pubkey_serialize(
                secp256k1_context_no_precomp,
                buf.as_mut_c_ptr(),
                &mut len,
                self,
                SECP256K1_SER_COMPRESSED,
            );
            debug_assert_eq!(ret, 1);
            debug_assert_eq!(len, 33);
        };
        buf
    }
}

#[cfg(not(secp256k1_fuzz))]
impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(secp256k1_fuzz))]
impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> core::cmp::Ordering {
        let ret = unsafe { secp256k1_ec_pubkey_cmp(secp256k1_context_no_precomp, self, other) };
        ret.cmp(&0i32)
    }
}

#[cfg(not(secp256k1_fuzz))]
impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == core::cmp::Ordering::Equal
    }
}

#[cfg(not(secp256k1_fuzz))]
impl Eq for PublicKey {}

#[cfg(not(secp256k1_fuzz))]
impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let ser = self.serialize();
        ser.hash(state);
    }
}

/// Library-internal representation of a Secp256k1 signature
#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(secp256k1_fuzz, derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct Signature([c_uchar; 64]);
impl_array_newtype!(Signature, c_uchar, 64);
impl_raw_debug!(Signature);

impl Signature {
    /// Creates an "uninitialized" FFI signature which is zeroed out
    ///
    /// # Safety
    ///
    /// If you pass this to any FFI functions, except as an out-pointer,
    /// the result is likely to be an assertation failure and process
    /// termination.
    pub unsafe fn new() -> Self {
        Self::from_array_unchecked([0; 64])
    }

    /// Create a new signature usable for the FFI interface from raw bytes
    ///
    /// # Safety
    ///
    /// Does not check the validity of the underlying representation. If it is
    /// invalid the result may be assertation failures (and process aborts) from
    /// the underlying library. You should not use this method except with data
    /// that you obtained from the FFI interface of the same version of this
    /// library.
    pub unsafe fn from_array_unchecked(data: [c_uchar; 64]) -> Self {
        Signature(data)
    }

    /// Returns the underlying FFI opaque representation of the signature
    ///
    /// You should not use this unless you really know what you are doing. It is
    /// essentially only useful for extending the FFI interface itself.
    pub fn underlying_bytes(self) -> [c_uchar; 64] {
        self.0
    }
}

/// Does a best attempt at secure erasure using Rust intrinsics.
///
/// The implementation is based on the approach used by the [`zeroize`](https://docs.rs/zeroize) crate.
#[inline(always)]
pub fn non_secure_erase_impl<T>(dst: &mut T, src: T) {
    use core::sync::atomic;
    // overwrite using volatile value
    unsafe {
        ptr::write_volatile(dst, src);
    }

    // prevent future accesses from being reordered to before erasure
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}

extern "C" {
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_no_precomp"
    )]
    pub static secp256k1_context_no_precomp: *const Context;

    // Contexts
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_preallocated_destroy"
    )]
    pub fn secp256k1_context_preallocated_destroy(cx: NonNull<Context>);

    // Signatures
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_seckey_verify"
    )]
    pub fn secp256k1_ec_seckey_verify(cx: *const Context, sk: *const c_uchar) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_seckey_negate"
    )]
    pub fn secp256k1_ec_seckey_negate(cx: *const Context, sk: *mut c_uchar) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_seckey_tweak_add"
    )]
    pub fn secp256k1_ec_seckey_tweak_add(
        cx: *const Context,
        sk: *mut c_uchar,
        tweak: *const c_uchar,
    ) -> c_int;
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_seckey_tweak_mul"
    )]
    pub fn secp256k1_ec_seckey_tweak_mul(
        cx: *const Context,
        sk: *mut c_uchar,
        tweak: *const c_uchar,
    ) -> c_int;
}

#[cfg(not(secp256k1_fuzz))]
extern "C" {
    // Contexts
    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_preallocated_size"
    )]
    pub fn secp256k1_context_preallocated_size(flags: c_uint) -> size_t;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_preallocated_create"
    )]
    pub fn secp256k1_context_preallocated_create(
        prealloc: NonNull<c_void>,
        flags: c_uint,
    ) -> NonNull<Context>;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_preallocated_clone_size"
    )]
    pub fn secp256k1_context_preallocated_clone_size(cx: *const Context) -> size_t;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_preallocated_clone"
    )]
    pub fn secp256k1_context_preallocated_clone(
        cx: *const Context,
        prealloc: NonNull<c_void>,
    ) -> NonNull<Context>;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_context_randomize"
    )]
    pub fn secp256k1_context_randomize(cx: NonNull<Context>, seed32: *const c_uchar) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_pubkey_serialize"
    )]
    pub fn secp256k1_ec_pubkey_serialize(
        cx: *const Context,
        output: *mut c_uchar,
        out_len: *mut size_t,
        pk: *const PublicKey,
        compressed: c_uint,
    ) -> c_int;

    #[cfg_attr(
        not(rust_secp_zkp_no_symbol_renaming),
        link_name = "rustsecp256k1zkp_v0_11_0_ec_pubkey_cmp"
    )]
    pub fn secp256k1_ec_pubkey_cmp(
        cx: *const Context,
        pubkey1: *const PublicKey,
        pubkey2: *const PublicKey,
    ) -> c_int;
}

/// A reimplementation of the C function `secp256k1_context_create` in rust.
///
/// This function allocates memory, the pointer should be deallocated using
/// `secp256k1_context_destroy`. Failure to do so will result in a memory leak.
///
/// Input `flags` control which parts of the context to initialize.
///
/// # Safety
///
/// This function is unsafe because it calls unsafe functions however (assuming no bugs) no
/// undefined behavior is possible.
///
/// # Returns
///
/// The newly created secp256k1 raw context.
#[cfg(all(feature = "alloc", not(rust_secp_zkp_no_symbol_renaming)))]
pub unsafe fn secp256k1_context_create(flags: c_uint) -> NonNull<Context> {
    rustsecp256k1zkp_v0_11_0_context_create(flags)
}

/// A reimplementation of the C function `secp256k1_context_create` in rust.
///
/// See [`secp256k1_context_create`] for documentation and safety constraints.
#[no_mangle]
#[allow(clippy::missing_safety_doc)] // Documented above.
#[cfg(all(feature = "alloc", not(rust_secp_zkp_no_symbol_renaming)))]
pub unsafe extern "C" fn rustsecp256k1zkp_v0_11_0_context_create(
    flags: c_uint,
) -> NonNull<Context> {
    use crate::alloc::alloc;
    use core::mem;
    assert!(ALIGN_TO >= mem::align_of::<usize>());
    assert!(ALIGN_TO >= mem::align_of::<&usize>());
    assert!(ALIGN_TO >= mem::size_of::<usize>());

    // We need to allocate `ALIGN_TO` more bytes in order to write the amount of bytes back.
    let bytes = secp256k1_context_preallocated_size(flags) + ALIGN_TO;
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    let ptr = alloc::alloc(layout);
    if ptr.is_null() {
        alloc::handle_alloc_error(layout);
    }
    (ptr as *mut usize).write(bytes);
    // We must offset a whole ALIGN_TO in order to preserve the same alignment
    // this means we "lose" ALIGN_TO-size_of(usize) for padding.
    let ptr = ptr.add(ALIGN_TO);
    let ptr = NonNull::new_unchecked(ptr as *mut c_void); // Checked above.
    secp256k1_context_preallocated_create(ptr, flags)
}

/// A reimplementation of the C function `secp256k1_context_destroy` in rust.
///
/// This function destroys and deallcates the context created by `secp256k1_context_create`.
///
/// The pointer shouldn't be used after passing to this function, consider it as passing it to `free()`.
///
/// # Safety
///
///  `ctx` must be a valid pointer to a block of memory created using [`secp256k1_context_create`].
#[cfg(all(feature = "alloc", not(rust_secp_zkp_no_symbol_renaming)))]
pub unsafe fn secp256k1_context_destroy(ctx: NonNull<Context>) {
    rustsecp256k1zkp_v0_11_0_context_destroy(ctx)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)] // Documented above.
#[cfg(all(feature = "alloc", not(rust_secp_zkp_no_symbol_renaming)))]
pub unsafe extern "C" fn rustsecp256k1zkp_v0_11_0_context_destroy(mut ctx: NonNull<Context>) {
    use crate::alloc::alloc;
    secp256k1_context_preallocated_destroy(ctx);
    let ctx: *mut Context = ctx.as_mut();
    let ptr = (ctx as *mut u8).sub(ALIGN_TO);
    let bytes = (ptr as *mut usize).read();
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    alloc::dealloc(ptr, layout);
}

/// **This function is an override for the C function, this is the an edited version of the original description:**
///
/// A callback function to be called when an illegal argument is passed to
/// an API call. It will only trigger for violations that are mentioned
/// explicitly in the header. **This will cause a panic**.
///
/// The philosophy is that these shouldn't be dealt with through a
/// specific return value, as calling code should not have branches to deal with
/// the case that this code itself is broken.
///
/// On the other hand, during debug stage, one would want to be informed about
/// such mistakes, and the default (crashing) may be inadvisable.
/// When this callback is triggered, the API function called is guaranteed not
/// to cause a crash, though its return value and output arguments are
/// undefined.
///
/// See also secp256k1_default_error_callback_fn.
///
///
/// # Safety
///
/// `message` string should be a null terminated C string and, up to the first null byte, must be valid UTF8.
///
/// For exact safety constraints see [`std::slice::from_raw_parts`] and [`std::str::from_utf8_unchecked`].
#[no_mangle]
#[cfg(not(rust_secp_zkp_no_symbol_renaming))]
pub unsafe extern "C" fn rustsecp256k1zkp_v0_11_0_default_illegal_callback_fn(
    message: *const c_char,
    _data: *mut c_void,
) {
    use core::str;
    let msg_slice = slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = str::from_utf8_unchecked(msg_slice);
    panic!("[libsecp256k1] illegal argument. {}", msg);
}

/// **This function is an override for the C function, this is the an edited version of the original description:**
///
/// A callback function to be called when an internal consistency check
/// fails. **This will cause a panic**.
///
/// This can only trigger in case of a hardware failure, miscompilation,
/// memory corruption, serious bug in the library, or other error would can
/// otherwise result in undefined behaviour. It will not trigger due to mere
/// incorrect usage of the API (see secp256k1_default_illegal_callback_fn
/// for that). After this callback returns, anything may happen, including
/// crashing.
///
/// See also secp256k1_default_illegal_callback_fn.
///
/// # Safety
///
/// `message` string should be a null terminated C string and, up to the first null byte, must be valid UTF8.
///
/// For exact safety constraints see [`std::slice::from_raw_parts`] and [`std::str::from_utf8_unchecked`].
#[no_mangle]
#[cfg(not(rust_secp_zkp_no_symbol_renaming))]
pub unsafe extern "C" fn rustsecp256k1zkp_v0_11_0_default_error_callback_fn(
    message: *const c_char,
    _data: *mut c_void,
) {
    use core::str;
    let msg_slice = slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = str::from_utf8_unchecked(msg_slice);
    panic!("[libsecp256k1] internal consistency check failed {}", msg);
}

/// Returns the length of the `str_ptr` string.
///
/// # Safety
///
/// `str_ptr` must be valid pointer and point to a valid null terminated C string.
#[cfg(not(rust_secp_zkp_no_symbol_renaming))]
unsafe fn strlen(mut str_ptr: *const c_char) -> usize {
    let mut ctr = 0;
    while *str_ptr != '\0' as c_char {
        ctr += 1;
        str_ptr = str_ptr.offset(1);
    }
    ctr
}

/// A trait for producing pointers that will always be valid in C (assuming NULL pointer is a valid
/// no-op).
///
/// Rust does not guarantee pointers to Zero Sized Types
/// (<https://doc.rust-lang.org/nomicon/exotic-sizes.html#zero-sized-types-zsts>). In case the type
/// is empty this trait will return a NULL pointer, which should be handled in C.
pub trait CPtr {
    type Target;
    fn as_c_ptr(&self) -> *const Self::Target;
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target;
}

impl<T> CPtr for [T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            ptr::null()
        } else {
            self.as_ptr()
        }
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        if self.is_empty() {
            ptr::null_mut::<Self::Target>()
        } else {
            self.as_mut_ptr()
        }
    }
}

impl<T> CPtr for &[T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            ptr::null()
        } else {
            self.as_ptr()
        }
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        if self.is_empty() {
            ptr::null_mut()
        } else {
            self.as_ptr() as *mut Self::Target
        }
    }
}

impl CPtr for [u8; 32] {
    type Target = u8;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl<T: CPtr> CPtr for Option<T> {
    type Target = T::Target;
    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        match self {
            Some(contents) => contents.as_mut_c_ptr(),
            None => ptr::null_mut(),
        }
    }
    fn as_c_ptr(&self) -> *const Self::Target {
        match self {
            Some(content) => content.as_c_ptr(),
            None => ptr::null(),
        }
    }
}

#[cfg(secp256k1_fuzz)]
mod fuzz_dummy {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(rust_secp_zkp_no_symbol_renaming)]
    compile_error!("We do not support fuzzing with rust_secp_zkp_no_symbol_renaming");

    extern "C" {
        fn rustsecp256k1zkp_v0_11_0_context_preallocated_size(flags: c_uint) -> size_t;
        fn rustsecp256k1zkp_v0_11_0_context_preallocated_create(
            prealloc: NonNull<c_void>,
            flags: c_uint,
        ) -> NonNull<Context>;
        fn rustsecp256k1zkp_v0_11_0_context_preallocated_clone(
            cx: *const Context,
            prealloc: NonNull<c_void>,
        ) -> NonNull<Context>;
    }

    const CTX_SIZE: usize = 512;
    // Contexts
    pub unsafe fn secp256k1_context_preallocated_size(flags: c_uint) -> size_t {
        assert!(
            rustsecp256k1zkp_v0_11_0_context_preallocated_size(flags)
                + std::mem::size_of::<c_uint>()
                <= CTX_SIZE
        );
        CTX_SIZE
    }

    static HAVE_PREALLOCATED_CONTEXT: AtomicUsize = AtomicUsize::new(0);
    const HAVE_CONTEXT_NONE: usize = 0;
    const HAVE_CONTEXT_WORKING: usize = 1;
    const HAVE_CONTEXT_DONE: usize = 2;
    static mut PREALLOCATED_CONTEXT: [u8; CTX_SIZE] = [0; CTX_SIZE];
    pub unsafe fn secp256k1_context_preallocated_create(
        prealloc: NonNull<c_void>,
        flags: c_uint,
    ) -> NonNull<Context> {
        // While applications should generally avoid creating too many contexts, sometimes fuzzers
        // perform tasks repeatedly which real applications may only do rarely. Thus, we want to
        // avoid being overly slow here. We do so by having a static context and copying it into
        // new buffers instead of recalculating it. Because we shouldn't rely on std, we use a
        // simple hand-written OnceFlag built out of an atomic to gate the global static.
        let mut have_ctx = HAVE_PREALLOCATED_CONTEXT.load(Ordering::Relaxed);
        while have_ctx != HAVE_CONTEXT_DONE {
            if have_ctx == HAVE_CONTEXT_NONE {
                have_ctx = HAVE_PREALLOCATED_CONTEXT.swap(HAVE_CONTEXT_WORKING, Ordering::AcqRel);
                if have_ctx == HAVE_CONTEXT_NONE {
                    assert!(
                        rustsecp256k1zkp_v0_11_0_context_preallocated_size(
                            SECP256K1_START_SIGN | SECP256K1_START_VERIFY
                        ) + std::mem::size_of::<c_uint>()
                            <= CTX_SIZE
                    );
                    assert_eq!(
                        rustsecp256k1zkp_v0_11_0_context_preallocated_create(
                            NonNull::new_unchecked(
                                PREALLOCATED_CONTEXT[..].as_mut_ptr() as *mut c_void
                            ),
                            SECP256K1_START_SIGN | SECP256K1_START_VERIFY
                        ),
                        NonNull::new_unchecked(
                            PREALLOCATED_CONTEXT[..].as_mut_ptr() as *mut Context
                        )
                    );
                    assert_eq!(
                        HAVE_PREALLOCATED_CONTEXT.swap(HAVE_CONTEXT_DONE, Ordering::AcqRel),
                        HAVE_CONTEXT_WORKING
                    );
                } else if have_ctx == HAVE_CONTEXT_DONE {
                    // Another thread finished while we were swapping.
                    HAVE_PREALLOCATED_CONTEXT.store(HAVE_CONTEXT_DONE, Ordering::Release);
                }
            } else {
                // Another thread is building, just busy-loop until they're done.
                assert_eq!(have_ctx, HAVE_CONTEXT_WORKING);
                have_ctx = HAVE_PREALLOCATED_CONTEXT.load(Ordering::Acquire);
                #[cfg(feature = "std")]
                std::thread::yield_now();
            }
        }
        ptr::copy_nonoverlapping(
            PREALLOCATED_CONTEXT[..].as_ptr(),
            prealloc.as_ptr() as *mut u8,
            CTX_SIZE,
        );
        let ptr = (prealloc.as_ptr())
            .add(CTX_SIZE)
            .sub(std::mem::size_of::<c_uint>());
        (ptr as *mut c_uint).write(flags);
        NonNull::new_unchecked(prealloc.as_ptr() as *mut Context)
    }
    pub unsafe fn secp256k1_context_preallocated_clone_size(_cx: *const Context) -> size_t {
        CTX_SIZE
    }
    pub unsafe fn secp256k1_context_preallocated_clone(
        cx: *const Context,
        prealloc: NonNull<c_void>,
    ) -> NonNull<Context> {
        let orig_ptr = (cx as *mut u8)
            .add(CTX_SIZE)
            .sub(std::mem::size_of::<c_uint>());
        let new_ptr = (prealloc.as_ptr() as *mut u8)
            .add(CTX_SIZE)
            .sub(std::mem::size_of::<c_uint>());
        let flags = (orig_ptr as *mut c_uint).read();
        (new_ptr as *mut c_uint).write(flags);
        rustsecp256k1zkp_v0_11_0_context_preallocated_clone(cx, prealloc)
    }

    pub unsafe fn secp256k1_context_randomize(
        cx: NonNull<Context>,
        _seed32: *const c_uchar,
    ) -> c_int {
        // This function is really slow, and unsuitable for fuzzing
        check_context_flags(cx.as_ptr(), 0);
        1
    }

    unsafe fn check_context_flags(cx: *const Context, required_flags: c_uint) {
        assert!(!cx.is_null());
        let cx_flags = if cx == secp256k1_context_no_precomp {
            1
        } else {
            let ptr = (cx as *const u8)
                .add(CTX_SIZE)
                .sub(std::mem::size_of::<c_uint>());
            (ptr as *const c_uint).read()
        };
        assert_eq!(cx_flags & 1, 1); // SECP256K1_FLAGS_TYPE_CONTEXT
        assert_eq!(cx_flags & required_flags, required_flags);
    }

    /// Checks that pk != 0xffff...ffff and pk[1..32] == pk[33..64]
    unsafe fn test_pk_validate(cx: *const Context, pk: *const PublicKey) -> c_int {
        check_context_flags(cx, 0);
        if (&*pk).0[1..32] != (&*pk).0[33..64]
            || ((&*pk).0[32] != 0 && (&*pk).0[32] != 0xff)
            || secp256k1_ec_seckey_verify(cx, (&*pk).0[0..32].as_ptr()) == 0
        {
            0
        } else {
            1
        }
    }

    /// Serialize PublicKey back to 33/65 byte pubkey
    pub unsafe fn secp256k1_ec_pubkey_serialize(
        cx: *const Context,
        output: *mut c_uchar,
        out_len: *mut size_t,
        pk: *const PublicKey,
        compressed: c_uint,
    ) -> c_int {
        check_context_flags(cx, 0);
        assert_eq!(test_pk_validate(cx, pk), 1);
        if compressed == SECP256K1_SER_COMPRESSED {
            assert_eq!(*out_len, 33);
            if (*pk).0[32] <= 0x7f {
                *output = 2;
            } else {
                *output = 3;
            }
            ptr::copy((*pk).0.as_ptr(), output.offset(1), 32);
        } else if compressed == SECP256K1_SER_UNCOMPRESSED {
            assert_eq!(*out_len, 65);
            *output = 4;
            ptr::copy((*pk).0.as_ptr(), output.offset(1), 64);
        } else {
            panic!("Bad flags");
        }
        1
    }
}

#[cfg(secp256k1_fuzz)]
pub use self::fuzz_dummy::*;

#[cfg(test)]
mod tests {
    #[cfg(not(rust_secp_zkp_no_symbol_renaming))]
    #[test]
    fn test_strlen() {
        use super::strlen;
        use std::ffi::CString;

        let orig = "test strlen \t \n";
        let test = CString::new(orig).unwrap();

        assert_eq!(orig.len(), unsafe { strlen(test.as_ptr()) });
    }
}
