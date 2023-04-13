//! Defines the external error callbacks for the secp256k1zkp context.
//!
//! We need to define these callbacks so we can enable the `USE_EXTERNAL_DEFAULT_CALLBACKS` feature flag.
//! Without this feature flag, the C code does not compile to WASM.
//!
//! We are not using the context from libsecp256k1zkp but are reusing the one from libsecp256k1 so these callbacks don't need to actually do anything and can be empty.

use secp256k1_sys::types::{c_char, c_void};

#[no_mangle]
#[cfg(not(feature = "external-symbols"))]
pub unsafe extern "C" fn rustsecp256k1zkp_v0_8_0_default_illegal_callback_fn(
    _: *const c_char,
    _data: *mut c_void,
) {
    unimplemented!("should never be called, see rustdoc above")
}

#[no_mangle]
#[cfg(not(feature = "external-symbols"))]
pub unsafe extern "C" fn rustsecp256k1zkp_v0_8_0_default_error_callback_fn(
    _: *const c_char,
    _data: *mut c_void,
) {
    unimplemented!("should never be called. see rustdoc above")
}
