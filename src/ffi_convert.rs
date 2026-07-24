// SPDX-License-Identifier: CC0-1.0

use core::mem::transmute;

use crate::ffi;

/// Private conversion trait for secp256k1-zkp FFI types which we know to
/// have identical representation to the secp256k1 FFI types.
pub trait ConvertFromUpstream {
    type Target;

    fn to_zkp_ffi(self) -> Self::Target;
}

impl ConvertFromUpstream for secp256k1::ffi::PublicKey {
    type Target = ffi::PublicKey;

    fn to_zkp_ffi(self) -> Self::Target {
        unsafe {
            // SAFETY: both ffi::PublicKey types are repr(C) wrappers around a fixed-size
            // byte array. If either changes to differ in size, this will stop compiling.
            // (The other impls, which convert references, will continue to compile! So
            // this one serves as an important sentinel. Please don't delete it even if
            // it appears unused.)
            transmute::<Self, Self::Target>(self)
        }
    }
}

impl ConvertFromUpstream for &secp256k1::PublicKey {
    type Target = *const ffi::PublicKey;

    fn to_zkp_ffi(self) -> Self::Target {
        use secp256k1::ffi::CPtr as _;

        // SAFETY: technically, both these pointer casts are safe, and it's only downstream
        // dereferences that require unsafe{} blocks. But such dereferences are guaranteed
        // to be sound by the reasoning in the above impl for `secp256k1::ffi::PublicKey`.
        let ffi_ptr = self.as_c_ptr();
        ffi_ptr.cast::<ffi::PublicKey>()
    }
}

impl ConvertFromUpstream for &[secp256k1::PublicKey] {
    type Target = *const ffi::PublicKey;

    fn to_zkp_ffi(self) -> Self::Target {
        // We must special-case the empty slice because Rust does not guarantee that
        // [T]::as_ptr will produce anything meaningful (to C) if the slice is empty.
        if self.is_empty() {
            return core::ptr::null();
        }

        unsafe {
            // SAFETY: we may transmute between secp256k1::PublicKey and secp256k1::ffi::PublicKey
            // because the former is #[repr(transparent)] holding this type. (This is technically
            // not part of the public API of rust-secp256k1, but rust-secp itself would not work
            // without it and it's hard to imagine it changing. Furthermore, since rust-secp256k1
            // and rust-secp256k1-zkp are developed in tandem, any changes would be done to ensure
            // that this crate does not become unsound.)
            //
            // Then from secp256k1::ffi::PublicKey to ffi::PublicKey is permissible since both are
            // #[repr(C)] around a [u8; 64]. Again, hard to imagine this changing, but if it *did*
            // change, with high likelihood the above impl for `secp256k1::ffi::PublicKey` would
            // break.
            let self_ffi = transmute::<&[secp256k1::PublicKey], &[secp256k1::ffi::PublicKey]>(self);
            let self_zkp = transmute::<&[secp256k1::ffi::PublicKey], &[ffi::PublicKey]>(self_ffi);
            self_zkp.as_ptr()
        }
    }
}

impl ConvertFromUpstream for &secp256k1::ecdsa::Signature {
    type Target = *const ffi::Signature;

    fn to_zkp_ffi(self) -> Self::Target {
        use secp256k1::ffi::CPtr as _;

        // SAFETY: technically, both these pointer casts are safe, and it's only downstream
        // dereferences that require unsafe{} blocks. But such dereferences are guaranteed
        // to be sound because both libraries have identical representations of ECDSA signatures
        // (that is, a repr(C) around [u8; 64]).
        let ffi_ptr = self.as_c_ptr();
        ffi_ptr.cast::<ffi::Signature>()
    }
}
