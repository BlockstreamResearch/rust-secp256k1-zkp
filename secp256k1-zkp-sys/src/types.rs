// SPDX-License-Identifier: CC0-1.0

#[allow(non_camel_case_types)]
pub type size_t = usize;

/// A type that is as aligned as the biggest alignment for fundamental types in C
/// since C11 that means as aligned as `max_align_t` is.
/// the exact size/alignment is unspecified.
// 16 matches is as big as the biggest alignment in any arch that rust currently supports https://github.com/rust-lang/rust/blob/2c31b45ae878b821975c4ebd94cc1e49f6073fd0/library/std/src/sys_common/alloc.rs
#[repr(align(16))]
#[derive(Default, Copy, Clone)]
#[allow(dead_code)] // We never access the inner data directly, only by way of a pointer.
pub struct AlignedType([u8; 16]);

impl AlignedType {
    pub fn zeroed() -> Self {
        AlignedType([0u8; 16])
    }

    /// A static zeroed out AlignedType for use in static assignments of [AlignedType; _]
    pub const ZERO: AlignedType = AlignedType([0u8; 16]);
}

#[cfg(all(feature = "alloc", not(rust_secp_zkp_no_symbol_renaming)))]
pub(crate) const ALIGN_TO: usize = core::mem::align_of::<AlignedType>();

#[cfg(test)]
mod tests {
    extern crate libc;
    use super::AlignedType;
    use std::mem;

    #[test]
    fn verify_types() {
        assert!(mem::align_of::<AlignedType>() >= mem::align_of::<self::libc::max_align_t>());
    }
}

#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn sanity_checks_for_wasm() {
    use core::ffi::{c_int, c_uchar, c_uint};
    use core::mem::{align_of, size_of};
    extern "C" {
        pub static WASM32_INT_SIZE: c_uchar;
        pub static WASM32_INT_ALIGN: c_uchar;

        pub static WASM32_UNSIGNED_INT_SIZE: c_uchar;
        pub static WASM32_UNSIGNED_INT_ALIGN: c_uchar;

        pub static WASM32_SIZE_T_SIZE: c_uchar;
        pub static WASM32_SIZE_T_ALIGN: c_uchar;

        pub static WASM32_UNSIGNED_CHAR_SIZE: c_uchar;
        pub static WASM32_UNSIGNED_CHAR_ALIGN: c_uchar;

        pub static WASM32_PTR_SIZE: c_uchar;
        pub static WASM32_PTR_ALIGN: c_uchar;
    }
    unsafe {
        assert_eq!(size_of::<c_int>(), WASM32_INT_SIZE as usize);
        assert_eq!(align_of::<c_int>(), WASM32_INT_ALIGN as usize);

        assert_eq!(size_of::<c_uint>(), WASM32_UNSIGNED_INT_SIZE as usize);
        assert_eq!(align_of::<c_uint>(), WASM32_UNSIGNED_INT_ALIGN as usize);

        assert_eq!(size_of::<size_t>(), WASM32_SIZE_T_SIZE as usize);
        assert_eq!(align_of::<size_t>(), WASM32_SIZE_T_ALIGN as usize);

        assert_eq!(size_of::<c_uchar>(), WASM32_UNSIGNED_CHAR_SIZE as usize);
        assert_eq!(align_of::<c_uchar>(), WASM32_UNSIGNED_CHAR_ALIGN as usize);

        assert_eq!(size_of::<*const ()>(), WASM32_PTR_SIZE as usize);
        assert_eq!(align_of::<*const ()>(), WASM32_PTR_ALIGN as usize);
    }
}
