// secp256k1-zkp bindings
// Written in 2019 by
//   Jonas Nick
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.
use secp256k1::ffi::Context;

/// Opaque type for pointers to scratch spaces
pub enum ScratchSpace {}

extern "C" {
    pub fn secp256k1_zkp_scratch_space_create(
        cx: *const Context,
        max_size: usize,
    ) -> *mut ScratchSpace;

    pub fn secp256k1_zkp_scratch_space_destroy(scratch: *mut ScratchSpace);
}
