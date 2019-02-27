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

//! # Secp256k1-zkp
//! Rust bindings for the secp256k1-zkp library.

#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#[cfg(any(test))]
pub extern crate rand;

#[cfg(test)]
extern crate core;
#[cfg(test)]
extern crate secp256k1_zkp_dev;

pub extern crate secp256k1;

#[macro_use]
mod macros;
pub mod ffi;
pub mod schnorrsig;
mod types;

/// The purpose of this rewriteable structure is to replace dynamic memory allocations in the
/// libsecp256k1-zkp library. See its documentation for further information.
pub struct ScratchSpace {
    scratch_space: *mut ffi::ScratchSpace,
}

impl ScratchSpace {
    /// Creates a new scratch space which can hold `max_size` bytges.
    pub fn new<C>(secp256k1: &secp256k1::Secp256k1<C>, max_size: usize) -> ScratchSpace {
        unsafe {
            let space = ffi::secp256k1_zkp_scratch_space_create(*secp256k1.ctx(), max_size);
            ScratchSpace {
                scratch_space: space,
            }
        }
    }
    fn scratch_space(&self) -> *mut ffi::ScratchSpace {
        self.scratch_space
    }
}

impl Drop for ScratchSpace {
    fn drop(&mut self) {
        unsafe {
            ffi::secp256k1_zkp_scratch_space_destroy(self.scratch_space);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScratchSpace;
    use secp256k1::Secp256k1;

    #[test]
    fn scratch_space() {
        let s = Secp256k1::new();
        {
            let scratch_space1 = ScratchSpace::new(&s, 0);
            let scratch_space2 = ScratchSpace::new(&s, 100);
            let _ = scratch_space1.scratch_space();
            let _ = scratch_space2.scratch_space();
            // drop
        }
    }
}
