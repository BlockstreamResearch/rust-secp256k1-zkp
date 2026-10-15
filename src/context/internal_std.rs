// SPDX-License-Identifier: CC0-1.0

use std::cell::RefCell;
use std::ptr::NonNull;

use crate::{ffi, All, Secp256k1};

thread_local! {
    static SECP256K1: RefCell<Secp256k1<All>> = RefCell::new(Secp256k1::new());
}

/// Borrows the global context as a raw pointer and does some operation on it.
///
/// If `rerandomize_seed` is provided, then [`rerandomize_global_context`] is called on the context
/// before the operation. This argument should be provided alongside any operation that uses secret
/// data (e.g. signing, but not verification). If you have random data available, it should be
/// provided here; it will be mixed with the current random state as well as the system RNG if it is
/// available. If you do not have any random data, it is fine to provide all zeros, or a counter, or
/// a weak source of entropy. This is a defense-in-depth measure to protect against side-channel
/// attacks, and anything helps (and nothing will hurt).
pub fn with_raw_global_context<T, F: FnOnce(NonNull<ffi::Context>) -> T>(
    f: F,
    rerandomize_seed: Option<&[u8; 32]>,
) -> T {
    SECP256K1.with(|secp| {
        if let Some(seed) = rerandomize_seed {
            rerandomize_global_context(seed);
        }

        let borrow = secp.borrow();
        let ret = f(borrow.ctx);
        drop(borrow);
        ret
    })
}

/// Rerandomize the global context, using the given data as a seed.
///
/// The provided data will be mixed with the entropy from previous calls in a timing
/// analysis resistant way. It is safe to directly pass secret data to this function.
pub fn rerandomize_global_context(seed: &[u8; 32]) {
    SECP256K1.with(|secp| {
        let mut borrow = secp.borrow_mut();

        // If we have access to the thread rng then use it as well.
        #[cfg(feature = "rand")]
        {
            use rand::TryRngCore as _;

            let mut new_seed = [0u8; 32];
            let _ = rand::rng().try_fill_bytes(&mut new_seed);
            for (new, byte) in new_seed.iter_mut().zip(seed.iter()) {
                *new ^= *byte;
            }
            borrow.seeded_randomize(&new_seed);
        }
        #[cfg(not(feature = "rand"))]
        {
            borrow.seeded_randomize(seed);
        }
    });
}
