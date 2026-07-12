// SPDX-License-Identifier: CC0-1.0

//! Helpers for displaying secret values

use core::fmt;

use crate::constants::SECRET_KEY_SIZE;
use crate::key::{Keypair, SecretKey};
use crate::to_hex;
macro_rules! impl_display_secret {
    // Default hasher exists only in standard library and not alloc
    ($thing:ident) => {
        #[cfg(feature = "hashes")]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use hashes::{sha256::Midstate, sha256t};

                #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
                pub(crate) struct DebugTag;
                impl sha256t::Tag for DebugTag {
                    const MIDSTATE: Midstate = Midstate::hash_tag(b"rust-secp256k1DEBUG");
                }

                let hash = sha256t::hash::<DebugTag>(&self.secret_bytes());

                f.debug_tuple(stringify!($thing))
                    .field(&format_args!("#{:.16}", hash))
                    .finish()
            }
        }

        #[cfg(not(feature = "hashes"))]
        impl ::core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(
                    f,
                    "<secret key; enable `hashes` feature of `secp256k1` to display fingerprint>"
                )
            }
        }
    };
}

/// Helper struct for safely printing secrets (like [`SecretKey`] value).
/// Formats the explicit byte value of the secret kept inside the type as a
/// little-endian hexadecimal string using the provided formatter.
///
/// Secrets should not implement neither [`Debug`] and [`Display`] traits directly,
/// and instead provide `fn display_secret<'a>(&'a self) -> DisplaySecret<'a>`
/// function to be used in different display contexts (see "examples" below).
///
/// [`Display`]: fmt::Display
/// [`Debug`]: fmt::Debug
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplaySecret {
    secret: [u8; SECRET_KEY_SIZE],
}
impl_non_secure_erase!(DisplaySecret, secret, [0u8; SECRET_KEY_SIZE]);

impl fmt::Debug for DisplaySecret {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut slice = [0u8; SECRET_KEY_SIZE * 2];
        let hex = to_hex(&self.secret, &mut slice).expect("fixed-size hex serializer failed");
        f.debug_tuple("DisplaySecret").field(&hex).finish()
    }
}

impl fmt::Display for DisplaySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.secret {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl SecretKey {
    /// Formats the explicit byte value of the secret key kept inside the type as a
    /// little-endian hexadecimal string using the provided formatter.
    ///
    /// This is the only method that outputs the actual secret key value, and, thus,
    /// should be used with extreme caution.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// # use std::str::FromStr;
    /// use secp256k1::SecretKey;
    /// let key = SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    ///
    /// // Normal debug hides value (`Display` is not implemented for `SecretKey`).
    /// // E.g., `format!("{:?}", key)` prints "SecretKey(#2518682f7819fb2d)".
    ///
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     "0000000000000000000000000000000000000000000000000000000000000001",
    ///     format!("{}", key.display_secret())
    /// );
    /// // Also, we can explicitly display with `Debug`:
    /// assert_eq!(
    ///     format!("{:?}", key.display_secret()),
    ///     format!("DisplaySecret(\"{}\")", key.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret {
            secret: self.secret_bytes(),
        }
    }
}

impl Keypair {
    /// Formats the explicit byte value of the secret key kept inside the type as a
    /// little-endian hexadecimal string using the provided formatter.
    ///
    /// This is the only method that outputs the actual secret key value, and, thus,
    /// should be used with extreme precaution.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// # use std::str::FromStr;
    /// use secp256k1::{Keypair, Secp256k1, SecretKey};
    ///
    /// let secp = Secp256k1::new();
    /// let key = SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    /// let key = Keypair::from_secret_key(&secp, &key);
    /// // Here we explicitly display the secret value:
    /// assert_eq!(
    ///     "0000000000000000000000000000000000000000000000000000000000000001",
    ///     format!("{}", key.display_secret())
    /// );
    /// // Also, we can explicitly display with `Debug`:
    /// assert_eq!(
    ///     format!("{:?}", key.display_secret()),
    ///     format!("DisplaySecret(\"{}\")", key.display_secret())
    /// );
    /// # }
    /// ```
    #[inline]
    pub fn display_secret(&self) -> DisplaySecret {
        DisplaySecret {
            secret: self.secret_bytes(),
        }
    }
}
