use crate::ffi;
use core::fmt;

/// Represents a tag.
///
/// Tags are 32-byte data structures used in surjection proofs. Usually, tags are created from hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Tag(ffi::Tag);

impl Tag {
    /// Converts a byte array to a [`Tag`].
    #[inline]
    pub fn from_byte_array(data: [u8; 32]) -> Self {
        Self(data.into())
    }

    /// Returns the tag as a byte array.
    #[inline]
    pub fn to_byte_array(&self) -> [u8; 32] {
        self.0.into()
    }

    /// Returns the tag as a byte array.
    #[inline]
    pub fn as_byte_array(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    #[inline]
    pub(crate) fn as_inner(&self) -> &ffi::Tag {
        &self.0
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::LowerHex for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::fmt_hex_exact!(f, 32, self.as_byte_array(), hex::Case::Lower)
    }
}

impl fmt::UpperHex for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::fmt_hex_exact!(f, 32, self.as_byte_array(), hex::Case::Upper)
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[cfg(feature = "rand")]
impl Tag {
    /// Generates a uniformly random tag.
    pub fn random() -> Self {
        use crate::rand::RngCore;

        let mut bytes = [0u8; 32];
        crate::rand::rng().fill_bytes(&mut bytes);

        Self::from_byte_array(bytes)
    }
}
