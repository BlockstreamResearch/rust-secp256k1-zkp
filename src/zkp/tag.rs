use crate::ffi;
use core::fmt;

/// Represents a tag.
///
/// Tags are 32-byte data structures used in surjection proofs. Usually, tags are created from hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Tag(ffi::Tag);

impl Tag {
    pub(crate) fn into_inner(self) -> ffi::Tag {
        self.0
    }

    #[cfg(all(feature = "actual-rand", feature = "std"))]
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
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl fmt::LowerHex for Tag {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        for i in self.0.as_ref() {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "rand-std"))]
impl Tag {
    pub fn random() -> Self {
        use rand::thread_rng;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut bytes);

        Self::from(bytes)
    }
}

impl From<[u8; 32]> for Tag {
    fn from(bytes: [u8; 32]) -> Self {
        Tag(ffi::Tag::from(bytes))
    }
}

impl From<Tag> for [u8; 32] {
    fn from(tag: Tag) -> Self {
        tag.0.into()
    }
}
