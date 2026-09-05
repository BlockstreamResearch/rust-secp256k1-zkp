use crate::ffi::{self, CPtr};
#[cfg(feature = "rand")]
use crate::rand::Rng;
use crate::{constants, Tag};
use core::{fmt, str};

/// Represents a blinding factor/Tweak on secp256k1 curve
///
/// Contrary to a [`crate::SecretKey`], the value 0 is also a valid tweak.
/// Values outside secp curve order are invalid tweaks.
#[derive(Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Tweak([u8; constants::SECRET_KEY_SIZE]);
secp256k1_zkp_sys::impl_array_newtype!(Tweak, u8, constants::SECRET_KEY_SIZE);

/// Attempted to construct a tweak but the underlying byte array represented an out-of-range
/// value.
#[derive(PartialEq, Eq, Clone, Debug)]
#[non_exhaustive]
pub struct TweakOutOfBoundsError;

impl fmt::Display for TweakOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("tweak exceeded the secp256k1 group order")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TweakOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let TweakOutOfBoundsError {} = *self; // guard against changes in representation
        None
    }
}

/// An error with parsing a [`Tweak`].
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum TweakError {
    /// Decoding a hex string failed.
    Hex(hex::DecodeFixedLengthBytesError),
    /// Bad generator
    OutOfBounds(TweakOutOfBoundsError),
}

impl fmt::Display for TweakError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Self::Hex(_) => f.write_str("failed to decode hex string"),
            Self::OutOfBounds(_) => f.write_str("tweak exceeded the group order"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TweakError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Hex(ref e) => Some(e),
            Self::OutOfBounds(ref e) => Some(e),
        }
    }
}

/// The zero Tweak
pub const ZERO_TWEAK: Tweak = Tweak([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

impl fmt::Debug for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tweak(")?;
        for i in &self[..] {
            write!(f, "{:02x}", i)?;
        }
        write!(f, ")")
    }
}

impl fmt::LowerHex for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::fmt_hex_exact!(f, constants::SECRET_KEY_SIZE, self.0, hex::Case::Lower)
    }
}

impl fmt::UpperHex for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::fmt_hex_exact!(f, constants::SECRET_KEY_SIZE, self.0, hex::Case::Upper)
    }
}

impl fmt::Display for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for Tweak {
    type Err = TweakError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arr = hex::decode_to_array(s).map_err(TweakError::Hex)?;
        Self::from_byte_array(arr).map_err(TweakError::OutOfBounds)
    }
}

impl Tweak {
    /// Generate a new random Tweak
    #[cfg(feature = "rand")]
    pub fn new<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut ret = [0u8; constants::SECRET_KEY_SIZE];
        rng.fill_bytes(&mut ret);
        Tweak(ret)
    }

    /// Converts a [`Tweak`] to a byte array.
    #[inline]
    pub fn to_byte_array(&self) -> [u8; 32] {
        self.0
    }

    /// Converts a [`Tweak`] to a byte array.
    #[inline]
    pub fn as_byte_array(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decodes a 32-byte array to a [`Tweak`].
    ///
    /// # Errors
    ///
    /// Errors if the tweak, when interpreted as a big-endian integer, is out of bounds for
    /// the secp256k1 group.
    #[inline]
    pub fn from_byte_array(data: [u8; 32]) -> Result<Self, TweakOutOfBoundsError> {
        unsafe {
            if ffi::secp256k1_ec_seckey_verify(
                ffi::secp256k1_context_static,
                data.as_ref().as_c_ptr(),
            ) == 0
            {
                if data.iter().all(|x| *x == 0) {
                    return Ok(Tweak(data));
                }
                return Err(TweakOutOfBoundsError);
            }
        }
        Ok(Tweak(data))
    }
}

/// An error related to [`Generator`].
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Error {
    /// Decoding a hex string failed.
    Hex(hex::DecodeFixedLengthBytesError),
    /// Bad generator
    InvalidGenerator,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Self::Hex(_) => f.write_str("failed to decode hex string"),
            Self::InvalidGenerator => f.write_str("invalid generator"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Hex(ref e) => Some(e),
            Self::InvalidGenerator => None,
        }
    }
}

/// Represents a generator on the secp256k1 curve.
///
/// A generator is a public key internally but has a slightly different serialization with the first byte being tweaked.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Generator(ffi::PublicKey);

impl Generator {
    /// Number of bytes that a [`Generator`] serializes to.
    pub const SERIALIZED_SIZE: usize = 33;

    /// Converts a [`Generator`] to a byte array.
    pub fn to_byte_array(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut output = [0u8; Self::SERIALIZED_SIZE];

        let ret = unsafe {
            ffi::secp256k1_generator_serialize(
                ffi::secp256k1_context_static,
                output.as_mut_ptr(),
                &self.0,
            )
        };
        assert_eq!(ret, 1);

        output
    }

    /// Decodes a 33-byte array to a [`Generator`].
    ///
    /// # Errors
    ///
    /// Errors if the provided array does not represent a generator. (It has an invalid prefix
    /// byte or it is off the curve.)
    pub fn from_byte_array(bytes: [u8; Self::SERIALIZED_SIZE]) -> Result<Self, Error> {
        let mut public_key = unsafe { ffi::PublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_generator_parse(
                ffi::secp256k1_context_static,
                &mut public_key,
                bytes.as_ptr(),
            )
        };

        if ret == 0 {
            return Err(Error::InvalidGenerator);
        }

        Ok(Generator(public_key))
    }

    /// Creates a new [`Generator`] by blinding a [`Tag`] using the given blinding factor.
    /// Use [`Generator::new_unblinded`] for creating a [`Generator`] with zero blinding factor
    pub fn new_blinded(tag: Tag, blinding_factor: Tweak) -> Self {
        let mut generator = unsafe { ffi::PublicKey::new() };

        let ret = crate::context::with_raw_global_context(
            |ctx| unsafe {
                ffi::secp256k1_generator_generate_blinded(
                    ctx.as_ptr(),
                    &mut generator,
                    tag.as_inner().as_c_ptr(),
                    blinding_factor.as_c_ptr(),
                )
            },
            Some(blinding_factor.as_byte_array()),
        );
        assert_eq!(ret, 1);

        Generator(generator)
    }

    /// Creates a new unblinded [`Generator`] by from [`Tag`]
    /// Same as using zero [`Tweak`] with [`Generator::new_blinded`]
    pub fn new_unblinded(tag: Tag) -> Self {
        Generator::new_blinded(tag, ZERO_TWEAK)
    }

    /// Extracts the internal representation of this generator.
    ///
    /// This is `pub(crate)` because generators have a different serialization from regular public keys.
    /// As such, certain invariants need to be upheld which is easier if we don't allow users to access the internal representation of generators.
    pub(crate) fn as_inner(&self) -> &ffi::PublicKey {
        &self.0
    }
}

impl fmt::LowerHex for Generator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.to_byte_array();
        hex::fmt_hex_exact!(f, 33, ser, hex::Case::Lower)
    }
}

impl fmt::Display for Generator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for Generator {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arr = hex::decode_to_array(s).map_err(Error::Hex)?;
        Self::from_byte_array(arr)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for Generator {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.to_byte_array())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Generator {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::ArrayVisitor::new(
                "a length-33 bytestring",
                Generator::from_byte_array,
            ))
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for Tweak {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(self.as_ref())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for Tweak {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::serde_util;

        if d.is_human_readable() {
            d.deserialize_str(serde_util::FromStrVisitor::new("an ASCII hex string"))
        } else {
            d.deserialize_bytes(serde_util::ArrayVisitor::new(
                "a length-32 bytestring",
                Tweak::from_byte_array,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: Test prefix of serialization
}
