use crate::ffi::{self, CPtr};
use crate::{constants, from_hex, Error, Secp256k1, Signing, Tag};
use core::{fmt, str};
#[cfg(feature = "actual-rand")]
use rand::Rng;

/// Represents a blinding factor/Tweak on secp256k1 curve
///
/// Contrary to a [`crate::SecretKey`], the value 0 is also a valid tweak.
/// Values outside secp curve order are invalid tweaks.
#[derive(Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Tweak([u8; constants::SECRET_KEY_SIZE]);
secp256k1_zkp_sys::impl_array_newtype!(Tweak, u8, constants::SECRET_KEY_SIZE);

/// The zero Tweak
pub const ZERO_TWEAK: Tweak = Tweak([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

impl fmt::Debug for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tweak(")?;
        for i in self[..].iter() {
            write!(f, "{:02x}", i)?;
        }
        write!(f, ")")
    }
}

impl fmt::LowerHex for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.0[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for Tweak {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for Tweak {
    type Err = Error;
    fn from_str(s: &str) -> Result<Tweak, Error> {
        let mut res = [0; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => Tweak::from_inner(res),
            _ => Err(Error::InvalidTweakLength),
        }
    }
}

impl Tweak {
    /// Generate a new random Tweak
    #[cfg(feature = "actual-rand")]
    pub fn new<R: Rng + ?Sized>(rng: &mut R) -> Tweak {
        let mut ret = [0u8; constants::SECRET_KEY_SIZE];
        rng.fill_bytes(&mut ret);
        Tweak(ret)
    }

    /// Converts a byte slice to a Tweak
    /// Fails if tweak is not 32 bytes or if tweak is outside secp curve order
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Tweak, Error> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                let mut ret = [0; constants::SECRET_KEY_SIZE];
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(
                        ffi::secp256k1_context_no_precomp,
                        data.as_ref().as_c_ptr(),
                    ) == 0
                    {
                        if data.iter().all(|x| *x == 0) {
                            return Ok(Tweak(ret));
                        }
                        return Err(Error::TweakOutOfBounds);
                    }
                }
                ret[..].copy_from_slice(data);
                Ok(Tweak(ret))
            }
            _ => Err(Error::InvalidTweakLength),
        }
    }

    /// Converts a `SECRET_KEY_SIZE`(32)- array to a tweak
    #[inline]
    pub fn from_inner(data: [u8; 32]) -> Result<Tweak, Error> {
        unsafe {
            if ffi::secp256k1_ec_seckey_verify(
                ffi::secp256k1_context_no_precomp,
                data.as_ref().as_c_ptr(),
            ) == 0
            {
                if data.iter().all(|x| *x == 0) {
                    return Ok(Tweak(data));
                }
                return Err(Error::TweakOutOfBounds);
            }
        }
        Ok(Tweak(data))
    }
}
/// Represents a generator on the secp256k1 curve.
///
/// A generator is a public key internally but has a slightly different serialization with the first byte being tweaked.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Generator(ffi::PublicKey);

impl Generator {
    /// Serialize the generator to a byte array.
    pub fn serialize(&self) -> [u8; 33] {
        let mut output = [0u8; 33];

        let ret = unsafe {
            ffi::secp256k1_generator_serialize(
                ffi::secp256k1_context_no_precomp,
                output.as_mut_ptr(),
                &self.0,
            )
        };
        // TODO: Replace most assert_eq with debug_assert_eq
        assert_eq!(ret, 1);

        output
    }

    /// Parse a generator from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut public_key = unsafe { ffi::PublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_generator_parse(
                ffi::secp256k1_context_no_precomp,
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
    /// Use [Generator::new_unblinded] for creating a [`Generator`] with zero blinding factor
    pub fn new_blinded<C: Signing>(secp: &Secp256k1<C>, tag: Tag, blinding_factor: Tweak) -> Self {
        let mut generator = unsafe { ffi::PublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_generator_generate_blinded(
                secp.ctx().as_ptr(),
                &mut generator,
                tag.into_inner().as_c_ptr(),
                blinding_factor.as_c_ptr(),
            )
        };
        assert_eq!(ret, 1);

        Generator(generator)
    }

    /// Creates a new unblinded [`Generator`] by from [`Tag`]
    /// Same as using zero [`Tweak`] with [`Generator::new_blinded`]
    pub fn new_unblinded<C: Signing>(secp: &Secp256k1<C>, tag: Tag) -> Self {
        Generator::new_blinded(secp, tag, ZERO_TWEAK)
    }

    /// Extracts the internal representation of this generator.
    ///
    /// This is `pub(crate)` because generators have a different serialization from regular public keys.
    /// As such, certain invariants need to be upheld which is easier if we don't allow users to access the internal representation of generators.
    #[cfg(feature = "std")] // for un-used warnings
    pub(crate) fn as_inner(&self) -> &ffi::PublicKey {
        &self.0
    }
}

impl fmt::LowerHex for Generator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for Generator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for Generator {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mut res = [0; constants::PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::PUBLIC_KEY_SIZE) => Self::from_slice(&res[0..constants::PUBLIC_KEY_SIZE]),
            _ => Err(Error::InvalidGenerator),
        }
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for Generator {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.serialize())
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
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                Generator::from_slice,
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
            d.deserialize_bytes(serde_util::BytesVisitor::new(
                "a bytestring",
                Tweak::from_slice,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: Test prefix of serialization
}
