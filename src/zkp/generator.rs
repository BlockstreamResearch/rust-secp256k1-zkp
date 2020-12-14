use core::{fmt, str};
use ffi;
use {constants, from_hex, Error, Secp256k1, SecretKey, Signing, Tag};

/// Represents a generator on the secp256k1 curve.
///
/// A generator is a public key internally but has a slightly different serialization with the first byte being tweaked.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
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
    pub fn new_blinded<C: Signing>(
        secp: &Secp256k1<C>,
        tag: Tag,
        blinding_factor: SecretKey,
    ) -> Self {
        let mut generator = unsafe { ffi::PublicKey::new() };

        let ret = unsafe {
            ffi::secp256k1_generator_generate_blinded(
                *secp.ctx(),
                &mut generator,
                tag.into_inner().as_ptr(),
                blinding_factor.as_ptr(),
            )
        };
        assert_eq!(ret, 1);

        Generator(generator)
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
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = Generator;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = str::from_utf8(v) {
                        str::FromStr::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    str::FromStr::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = Generator;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    Generator::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: Test prefix of serialization
}
