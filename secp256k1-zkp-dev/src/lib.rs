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

//! The functions in this module are copied from secp256k1 because they can only be used when
//! compiled with the `rand` feature. But the other libraries need them as a dev-dependency for
//! `cargo test` also when `rand` is not enabled. Currently with cargo we can't have a `rand`
//! dev-dependency and a non-`rand` dependency at the same time (see
//! https://github.com/rust-lang/cargo/issues/1796).
pub extern crate rand;
pub extern crate secp256k1;

use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};

fn random_32_bytes<R: Rng>(rng: &mut R) -> [u8; 32] {
    let mut ret = [0u8; 32];
    rng.fill_bytes(&mut ret);
    ret
}

trait NewSecretKey {
    fn new<R: Rng>(rng: &mut R) -> SecretKey;
}

impl NewSecretKey for SecretKey {
    /// Creates a new random secret key.
    #[inline]
    fn new<R: Rng>(rng: &mut R) -> SecretKey {
        loop {
            if let Ok(key) = SecretKey::from_slice(&random_32_bytes(rng)) {
                return key;
            }
        }
    }
}

pub trait GenerateKeypair {
    /// Generates a random keypair.
    fn generate_keypair<R: Rng>(&self, rng: &mut R) -> (SecretKey, PublicKey);
}

impl<C: Signing> GenerateKeypair for Secp256k1<C> {
    #[inline]
    fn generate_keypair<R: Rng>(&self, rng: &mut R) -> (SecretKey, PublicKey) {
        let sk = SecretKey::new(rng);
        let pk = PublicKey::from_secret_key(self, &sk);
        (sk, pk)
    }
}
