use base58::ToBase58;
use onlyerror::Error;
use secp256k1::Secp256k1;
pub use secp256k1::{PublicKey, SecretKey};

/// Multikey prefix specified by [Data Integrity BIP340 Cryptosuites]
///
/// [Data Integrity BIP340 Cryptosuites]: https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#multikey
const MULTIKEY_PREFIX: [u8; 2] = [0xe7, 0x01];

// TODO: This a prefix from an old version of the specification changed in [#14].
// `./fixtures/exampleTargetDocument.json` uses this for its "publicKeyMultibase".
//
// [#14]: https://github.com/dcdpr/data-integrity-schnorr-secp256k1/pull/14
const OLD_MULTIKEY_PREFIX: [u8; 2] = [0xe1, 0x4a];

#[derive(Error, Debug)]
pub enum Error {
    /// Failed to create public key from bytes
    InvalidBytesForPublicKey(#[source] secp256k1::Error),

    /// Failed to create secret key from bytes
    InvalidBytesForSecretKey(#[source] secp256k1::Error),

    /// Multikey must start with 'z' (base58-btc)
    MultibasePrefix,

    /// Failed to decode base58
    MultikeyBase58,

    /// Invalid Multikey prefix for secp256k1 x-only public key
    MultikeyPrefix,
}

pub trait PublicKeyExt {
    /// Create a `PublicKey` from a BIP-340 Multikey.
    fn from_multikey(multikey: &str) -> Result<Self, Error>
    where
        Self: Sized;

    /// Encode a `PublicKey` into a BIP-340 Multikey.
    fn to_multikey(&self) -> String;
}

pub trait SecretKeyExt {
    /// Generate a new random secret key.
    fn generate() -> Self;
}

impl PublicKeyExt for PublicKey {
    fn from_multikey(multikey: &str) -> Result<Self, Error> {
        // Ensure multikey starts with 'z' (base58-btc)
        if !multikey.starts_with('z') {
            return Err(Error::MultibasePrefix);
        }

        // Remove 'z' prefix and decode base58
        let data =
            base58::FromBase58::from_base58(&multikey[1..]).map_err(|_| Error::MultikeyBase58)?;

        // Check prefix
        // TODO: Remove `OLD_MULTIKEY_PREFIX` when the test vectors are fixed.
        if data.len() < 2 || (data[0..2] != MULTIKEY_PREFIX && data[0..2] != OLD_MULTIKEY_PREFIX) {
            return Err(Error::MultikeyPrefix);
        }

        // Extract key data (after the 2-byte prefix)
        Self::from_slice(&data[2..]).map_err(Error::InvalidBytesForPublicKey)
    }

    fn to_multikey(&self) -> String {
        // Serialize to bytes
        let key_bytes = self.serialize();

        // Prepend Multikey prefix for secp256k1 x-only (0xe14a)
        let mut data = Vec::with_capacity(2 + key_bytes.len());
        data.push(0xe1);
        data.push(0x4a);
        data.extend_from_slice(&key_bytes);

        // Encode with base58-btc
        let encoded = data.to_base58();

        // Prepend 'z' for base58-btc
        format!("z{encoded}")
    }
}

impl SecretKeyExt for SecretKey {
    fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;

        Self::new(&mut rng)
    }
}

/// Represents a key pair (public and secret key)
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// The public key
    pub public_key: PublicKey,
    /// The secret key
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Create a new key pair from a secret key
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = secret_key.public_key(&secp);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Generate a new random key pair
    pub fn generate() -> Self {
        Self::from_secret_key(SecretKey::generate())
    }
}
