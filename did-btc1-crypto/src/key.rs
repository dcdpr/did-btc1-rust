use crate::error::{Error, Result};
use base58::ToBase58;
use secp256k1::{Secp256k1, SecretKey as SecpSecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize, de::Visitor};
use std::fmt;

/// Represents a public key
#[derive(Clone)]
pub struct PublicKey {
    /// The x-only public key for secp256k1
    pub key: XOnlyPublicKey,
}

impl PublicKey {
    /// Create a new public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let x_only_bytes = &bytes[1..]; // Skip the first parity byte
        let key = XOnlyPublicKey::from_slice(x_only_bytes)
            .map_err(|e| Error::Key(format!("Failed to create public key from bytes: {e:?}")))?;
        Ok(Self { key })
    }

    /// Returns the 32-byte x-only representation as a Vec<u8>
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
    }

    /// Create a public key from a multikey
    pub fn from_multikey(multikey: &str) -> Result<Self> {
        // Ensure multikey starts with 'z' (base58-btc)
        if !multikey.starts_with('z') {
            return Err(Error::Key(
                "Multikey must start with 'z' (base58-btc)".to_string(),
            ));
        }

        // Remove 'z' prefix and decode base58
        let data = base58::FromBase58::from_base58(&multikey[1..])
            .map_err(|e| Error::Key(format!("Failed to decode base58: {e:?}")))?;

        // Check prefix
        if data.len() < 2 || data[0] != 0xe1 || data[1] != 0x4a {
            return Err(Error::Key(
                "Invalid Multikey prefix for secp256k1 x-only public key".to_string(),
            ));
        }

        // Extract key data (after the 2-byte prefix)
        Self::from_bytes(&data[2..])
    }

    /// Encode the public key in a specific format
    pub fn encode(&self) -> Result<String> {
        // Serialize to bytes
        let key_bytes = self.key.serialize();

        // Prepend Multikey prefix for secp256k1 x-only (0xe14a)
        let mut data = Vec::with_capacity(2 + key_bytes.len());
        data.push(0xe1);
        data.push(0x4a);
        data.extend_from_slice(&key_bytes);

        // Encode with base58-btc
        let encoded = data.to_base58();

        // Prepend 'z' for base58-btc
        Ok(format!("z{encoded}"))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(
            &self
                .encode()
                .map_err(|err| serde::ser::Error::custom(err))?,
        )
    }
}

struct PublicKeyVisitor;

impl<'de> Visitor<'de> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a multibase encoded secp256k1 public key")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        PublicKey::from_bytes(bytes).map_err(|err| serde::de::Error::custom(err))
    }

    fn visit_str<E>(self, multikey: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        PublicKey::from_multikey(multikey).map_err(|err| serde::de::Error::custom(err))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.encode() {
            Ok(multikey) => write!(f, "PublicKey({multikey})"),
            Err(_) => write!(f, "PublicKey(<invalid>)"),
        }
    }
}

/// Represents a secret key
#[derive(Clone)]
pub struct SecretKey {
    /// The secret key for secp256k1
    pub key: SecpSecretKey,
}

impl SecretKey {
    /// Create a new secret key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = SecpSecretKey::from_slice(bytes)
            .map_err(|e| Error::Key(format!("Failed to create secret key from bytes: {e:?}")))?;
        Ok(Self { key })
    }

    /// Generate a new random secret key
    pub fn generate() -> Result<Self> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let key = SecpSecretKey::new(&mut rng);
        Ok(Self { key })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(<redacted>)")
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
        let public_key = PublicKey {
            key: secret_key.key.x_only_public_key(&secp).0,
        };
        Self {
            public_key,
            secret_key,
        }
    }

    /// Generate a new random key pair
    pub fn generate() -> Result<Self> {
        let secret_key = SecretKey::generate()?;
        Ok(Self::from_secret_key(secret_key))
    }
}
