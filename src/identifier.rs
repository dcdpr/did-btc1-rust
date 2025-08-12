//! # DID:BTC1 Encoding
//!
//! This crate provides encoding and decoding functionality for DID:BTC1 identifiers
//! as specified in the DID:BTC1 DID Method Specification.
//!
//! ## DID:BTC1 Identifier Format
//!
//! A DID:BTC1 identifier consists of:
//! - `did:btc1:` prefix
//! - Bech32m-encoded data containing:
//!   - Version (4 bits)
//!   - Network identifier (4 bits)
//!   - Genesis bytes (32 bytes for key-based, variable for external)
//!
//! ## Examples
//!
//! ```rust
//! use did_btc1::identifier::{parse_did_identifier, encode_did_identifier, DidComponents, Network, IdType, Error, DidVersion};
//!
//! // Parse a DID identifier
//! let did = "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
//! let components = parse_did_identifier(did)?;
//!
//! assert_eq!(components.version(), DidVersion::One);
//! assert_eq!(components.network(), Network::Mainnet);
//! assert_eq!(components.id_type(), IdType::Key);
//!
//! // Create a new DID identifier
//! let genesis_bytes = [0u8; 33]; // 33-byte compressed secp256k1 public key
//! let did = encode_did_identifier(DidVersion::One, Network::Mainnet, IdType::Key, &genesis_bytes)?;
//! # Ok::<(), Error>(())
//! ```

use bech32_rust::{Bech32Error, decode, encode};
use onlyerror::Error;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::PublicKey;

/// The DID method prefix for BTC1 identifiers
pub const DID_BTC1_PREFIX: &str = "did:btc1:";

/// Human-readable part for key-based DID identifiers
pub const HRP_KEY: &str = "k";

/// Human-readable part for external document-based DID identifiers
pub const HRP_EXTERNAL: &str = "x";

/// Expected length of a compressed secp256k1 public key
pub const SECP256K1_COMPRESSED_KEY_LEN: usize = 33;

/// Expected length of a SHA-256 hash
pub const SHA256_HASH_LEN: usize = 32;

/// Errors that can occur during DID identifier encoding/decoding
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid DID format - missing or incorrect prefix
    #[error("Invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// Invalid version number
    #[error("Invalid version: {0} (must be 1-16)")]
    InvalidVersion(u8),

    /// Invalid network identifier
    #[error("Invalid network identifier: {0}")]
    InvalidNetwork(u8),

    /// Invalid human-readable part
    #[error("Invalid HRP: {0} (must be 'k' or 'x')")]
    InvalidHrp(String),

    /// Invalid genesis bytes length
    #[error("Invalid genesis bytes length: {0} (expected {1})")]
    InvalidGenesisLength(usize, usize),

    /// Bech32 encoding/decoding error
    #[error("Bech32 error: {0}")]
    Bech32(#[from] Bech32Error),

    /// Invalid identifier type
    #[error("Invalid identifier type: {0}")]
    InvalidIdType(String),

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// Expected public key hash
    #[error("Expected public key hash")]
    ExpectedPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Did {
    encoded: String,
    components: DidComponents,
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(did: &str) -> Result<Self, Self::Err> {
        let components = parse_did_identifier(did)?;

        Ok(Self {
            encoded: did.to_string(),
            components,
        })
    }
}

impl From<DidComponents> for Did {
    fn from(components: DidComponents) -> Self {
        let encoded = encode_did_identifier(
            components.version,
            components.network,
            components.id_type,
            &components.genesis_bytes,
        )
        .unwrap();

        Self {
            encoded,
            components,
        }
    }
}

impl Did {
    pub fn encode(&self) -> &str {
        &self.encoded
    }

    pub fn components(&self) -> &DidComponents {
        &self.components
    }

    // TODO: should be infallible!
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        match self.components.id_type {
            IdType::Key => Ok(PublicKey::from_bytes(&self.components.genesis_bytes)?),
            IdType::External => Err(Error::ExpectedPublicKey),
        }
    }
}

/// DID:BTC1 encoding version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DidVersion {
    One = 1,
}

impl TryFrom<u8> for DidVersion {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            _ => Err(Error::InvalidVersion(value)),
        }
    }
}

impl From<DidVersion> for u8 {
    fn from(value: DidVersion) -> Self {
        value as u8
    }
}

/// Bitcoin networks supported by DID:BTC1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet = 0,
    /// Bitcoin signet
    Signet = 1,
    /// Bitcoin regtest
    Regtest = 2,
    /// Bitcoin testnet v3
    TestnetV3 = 3,
    /// Bitcoin testnet v4
    TestnetV4 = 4,
    /// Mutinynet
    Mutinynet = 5,
    /// Custom test network (6-11)
    Custom(u8),
}

impl TryFrom<u8> for Network {
    type Error = Error;
    fn try_from(nibble: u8) -> Result<Self, Self::Error> {
        match nibble {
            0 => Ok(Network::Mainnet),
            1 => Ok(Network::Signet),
            2 => Ok(Network::Regtest),
            3 => Ok(Network::TestnetV3),
            4 => Ok(Network::TestnetV4),
            5 => Ok(Network::Mutinynet),
            6..=15 => Ok(Network::Custom(nibble)),
            _ => Err(Error::InvalidNetwork(nibble)),
        }
    }
}

impl From<Network> for u8 {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => 0,
            Network::Signet => 1,
            Network::Regtest => 2,
            Network::TestnetV3 => 3,
            Network::TestnetV4 => 4,
            Network::Mutinynet => 5,
            Network::Custom(n) => n,
        }
    }
}

/// Type of DID identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdType {
    /// Key-based identifier (secp256k1 public key)
    Key,
    /// External document-based identifier (hash of external document)
    External,
}

impl IdType {
    /// Get the human-readable part for this identifier type
    pub fn hrp(&self) -> &'static str {
        match self {
            IdType::Key => HRP_KEY,
            IdType::External => HRP_EXTERNAL,
        }
    }

    /// Convert from human-readable part
    pub fn from_hrp(hrp: &str) -> Result<Self, Error> {
        match hrp {
            HRP_KEY => Ok(IdType::Key),
            HRP_EXTERNAL => Ok(IdType::External),
            _ => Err(Error::InvalidHrp(hrp.to_string())),
        }
    }

    /// Expected length of genesis bytes for this identifier type
    pub fn expected_genesis_length(&self) -> usize {
        match self {
            IdType::Key => SECP256K1_COMPRESSED_KEY_LEN,
            IdType::External => SHA256_HASH_LEN,
        }
    }
}

/// Components of a parsed DID:BTC1 identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidComponents {
    /// Specification version (1-16)
    version: DidVersion,
    /// Bitcoin network
    network: Network,
    /// Identifier type
    id_type: IdType,
    /// Genesis bytes (public key or hash)
    genesis_bytes: Vec<u8>,
}

impl DidComponents {
    /// Create new DID components with validation
    pub fn new(
        version: DidVersion,
        network: Network,
        id_type: IdType,
        genesis_bytes: Vec<u8>,
    ) -> Result<Self, Error> {
        // Validate genesis bytes length
        let expected_len = id_type.expected_genesis_length();
        if genesis_bytes.len() != expected_len {
            return Err(Error::InvalidGenesisLength(
                genesis_bytes.len(),
                expected_len,
            ));
        }

        Ok(Self {
            version,
            network,
            id_type,
            genesis_bytes,
        })
    }

    pub fn version(&self) -> DidVersion {
        self.version
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn id_type(&self) -> IdType {
        self.id_type
    }

    pub fn genesis_bytes(&self) -> &[u8] {
        &self.genesis_bytes
    }
}

/// Parse a DID:BTC1 identifier string into its components
///
/// # Arguments
///
/// * `did` - The DID identifier string to parse
///
/// # Returns
///
/// * `Ok(DidComponents)` - The parsed components
/// * `Err(Error)` - If parsing fails
///
/// # Examples
///
/// ```rust
/// use did_btc1::identifier::{parse_did_identifier, Network, IdType, Error, DidVersion};
///
/// let did = "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
/// let components = parse_did_identifier(did)?;
///
/// assert_eq!(components.version(), DidVersion::One);
/// assert_eq!(components.network(), Network::Mainnet);
/// assert_eq!(components.id_type(), IdType::Key);
/// # Ok::<(), Error>(())
/// ```
pub fn parse_did_identifier(did: &str) -> Result<DidComponents, Error> {
    // Check DID prefix
    if !did.starts_with(DID_BTC1_PREFIX) {
        return Err(Error::InvalidDidFormat(format!(
            "DID must start with '{DID_BTC1_PREFIX}'",
        )));
    }

    // Extract the bech32 part
    let bech32_part = &did[DID_BTC1_PREFIX.len()..];

    // Decode the bech32 string
    let decoded = decode(bech32_part)?;

    // Determine identifier type from HRP
    let id_type = IdType::from_hrp(&decoded.hrp)?;

    // Parse the decoded data
    if decoded.dp.is_empty() {
        return Err(Error::InvalidDidFormat(
            "No data in DID identifier".to_string(),
        ));
    }

    // First byte contains version (high nibble) and network (low nibble)
    let version_network_byte = decoded.dp[0];
    let version = ((version_network_byte >> 4) & 0x0F) + 1; // High nibble + 1
    let network_nibble = version_network_byte & 0x0F; // Low nibble
    let network = Network::try_from(network_nibble)?;

    // Remaining bytes are genesis data
    let genesis_bytes = decoded.dp[1..].to_vec();

    // Create and validate components
    DidComponents::new(version.try_into()?, network, id_type, genesis_bytes)
}

/// Encode DID components into a DID:BTC1 identifier string
///
/// # Arguments
///
/// * `version` - Specification version (1-16)
/// * `network` - Bitcoin network
/// * `id_type` - Identifier type
/// * `genesis_bytes` - Genesis data (public key or hash)
///
/// # Returns
///
/// * `Ok(String)` - The encoded DID identifier
/// * `Err(Error)` - If encoding fails
///
/// # Examples
///
/// ```rust
/// use did_btc1::identifier::{encode_did_identifier, Network, IdType, Error, DidVersion};
///
/// let genesis_bytes = [0u8; 33]; // 33-byte compressed secp256k1 public key
/// let did = encode_did_identifier(DidVersion::One, Network::Mainnet, IdType::Key, &genesis_bytes)?;
/// assert!(did.starts_with("did:btc1:k1"));
/// # Ok::<(), Error>(())
/// ```
pub fn encode_did_identifier(
    version: DidVersion,
    network: Network,
    id_type: IdType,
    genesis_bytes: &[u8],
) -> Result<String, Error> {
    // Validate genesis bytes length
    let expected_len = id_type.expected_genesis_length();
    if genesis_bytes.len() != expected_len {
        return Err(Error::InvalidGenesisLength(
            genesis_bytes.len(),
            expected_len,
        ));
    }

    // Build the data payload
    let mut data = Vec::with_capacity(1 + genesis_bytes.len());

    // First byte: version (high nibble) + network (low nibble)
    let version_nibble = (u8::from(version) - 1) & 0x0F; // Version - 1, mask to 4 bits
    let network_nibble = u8::from(network) & 0x0F; // Mask to 4 bits
    let version_network_byte = (version_nibble << 4) | network_nibble;
    data.push(version_network_byte);

    // Add genesis bytes
    data.extend_from_slice(genesis_bytes);

    // Encode with bech32m
    let bech32_part = encode(id_type.hrp(), &data)?;

    // Construct full DID
    Ok(format!("{DID_BTC1_PREFIX}{bech32_part}"))
}

/// Extract the network from a DID:BTC1 identifier
///
/// This is a convenience function for when you only need the network information.
///
/// # Arguments
///
/// * `did` - The DID identifier string
///
/// # Returns
///
/// * `Ok(Network)` - The network
/// * `Err(Error)` - If extraction fails
pub fn extract_network(did: &str) -> Result<Network, Error> {
    let components = parse_did_identifier(did)?;
    Ok(components.network)
}

/// Extract the genesis bytes from a DID:BTC1 identifier
///
/// This is a convenience function for when you only need the genesis data.
///
/// # Arguments
///
/// * `did` - The DID identifier string
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The genesis bytes
/// * `Err(Error)` - If extraction fails
pub fn extract_genesis_bytes(did: &str) -> Result<Vec<u8>, Error> {
    let components = parse_did_identifier(did)?;
    Ok(components.genesis_bytes)
}

/// Check if a string is a valid DID:BTC1 identifier
///
/// # Arguments
///
/// * `did` - The string to validate
///
/// # Returns
///
/// * `true` - If the string is a valid DID:BTC1 identifier
/// * `false` - If the string is invalid
pub fn is_valid_did(did: &str) -> bool {
    parse_did_identifier(did).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_conversion() {
        assert_eq!(Network::try_from(0).unwrap(), Network::Mainnet);
        assert_eq!(Network::try_from(1).unwrap(), Network::Signet);
        assert_eq!(Network::try_from(5).unwrap(), Network::Mutinynet);
        assert_eq!(Network::try_from(12).unwrap(), Network::Custom(12));
        assert!(Network::try_from(16).is_err());

        assert_eq!(u8::from(Network::Mainnet), 0);
        assert_eq!(u8::from(Network::Signet), 1);
        assert_eq!(u8::from(Network::Custom(12)), 12);
    }

    #[test]
    fn test_id_type_conversion() {
        assert_eq!(IdType::Key.hrp(), "k");
        assert_eq!(IdType::External.hrp(), "x");

        assert_eq!(IdType::from_hrp("k").unwrap(), IdType::Key);
        assert_eq!(IdType::from_hrp("x").unwrap(), IdType::External);
        assert!(IdType::from_hrp("invalid").is_err());
    }

    #[test]
    fn test_encode_decode_key_based() {
        let genesis_bytes = vec![0u8; 33]; // 33-byte compressed public key
        let did = encode_did_identifier(
            DidVersion::One,
            Network::Mainnet,
            IdType::Key,
            &genesis_bytes,
        )
        .unwrap();

        assert!(did.starts_with("did:btc1:k1"));

        let components = parse_did_identifier(&did).unwrap();
        assert_eq!(u8::from(components.version), 1);
        assert_eq!(components.network, Network::Mainnet);
        assert_eq!(components.id_type, IdType::Key);
        assert_eq!(components.genesis_bytes, genesis_bytes);
    }

    #[test]
    fn test_encode_decode_external() {
        let genesis_bytes = vec![0xffu8; 32]; // 32-byte hash
        let did = encode_did_identifier(
            DidVersion::One,
            Network::Signet,
            IdType::External,
            &genesis_bytes,
        )
        .unwrap();

        assert!(did.starts_with("did:btc1:x1"));

        let components = parse_did_identifier(&did).unwrap();
        assert_eq!(u8::from(components.version), 1);
        assert_eq!(components.network, Network::Signet);
        assert_eq!(components.id_type, IdType::External);
        assert_eq!(components.genesis_bytes, genesis_bytes);
    }

    #[test]
    fn test_invalid_prefix() {
        let result = parse_did_identifier("did:example:123");
        assert!(matches!(result, Err(Error::InvalidDidFormat(_))));
    }

    #[test]
    fn test_invalid_genesis_length() {
        let short_bytes = vec![0u8; 10];
        let result =
            encode_did_identifier(DidVersion::One, Network::Mainnet, IdType::Key, &short_bytes);
        assert!(matches!(result, Err(Error::InvalidGenesisLength(10, 33))));
    }

    #[test]
    fn test_extract_functions() {
        let genesis_bytes = vec![0x42u8; 33];
        let did = encode_did_identifier(
            DidVersion::One,
            Network::TestnetV4,
            IdType::Key,
            &genesis_bytes,
        )
        .unwrap();

        assert_eq!(extract_network(&did).unwrap(), Network::TestnetV4);
        assert_eq!(extract_genesis_bytes(&did).unwrap(), genesis_bytes);
        assert!(is_valid_did(&did));
        assert!(!is_valid_did("invalid-did"));
    }

    #[test]
    fn test_custom_network() {
        let genesis_bytes = vec![0u8; 33];
        let did = encode_did_identifier(
            DidVersion::One,
            Network::Custom(15),
            IdType::Key,
            &genesis_bytes,
        )
        .unwrap();

        let components = parse_did_identifier(&did).unwrap();
        assert_eq!(components.network, Network::Custom(15));
    }
}
