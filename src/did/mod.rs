//! # DID-specific functionality for DID:BTC1
//!
//! This module provides DID-specific extensions to the generic cryptographic
//! functionality, including key resolution, verification method management,
//! and DID document integration.

pub mod key_resolver;

use crate::error::Result;
use crate::identifier::{DidComponents, IdType, parse_did_identifier};

/// Extract a public key from DID:BTC1 identifier components
///
/// For key-based DIDs, this extracts the secp256k1 public key from the genesis bytes.
/// For external DIDs, this returns an error since they don't contain embedded keys.
///
/// # Arguments
///
/// * `components` - Parsed DID identifier components
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The public key bytes (33-byte compressed secp256k1)
/// * `Err(Error)` - If the DID doesn't contain a key or is invalid
pub fn extract_public_key_from_did(components: &DidComponents) -> Result<Vec<u8>> {
    match components.id_type() {
        IdType::Key => {
            // Genesis bytes should be a 33-byte compressed secp256k1 public key
            if components.genesis_bytes().len() != 33 {
                return Err(crate::error::Error::DidKey(format!(
                    "Invalid key length: expected 33 bytes, got {}",
                    components.genesis_bytes().len()
                )));
            }
            Ok(components.genesis_bytes().to_vec())
        }
        IdType::External => Err(crate::error::Error::DidKey(
            "External DIDs do not contain embedded public keys".to_string(),
        )),
    }
}

/// Parse a verification method ID and extract the DID and fragment
///
/// Verification method IDs have the format: `did:btc1:...#fragment`
///
/// # Arguments
///
/// * `verification_method_id` - The full verification method ID
///
/// # Returns
///
/// * `Ok((String, String))` - Tuple of (DID identifier, fragment)
/// * `Err(Error)` - If the ID format is invalid
pub fn parse_verification_method_id(verification_method_id: &str) -> Result<(String, String)> {
    if let Some(hash_pos) = verification_method_id.rfind('#') {
        let did_part = &verification_method_id[..hash_pos];
        let fragment = &verification_method_id[hash_pos + 1..];

        // Validate that the DID part is a valid DID:BTC1 identifier
        parse_did_identifier(did_part).map_err(|e| {
            crate::error::Error::DidKey(format!("Invalid DID in verification method: {e:?}"))
        })?;

        if fragment.is_empty() {
            return Err(crate::error::Error::DidKey(
                "Verification method fragment cannot be empty".to_string(),
            ));
        }

        Ok((did_part.to_string(), fragment.to_string()))
    } else {
        Err(crate::error::Error::DidKey(
            "Verification method ID must contain a fragment (# character)".to_string(),
        ))
    }
}

/// Create a verification method ID from a DID and fragment
///
/// # Arguments
///
/// * `did_identifier` - The DID identifier
/// * `fragment` - The fragment (without # prefix)
///
/// # Returns
///
/// * The full verification method ID
pub fn create_verification_method_id(did_identifier: &str, fragment: &str) -> String {
    format!("{did_identifier}#{fragment}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::{DidVersion, Network};

    const TEST_DID: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
    const TEST_VERIFICATION_METHOD: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx#initialKey";

    #[test]
    fn test_extract_public_key_from_key_based_did() {
        let components = parse_did_identifier(TEST_DID).unwrap();
        let public_key = extract_public_key_from_did(&components).unwrap();

        assert_eq!(public_key.len(), 33);
        assert_eq!(components.id_type(), IdType::Key);
    }

    #[test]
    fn test_extract_public_key_from_external_did_fails() {
        // Create external DID components
        let external_components = DidComponents::new(
            DidVersion::One,
            Network::Mainnet,
            IdType::External,
            vec![0u8; 32], // 32-byte hash
        )
        .unwrap();

        let result = extract_public_key_from_did(&external_components);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_verification_method_id() {
        let (did, fragment) = parse_verification_method_id(TEST_VERIFICATION_METHOD).unwrap();

        assert_eq!(did, TEST_DID);
        assert_eq!(fragment, "initialKey");
    }

    #[test]
    fn test_parse_verification_method_id_invalid() {
        // Missing fragment
        assert!(parse_verification_method_id(TEST_DID).is_err());

        // Empty fragment
        assert!(parse_verification_method_id(&format!("{TEST_DID}#")).is_err());

        // Invalid DID
        assert!(parse_verification_method_id("invalid:did#fragment").is_err());
    }

    #[test]
    fn test_create_verification_method_id() {
        let vm_id = create_verification_method_id(TEST_DID, "initialKey");
        assert_eq!(vm_id, TEST_VERIFICATION_METHOD);
    }
}
