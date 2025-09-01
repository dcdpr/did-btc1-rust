//! Root Capability derivation and management for DID:BTC1
//!
//! This module implements the algorithms specified in section 9.4 of the DID:BTC1
//! specification for deriving and dereferencing root capabilities.

use super::ZCAP_CONTEXT;
use crate::error::Error;
use serde::{Deserialize, Serialize};

/// A ZCAP-LD root capability object
///
/// Root capabilities in DID:BTC1 are deterministically derived from DID identifiers
/// and provide the authorization to update that specific DID's document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RootCapability {
    /// JSON-LD context - always "https://w3id.org/zcap/v1" for ZCAP-LD
    #[serde(rename = "@context")]
    pub(crate) context: String,

    /// Capability identifier in format: urn:zcap:root:{url_encoded_did}
    pub(crate) id: String,

    /// Controller of the capability (the DID identifier)
    pub(crate) controller: String,

    /// Target that this capability can invoke actions on (same as controller for root capabilities)
    #[serde(rename = "invocationTarget")]
    pub(crate) invocation_target: String,
}

impl RootCapability {
    /// Create a new root capability
    pub(crate) fn new(capability_id: String, did_identifier: String) -> Self {
        Self {
            context: ZCAP_CONTEXT.to_string(),
            id: capability_id,
            controller: did_identifier.clone(),
            invocation_target: did_identifier,
        }
    }

    /// Validate that this root capability is well-formed
    pub(crate) fn validate(&self) -> Result<(), Error> {
        // Check context
        if self.context != ZCAP_CONTEXT {
            return Err(Error::Zcap(format!(
                "Invalid context: expected {ZCAP_CONTEXT}, got {}",
                self.context
            )));
        }

        // Validate capability ID format
        super::validation::validate_capability_id(&self.id)?;

        // Extract DID from capability ID and verify it matches controller
        let extracted_did = super::validation::extract_did_from_capability_id(&self.id)?;
        if extracted_did != self.controller {
            return Err(Error::Zcap(format!(
                "Controller mismatch: capability ID contains '{extracted_did}' but controller is '{}'",
                self.controller
            )));
        }

        // For root capabilities, controller and invocation target must be the same
        if self.controller != self.invocation_target {
            return Err(Error::Zcap(
                "Root capability must have same controller and invocation target".to_string(),
            ));
        }

        Ok(())
    }
}

/// Derive a root capability from a DID:BTC1 identifier
///
/// This implements the algorithm from section 9.4.1 of the DID:BTC1 specification:
/// "Derive Root Capability from did:btc1 Identifier"
///
/// # Arguments
///
/// * `did_identifier` - The DID:BTC1 identifier (e.g., "did:btc1:k1qqpuww...")
///
/// # Returns
///
/// * `Ok(RootCapability)` - The derived root capability
/// * `Err(Error)` - If the DID identifier is invalid
pub(crate) fn derive_root_capability(did_identifier: &str) -> Result<RootCapability, Error> {
    // Validate DID identifier format
    if !did_identifier.starts_with("did:btc1:") {
        return Err(Error::Zcap(format!(
            "Invalid DID identifier: {did_identifier}"
        )));
    }

    // Step 3: URL encode the DID identifier
    let encoded_identifier = urlencoding::encode(did_identifier);

    // Step 4: Construct capability ID
    let capability_id = format!("urn:zcap:root:{encoded_identifier}");

    // Create the root capability object
    let root_capability = RootCapability::new(capability_id, did_identifier.to_string());

    // Validate the result
    root_capability.validate()?;

    Ok(root_capability)
}

/// Dereference a root capability identifier to get the capability object
///
/// This implements the algorithm from section 9.4.2 of the DID:BTC1 specification:
/// "Dereference Root Capability Identifier"
///
/// # Arguments
///
/// * `capability_id` - The capability identifier (e.g., "urn:zcap:root:did%3Abtc1%3A...")
///
/// # Returns
///
/// * `Ok(RootCapability)` - The dereferenced root capability
/// * `Err(Error)` - If the capability ID is invalid
pub(crate) fn dereference_root_capability(capability_id: &str) -> Result<RootCapability, Error> {
    // Step 2-3: Split and validate components (handled by validation function)
    super::validation::validate_capability_id(capability_id)?;

    // Step 4-5: Extract and decode the DID identifier
    let did_identifier = super::validation::extract_did_from_capability_id(capability_id)?;

    // Steps 6-8: Create the root capability object
    let root_capability = RootCapability::new(capability_id.to_string(), did_identifier);

    // Validate the result
    root_capability.validate()?;

    Ok(root_capability)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DID: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
    const TEST_CAP_ID: &str = "urn:zcap:root:did%3Abtc1%3Ak1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";

    #[test]
    fn test_derive_root_capability() {
        let root_cap = derive_root_capability(TEST_DID).unwrap();

        assert_eq!(root_cap.context, ZCAP_CONTEXT);
        assert_eq!(root_cap.controller, TEST_DID);
        assert_eq!(root_cap.invocation_target, TEST_DID);
        assert!(root_cap.id.starts_with("urn:zcap:root:"));
        assert!(root_cap.id.contains("did%3Abtc1%3A")); // URL encoded "did:btc1:"
    }

    #[test]
    fn test_derive_root_capability_invalid_did() {
        // Invalid DID format
        assert!(derive_root_capability("invalid:did").is_err());
        assert!(derive_root_capability("did:example:123").is_err());
        assert!(derive_root_capability("").is_err());
    }

    #[test]
    fn test_dereference_root_capability() {
        let root_cap = dereference_root_capability(TEST_CAP_ID).unwrap();

        assert_eq!(root_cap.context, ZCAP_CONTEXT);
        assert_eq!(root_cap.id, TEST_CAP_ID);
        assert_eq!(root_cap.controller, TEST_DID);
        assert_eq!(root_cap.invocation_target, TEST_DID);
    }

    #[test]
    fn test_dereference_root_capability_invalid_id() {
        // Invalid capability ID formats
        assert!(dereference_root_capability("invalid").is_err());
        assert!(dereference_root_capability("urn:zcap:invalid:test").is_err());
        assert!(dereference_root_capability("urn:invalid:root:test").is_err());
        assert!(dereference_root_capability("invalid:zcap:root:test").is_err());
    }

    #[test]
    fn test_round_trip() {
        // Derive capability from DID
        let derived = derive_root_capability(TEST_DID).unwrap();

        // Dereference the capability ID
        let dereferenced = dereference_root_capability(&derived.id).unwrap();

        // Should be equivalent
        assert_eq!(derived, dereferenced);
    }

    #[test]
    fn test_root_capability_validation() {
        // Valid capability
        let valid_cap = RootCapability::new(TEST_CAP_ID.to_string(), TEST_DID.to_string());
        assert!(valid_cap.validate().is_ok());

        // Invalid context
        let mut invalid_cap = valid_cap.clone();
        invalid_cap.context = "invalid".to_string();
        assert!(invalid_cap.validate().is_err());

        // Mismatched controller and invocation target
        let mut invalid_cap = valid_cap.clone();
        invalid_cap.invocation_target = "different".to_string();
        assert!(invalid_cap.validate().is_err());

        // Invalid capability ID
        let mut invalid_cap = valid_cap.clone();
        invalid_cap.id = "invalid".to_string();
        assert!(invalid_cap.validate().is_err());
    }

    #[test]
    fn test_serialize_deserialize() {
        let root_cap = derive_root_capability(TEST_DID).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&root_cap).unwrap();

        // Deserialize back
        let deserialized: RootCapability = serde_json::from_str(&json).unwrap();

        assert_eq!(root_cap, deserialized);
    }
}
