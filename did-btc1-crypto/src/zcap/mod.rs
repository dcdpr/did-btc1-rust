//! # Authorization Capabilities (ZCAP) for DID:BTC1
//!
//! This module implements the ZCAP-LD (Authorization Capabilities Linked Data)
//! functionality required by the DID:BTC1 specification. It provides:
//!
//! - Root capability derivation from DID identifiers
//! - Capability invocation proofs for DID updates
//! - ZCAP object management and validation
//!
//! ## Key Concepts
//!
//! - **Root Capability**: A deterministic capability derived from a DID identifier
//!   that authorizes updates to that DID's document
//! - **Capability Invocation**: A cryptographic proof that invokes a capability
//!   to perform an authorized action (like updating a DID document)
//! - **Capability Action**: The specific action being authorized (typically "Write" for DID updates)
//!
//! ## Example
//!
//! ```rust
//! use did_btc1_crypto::zcap::{derive_root_capability, create_capability_invocation_proof, CapabilityInvocationOptions, CapabilityAction};
//! use did_btc1_crypto::Document;
//! use urlencoding;
//! use serde_json::json;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Derive root capability from DID
//! let did = "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
//! let root_cap = derive_root_capability(did)?;
//!
//! // Create a DID update payload document
//! let payload_data = json!({
//!     "@context": [
//!         "https://w3id.org/zcap/v1",
//!         "https://w3id.org/security/data-integrity/v2",
//!         "https://w3id.org/json-ld-patch/v1"
//!     ],
//!     "patch": [{
//!         "op": "add",
//!         "path": "/service/1",
//!         "value": {
//!             "id": "#my-service",
//!             "type": "MyService",
//!             "serviceEndpoint": "https://example.com"
//!         }
//!     }],
//!     "sourceHash": "z123...",
//!     "targetHash": "z456...",
//!     "targetVersionId": 2
//! });
//! let document = Document::from_json_value(payload_data)?;
//!
//! // Create capability invocation proof options
//! let options = CapabilityInvocationOptions::new()
//!     .with_verification_method(&format!("{did}#initialKey"))
//!     .with_capability(&root_cap.id)
//!     .with_capability_action(CapabilityAction::Write)
//!     .with_invocation_target(did);
//!
//! // Create the signed document (Note: will fail without key resolution)
//! // let signed_document = create_capability_invocation_proof(&document, &options)?;
//! # Ok(())
//! # }
//! ```
pub mod invocation;
pub mod root_capability;

pub use invocation::{
    CapabilityInvocationOptions, create_capability_invocation_proof,
    verify_capability_invocation_proof,
};
pub use root_capability::{RootCapability, dereference_root_capability, derive_root_capability};

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// ZCAP-LD context URL
pub const ZCAP_CONTEXT: &str = "https://w3id.org/zcap/v1";

/// Standard capability actions for DID operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityAction {
    /// Write action - allows updating DID documents
    Write,
    /// Read action - allows reading DID documents
    Read,
    /// Custom action with string value
    Custom(String),
}

impl CapabilityAction {
    /// Convert to string representation
    pub fn as_str(&self) -> &str {
        match self {
            CapabilityAction::Write => "Write",
            CapabilityAction::Read => "Read",
            CapabilityAction::Custom(s) => s,
        }
    }
}

impl From<&str> for CapabilityAction {
    fn from(s: &str) -> Self {
        match s {
            "Write" => CapabilityAction::Write,
            "Read" => CapabilityAction::Read,
            _ => CapabilityAction::Custom(s.to_string()),
        }
    }
}

/// Common ZCAP validation functions
pub mod validation {
    use super::*;

    /// Validate that a capability ID follows the expected format
    /// Format: urn:zcap:root:{url_encoded_did}
    pub fn validate_capability_id(capability_id: &str) -> Result<()> {
        let components: Vec<&str> = capability_id.split(':').collect();

        if components.len() != 4 {
            return Err(crate::error::Error::Zcap(format!(
                "Invalid capability ID format: {capability_id}"
            )));
        }

        if components[0] != "urn" || components[1] != "zcap" || components[2] != "root" {
            return Err(crate::error::Error::Zcap(format!(
                "Invalid capability ID prefix: {capability_id}"
            )));
        }

        // components[3] should be a URL-encoded DID identifier
        if components[3].is_empty() {
            return Err(crate::error::Error::Zcap(
                "Empty DID identifier in capability ID".to_string(),
            ));
        }

        Ok(())
    }

    /// Extract the DID identifier from a capability ID
    pub fn extract_did_from_capability_id(capability_id: &str) -> Result<String> {
        validate_capability_id(capability_id)?;

        let components: Vec<&str> = capability_id.split(':').collect();
        let encoded_did = components[3];

        // URL decode the DID identifier
        let decoded_did = urlencoding::decode(encoded_did).map_err(|e| {
            crate::error::Error::Zcap(format!("Failed to decode DID from capability ID: {e:?}"))
        })?;

        Ok(decoded_did.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::validation::*;
    use super::*;

    #[test]
    fn test_capability_action_conversion() {
        assert_eq!(CapabilityAction::Write.as_str(), "Write");
        assert_eq!(CapabilityAction::Read.as_str(), "Read");
        assert_eq!(
            CapabilityAction::Custom("Delete".to_string()).as_str(),
            "Delete"
        );

        assert_eq!(CapabilityAction::from("Write"), CapabilityAction::Write);
        assert_eq!(CapabilityAction::from("Read"), CapabilityAction::Read);
        assert_eq!(
            CapabilityAction::from("Custom"),
            CapabilityAction::Custom("Custom".to_string())
        );
    }

    #[test]
    fn test_validate_capability_id() {
        // Valid capability ID
        let valid_id = "urn:zcap:root:did%3Abtc1%3Ak1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
        assert!(validate_capability_id(valid_id).is_ok());

        // Invalid format - wrong number of components
        assert!(validate_capability_id("urn:zcap:root").is_err());
        assert!(validate_capability_id("urn:zcap:root:id:extra").is_err());

        // Invalid prefix
        assert!(validate_capability_id("urn:invalid:root:did%3Abtc1").is_err());
        assert!(validate_capability_id("invalid:zcap:root:did%3Abtc1").is_err());

        // Empty DID
        assert!(validate_capability_id("urn:zcap:root:").is_err());
    }

    #[test]
    fn test_extract_did_from_capability_id() {
        let capability_id = "urn:zcap:root:did%3Abtc1%3Ak1test";
        let extracted = extract_did_from_capability_id(capability_id).unwrap();
        assert_eq!(extracted, "did:btc1:k1test");

        // Invalid capability ID should fail
        assert!(extract_did_from_capability_id("invalid").is_err());
    }
}
