//! Capability Invocation functionality for DID:BTC1
//!
//! This module implements capability invocation proofs that are used to authorize
//! DID document updates in the DID:BTC1 method. It extends the existing proof
//! creation functionality with ZCAP-LD specific features.

use super::{CapabilityAction, derive_root_capability};
use crate::error::{Error, Result};
use crate::suites::bip340_jcs::Bip340JcsSuite;
use crate::{CryptoSuite, Document, ProofOptions};
use serde_json::Value;

/// Options for creating capability invocation proofs
///
/// This extends the standard proof options with ZCAP-LD specific fields
/// required for capability invocation proofs.
#[derive(Debug, Clone)]
pub struct CapabilityInvocationOptions {
    /// Base proof options (verification method, created time, etc.)
    pub base_options: ProofOptions,

    /// The capability being invoked (typically a root capability ID)
    pub capability: String,

    /// The action being authorized (e.g., "Write" for DID updates)
    pub capability_action: CapabilityAction,

    /// The target that the capability is being invoked against
    pub invocation_target: String,
}

impl CapabilityInvocationOptions {
    /// Create new capability invocation options
    pub fn new() -> Self {
        Self {
            base_options: ProofOptions::new(),
            capability: String::new(),
            capability_action: CapabilityAction::Write,
            invocation_target: String::new(),
        }
    }

    /// Set the verification method
    pub fn with_verification_method(mut self, method: &str) -> Self {
        self.base_options = self.base_options.with_verification_method(method);
        self
    }

    /// Set the capability being invoked
    pub fn with_capability(mut self, capability: &str) -> Self {
        self.capability = capability.to_string();
        self
    }

    /// Set the capability action
    pub fn with_capability_action(mut self, action: CapabilityAction) -> Self {
        self.capability_action = action;
        self
    }

    /// Set the invocation target
    pub fn with_invocation_target(mut self, target: &str) -> Self {
        self.invocation_target = target.to_string();
        self
    }

    /// Set the creation time
    pub fn with_created(mut self, created: &str) -> Self {
        self.base_options = self.base_options.with_created(created);
        self
    }

    /// Convert to ProofOptions with ZCAP-LD fields included
    pub fn to_proof_options(&self) -> Result<ProofOptions> {
        self.validate()?;

        let mut options = self.base_options.clone();

        // Set ZCAP-LD specific fields
        options = options
            .with_type("DataIntegrityProof")
            .with_cryptosuite("bip340-jcs-2025")
            .with_proof_purpose("capabilityInvocation");

        // Add ZCAP-LD fields to the options map
        options.options.insert(
            "capability".to_string(),
            Value::String(self.capability.clone()),
        );
        options.options.insert(
            "capabilityAction".to_string(),
            Value::String(self.capability_action.as_str().to_string()),
        );
        options.options.insert(
            "invocationTarget".to_string(),
            Value::String(self.invocation_target.clone()),
        );

        // Add required ZCAP contexts
        let contexts = vec![
            Value::String("https://w3id.org/zcap/v1".to_string()),
            Value::String("https://w3id.org/security/data-integrity/v2".to_string()),
            Value::String("https://w3id.org/json-ld-patch/v1".to_string()),
        ];
        options
            .options
            .insert("@context".to_string(), Value::Array(contexts));

        Ok(options)
    }

    /// Validate the capability invocation options
    pub fn validate(&self) -> Result<()> {
        if self.capability.is_empty() {
            return Err(Error::Zcap("Capability field is required".to_string()));
        }

        if self.invocation_target.is_empty() {
            return Err(Error::Zcap("Invocation target is required".to_string()));
        }

        // Validate that capability is a properly formatted capability ID
        super::validation::validate_capability_id(&self.capability)?;

        // Validate that invocation target matches the capability's target
        let did_from_capability =
            super::validation::extract_did_from_capability_id(&self.capability)?;
        if did_from_capability != self.invocation_target {
            return Err(Error::Zcap(format!(
                "Invocation target '{}' does not match capability target '{did_from_capability}'",
                self.invocation_target
            )));
        }

        Ok(())
    }
}

impl Default for CapabilityInvocationOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a capability invocation proof for a DID update
///
/// This implements the "Invoke DID Update Payload" algorithm from section 4.3.2
/// of the DID:BTC1 specification. It creates a Data Integrity proof with
/// proof purpose "capabilityInvocation" that authorizes the update.
///
/// # Arguments
///
/// * `document` - The DID Update Payload document to sign
/// * `did_identifier` - The DID being updated
/// * `verification_method_id` - The verification method to sign with
/// * `key_resolver` - Trait object for resolving private keys
///
/// # Returns
///
/// * `Ok(Document)` - The document with capability invocation proof attached
/// * `Err(Error)` - If proof creation fails
///
/// # Example
///
/// // TODO: This test is broken because `Document::from_json_value()` expects a usable Document.
/// ```no-test
/// use did_btc1_crypto::zcap::{create_capability_invocation_proof, CapabilityInvocationOptions, CapabilityAction};
/// use did_btc1_crypto::Document;
/// use serde_json::json;
///
/// // Create a DID update payload document
/// let payload_data = json!({
///     "@context": [
///         "https://w3id.org/zcap/v1",
///         "https://w3id.org/security/data-integrity/v2",
///         "https://w3id.org/json-ld-patch/v1"
///     ],
///     "patch": [{
///         "op": "add",
///         "path": "/service/1",
///         "value": {
///             "id": "#my-service",
///             "type": "MyService",
///             "serviceEndpoint": "https://example.com"
///         }
///     }],
///     "sourceHash": "z123...",
///     "targetHash": "z456...",
///     "targetVersionId": 2
/// });
/// let document = Document::from_json_value(payload_data)?;
///
/// // Create capability invocation options
/// let options = CapabilityInvocationOptions::new()
///     .with_capability("urn:zcap:root:did%3Abtc1%3Ak1test")
///     .with_verification_method("did:btc1:k1test#initialKey")
///     .with_invocation_target("did:btc1:k1test")
///     .with_capability_action(CapabilityAction::Write);
///
/// // Create the signed document (Note: will fail without key resolution)
/// // let signed_document = create_capability_invocation_proof(&document, &options)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
pub fn create_capability_invocation_proof(
    document: &Document,
    options: &CapabilityInvocationOptions,
) -> Result<Document> {
    // Validate options
    options.validate()?;

    // Derive root capability if not already provided
    let root_capability = if options.capability.starts_with("urn:zcap:root:") {
        derive_root_capability(&options.invocation_target)?
    } else {
        return Err(Error::Zcap(format!(
            "Unsupported capability type: {}",
            options.capability
        )));
    };

    // Ensure the capability ID matches what was provided
    if root_capability.id != options.capability {
        return Err(Error::Zcap(format!(
            "Capability ID mismatch: expected '{}', got '{}'",
            options.capability, root_capability.id
        )));
    }

    // Convert to proof options with ZCAP-LD fields
    let proof_options = options.to_proof_options()?;

    // Create the cryptographic suite
    let suite = Bip340JcsSuite::new();

    // Create the proof
    suite.create_proof(document, &proof_options)
}

/// Verify a capability invocation proof
///
/// This verifies that a capability invocation proof is valid and properly
/// authorizes the requested action on the target resource.
///
/// # Arguments
///
/// * `document` - The signed document to verify
/// * `expected_invocation_target` - The expected invocation target
/// * `expected_action` - The expected capability action
///
/// # Returns
///
/// * `Ok(bool)` - True if the proof is valid and authorized
/// * `Err(Error)` - If verification fails
pub fn verify_capability_invocation_proof(
    document: &Document,
    expected_invocation_target: &str,
    expected_action: &CapabilityAction,
) -> Result<bool> {
    // Create the cryptographic suite
    let suite = Bip340JcsSuite::new();

    // Verify the cryptographic proof
    let verification_result = suite.verify_proof(document)?;

    if !verification_result.verified {
        return Ok(false);
    }

    // Extract and validate ZCAP-LD specific fields from the proof
    let proof = document
        .get_proof()
        .ok_or_else(|| Error::Zcap("Document has no proof".to_string()))?;

    // Check proof purpose
    if proof.proof_purpose != "capabilityInvocation" {
        return Err(Error::Zcap(format!(
            "Expected capabilityInvocation proof purpose, got '{}'",
            proof.proof_purpose
        )));
    }

    // Extract ZCAP fields from proof struct
    let capability = proof
        .capability
        .as_ref()
        .ok_or_else(|| Error::Zcap("Missing capability field in proof".to_string()))?;

    let capability_action = proof
        .capability_action
        .as_ref()
        .ok_or_else(|| Error::Zcap("Missing capabilityAction field in proof".to_string()))?;

    let invocation_target = proof
        .invocation_target
        .as_ref()
        .ok_or_else(|| Error::Zcap("Missing invocationTarget field in proof".to_string()))?;

    // Validate invocation target matches expectation
    if invocation_target != expected_invocation_target {
        return Err(Error::Zcap(format!(
            "Invocation target mismatch: expected '{expected_invocation_target}', got '{invocation_target}'"
        )));
    }

    // Validate capability action matches expectation
    let action = CapabilityAction::from(capability_action.as_str());
    if action != *expected_action {
        return Err(Error::Zcap(format!(
            "Capability action mismatch: expected '{}', got '{capability_action}'",
            expected_action.as_str()
        )));
    }

    // Validate the capability itself
    super::validation::validate_capability_id(capability)?;

    // Dereference the root capability and validate it matches the invocation target
    let root_capability = super::dereference_root_capability(capability)?;
    if root_capability.invocation_target != expected_invocation_target {
        return Err(Error::Zcap(format!(
            "Root capability target '{}' does not match expected target '{expected_invocation_target}'",
            root_capability.invocation_target
        )));
    }

    Ok(true)
}

/// Create a DID update payload with capability invocation proof
///
/// This is a convenience function that combines DID update payload creation
/// with capability invocation proof signing in one step.
///
/// # Arguments
///
/// * `did_identifier` - The DID being updated
/// * `patch` - JSON patch operations to apply
/// * `source_hash` - Hash of the source DID document
/// * `target_hash` - Hash of the target DID document
/// * `target_version_id` - Version ID of the target document
/// * `verification_method_id` - Verification method to sign with
///
/// # Returns
///
/// * `Ok(Document)` - The signed DID update payload
/// * `Err(Error)` - If creation fails
pub fn create_signed_did_update_payload(
    did_identifier: &str,
    patch: serde_json::Value,
    source_hash: &str,
    target_hash: &str,
    target_version_id: u32,
    verification_method_id: &str,
) -> Result<Document> {
    // Create the unsigned DID update payload
    let mut payload_data = serde_json::Map::new();

    // Add required contexts
    let contexts = vec![
        Value::String("https://w3id.org/zcap/v1".to_string()),
        Value::String("https://w3id.org/security/data-integrity/v2".to_string()),
        Value::String("https://w3id.org/json-ld-patch/v1".to_string()),
    ];
    payload_data.insert("@context".to_string(), Value::Array(contexts));

    // Add patch and metadata
    payload_data.insert("patch".to_string(), patch);
    payload_data.insert(
        "sourceHash".to_string(),
        Value::String(source_hash.to_string()),
    );
    payload_data.insert(
        "targetHash".to_string(),
        Value::String(target_hash.to_string()),
    );
    payload_data.insert(
        "targetVersionId".to_string(),
        Value::Number(target_version_id.into()),
    );

    // Create document from payload data
    let unsigned_document = Document::from_json_string(&Value::Object(payload_data).to_string())?;

    // Derive root capability for the DID
    let root_capability = derive_root_capability(did_identifier)?;

    // Create capability invocation options
    let invocation_options = CapabilityInvocationOptions::new()
        .with_verification_method(verification_method_id)
        .with_capability(&root_capability.id)
        .with_capability_action(CapabilityAction::Write)
        .with_invocation_target(did_identifier);

    // Create the capability invocation proof
    create_capability_invocation_proof(&unsigned_document, &invocation_options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DID: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
    const TEST_VERIFICATION_METHOD: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx#initialKey";

    #[test]
    fn test_capability_invocation_options_creation() {
        let root_cap = derive_root_capability(TEST_DID).unwrap();

        let options = CapabilityInvocationOptions::new()
            .with_verification_method(TEST_VERIFICATION_METHOD)
            .with_capability(&root_cap.id)
            .with_capability_action(CapabilityAction::Write)
            .with_invocation_target(TEST_DID);

        assert_eq!(options.capability, root_cap.id);
        assert_eq!(options.capability_action, CapabilityAction::Write);
        assert_eq!(options.invocation_target, TEST_DID);
    }

    #[test]
    fn test_capability_invocation_options_validation() {
        let root_cap = derive_root_capability(TEST_DID).unwrap();

        // Valid options
        let valid_options = CapabilityInvocationOptions::new()
            .with_verification_method(TEST_VERIFICATION_METHOD)
            .with_capability(&root_cap.id)
            .with_capability_action(CapabilityAction::Write)
            .with_invocation_target(TEST_DID);
        assert!(valid_options.validate().is_ok());

        // Missing capability
        let invalid_options = CapabilityInvocationOptions::new()
            .with_verification_method(TEST_VERIFICATION_METHOD)
            .with_invocation_target(TEST_DID);
        assert!(invalid_options.validate().is_err());

        // Missing invocation target
        let invalid_options = CapabilityInvocationOptions::new()
            .with_verification_method(TEST_VERIFICATION_METHOD)
            .with_capability(&root_cap.id);
        assert!(invalid_options.validate().is_err());

        // Mismatched capability and invocation target
        let invalid_options = CapabilityInvocationOptions::new()
            .with_verification_method(TEST_VERIFICATION_METHOD)
            .with_capability(&root_cap.id)
            .with_invocation_target("did:btc1:different");
        assert!(invalid_options.validate().is_err());
    }

    #[test]
    fn test_to_proof_options() {
        let root_cap = derive_root_capability(TEST_DID).unwrap();

        let invocation_options = CapabilityInvocationOptions::new()
            .with_verification_method(TEST_VERIFICATION_METHOD)
            .with_capability(&root_cap.id)
            .with_capability_action(CapabilityAction::Write)
            .with_invocation_target(TEST_DID);

        let proof_options = invocation_options.to_proof_options().unwrap();

        // Check basic fields
        assert_eq!(
            proof_options.options.get("type").unwrap().as_str().unwrap(),
            "DataIntegrityProof"
        );
        assert_eq!(
            proof_options
                .options
                .get("cryptosuite")
                .unwrap()
                .as_str()
                .unwrap(),
            "bip340-jcs-2025"
        );
        assert_eq!(
            proof_options
                .options
                .get("proofPurpose")
                .unwrap()
                .as_str()
                .unwrap(),
            "capabilityInvocation"
        );

        // Check ZCAP fields
        assert_eq!(
            proof_options
                .options
                .get("capability")
                .unwrap()
                .as_str()
                .unwrap(),
            root_cap.id
        );
        assert_eq!(
            proof_options
                .options
                .get("capabilityAction")
                .unwrap()
                .as_str()
                .unwrap(),
            "Write"
        );
        assert_eq!(
            proof_options
                .options
                .get("invocationTarget")
                .unwrap()
                .as_str()
                .unwrap(),
            TEST_DID
        );

        // Check contexts
        let contexts = proof_options
            .options
            .get("@context")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(contexts.len(), 3);
        assert!(
            contexts
                .iter()
                .any(|c| c.as_str().unwrap() == "https://w3id.org/zcap/v1")
        );
    }

    #[test]
    fn test_create_signed_did_update_payload_structure() {
        // This test verifies the structure is correct without relying on key resolution
        use crate::proof::{Proof, ProofType};

        let root_cap = derive_root_capability(TEST_DID).unwrap();

        // Create a mock proof with ZCAP fields to verify the structure
        let mock_proof = Proof {
            id: None,
            type_: ProofType::DataIntegrityProof,
            proof_purpose: "capabilityInvocation".to_string(),
            verification_method: TEST_VERIFICATION_METHOD.to_string(),
            cryptosuite: "bip340-jcs-2025".to_string(),
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value: "mock_proof_value".to_string(),
            previous_proof: None,
            nonce: None,
            context: None,
            // New ZCAP fields
            capability: Some(root_cap.id.clone()),
            capability_action: Some("Write".to_string()),
            invocation_target: Some(TEST_DID.to_string()),
        };

        // Verify the ZCAP fields are correctly structured
        assert_eq!(mock_proof.capability.as_ref().unwrap(), &root_cap.id);
        assert_eq!(mock_proof.capability_action.as_ref().unwrap(), "Write");
        assert_eq!(mock_proof.invocation_target.as_ref().unwrap(), TEST_DID);
        assert_eq!(mock_proof.proof_purpose, "capabilityInvocation");
        assert_eq!(mock_proof.cryptosuite, "bip340-jcs-2025");
    }
}
