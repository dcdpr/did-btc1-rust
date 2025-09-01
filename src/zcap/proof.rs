use crate::document::Document;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Types of proofs supported by the library
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProofType {
    /// General Data Integrity Proof
    DataIntegrityProof,
    /// Other types
    #[serde(other)]
    Other,
}

impl Default for ProofType {
    fn default() -> Self {
        Self::DataIntegrityProof
    }
}

/// Purposes for cryptographic proofs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProofPurpose {
    /// Authentication of entity identified by a DID
    Authentication,
    /// Assertion method for making verifiable claims
    AssertionMethod,
    /// Capability invocation
    CapabilityInvocation,
    /// Capability delegation
    CapabilityDelegation,
    /// Other purposes
    #[serde(untagged)]
    Other(String),
}

/// Represents a cryptographic proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    /// Optional identifier for the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<String>,

    /// Type of proof
    #[serde(rename = "type")]
    pub(crate) proof_type: ProofType,

    /// Purpose of the proof
    pub(crate) proof_purpose: String,

    /// Verification method that can be used to verify the proof
    pub(crate) verification_method: String,

    /// Cryptographic suite used for the proof
    pub(crate) cryptosuite: String,

    /// When the proof was created (ISO8601 dateTime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) created: Option<String>,

    /// When the proof expires (ISO8601 dateTime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires: Option<String>,

    /// Security domain for the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) domain: Option<String>,

    /// Challenge to prevent replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) challenge: Option<String>,

    /// Proof value (encoded binary data)
    pub(crate) proof_value: String,

    /// Previous proof ID or array of IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) previous_proof: Option<Value>,

    /// Random value to increase privacy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,

    /// Optional JSON-LD context
    pub(crate) context: Vec<String>,

    /// ZCAP: Capability being invoked (for capabilityInvocation proof purpose)
    pub(crate) capability: String,

    /// ZCAP: Action being performed with the capability
    pub(crate) capability_action: String,

    /// ZCAP: Target of the capability invocation
    pub(crate) invocation_target: String,
}

/// Options for creating a proof
#[derive(Debug, Clone, Default)]
pub(crate) struct ProofOptions {
    // TODO: Need to add the fields required by Data Integrity Schnorr Secp256k1 Cryptosuites

    // SPEC: 3.3.1 Create Proof (bip340-jcs-2025)
    // @context

    // SPEC: 3.3.5 Proof Configuration (bip340-jcs-2025)
    // type
    // cryptosuite
    // created

    // SPEC: 3.3.6 Proof Serialization (bip340-jcs-2025)
    // verificationMethod
}

impl ProofOptions {
    /// Create a new empty set of proof options
    pub(crate) fn new() -> Self {
        Self {
            // options: HashMap::new(),
        }
    }

    /// Set the proof type (default is "DataIntegrityProof")
    pub(crate) fn with_type(self, _proof_type: &str) -> Self {
        todo!()
    }

    /// Set the cryptosuite
    pub(crate) fn with_cryptosuite(self, _cryptosuite: &str) -> Self {
        todo!()
    }

    /// Set the verification method
    pub(crate) fn with_verification_method(self, _method: &str) -> Self {
        todo!()
    }

    /// Set the proof purpose
    pub(crate) fn with_proof_purpose(self, _purpose: &str) -> Self {
        todo!()
    }

    /// Set the creation date
    pub(crate) fn with_created(self, _created: &str) -> Self {
        todo!()
    }

    // /// Set the expiration date
    // pub(crate) fn with_expires(mut self, expires: &str) -> Self {
    //     self.options
    //         .insert("expires".to_string(), Value::String(expires.to_string()));
    //     self
    // }

    // /// Set the security domain
    // pub(crate) fn with_domain(mut self, domain: &str) -> Self {
    //     self.options
    //         .insert("domain".to_string(), Value::String(domain.to_string()));
    //     self
    // }

    // /// Set the challenge
    // pub(crate) fn with_challenge(mut self, challenge: &str) -> Self {
    //     self.options.insert(
    //         "challenge".to_string(),
    //         Value::String(challenge.to_string()),
    //     );
    //     self
    // }

    // /// Set the nonce
    // pub(crate) fn with_nonce(mut self, nonce: &str) -> Self {
    //     self.options
    //         .insert("nonce".to_string(), Value::String(nonce.to_string()));
    //     self
    // }

    /// Convert options to a JSON Value
    pub(crate) fn to_value(&self) -> Value {
        todo!();
    }
}

/// Result of verifying a proof
#[derive(Debug, Clone)]
pub(crate) struct VerificationResult {
    /// Whether the proof is valid
    pub(crate) verified: bool,

    /// The verified document (if verification succeeded)
    pub(crate) verified_document: Option<Document>,
}
