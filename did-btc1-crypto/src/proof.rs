use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::document::Document;

/// Types of proofs supported by the library
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProofType {
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
pub enum ProofPurpose {
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
    pub id: Option<String>,

    /// Type of proof
    #[serde(rename = "type")]
    pub type_: ProofType,

    /// Purpose of the proof
    pub proof_purpose: String,

    /// Verification method that can be used to verify the proof
    pub verification_method: String,

    /// Cryptographic suite used for the proof
    pub cryptosuite: String,

    /// When the proof was created (ISO8601 dateTime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// When the proof expires (ISO8601 dateTime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Security domain for the proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Challenge to prevent replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Proof value (encoded binary data)
    pub proof_value: String,

    /// Previous proof ID or array of IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<Value>,

    /// Random value to increase privacy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Optional JSON-LD context
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,

    /// ZCAP: Capability being invoked (for capabilityInvocation proof purpose)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,

    /// ZCAP: Action being performed with the capability
    #[serde(rename = "capabilityAction", skip_serializing_if = "Option::is_none")]
    pub capability_action: Option<String>,

    /// ZCAP: Target of the capability invocation
    #[serde(rename = "invocationTarget", skip_serializing_if = "Option::is_none")]
    pub invocation_target: Option<String>,
}

/// Options for creating a proof
#[derive(Debug, Clone, Default)]
pub struct ProofOptions {
    /// Key-value pairs of proof options
    pub options: HashMap<String, Value>,
}

impl ProofOptions {
    /// Create a new empty set of proof options
    pub fn new() -> Self {
        Self {
            options: HashMap::new(),
        }
    }

    /// Set the proof type (default is "DataIntegrityProof")
    pub fn with_type(mut self, type_: &str) -> Self {
        self.options
            .insert("type".to_string(), Value::String(type_.to_string()));
        self
    }

    /// Set the cryptosuite
    pub fn with_cryptosuite(mut self, cryptosuite: &str) -> Self {
        self.options.insert(
            "cryptosuite".to_string(),
            Value::String(cryptosuite.to_string()),
        );
        self
    }

    /// Set the verification method
    pub fn with_verification_method(mut self, method: &str) -> Self {
        self.options.insert(
            "verificationMethod".to_string(),
            Value::String(method.to_string()),
        );
        self
    }

    /// Set the proof purpose
    pub fn with_proof_purpose(mut self, purpose: &str) -> Self {
        self.options.insert(
            "proofPurpose".to_string(),
            Value::String(purpose.to_string()),
        );
        self
    }

    /// Set the creation date
    pub fn with_created(mut self, created: &str) -> Self {
        self.options
            .insert("created".to_string(), Value::String(created.to_string()));
        self
    }

    /// Set the expiration date
    pub fn with_expires(mut self, expires: &str) -> Self {
        self.options
            .insert("expires".to_string(), Value::String(expires.to_string()));
        self
    }

    /// Set the security domain
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.options
            .insert("domain".to_string(), Value::String(domain.to_string()));
        self
    }

    /// Set the challenge
    pub fn with_challenge(mut self, challenge: &str) -> Self {
        self.options.insert(
            "challenge".to_string(),
            Value::String(challenge.to_string()),
        );
        self
    }

    /// Set the nonce
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.options
            .insert("nonce".to_string(), Value::String(nonce.to_string()));
        self
    }

    /// Convert options to a JSON Value
    pub fn to_value(&self) -> Value {
        Value::Object(serde_json::Map::from_iter(
            self.options.iter().map(|(k, v)| (k.clone(), v.clone())),
        ))
    }
}

/// Result of verifying a proof
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub verified: bool,

    /// The verified document (if verification succeeded)
    pub verified_document: Option<Document>,
}
