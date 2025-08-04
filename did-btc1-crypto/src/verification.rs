use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::key::{KeyFormat, PublicKey};

/// Verification method types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationMethodType {
    /// Multikey verification method
    Multikey,
    /// Other types
    #[serde(other)]
    Other,
}

/// Represents a verification method for cryptographic proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Identifier for the verification method
    pub id: String,

    /// Type of verification method
    #[serde(rename = "type")]
    pub type_: VerificationMethodType,

    /// The controller of this verification method
    pub controller: String,

    /// Public key in multibase format
    pub public_key_multibase: String,
}

impl VerificationMethod {
    /// Create a new verification method
    pub fn new(id: &str, controller: &str, public_key: &PublicKey) -> Result<Self> {
        let public_key_multibase = public_key.encode(KeyFormat::Multikey)?;

        Ok(Self {
            id: id.to_string(),
            type_: VerificationMethodType::Multikey,
            controller: controller.to_string(),
            public_key_multibase,
        })
    }

    /// Get the public key from this verification method
    pub fn public_key(&self) -> Result<PublicKey> {
        if self.type_ != VerificationMethodType::Multikey {
            return Err(Error::Key(format!(
                "Unsupported verification method type: {:?}",
                self.type_
            )));
        }

        PublicKey::from_multikey(&self.public_key_multibase)
    }
}

/// Mock verification method resolver for testing
#[derive(Debug, Default)]
pub struct MockVerificationMethodResolver {
    methods: Vec<VerificationMethod>,
}

impl MockVerificationMethodResolver {
    /// Create a new empty resolver
    pub fn new() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    /// Add a verification method to the resolver
    pub fn add_method(&mut self, method: VerificationMethod) {
        self.methods.push(method);
    }

    /// Resolve a verification method by ID
    pub fn resolve(&self, id: &str) -> Option<&VerificationMethod> {
        self.methods.iter().find(|m| m.id == id)
    }
}

/// Trait for resolving verification methods
pub trait VerificationMethodResolver {
    /// Resolve a verification method by ID
    fn resolve(&self, id: &str) -> Result<VerificationMethod>;
}
