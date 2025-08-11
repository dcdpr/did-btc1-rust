use did_btc1_identifier::Did;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::key::PublicKey;

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

/// Verification method ID
///
/// These look like DIDs with a `#fragment`. Used to identify [`VerificationMethod`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethodId(String);

impl FromStr for VerificationMethodId {
    type Err = Error;

    fn from_str(method_id: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(method_id.to_string()))
    }
}

/// Represents a verification method for cryptographic proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// Identifier for the verification method
    pub id: VerificationMethodId,

    /// Type of verification method
    #[serde(rename = "type")]
    pub type_: VerificationMethodType,

    /// The controller of this verification method
    pub controller: Did,

    /// Public key
    public_key: PublicKey,
}

impl VerificationMethod {
    /// Create a new verification method
    pub fn new(id: VerificationMethodId, controller: Did, public_key: PublicKey) -> Result<Self> {
        Ok(Self {
            id,
            type_: VerificationMethodType::Multikey,
            controller,
            public_key,
        })
    }

    /// Get the public key from this verification method
    pub fn public_key(&self) -> Result<&PublicKey> {
        if self.type_ != VerificationMethodType::Multikey {
            return Err(Error::Key(format!(
                "Unsupported verification method type: {:?}",
                self.type_
            )));
        }

        Ok(&self.public_key)
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
    pub fn resolve(&self, id: VerificationMethodId) -> Option<&VerificationMethod> {
        self.methods.iter().find(|m| m.id == id)
    }
}

/// Trait for resolving verification methods
pub trait VerificationMethodResolver {
    /// Resolve a verification method by ID
    fn resolve(&self, id: &str) -> Result<VerificationMethod>;
}
