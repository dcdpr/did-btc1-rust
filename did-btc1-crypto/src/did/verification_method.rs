//! Verification method utilities for DID:BTC1
//!
//! This module provides utilities for working with DID verification methods,
//! including creation, validation, and key resolution.

use super::DidKeyResolver;
use crate::error::{Error, Result};
use crate::key::PublicKey;
use crate::verification::VerificationMethod;

/// DID-specific verification method that includes DID context
#[derive(Debug, Clone)]
pub struct DidVerificationMethod {
    /// The underlying verification method
    pub verification_method: VerificationMethod,
    /// The DID identifier this verification method belongs to
    pub did_identifier: String,
    /// The fragment (without # prefix)
    pub fragment: String,
}

impl DidVerificationMethod {
    /// Create a new DID verification method
    ///
    /// # Arguments
    ///
    /// * `did_identifier` - The DID identifier
    /// * `fragment` - The fragment (without # prefix)
    /// * `public_key` - The public key for this verification method
    ///
    /// # Returns
    ///
    /// * `Ok(DidVerificationMethod)` - The created verification method
    /// * `Err(Error)` - If creation fails
    pub fn new(did_identifier: &str, fragment: &str, public_key: &PublicKey) -> Result<Self> {
        // Validate DID identifier
        did_btc1_encoding::parse_did_identifier(did_identifier)
            .map_err(|e| Error::DidKey(format!("Invalid DID identifier: {e:?}")))?;

        // Create verification method ID
        let verification_method_id = super::create_verification_method_id(did_identifier, fragment);

        // Create the underlying verification method
        let verification_method =
            VerificationMethod::new(&verification_method_id, did_identifier, public_key)?;

        Ok(Self {
            verification_method,
            did_identifier: did_identifier.to_string(),
            fragment: fragment.to_string(),
        })
    }

    /// Get the full verification method ID
    pub fn id(&self) -> &str {
        &self.verification_method.id
    }

    /// Get the public key in Multikey format
    pub fn public_key_multibase(&self) -> &str {
        &self.verification_method.public_key_multibase
    }

    /// Create an "initialKey" verification method from a DID identifier
    ///
    /// For key-based DIDs, this extracts the public key from the DID and
    /// creates a verification method with the standard "initialKey" fragment.
    ///
    /// # Arguments
    ///
    /// * `did_identifier` - The DID identifier
    ///
    /// # Returns
    ///
    /// * `Ok(DidVerificationMethod)` - The created initial key verification method
    /// * `Err(Error)` - If the DID is not key-based or creation fails
    pub fn create_initial_key(did_identifier: &str) -> Result<Self> {
        // Parse the DID identifier
        let components = did_btc1_encoding::parse_did_identifier(did_identifier)
            .map_err(|e| Error::DidKey(format!("Invalid DID identifier: {e:?}")))?;

        // Extract public key from key-based DID
        let key_bytes = super::extract_public_key_from_did(&components)?;
        let public_key = PublicKey::from_bytes(&key_bytes)?;

        // Create verification method with "initialKey" fragment
        Self::new(did_identifier, "initialKey", &public_key)
    }

    /// Convert to the underlying VerificationMethod
    pub fn into_verification_method(self) -> VerificationMethod {
        self.verification_method
    }

    /// Get a reference to the underlying VerificationMethod
    pub fn as_verification_method(&self) -> &VerificationMethod {
        &self.verification_method
    }
}

/// Resolve a public key from a verification method ID using a key resolver
///
/// This is a convenience function that uses a DidKeyResolver to look up
/// the public key associated with a verification method.
///
/// # Arguments
///
/// * `verification_method_id` - Full verification method ID
/// * `resolver` - The key resolver to use
///
/// # Returns
///
/// * `Ok(PublicKey)` - The resolved public key
/// * `Err(Error)` - If resolution fails
pub fn resolve_verification_method_key(
    verification_method_id: &str,
    resolver: &dyn DidKeyResolver,
) -> Result<PublicKey> {
    resolver.resolve_public_key(verification_method_id)
}

/// Create a DidVerificationMethod from a verification method ID and resolver
///
/// This resolves the public key and creates a complete DidVerificationMethod.
///
/// # Arguments
///
/// * `verification_method_id` - Full verification method ID
/// * `resolver` - The key resolver to use
///
/// # Returns
///
/// * `Ok(DidVerificationMethod)` - The created verification method
/// * `Err(Error)` - If resolution or creation fails
pub fn create_verification_method_from_id(
    verification_method_id: &str,
    resolver: &dyn DidKeyResolver,
) -> Result<DidVerificationMethod> {
    // Parse the verification method ID
    let (did_identifier, fragment) = super::parse_verification_method_id(verification_method_id)?;

    // Resolve the public key
    let public_key = resolver.resolve_public_key(verification_method_id)?;

    // Create the DID verification method
    DidVerificationMethod::new(&did_identifier, &fragment, &public_key)
}

/// Validate that a verification method ID is supported by a resolver
///
/// # Arguments
///
/// * `verification_method_id` - Full verification method ID
/// * `resolver` - The key resolver to check
///
/// # Returns
///
/// * `Ok(())` - If the verification method is supported
/// * `Err(Error)` - If the verification method is not supported
pub fn validate_verification_method_support(
    verification_method_id: &str,
    resolver: &dyn DidKeyResolver,
) -> Result<()> {
    if resolver.supports_verification_method(verification_method_id) {
        Ok(())
    } else {
        Err(Error::DidKey(format!(
            "Verification method not supported: {verification_method_id}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::InMemoryKeyResolver;
    use crate::key::KeyPair;

    const TEST_DID: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
    const TEST_VERIFICATION_METHOD: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx#initialKey";

    #[test]
    fn test_create_initial_key_verification_method() {
        let vm = DidVerificationMethod::create_initial_key(TEST_DID).unwrap();

        assert_eq!(vm.did_identifier, TEST_DID);
        assert_eq!(vm.fragment, "initialKey");
        assert_eq!(vm.id(), TEST_VERIFICATION_METHOD);

        // Should have a valid public key in Multikey format
        assert!(vm.public_key_multibase().starts_with('z'));
    }

    #[test]
    fn test_create_custom_verification_method() {
        let key_pair = KeyPair::generate().unwrap();
        let vm = DidVerificationMethod::new(TEST_DID, "custom-key", &key_pair.public_key).unwrap();

        assert_eq!(vm.did_identifier, TEST_DID);
        assert_eq!(vm.fragment, "custom-key");
        assert_eq!(vm.id(), &format!("{TEST_DID}#custom-key"));
    }

    #[test]
    fn test_resolve_verification_method_key() {
        let resolver = InMemoryKeyResolver::new();

        // Should be able to resolve initialKey from key-based DID
        let public_key =
            resolve_verification_method_key(TEST_VERIFICATION_METHOD, &resolver).unwrap();

        // Verify it's a valid 32 byte secp256k1 key
        let key_bytes = public_key.to_bytes();
        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_create_verification_method_from_id() {
        let resolver = InMemoryKeyResolver::new();

        let vm = create_verification_method_from_id(TEST_VERIFICATION_METHOD, &resolver).unwrap();

        assert_eq!(vm.did_identifier, TEST_DID);
        assert_eq!(vm.fragment, "initialKey");
        assert_eq!(vm.id(), TEST_VERIFICATION_METHOD);
    }

    #[test]
    fn test_validate_verification_method_support() {
        let resolver = InMemoryKeyResolver::new();

        // Should support initialKey for key-based DIDs
        assert!(validate_verification_method_support(TEST_VERIFICATION_METHOD, &resolver).is_ok());

        // Should not support non-existent verification methods
        let unsupported = "did:btc1:k1test#nonexistent";
        assert!(validate_verification_method_support(unsupported, &resolver).is_err());
    }

    #[test]
    fn test_verification_method_with_stored_key() {
        let mut resolver = InMemoryKeyResolver::new();
        let key_pair = KeyPair::generate().unwrap();
        let custom_vm_id = &format!("{TEST_DID}#stored-key");

        // Add key to resolver
        resolver
            .add_secret_key(custom_vm_id, key_pair.secret_key.clone())
            .unwrap();

        // Should be able to create verification method from stored key
        let vm = create_verification_method_from_id(custom_vm_id, &resolver).unwrap();
        assert_eq!(vm.fragment, "stored-key");

        // Should be able to resolve both public and secret keys
        assert!(resolver.resolve_public_key(custom_vm_id).is_ok());
        assert!(resolver.resolve_secret_key(custom_vm_id).is_ok());
    }
}
