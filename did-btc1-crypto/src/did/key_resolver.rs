//! Key resolution for DID:BTC1 verification methods
//!
//! This module provides traits and implementations for resolving cryptographic
//! keys from DID verification method identifiers.

use super::{extract_public_key_from_did, parse_verification_method_id};
use crate::error::{Error, Result};
use crate::key::{PublicKey, SecretKey};
use did_btc1_encoding::parse_did_identifier;
use std::collections::HashMap;

/// Trait for resolving keys from DID verification method identifiers
///
/// This trait abstracts the process of looking up cryptographic keys
/// associated with verification methods in DID documents.
pub trait DidKeyResolver {
    /// Resolve a public key from a verification method ID
    ///
    /// # Arguments
    ///
    /// * `verification_method_id` - Full verification method ID (e.g., "did:btc1:...#key-1")
    ///
    /// # Returns
    ///
    /// * `Ok(PublicKey)` - The resolved public key
    /// * `Err(Error)` - If the key cannot be resolved
    fn resolve_public_key(&self, verification_method_id: &str) -> Result<PublicKey>;

    /// Resolve a secret key from a verification method ID
    ///
    /// # Arguments
    ///
    /// * `verification_method_id` - Full verification method ID
    ///
    /// # Returns
    ///
    /// * `Ok(SecretKey)` - The resolved secret key
    /// * `Err(Error)` - If the key cannot be resolved or is not available
    fn resolve_secret_key(&self, verification_method_id: &str) -> Result<SecretKey>;

    /// Check if a verification method is supported by this resolver
    ///
    /// # Arguments
    ///
    /// * `verification_method_id` - Full verification method ID
    ///
    /// # Returns
    ///
    /// * `true` if the verification method can be resolved
    /// * `false` otherwise
    fn supports_verification_method(&self, verification_method_id: &str) -> bool;
}

/// In-memory key resolver for testing and simple use cases
///
/// This resolver stores key pairs in memory and can resolve both public
/// and private keys.
pub struct InMemoryKeyResolver {
    /// Map from verification method ID to secret key
    secret_keys: HashMap<String, SecretKey>,
    /// Map from verification method ID to public key (for keys without secrets)
    public_keys: HashMap<String, PublicKey>,
}

impl InMemoryKeyResolver {
    /// Create a new empty in-memory key resolver
    pub fn new() -> Self {
        Self {
            secret_keys: HashMap::new(),
            public_keys: HashMap::new(),
        }
    }

    /// Add a secret key for a verification method
    ///
    /// This automatically derives and stores the corresponding public key.
    ///
    /// # Arguments
    ///
    /// * `verification_method_id` - Full verification method ID
    /// * `secret_key` - The secret key to store
    pub fn add_secret_key(
        &mut self,
        verification_method_id: &str,
        secret_key: SecretKey,
    ) -> Result<()> {
        // Validate the verification method ID format
        parse_verification_method_id(verification_method_id)?;

        // Derive the public key from the secret key
        let key_pair = crate::key::KeyPair::from_secret_key(secret_key.clone());

        // Store both keys
        self.secret_keys
            .insert(verification_method_id.to_string(), secret_key);
        self.public_keys
            .insert(verification_method_id.to_string(), key_pair.public_key);

        Ok(())
    }

    /// Add a public key for a verification method
    ///
    /// This is useful for verification-only scenarios where the private key
    /// is not available or needed.
    ///
    /// # Arguments
    ///
    /// * `verification_method_id` - Full verification method ID
    /// * `public_key` - The public key to store
    pub fn add_public_key(
        &mut self,
        verification_method_id: &str,
        public_key: PublicKey,
    ) -> Result<()> {
        // Validate the verification method ID format
        parse_verification_method_id(verification_method_id)?;

        self.public_keys
            .insert(verification_method_id.to_string(), public_key);
        Ok(())
    }

    /// Remove a key pair for a verification method
    ///
    /// # Arguments
    ///
    /// * `verification_method_id` - Full verification method ID
    pub fn remove_key(&mut self, verification_method_id: &str) {
        self.secret_keys.remove(verification_method_id);
        self.public_keys.remove(verification_method_id);
    }

    /// Get the number of keys stored in this resolver
    pub fn key_count(&self) -> usize {
        self.public_keys.len()
    }
}

impl Default for InMemoryKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DidKeyResolver for InMemoryKeyResolver {
    fn resolve_public_key(&self, verification_method_id: &str) -> Result<PublicKey> {
        // First try stored keys
        if let Some(public_key) = self.public_keys.get(verification_method_id) {
            return Ok(public_key.clone());
        }

        // If not found, try to extract from DID for key-based DIDs with "initialKey" fragment
        let (did_identifier, fragment) = parse_verification_method_id(verification_method_id)?;

        if fragment == "initialKey" {
            // Try to extract public key directly from the DID identifier
            let components = parse_did_identifier(&did_identifier)
                .map_err(|e| Error::DidKey(format!("Invalid DID: {e:?}")))?;

            let key_bytes = extract_public_key_from_did(&components)?;

            // Create PublicKey from the extracted bytes
            PublicKey::from_bytes(&key_bytes)
        } else {
            Err(Error::DidKey(format!(
                "Verification method not found: {verification_method_id}"
            )))
        }
    }

    fn resolve_secret_key(&self, verification_method_id: &str) -> Result<SecretKey> {
        self.secret_keys
            .get(verification_method_id)
            .cloned()
            .ok_or_else(|| {
                Error::DidKey(format!(
                    "Secret key not found for verification method: {verification_method_id}"
                ))
            })
    }

    fn supports_verification_method(&self, verification_method_id: &str) -> bool {
        // Check if we have the key stored
        if self.public_keys.contains_key(verification_method_id) {
            return true;
        }

        // Check if it's a key-based DID with "initialKey" fragment (can be derived)
        if let Ok((did_identifier, fragment)) = parse_verification_method_id(verification_method_id)
        {
            if fragment == "initialKey" {
                if let Ok(components) = parse_did_identifier(&did_identifier) {
                    return matches!(components.id_type, did_btc1_encoding::IdType::Key);
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    const TEST_DID: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx";
    const TEST_VERIFICATION_METHOD: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx#initialKey";
    const TEST_CUSTOM_VERIFICATION_METHOD: &str =
        "did:btc1:k1qqpuwwde82nennsavvf0lqfnlvx7frrgzs57lchr02q8mz49qzaaxmqphnvcx#key-1";

    #[test]
    fn test_in_memory_resolver_basic() {
        let mut resolver = InMemoryKeyResolver::new();
        assert_eq!(resolver.key_count(), 0);

        // Generate a key pair for testing
        let key_pair = KeyPair::generate().unwrap();

        // Add secret key
        resolver
            .add_secret_key(TEST_CUSTOM_VERIFICATION_METHOD, key_pair.secret_key.clone())
            .unwrap();
        assert_eq!(resolver.key_count(), 1);

        // Should be able to resolve both public and secret keys
        assert!(resolver.supports_verification_method(TEST_CUSTOM_VERIFICATION_METHOD));

        let _resolved_public = resolver
            .resolve_public_key(TEST_CUSTOM_VERIFICATION_METHOD)
            .unwrap();
        let resolved_secret = resolver
            .resolve_secret_key(TEST_CUSTOM_VERIFICATION_METHOD)
            .unwrap();

        // Verify the keys match what we stored
        assert_eq!(
            resolved_secret.key.secret_bytes(),
            key_pair.secret_key.key.secret_bytes()
        );
    }

    #[test]
    fn test_in_memory_resolver_public_key_only() {
        let mut resolver = InMemoryKeyResolver::new();

        // Generate a key pair for testing
        let key_pair = KeyPair::generate().unwrap();

        // Add only public key
        resolver
            .add_public_key(TEST_CUSTOM_VERIFICATION_METHOD, key_pair.public_key.clone())
            .unwrap();

        // Should be able to resolve public key but not secret key
        assert!(resolver.supports_verification_method(TEST_CUSTOM_VERIFICATION_METHOD));
        assert!(
            resolver
                .resolve_public_key(TEST_CUSTOM_VERIFICATION_METHOD)
                .is_ok()
        );
        assert!(
            resolver
                .resolve_secret_key(TEST_CUSTOM_VERIFICATION_METHOD)
                .is_err()
        );
    }

    #[test]
    fn test_resolve_initial_key_from_did() {
        let resolver = InMemoryKeyResolver::new();

        // Should support "initialKey" for key-based DIDs even without explicit storage
        assert!(resolver.supports_verification_method(TEST_VERIFICATION_METHOD));

        // Should be able to resolve the public key from the DID
        let resolved_public = resolver
            .resolve_public_key(TEST_VERIFICATION_METHOD)
            .unwrap();

        // The resolved key should be 32 bytes
        let key_bytes = resolved_public.to_bytes();
        assert_eq!(key_bytes.len(), 32);

        // Should NOT be able to resolve secret key (not stored)
        assert!(
            resolver
                .resolve_secret_key(TEST_VERIFICATION_METHOD)
                .is_err()
        );
    }

    #[test]
    fn test_resolver_remove_key() {
        let mut resolver = InMemoryKeyResolver::new();
        let key_pair = KeyPair::generate().unwrap();

        resolver
            .add_secret_key(TEST_CUSTOM_VERIFICATION_METHOD, key_pair.secret_key)
            .unwrap();
        assert_eq!(resolver.key_count(), 1);

        resolver.remove_key(TEST_CUSTOM_VERIFICATION_METHOD);
        assert_eq!(resolver.key_count(), 0);
        assert!(!resolver.supports_verification_method(TEST_CUSTOM_VERIFICATION_METHOD));
    }

    #[test]
    fn test_invalid_verification_method_ids() {
        let mut resolver = InMemoryKeyResolver::new();
        let key_pair = KeyPair::generate().unwrap();

        // Invalid verification method IDs should be rejected
        assert!(
            resolver
                .add_secret_key("invalid-id", key_pair.secret_key.clone())
                .is_err()
        );
        assert!(
            resolver
                .add_secret_key(&format!("{TEST_DID}#"), key_pair.secret_key)
                .is_err()
        );
    }
}
