// TODO: This module is incomplete
#![allow(dead_code)]

use crate::document::Document;
use crate::zcap::proof::{Proof, ProofOptions, VerificationResult};
use onlyerror::Error;

/// BIP340 JCS cryptosuite implementation
pub(crate) mod bip340_jcs;

// /// BIP340 RDFC cryptosuite implementation
// pub(crate) mod bip340_rdfc;

/// Shared utilities for cryptosuites
pub(crate) mod utils;

pub(crate) mod transformation;

#[derive(Error, Debug)]
pub enum Error {
    /// JSON parse error
    Json(#[from] serde_json::Error),

    /// DID document error
    Document(#[from] crate::document::Error),

    /// Cryptographic error
    Secp256k1(#[from] secp256k1::Error),

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// Invalid proof configuration
    #[error("Invalid proof configuration: {0}")]
    InvalidProofConfig(String),

    /// Error during proof transformation
    #[error("Proof transformation error: {0}")]
    ProofTransformation(String),

    /// Error during proof generation
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),

    /// Error during proof verification
    #[error("Proof verification error: {0}")]
    ProofVerification(String),

    /// Error with cryptographic operations
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    /// Error with canonicalization
    #[error("Canonicalization error: {0}")]
    Canonicalization(String),

    /// Multibase error
    Multibase(#[from] multibase::Error),
}

/// Trait defining the main interface for cryptographic suites
pub(crate) trait CryptoSuite {
    /// Name of the cryptographic suite
    fn name(&self) -> &'static str;

    /// Create a proof for a document with given options
    fn create_proof(&self, document: &Document, options: &ProofOptions) -> Result<Document, Error>;

    /// Verify a document with a proof
    fn verify_proof(&self, document: &Document) -> Result<VerificationResult, Error>;

    /// Transform a document for hashing
    fn transform(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>, Error>;

    /// Hash transformed data
    fn hash(&self, transformed_data: &[u8], proof_config: &[u8]) -> Result<Vec<u8>, Error>;

    /// Configure a proof from options
    fn configure_proof(
        &self,
        document: &Document,
        options: &ProofOptions,
    ) -> Result<Vec<u8>, Error>;

    /// Serialize a proof
    fn serialize_proof(&self, hash_data: &[u8], options: &ProofOptions) -> Result<Vec<u8>, Error>;

    /// Verify a proof
    fn verify(&self, hash_data: &[u8], proof_bytes: &[u8], options: &Proof) -> Result<bool, Error>;
}
