// TODO: This module is incomplete
#![allow(dead_code)]

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

pub(crate) enum CryptoSuite {
    Jsc, // TODO: Remove JSC asap
    Rdfc,
}
