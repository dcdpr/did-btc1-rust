use onlyerror::Error;

/// BIP340 JCS cryptosuite implementation
pub mod bip340_jcs;

/// BIP340 RDFC cryptosuite implementation
pub mod bip340_rdfc;

/// Shared utilities for cryptosuites
pub mod utils;

#[derive(Error, Debug)]
pub enum Error {
    /// Error with key operations
    Key(#[from] crate::key::Error),

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
}
