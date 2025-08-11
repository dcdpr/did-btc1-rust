use onlyerror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum Error {
    /// Error during document I/O operations
    #[error("Document I/O error")]
    DocumentIO(#[from] io::Error),

    /// Error parsing JSON document
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::Error),

    /// Error converting JSON Value to str
    #[error("Value can't be converted to str for key `{0}`")]
    JsonValueStr(String),

    /// Expected JSON string
    #[error("Expected JSON string")]
    ExpectedJsonStr,

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

    /// Error with key operations
    #[error("Key error: {0}")]
    Key(String),

    /// Error with canonicalization
    #[error("Canonicalization error: {0}")]
    Canonicalization(String),

    /// Error with multibase encoding/decoding
    #[error("Multibase error: {0}")]
    Multibase(String),

    /// Invalid proof configuration
    #[error("Invalid proof configuration: {0}")]
    InvalidProofConfig(String),

    /// Unsupported cryptographic suite
    #[error("Unsupported cryptographic suite: {0}")]
    UnsupportedCryptoSuite(String),

    /// Unsupported proof type
    #[error("Unsupported proof type: {0}")]
    UnsupportedProofType(String),

    /// ZCAP (Authorization Capabilities) related errors
    #[error("ZCAP error: {0}")]
    Zcap(String),

    /// DID-specific errors (key resolution, verification methods, etc.)
    #[error("DID key error: {0}")]
    DidKey(String),

    /// Generic error
    #[error("{0}")]
    Other(String),

    #[error("DID Encoding error")]
    DidEncoding(#[from] did_btc1_identifier::DidEncodingError),

}

/// Result type for this crate
pub type Result<T> = std::result::Result<T, Error>;
