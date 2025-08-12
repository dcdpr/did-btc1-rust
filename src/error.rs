use onlyerror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum Error {
    /// Error during document I/O operations
    #[error("Document I/O error")]
    DocumentIO(#[from] io::Error),

    // /// Error parsing JSON document
    // #[error("JSON parse error")]
    // JsonParse(#[from] serde_json::Error),

    /// Error converting JSON Value to str
    #[error("Value can't be converted to str for key `{0}`")]
    JsonValueStr(String),

    // /// Expected JSON string
    // #[error("Expected JSON string")]
    // ExpectedJsonStr,
    /// Error with key operations
    Key(#[from] crate::key::Error),

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

    // /// DID Encoding error
    // #[error("DID Encoding error")]
    // DidEncoding(#[from] crate::identifier::Error),
    // /// Document service endpoints error
    // #[error("Document service endpoints error")]
    // Service(#[from] crate::service::Error),
}

/// Result type for this crate
pub type Result<T> = std::result::Result<T, Error>;
