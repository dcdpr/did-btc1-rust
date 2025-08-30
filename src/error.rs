use crate::identifier::Sha256Hash;
use onlyerror::Error;
use serde_json::{Value, json};
use std::io;

#[derive(Error, Debug)]
pub enum Error {
    /// Error during document I/O operations
    DocumentIO(#[from] io::Error),

    /// JSON parse error
    Json(#[from] serde_json::Error),

    /// Data Integrity cryptosuite error
    Cryptosuite(#[from] crate::cryptosuite::Error),

    /// DID document error
    Document(#[from] crate::document::Error),

    /// Cryptographic error
    Secp256k1(#[from] secp256k1::Error),

    /// Error converting JSON Value to str
    #[error("Value can't be converted to str for key `{0}`")]
    JsonValueStr(String),

    /// Error with key operations
    Key(#[from] crate::key::Error),

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
}

// TODO: Remove this
/// Result type for this crate
pub type Result<T> = std::result::Result<T, Error>;

// Errors defined by the DID:BTC1 specification and other related specifications.

pub trait ProblemDetails {
    fn details(&self) -> Option<Value> {
        None
    }
}

#[derive(Error, Debug)]
pub enum Btc1Error {
    // Errors from DID Resolution Spec
    /// An invalid DID was detected during DID Resolution.
    InvalidDid(String),

    /// The DID document was malformed.
    InvalidDidDocument(String),

    // Errors from DID BTC1 Spec
    /// Sidecar data was invalid
    InvalidSidecarData(String),

    /// Update payload was published late
    LatePublishingError(String),
}

impl Btc1Error {
    pub(crate) fn late_publishing(found_hash: Sha256Hash, expected_hash: Sha256Hash) -> Self {
        Self::LatePublishingError(format!(
            "Found hash `{}`, expected `{}`",
            hex::encode(found_hash.0),
            hex::encode(expected_hash.0),
        ))
    }
}

impl ProblemDetails for Btc1Error {
    fn details(&self) -> Option<Value> {
        let prefix = match self {
            Self::InvalidDid(_) | Self::InvalidDidDocument(_) => "https://www.w3.org/ns/did",
            // TODO: Is this the right error namespace?
            // From: https://github.com/dcdpr/did-btc1/issues/71#issuecomment-3179550385
            Self::InvalidSidecarData(_) | Self::LatePublishingError(_) => {
                "https://btc1.dev/context/v1"
            }
        };

        let name = match self {
            Self::InvalidDid(_) => "INVALID_DID",
            Self::InvalidDidDocument(_) => "INVALID_DID_DOCUMENT",
            Self::InvalidSidecarData(_) => "INVALID_SIDECAR_DATA",
            Self::LatePublishingError(_) => "LATE_PUBLISHING_ERROR",
        };

        Some(json!({
            "type": format!("{prefix}#{name}"),
            "title": self.to_string(),
            "detail": match self {
                Self::InvalidDid(detail) => detail,
                Self::InvalidDidDocument(detail) => detail,
                Self::InvalidSidecarData(detail) => detail,
                Self::LatePublishingError(detail) => detail,
            },
        }))
    }
}
