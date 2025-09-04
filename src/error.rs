use crate::identifier::Sha256Hash;
use onlyerror::Error;
use serde_json::{Value, json};

// TODO: Remove this
#[derive(Error, Debug)]
pub enum Error {
    /// ZCAP (Authorization Capabilities) related errors
    #[error("ZCAP error: {0}")]
    Zcap(String),
}

// Errors defined by the DID:BTC1 specification and other related specifications.
pub trait ProblemDetails {
    fn details(&self) -> Option<Value> {
        None
    }
}

#[derive(Error, Debug)]
pub enum Btc1Error {
    // Errors from DID Resolution Spec
    //
    /// An invalid DID was detected during DID Resolution.
    InvalidDid(String),

    /// The DID document was malformed.
    InvalidDidDocument(String),

    // Errors from DID BTC1 Spec
    //
    /// Sidecar data was invalid
    InvalidSidecarData(String),

    /// Update payload was published late
    LatePublishingError(String),

    /// Invalid Update Proof
    InvalidUpdateProof(String),

    /// ZCAP (Authorization Capabilities) related errors
    Zcap(String),

    /// Problems when creating or applying a DID Update
    InvalidDidUpdate(String),

    // Errors from Verifiable Credentials Data Integrity Spec
    //
    /// Proof verification error
    ProofVerification(String),

    /// Proof transformation error
    ProofTransformation(String),

    /// Proof generation error
    ProofGeneration(String),
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
            Self::InvalidSidecarData(_)
            | Self::LatePublishingError(_)
            | Self::InvalidUpdateProof(_)
            | Self::Zcap(_)
            | Self::InvalidDidUpdate(_)
            | Self::ProofVerification(_)
            | Self::ProofTransformation(_)
            | Self::ProofGeneration(_) => "https://btc1.dev/context/v1",
        };

        let name = match self {
            Self::InvalidDid(_) => "INVALID_DID",
            Self::InvalidDidDocument(_) => "INVALID_DID_DOCUMENT",
            Self::InvalidSidecarData(_) => "INVALID_SIDECAR_DATA",
            Self::LatePublishingError(_) => "LATE_PUBLISHING_ERROR",
            Self::InvalidUpdateProof(_) => "INVALID_UPDATE_PROOF",
            Self::Zcap(_) => "ZCAP",
            Self::InvalidDidUpdate(_) => "INVALID_DID_UPDATE",
            Self::ProofVerification(_) => "PROOF_VERIFICATION_ERROR",
            Self::ProofTransformation(_) => "PROOF_TRANSFORMATION_ERROR",
            Self::ProofGeneration(_) => "PROOF_GENERATION_ERROR",
        };

        Some(json!({
            "type": format!("{prefix}#{name}"),
            "title": self.to_string(),
            "detail": match self {
                Self::InvalidDid(detail) => detail,
                Self::InvalidDidDocument(detail) => detail,
                Self::InvalidSidecarData(detail) => detail,
                Self::LatePublishingError(detail) => detail,
                Self::InvalidUpdateProof(detail) => detail,
                Self::Zcap(detail) => detail,
                Self::InvalidDidUpdate(detail) => detail,
                Self::ProofVerification(detail) => detail,
                Self::ProofTransformation(detail) => detail,
                Self::ProofGeneration(detail) => detail,
            },
        }))
    }
}
