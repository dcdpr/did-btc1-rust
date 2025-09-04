use crate::{error::Btc1Error, update::UnsecuredUpdate};

// TODO: Make this an enum
/// Trait for document transformation algorithms
pub(crate) trait Transformation {
    /// Transform a document for cryptographic operations
    fn transform(&self, unsecured_update: &UnsecuredUpdate) -> Result<String, Btc1Error>;
}

/// JSON Canonicalization Scheme (JCS) transformation
pub(crate) struct JcsTransformation;

impl JcsTransformation {
    /// Create a new JCS transformation
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Transformation for JcsTransformation {
    fn transform(&self, unsecured_update: &UnsecuredUpdate) -> Result<String, Btc1Error> {
        // Apply JCS canonicalization
        // Note: Using serde_jcs for JSON Canonicalization Scheme
        let canonical = serde_jcs::to_string(unsecured_update.as_ref()).map_err(|e| {
            Btc1Error::ProofVerification(format!("JCS canonicalization failed: {e:?}"))
        })?;

        Ok(canonical)
    }
}

/// RDF Dataset Canonicalization (RDFC) transformation
pub(crate) struct RdfcTransformation;

impl RdfcTransformation {
    /// Create a new RDFC transformation
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Transformation for RdfcTransformation {
    fn transform(&self, _unsecured_update: &UnsecuredUpdate) -> Result<String, Btc1Error> {
        // TODO: Implement RDF Dataset Canonicalization
        // Should convert document to RDF and apply the RDF Dataset Canonicalization Algorithm

        Err(Btc1Error::ProofTransformation(
            "RDF Dataset Canonicalization not yet implemented".to_string(),
        ))
    }
}
