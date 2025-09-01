// TODO: This module needs a lot of work!
#![allow(dead_code)]

use crate::cryptosuite::Error;
use crate::document::Document;
use crate::zcap::proof::ProofOptions;
use serde_json::Value;

// TODO: Make this an enum
/// Trait for document transformation algorithms
pub(crate) trait Transformation {
    /// Transform a document for cryptographic operations
    fn transform(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>, Error>;
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
    fn transform(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>, Error> {
        // Validate options
        let options_value = options.to_value();

        if let Some(Value::String(type_)) = options_value.get("type") {
            if type_ != "DataIntegrityProof" {
                return Err(Error::ProofTransformation(format!(
                    "Unsupported proof type: {type_}"
                )));
            }
        } else {
            return Err(Error::ProofTransformation(
                "Proof options must include 'type'".to_string(),
            ));
        }

        if let Some(Value::String(suite)) = options_value.get("cryptosuite") {
            if suite != "bip340-jcs-2025" {
                return Err(Error::ProofTransformation(format!(
                    "Unsupported cryptosuite: {suite}"
                )));
            }
        } else {
            return Err(Error::ProofTransformation(
                "Proof options must include 'cryptosuite'".to_string(),
            ));
        }

        // Convert document to JSON
        let json_value = Value::Object(document.get_data().clone());

        // Apply JCS canonicalization
        // Note: Using serde_jcs for JSON Canonicalization Scheme
        let canonical = serde_jcs::to_vec(&json_value)
            .map_err(|e| Error::Canonicalization(format!("JCS canonicalization failed: {e:?}")))?;

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
    fn transform(&self, _document: &Document, options: &ProofOptions) -> Result<Vec<u8>, Error> {
        // Validate options
        let options_value = options.to_value();

        if let Some(Value::String(type_)) = options_value.get("type") {
            if type_ != "DataIntegrityProof" {
                return Err(Error::ProofTransformation(format!(
                    "Unsupported proof type: {type_}"
                )));
            }
        } else {
            return Err(Error::ProofTransformation(
                "Proof options must include 'type'".to_string(),
            ));
        }

        if let Some(Value::String(suite)) = options_value.get("cryptosuite") {
            if suite != "bip340-rdfc-2025" {
                return Err(Error::ProofTransformation(format!(
                    "Unsupported cryptosuite: {suite}"
                )));
            }
        } else {
            return Err(Error::ProofTransformation(
                "Proof options must include 'cryptosuite'".to_string(),
            ));
        }

        // TODO: Implement RDF Dataset Canonicalization
        // Should convert document to RDF and apply the RDF Dataset Canonicalization Algorithm

        Err(Error::Canonicalization(
            "RDF Dataset Canonicalization not yet implemented".to_string(),
        ))
    }
}
