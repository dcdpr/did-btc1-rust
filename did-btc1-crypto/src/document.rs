use crate::error::{Error, Result};
use crate::key::{KeyFormat, PublicKey};
use crate::proof::Proof;
use did_btc1_encoding::DidComponents;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::fs;
use std::path::Path;

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/TR/did-1.1";
const DID_BTC1_CONTEXT: &str = "https://did-btc1/TBD/context";

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// The document data as a JSON Value
    #[serde(flatten)]
    pub data: Map<String, Value>,
}

impl Document {
    /// Create a new empty document
    pub fn new() -> Self {
        Self { data: Map::new() }
    }

    /// Load a document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create a document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(json)?;
        match value {
            Value::Object(map) => Ok(Self { data: map }),
            _ => Err(Error::JsonParse(serde_json::Error::custom(
                "Document root must be a JSON object",
            ))),
        }
    }

    /// Create a document from a JSON Value
    pub fn from_json_value(value: Value) -> Result<Self> {
        match value {
            Value::Object(map) => Ok(Self { data: map }),
            _ => Err(Error::JsonParse(serde_json::Error::custom(
                "Document root must be a JSON object",
            ))),
        }
    }

    /// Get the document data (for accessing raw JSON fields)
    pub fn get_data(&self) -> &Map<String, Value> {
        &self.data
    }

    /// Save the document to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.to_json_string()?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Convert the document to a JSON string
    pub fn to_json_string(&self) -> Result<String> {
        let value = Value::Object(self.data.clone());
        let json = serde_json::to_string_pretty(&value)?;
        Ok(json)
    }

    /// Get the proof from the document if it exists
    pub fn get_proof(&self) -> Option<Proof> {
        self.data
            .get("proof")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    }

    /// Create a new document with the proof removed
    pub fn without_proof(&self) -> Self {
        let mut data = self.data.clone();
        data.remove("proof");
        Self { data }
    }

    /// Create a new document with the given proof added
    pub fn with_proof(&self, proof: &Proof) -> Result<Self> {
        let mut data = self.data.clone();
        let proof_value = serde_json::to_value(proof)?;
        data.insert("proof".to_string(), proof_value);
        Ok(Self { data })
    }

    /// Get a context array if present
    pub fn get_context(&self) -> Option<Vec<Value>> {
        self.data.get("@context").and_then(|ctx| match ctx {
            Value::Array(arr) => Some(arr.clone()),
            Value::String(s) => Some(vec![Value::String(s.clone())]),
            _ => None,
        })
    }

    pub fn deterministically_generate_initial_did_document(
        did: &str,
        did_components: &DidComponents,
    ) -> Result<Document> {
        let key_bytes = &did_components.genesis_bytes;
        let verification_method_id = format!("{did}#initialKey");
        let verification_method_ids = json!([verification_method_id]);

        Self::from_json_value(json!({
            "id": did,
            "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
            "verificationMethod": [{
                "id": verification_method_id,
                "type": "MultiKey",
                "controller": did,
                "publicKeyMultibase": PublicKey::from_bytes(key_bytes)?.encode(KeyFormat::Multikey)?,
            }],
            "authentication": verification_method_ids,
            "assertionMethod": verification_method_ids,
            "capabilityInvocation": verification_method_ids,
            "capabilityDelegation": verification_method_ids,
        }))
    }
}
impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}
