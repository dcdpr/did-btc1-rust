use crate::VerificationMethod;
use crate::error::{Error, Result};
use crate::key::PublicKey;
use crate::proof::Proof;
use crate::verification::VerificationMethodId;
use did_btc1_identifier::{Did, DidComponents, DidVersion, Network};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/TR/did-1.1";
const DID_BTC1_CONTEXT: &str = "https://did-btc1/TBD/context";

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// DID identifier
    id: Did,

    /// Document context
    context: Vec<String>,

    /// Document controller
    controller: Vec<Did>,

    verification_method: Vec<VerificationMethod>,

    authentication: Vec<VerificationMethodId>,
    assertion_method: Vec<VerificationMethodId>,
    capability_invocation: Vec<VerificationMethodId>,
    capability_delegation: Vec<VerificationMethodId>,

    // TODO:
    // - service

    //
    // version: u64,
    //
    /// The document data as a JSON Value
    #[serde(flatten)]
    pub data: Map<String, Value>,
}

// Placeholders
pub struct ResolutionOptions;
pub struct DocumentPatch;

impl From<()> for ResolutionOptions {
    fn from(_: ()) -> Self {
        ResolutionOptions
    }
}

impl Document {
    // Spec section 4.1.1
    /// Create a document from an existing DID.
    pub fn from_did(did: Did) -> Result<Self> {
        todo!()
    }

    // Spec section 4.1.2
    /// Create a document from an initial JSON document that has been prepared externally.
    pub fn from_initial(
        // TODO: Arbitrary JSON is not a great interface, but it's better than pretending that the
        // `Document` type should be representable in an incomplete (and essentially unusable) form.
        // The alternative is taking a separate `InitialDocument` type that can at least pass the
        // JSON sniff test and cannot be confused with a real `Document`.
        //
        // The `from_file()`, `from_json_string()`, and `from_json_value()` constructors would be
        // moved to `InitialDocument`.
        doc: Value,
        version: Option<DidVersion>,
        network: Option<Network>,
    ) -> Result<Self> {
        todo!()
    }

    // Spec section 4.2
    //
    // TODO: Sans-I/O: This needs to not bake any I/O into the implementation. Instead, this should
    // return a finite state machine that represents the protocol described in the spec. This allows
    // the caller to do their own I/O and drive the state machine forward to `Document` resolution.
    pub fn read<O>(did: &Did, options: O) -> Result<Self>
    where
        O: Into<ResolutionOptions>,
    {
        todo!()
    }

    // Spec section 4.3
    //
    // TODO: Sans-I/O.
    //
    // TODO: Do we really want to expose this patching concept to users? How do they create patches?
    //
    // options:
    // a) user provides DocumentPatch
    //
    // b) user provides second document and we compute the diff and patch
    //
    // c) the patch can be constructed incrementally through various mutating methods,
    //     // like `add_service()`, and then committed with `update()`. You would want a way to check
    //     // whether there are staged patches.
    //
    //
    pub fn update(
        &mut self,
        // `btc1Identifier` is implied by `self.did`
        // `sourceDocument` is implied by `self`
        // `sourceVersionId` is implied by `self.version`
        patch: DocumentPatch,
        verification_method_id: usize,
        beacon_ids: &[usize],
    ) -> Result<Self> {
        todo!()
    }

    // Spec section 4.4
    //
    // TODO: Sans-I/O.
    pub fn deactivate(&mut self) -> Result<Self> {
        todo!()
    }
}

fn string_from_json<'value>(value: &'value Value, key: &str) -> Result<&'value str> {
    value[key]
        .as_str()
        .ok_or_else(|| Error::JsonValueStr(key.into()))
}

fn array_from_json<T, F>(value: &Value, key: &str, map_fn: F) -> Result<Vec<T>>
where
    F: Fn(&Value) -> Result<T>,
{
    value[key]
        .as_array()
        .ok_or_else(|| Error::JsonValueStr(key.into()))?
        .iter()
        .map(map_fn)
        .collect::<Result<Vec<_>>>()
}

fn string_from_value(value: &Value) -> Result<&str> {
    value.as_str().ok_or(Error::ExpectedJsonStr)
}

fn vec_from_json_value<T>(value: &Value, key: &str) -> Result<Vec<T>>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    array_from_json(&value, key, |v| Ok(string_from_value(v)?.parse()?))
}

impl Document {
    /// Load a document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create a document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value)
    }

    /// Create a document from a JSON Value
    pub fn from_json_value(value: Value) -> Result<Self> {
        let id: Did = string_from_json(&value, "id")?.parse()?;
        let context = array_from_json(&value, "context", |id| {
            string_from_value(id).map(ToString::to_string)
        })?;
        let controller = vec_from_json_value(&value, "controller")?;
        let verification_method = array_from_json(&value, "verificationMethod", |method| {
            VerificationMethod::new(
                string_from_json(method, "id")?.parse()?,
                string_from_json(method, "controller")?.parse()?,
                PublicKey::from_multikey(string_from_json(method, "publicKeyMultibase")?)?,
            )
        })?;
        let authentication = vec_from_json_value(&value, "authentication")?;
        let assertion_method = vec_from_json_value(&value, "assertionMethod")?;
        let capability_invocation = vec_from_json_value(&value, "capabilityInvocation")?;
        let capability_delegation = vec_from_json_value(&value, "capabilityDelegation")?;

        match value {
            Value::Object(map) => Ok(Self {
                id,
                context,
                controller,
                verification_method,
                authentication,
                assertion_method,
                capability_invocation,
                capability_delegation,
                data: map,
            }),
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
        Self {
            id: self.id.clone(),
            context: self.context.clone(),
            controller: self.controller.clone(),
            verification_method: self.verification_method.clone(),
            authentication: self.authentication.clone(),
            assertion_method: self.assertion_method.clone(),
            capability_invocation: self.capability_invocation.clone(),
            capability_delegation: self.capability_delegation.clone(),
            data,
        }
    }

    /// Create a new document with the given proof added
    pub fn with_proof(&self, proof: &Proof) -> Result<Self> {
        let mut data = self.data.clone();
        let proof_value = serde_json::to_value(proof)?;
        data.insert("proof".to_string(), proof_value);
        Ok(Self {
            id: self.id.clone(),
            context: self.context.clone(),
            controller: self.controller.clone(),
            verification_method: self.verification_method.clone(),
            authentication: self.authentication.clone(),
            assertion_method: self.assertion_method.clone(),
            capability_invocation: self.capability_invocation.clone(),
            capability_delegation: self.capability_delegation.clone(),
            data,
        })
    }
    
    pub fn deterministically_generate_initial_did_document(
        did: &str,
        did_components: &DidComponents,
    ) -> Result<Document> {
        let key_bytes = &did_components.genesis_bytes();
        let verification_method_id = format!("{did}#initialKey");
        let verification_method_ids = json!([verification_method_id]);

        Self::from_json_value(json!({
            "id": did,
            "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
            "verificationMethod": [{
                "id": verification_method_id,
                "type": "MultiKey",
                "controller": did,
                "publicKeyMultibase": PublicKey::from_bytes(key_bytes)?.encode()?,
            }],
            "authentication": verification_method_ids,
            "assertionMethod": verification_method_ids,
            "capabilityInvocation": verification_method_ids,
            "capabilityDelegation": verification_method_ids,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_document_read() {
    //     let did = "did:btc1:k1qgp5h79scv4sfqkzak5g6y89dsy3cq0pd2nussu2cm3zjfhn4ekwrucc4q7t7";
    //     let doc = Document::read(&did.parse().unwrap(), ()).unwrap();
    // }
}
