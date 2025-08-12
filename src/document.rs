use crate::identifier::{Did, DidComponents, DidVersion, Network};
use crate::service::Service;
use crate::verification::{VerificationMethod, VerificationMethodId};
use crate::{key::PublicKey, proof::Proof, verification};
use onlyerror::Error;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{fs, path::Path, str::FromStr};

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/TR/did-1.1";
const DID_BTC1_CONTEXT: &str = "https://did-btc1/TBD/context";

#[derive(Error, Debug)]
pub enum Error {
    /// Error during document I/O operations
    #[error("Document I/O error")]
    DocumentIO(#[from] std::io::Error),

    /// Error parsing JSON document
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::Error),

    /// Error converting JSON Value to str
    #[error("Value can't be converted to str for key `{0}`")]
    JsonValueStr(String),

    /// Expected JSON string
    #[error("Expected JSON string")]
    ExpectedJsonStr,

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// DID Encoding error
    DidEncoding(#[from] crate::identifier::Error),
    // /// Error with multibase encoding/decoding
    // #[error("Multibase error: {0}")]
    // Multibase(String),
    /// Verification Error
    Verification(#[from] verification::Error),

    /// Document service endpoints error
    #[error("Document service endpoints error")]
    Service(#[from] crate::service::Error),
}

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

    service: Vec<Service>,

    /// The document data as a JSON Value
    #[serde(flatten)]
    data: Map<String, Value>,
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
    pub fn from_did(_did: Did) -> Result<Self, Error> {
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
        _doc: Value,
        _version: Option<DidVersion>,
        _network: Option<Network>,
    ) -> Result<Self, Error> {
        todo!()
    }

    // Spec section 4.2
    //
    // TODO: Sans-I/O: This needs to not bake any I/O into the implementation. Instead, this should
    // return a finite state machine that represents the protocol described in the spec. This allows
    // the caller to do their own I/O and drive the state machine forward to `Document` resolution.
    pub fn read<O>(_did: &Did, _options: O) -> Result<Self, Error>
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
        _patch: DocumentPatch,
        _verification_method_id: usize,
        _beacon_ids: &[usize],
    ) -> Result<Self, Error> {
        todo!()
    }

    // Spec section 4.4
    //
    // TODO: Sans-I/O.
    pub fn deactivate(&mut self) -> Result<Self, Error> {
        todo!()
    }
}

fn string_from_json<'value>(value: &'value Value, key: &str) -> Result<&'value str, Error> {
    value[key]
        .as_str()
        .ok_or_else(|| Error::JsonValueStr(key.into()))
}

fn array_from_json<T, F>(value: &Value, key: &str, map_fn: F) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<T, Error>,
{
    value[key]
        .as_array()
        .ok_or_else(|| Error::JsonValueStr(key.into()))?
        .iter()
        .map(map_fn)
        .collect::<Result<Vec<_>, Error>>()
}

fn bikeshed_my_name(value: &Value, key: &str) -> Result<Vec<String>, Error> {
    let strings = array_from_json(value, key, |s| string_from_value(s).map(String::from))
        .or_else(|_| Ok::<_, Error>(vec![string_from_json(value, key)?.to_string()]))?;

    Ok(strings)
}

fn string_from_value(value: &Value) -> Result<&str, Error> {
    value.as_str().ok_or(Error::ExpectedJsonStr)
}

fn vec_from_json_value<T>(value: &Value, key: &str) -> Result<Vec<T>, Error>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    array_from_json(value, key, |v| Ok(string_from_value(v)?.parse()?))
}

impl Document {
    /// Load a document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create a document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value)
    }

    /// Create a document from a JSON Value
    pub fn from_json_value(value: Value) -> Result<Self, Error> {
        let id: Did = string_from_json(&value, "id")?.parse()?;
        let context = array_from_json(&value, "@context", |id| {
            string_from_value(id).map(ToString::to_string)
        })?;
        let controller = vec_from_json_value(&value, "controller")?;
        let verification_method = array_from_json(&value, "verificationMethod", |method| {
            Ok(VerificationMethod::new(
                string_from_json(method, "id")?.parse()?,
                string_from_json(method, "controller")?.parse()?,
                PublicKey::from_multikey(string_from_json(method, "publicKeyMultibase")?)?,
            ))
        })?;
        let authentication = vec_from_json_value(&value, "authentication")?;
        let assertion_method = vec_from_json_value(&value, "assertionMethod")?;
        let capability_invocation = vec_from_json_value(&value, "capabilityInvocation")?;
        let capability_delegation = vec_from_json_value(&value, "capabilityDelegation")?;
        let service = array_from_json(&value, "service", |service| {
            Ok(Service::new(
                Some(string_from_json(service, "id")?.to_string()),
                bikeshed_my_name(service, "type")?,
                bikeshed_my_name(service, "serviceEndpoint")?,
            )?)
        })?;

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
                service,
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
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let json = self.to_json_string()?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Convert the document to a JSON string
    pub fn to_json_string(&self) -> Result<String, Error> {
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
        let mut doc = self.clone();
        doc.data.remove("proof");

        doc
    }

    /// Create a new document with the given proof added
    pub fn with_proof(&self, proof: &Proof) -> Result<Self, Error> {
        let mut doc = self.clone();
        let proof_value = serde_json::to_value(proof)?;
        doc.data.insert("proof".to_string(), proof_value);

        Ok(doc)
    }

    // TODO: This could be used for Spec section 4.1
    #[allow(dead_code)]
    fn deterministically_generate_initial_did_document(
        did: &str,
        did_components: &DidComponents,
    ) -> Result<Document, Error> {
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

    #[test]
    fn test_document_parse() {
        // TODO: Parse the target document instead?
        let doc = Document::from_file(
            "../did-btc1/TestVectors/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp/initialDidDoc.json",
        ).unwrap();

        assert_eq!(doc.service.len(), 3);
        assert_eq!(doc.verification_method.len(), 1);
    }
}
