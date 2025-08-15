use crate::error::{Btc1Error, ProblemDetails};
use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network};
use crate::verification::{VerificationMethod, VerificationMethodId};
use crate::{key::PublicKey, proof::Proof, service::Service, verification};
use onlyerror::Error;
use serde::de::Error as SerdeError;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, str::FromStr};

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/TR/did-1.1";
const DID_BTC1_CONTEXT: &str = "https://did-btc1/TBD/context";

const DID_PLACEHOLDER: &str =
    "did:btc1:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

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

    /// Verification Error
    Verification(#[from] verification::Error),

    /// Document service endpoints error
    #[error("Document service endpoints error")]
    Service(#[from] crate::service::Error),

    /// DID:BTC1 error
    Btc1Error(#[from] crate::error::Btc1Error),
}

impl ProblemDetails for Error {
    fn details(&self) -> Option<Value> {
        match self {
            Self::Btc1Error(err) => err.details(),
            _ => None,
        }
    }
}

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone)]
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
    data: Map<String, Value>,
}

#[derive(Debug, Default)]
pub struct ResolutionOptions {
    /// The Media Type of the caller's preferred representation of the DID document
    accept: Option<String>,

    /// Flag which instructs a DID resolver to expand relative DID URLs
    expand_relative_urls: bool,

    /// The version of the identifier and/or DID document
    version_id: Option<String>,

    /// A timestamp used during resolution as a bound for when to stop resolving
    version_time: Option<String>, // TODO: Use chrono? UTCDateTime

    /// Data necessary for resolving a DID such as DID Update Payloads and SMT proofs
    sidecar_data: Option<SidecarData>,

    /// The bitcoin network used for resolution
    network: Option<Network>,
}

#[derive(Debug, Default)]
pub struct SidecarData {
    initial_document: Option<InitialDocument>,
}

// Placeholders
pub struct DocumentPatch;

impl Document {
    // Spec section 4.1.1
    pub fn from_did_components(did_components: DidComponents) -> Result<(Did, Self), Error> {
        todo!()
    }

    // Spec section 4.1.2
    /// Create a document from an initial JSON document that has been prepared externally.
    pub fn from_initial(
        _doc: InitialDocument,
        _version: Option<DidVersion>,
        _network: Option<Network>,
    ) -> Result<(Did, Self), Error> {
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
            // TODO: Use a new error variant?
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
}

#[derive(Clone, Debug)]
pub struct InitialDocument {
    json_data: Value,
}

impl InitialDocument {
    // Spec section 4.2.1
    /// Create an initial document from an existing DID.
    pub fn from_did(did: &Did, resolution_options: &ResolutionOptions) -> Result<Self, Error> {
        match did.components().id_type() {
            IdType::Key(_) => Ok(Self::deterministically_generate(did)),
            IdType::External(_) => Self::resolve_external(did, resolution_options),
        }
    }

    // Spec section 4.2.1.1
    fn deterministically_generate(did: &Did) -> Self {
        let verification_method_id = format!("{}#initialKey", did.encode());
        let verification_method_ids = json!([verification_method_id]);

        Self {
            json_data: json!({
                "id": did.encode(),
                "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
                "verificationMethod": [{
                    "id": verification_method_id,
                    "type": "MultiKey",
                    "controller": did.encode(),
                    "publicKeyMultibase": did.public_key_unchecked().encode(),
                }],
                "authentication": verification_method_ids,
                "assertionMethod": verification_method_ids,
                "capabilityInvocation": verification_method_ids,
                "capabilityDelegation": verification_method_ids,
                "service": generate_beacon_services(did),
            }),
        }
    }

    // Spec section 4.2.1.2
    fn resolve_external(did: &Did, resolution_options: &ResolutionOptions) -> Result<Self, Error> {
        // Step 1
        let initial_document = resolution_options
            .sidecar_data
            .as_ref()
            .and_then(|data| {
                data.initial_document
                    .as_ref()
                    .map(|doc| doc.sidecar_initial_validation(did))
            })
            .unwrap_or_else(|| todo!("Sans I/O CAS retrieval"))?;

        // Step 3: Validate conformant DID document according to the DID Core 1.1 specification

        // todo: call some simple validation function that checks for top-level "id" entry

        Ok(initial_document)
    }

    // Spec section 4.2.1.2.1
    fn sidecar_initial_validation(&self, did: &Did) -> Result<Self, Error> {
        fn find_and_replace(value: &mut Value, encoded: &str) {
            match value {
                Value::String(s) => {
                    *s = s.replace(encoded, DID_PLACEHOLDER);
                }
                Value::Array(array) => {
                    for item in array {
                        find_and_replace(item, encoded);
                    }
                }
                Value::Object(obj) => {
                    for (_, value) in obj {
                        find_and_replace(value, encoded);
                    }
                }
                _ => (),
            }
        }

        // Find and replace all DIDs with the DID placeholder string.
        let mut intermediate_doc = self.clone().json_data;
        find_and_replace(&mut intermediate_doc, did.encode());

        // Canonicalize the JSON doc to get a hash
        // todo: need to use RDFC canonicalization instead
        let jcs = serde_jcs::to_string(&intermediate_doc).expect("JSON is always valid JCS");
        let hash_bytes = Sha256::digest(jcs.as_bytes());

        let IdType::External(hash) = did.components().id_type() else {
            unreachable!();
        };

        if hash[..] != hash_bytes[..] {
            return Err(Btc1Error::InvalidDid(
                "TODO: description for sidecar_initial_validation() hash mismatch".to_string(),
            ))?;
        }

        Ok(self.clone())
    }
}

// Spec section 4.2.1.1.1
fn generate_beacon_services(did: &Did) -> Value {
    let p2pkh_beacon = "TODO: Create P2PKH address from wallet";
    let p2wpkh_beacon = "TODO: Create P2WPKH address from wallet";
    let p2tr_beacon = "TODO: Create P2TR address from wallet";

    json!([
        {
            "id": format!("{}#initialP2PKH", did.encode()),
            "type": "SingletonBeacon",
            "serviceEndpoint": p2pkh_beacon,
        },
        {
            "id": format!("{}#initialP2WPKH", did.encode()),
            "type": "SingletonBeacon",
            "serviceEndpoint": p2wpkh_beacon,
        },
        {
            "id": format!("{}#initialP2TR", did.encode()),
            "type": "SingletonBeacon",
            "serviceEndpoint": p2tr_beacon,
        },
    ])
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

    #[test]
    fn test_sidecar_initial_validation() {
        let json = fs::read_to_string(
            "../did-btc1/TestVectors/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf/initialDidDoc.json",
        ).unwrap();
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(SidecarData {
                initial_document: Some(InitialDocument {
                    json_data: json.parse().unwrap(),
                }),
            }),
            ..Default::default()
        };

        let did = "did:btc1:x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf"
            .parse()
            .unwrap();
        let initial_doc = InitialDocument::resolve_external(&did, &resolution_options).unwrap();
    }
}
