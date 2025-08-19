use crate::error::{Btc1Error, ProblemDetails};
use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network, SHA256_HASH_LEN};
use crate::key::PublicKeyExt as _;
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

    /// Missing element
    #[error("Element `{0}` does not exist")]
    JsonMissingElement(String),

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

    /// This should not happen
    Infallible(#[from] std::convert::Infallible),
}

impl ProblemDetails for Error {
    fn details(&self) -> Option<Value> {
        match self {
            Self::Btc1Error(err) => err.details(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DocumentFields<T> {
    /// DID identifier
    id: T,

    /// Document context
    context: Vec<String>,

    /// Document controller
    controller: Vec<T>,

    verification_method: Vec<VerificationMethod<T>>,

    authentication: Vec<VerificationMethodId>,
    assertion_method: Vec<VerificationMethodId>,
    capability_invocation: Vec<VerificationMethodId>,
    capability_delegation: Vec<VerificationMethodId>,

    service: Vec<Service>,
}

impl<T> TryFrom<&Value> for DocumentFields<T>
where
    T: FromStr,
    VerificationMethodId: FromStr,
    Error: From<<T as FromStr>::Err> + From<<VerificationMethodId as FromStr>::Err>,
{
    type Error = Error;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let id = string_from_json(value, "id")?.parse()?;

        // TODO: Might want to abstract this null-check for required keys.
        if value["@context"].is_null() {
            return Err(Error::JsonMissingElement("@context".into()));
        }
        let context = array_from_json(value, "@context", |id| {
            string_from_value(id).map(ToString::to_string)
        })?;

        // TODO: All of these are optional. Only `vec_from_json_value` has been fixed
        let controller = vec_from_json_value(value, "controller")?;
        let verification_method = array_from_json(value, "verificationMethod", |method| {
            Ok(VerificationMethod::new(
                string_from_json(method, "id")?.parse()?,
                string_from_json(method, "controller")?.parse()?,
                PublicKey::from_multikey(string_from_json(method, "publicKeyMultibase")?)?,
            ))
        })?;
        let authentication = vec_from_json_value(value, "authentication")?;
        let assertion_method = vec_from_json_value(value, "assertionMethod")?;
        let capability_invocation = vec_from_json_value(value, "capabilityInvocation")?;
        let capability_delegation = vec_from_json_value(value, "capabilityDelegation")?;
        let service = array_from_json(value, "service", |service| {
            Ok(Service::new(
                Some(string_from_json(service, "id")?.to_string()),
                bikeshed_my_name(service, "type")?,
                bikeshed_my_name(service, "serviceEndpoint")?,
            )?)
        })?;

        Ok(DocumentFields {
            id,
            context,
            controller,
            verification_method,
            authentication,
            assertion_method,
            capability_invocation,
            capability_delegation,
            service,
        })
    }
}

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// All structural Document fields
    fields: DocumentFields<Did>,
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
    version_id: Option<u64>,

    /// A timestamp used during resolution as a bound for when to stop resolving
    version_time: Option<u64>, // TODO: Use chrono? UTCDateTime

    /// Data necessary for resolving a DID such as DID Update Payloads and SMT proofs
    sidecar_data: Option<SidecarData>,

    /// The bitcoin network used for resolution
    network: Option<Network>,
}

#[derive(Debug)]
struct BlockchainTraversal {
    did: Did,
    contemporary_doc: ContemporaryDocument,
    contemporary_block_height: u32, // ?
    current_version_id: u64,
    target_condition: TargetCondition, // TODO: This may need both (what is the default for version_id???)
    did_document_history: Vec<ContemporaryDocument>,
    update_hash_history: Vec<[u8; SHA256_HASH_LEN]>, // TODO: We need a type alias or something for hashes
    signals_metadata: Option<SignalsMetadata>,
}

impl BlockchainTraversal {
    fn new(initial_doc: InitialDocument, resolution_options: &ResolutionOptions) -> Self {
        Self {
            did: initial_doc.did.clone(),
            contemporary_doc: initial_doc.into(),
            contemporary_block_height: 0,
            current_version_id: 1,
            target_condition: TargetCondition::from(resolution_options),
            did_document_history: vec![],
            update_hash_history: vec![],
            signals_metadata: resolution_options
                .sidecar_data
                .as_ref()
                .and_then(|sidecar_data| sidecar_data.signals_metadata.clone()),
        }
    }

    // Spec section 4.2.2.1
    fn traverse(&mut self) {
        todo!();
    }
}

#[derive(Debug)]
enum TargetCondition {
    VersionId(u64),
    Time(u64), // TODO: chrono or another DateTime type
}

impl From<&ResolutionOptions> for TargetCondition {
    fn from(resolution_options: &ResolutionOptions) -> Self {
        if let Some(version) = resolution_options.version_id {
            Self::VersionId(version)
        } else {
            Self::Time(
                resolution_options
                    .version_time
                    .unwrap_or_else(|| todo!("need chrono::now()")),
            )
        }
    }
}

#[derive(Debug, Default)]
pub struct SidecarData {
    initial_document: Option<InitialDocument>,
    signals_metadata: Option<SignalsMetadata>,
}

#[derive(Clone, Debug)]
struct SignalsMetadata {}

// Placeholders
pub struct DocumentPatch;

impl Document {
    // Spec section 4.1.1
    pub fn from_did_components(did_components: DidComponents) -> Result<(Did, Self), Error> {
        let did = Did::from(did_components);
        let initial_document = Self::read(&did, ResolutionOptions::default())?;
        Ok((did, initial_document))
    }

    // Spec section 4.2
    //
    // TODO: Sans-I/O: This needs to not bake any I/O into the implementation. Instead, this should
    // return a finite state machine that represents the protocol described in the spec. This allows
    // the caller to do their own I/O and drive the state machine forward to `Document` resolution.
    pub fn read<O>(did: &Did, resolution_options: O) -> Result<Self, Error>
    where
        O: Into<ResolutionOptions>,
    {
        let resolution_options = resolution_options.into();
        let initial_document = InitialDocument::from_did(&did, &resolution_options)?;
        Self::resolve(initial_document, &resolution_options)
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

    /// Spec section 4.2.2
    fn resolve(
        initial_document: InitialDocument,
        resolution_options: &ResolutionOptions,
    ) -> Result<Self, Error> {
        //YOUAREHERE
        // TODO: We need a way to capture Spec section 4.2.2, step 6
        // The will be resolved by identifying the expected default value for ResolutionOptions::version_id
        let blockchain_traversal = BlockchainTraversal::new(initial_document, resolution_options);

        todo!()
    }
}

fn string_from_json<'value>(value: &'value Value, key: &str) -> Result<&'value str, Error> {
    let obj = &value[key];

    if obj.is_null() {
        Err(Error::JsonMissingElement(key.into()))
    } else {
        obj.as_str().ok_or_else(|| Error::JsonValueStr(key.into()))
    }
}

fn array_from_json<T, F>(value: &Value, key: &str, map_fn: F) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<T, Error>,
{
    let obj = &value[key];

    if obj.is_null() {
        Ok(Vec::new())
    } else {
        obj.as_array()
            .ok_or_else(|| Error::JsonValueStr(key.into()))?
            .iter()
            .map(map_fn)
            .collect::<Result<Vec<_>, Error>>()
    }
}

// TODO: LOL let's pick a real name for this
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
        let fields = DocumentFields::try_from(&value)?;

        match value {
            Value::Object(map) => Ok(Self { fields, data: map }),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialDocument {
    did: Did,
    json_data: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContemporaryDocument {
    did: Did,
    json_data: Value,
}

impl From<InitialDocument> for ContemporaryDocument {
    fn from(initial_document: InitialDocument) -> Self {
        Self {
            did: initial_document.did,
            json_data: initial_document.json_data,
        }
    }
}

impl InitialDocument {
    /// Load an initial document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create an initial document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value)
    }

    /// Create an initial document from a JSON Value
    pub fn from_json_value(value: Value) -> Result<Self, Error> {
        let doc = Document::from_json_value(value)?;

        Ok(Self {
            did: doc.fields.id,
            json_data: Value::Object(doc.data),
        })
    }

    // Spec section 4.1.2
    /// Create a document from an external intermediate DID Document that has been prepared
    /// externally.
    pub fn from_external_intermediate(
        doc: IntermediateDocument,
        version: Option<DidVersion>,
        network: Option<Network>,
    ) -> Result<(Did, Self), Error> {
        let genesis_bytes = doc.compute_hash();

        let id_type = IdType::External(genesis_bytes);

        let did = DidComponents::new(
            version.unwrap_or_default(),
            network.unwrap_or_default(),
            id_type,
        )?
        .into();

        let initial_document = doc.into_initial(&did);

        // Step 9 is unimplemented (this is the caller's responsibility)
        // Optionally store canonicalBytes on a Content Addressable Storage (CAS) system like the InterPlanetary File System (IPFS).

        Ok((did, initial_document))
    }

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
            did: did.clone(),
            json_data: json!({
                "id": did.encode(),
                "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
                "verificationMethod": [{
                    "id": verification_method_id,
                    "type": "MultiKey",
                    "controller": did.encode(),
                    "publicKeyMultibase": did.public_key_unchecked().to_multikey(),
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
        let intermediate_doc = IntermediateDocument::from_initial(did, self);

        // Canonicalize the JSON doc to get a hash
        // todo: need to use RDFC canonicalization instead

        let hash_bytes = intermediate_doc.compute_hash();

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntermediateDocument {
    json_data: Value,
}

impl IntermediateDocument {
    /// Load an intermediate document from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content)
    }

    /// Create an intermediate document from a JSON string
    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value)
    }

    /// Create an intermediate document from a JSON Value
    pub fn from_json_value(value: Value) -> Result<Self, Error> {
        // validate structural integrity
        DocumentFields::<String>::try_from(&value)?;

        Ok(Self { json_data: value })
    }

    fn into_initial(self, did: &Did) -> InitialDocument {
        // Find and replace all DID placeholder strings with the DID.
        let mut json_data = self.json_data.clone();
        find_and_replace(&mut json_data, DID_PLACEHOLDER, did.encode());

        InitialDocument {
            did: did.clone(),
            json_data,
        }
    }

    fn from_initial(did: &Did, initial_doc: &InitialDocument) -> Self {
        // Find and replace all DIDs with the DID placeholder string.
        let mut json_data = initial_doc.json_data.clone();
        find_and_replace(&mut json_data, did.encode(), DID_PLACEHOLDER);

        Self { json_data }
    }

    fn compute_hash(&self) -> [u8; SHA256_HASH_LEN] {
        let jcs = serde_jcs::to_string(&self.json_data).expect("JSON is always valid JCS");
        let hash_bytes = Sha256::digest(jcs.as_bytes());

        hash_bytes[..].try_into().unwrap()
    }
}

fn find_and_replace(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(s) => {
            *s = s.replace(from, to);
        }
        Value::Array(array) => {
            for item in array {
                find_and_replace(item, from, to);
            }
        }
        Value::Object(obj) => {
            for (_, value) in obj {
                find_and_replace(value, from, to);
            }
        }
        _ => (),
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
    use std::path::PathBuf;

    #[test]
    fn test_document_parse() {
        let root = PathBuf::from(
            "../did-btc1/TestVectors/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
        );

        // TODO: Parse the target document instead?
        let doc = Document::from_file(root.join("initialDidDoc.json")).unwrap();

        assert_eq!(doc.fields.service.len(), 3);
        assert_eq!(doc.fields.verification_method.len(), 1);
    }

    #[test]
    fn test_sidecar_initial_validation() {
        let path = "./fixtures/initialDidDoc.json";
        let resolution_options = ResolutionOptions {
            sidecar_data: Some(SidecarData {
                initial_document: Some(InitialDocument::from_file(path).unwrap()),
                signals_metadata: None,
            }),
            ..Default::default()
        };

        let did = "did:btc1:x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf"
            .parse()
            .unwrap();
        let initial_doc = InitialDocument::resolve_external(&did, &resolution_options).unwrap();
    }

    #[test]
    fn test_document_validation_missing_elements() {
        let path = "./fixtures/initialDidDoc-missing-verificationMethod-id.json";
        assert!(matches!(
            InitialDocument::from_file(path),
            Err(Error::JsonMissingElement(key)) if key == "id"
        ));
    }

    #[test]
    #[ignore]
    fn test_document_from_did_components() {
        let id_type = IdType::from(
            PublicKey::from_slice(
                &hex::decode("03da2c07d2443fbf228aa773e5f685562158d39ee675b586b3ebdb897e7f1e56f5")
                    .unwrap(),
            )
            .unwrap(),
        );
        let did_components =
            DidComponents::new(DidVersion::One, Network::Regtest, id_type).unwrap();

        let (did, document) = Document::from_did_components(did_components).unwrap();
        assert!(document.fields.controller.contains(&did));
    }

    #[test]
    fn test_from_external_intermediate() {
        let root = PathBuf::from(
            "../did-btc1/TestVectors/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
        );
        let intermediate_doc =
            IntermediateDocument::from_file(root.join("intermediateDidDoc.json")).unwrap();
        let (did, initial_doc) = InitialDocument::from_external_intermediate(
            intermediate_doc,
            None,
            Some(Network::Regtest),
        )
        .unwrap();

        let expected_did = fs::read_to_string(root.join("did.txt")).unwrap();
        assert_eq!(did.encode(), expected_did.trim());

        let expected_doc = InitialDocument::from_file(root.join("initialDidDoc.json")).unwrap();
        assert_eq!(initial_doc, expected_doc);
    }
}
