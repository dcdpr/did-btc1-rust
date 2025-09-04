use crate::beacon::{AddressExt as _, Beacon};
use crate::canonical_hash::CanonicalHash;
use crate::cryptosuite::CryptoSuite;
use crate::error::{Btc1Error, ProblemDetails};
use crate::identifier::{Did, DidComponents, DidVersion, IdType, Network, Sha256Hash};
use crate::key::{PublicKey, PublicKeyExt as _};
use crate::update::{DocumentPatch, Update};
use crate::verification::{VerificationMethod, VerificationMethodId};
use crate::zcap::proof::ProofPurpose;
use crate::zcap::root_capability::dereference_root_capability;
use crate::{blockchain::Traversal, identifier::TryNetworkExt, json_tools, zcap::proof::Proof};
use chrono::{DateTime, Utc};
use esploda::bitcoin::{Address, Txid};
use onlyerror::Error;
use serde_json::{Map, Value, json};
use std::{collections::HashMap, fs, num::NonZeroU64, path::Path, str::FromStr};

const DID_CORE_V1_1_CONTEXT: &str = "https://www.w3.org/TR/did-1.1";
// TODO: Needs to be updated (eventually) to "https://btc1.dev/context/v1"
const DID_BTC1_CONTEXT: &str = "https://did-btc1/TBD/context";

const DID_PLACEHOLDER: &str =
    "did:btc1:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

#[derive(Error, Debug)]
pub enum Error {
    /// Error during document I/O operations
    DocumentIO(#[from] std::io::Error),

    /// Error parsing JSON document
    JsonParse(#[from] serde_json::Error),

    /// Error parsing JSON value
    JsonValue(#[from] json_tools::JsonError),

    /// DID Encoding error
    DidEncoding(#[from] crate::identifier::Error),

    /// DID:BTC1 error
    Btc1Error(#[from] Btc1Error),

    /// This should not happen: Only needed to satisfy `String: FromStr` trait bound
    Infallible(#[from] std::convert::Infallible),

    /// Bitcoin address parse error
    AddressParse(#[from] esploda::bitcoin::address::Error),

    /// Unexpected DID
    #[error("Expected `{0}` but found `{1}`")]
    UnexpectedDid(String, String),
}

impl ProblemDetails for Error {
    fn details(&self) -> Option<Value> {
        match self {
            Self::Btc1Error(err) => err.details(),
            _ => None,
        }
    }
}

/// Fully parsed and validated DID document fields.
///
/// The DID identifier can be either [`Did`] or [`String`]. This specifically allows parsing
/// intermediate DID documents with the "xxx" DID placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DocumentFields<T> {
    /// DID identifier
    pub(crate) id: T,

    /// Document context
    pub(crate) context: Vec<String>,

    /// Document controller
    controller: Vec<T>,

    pub(crate) verification_method: Vec<VerificationMethod<T>>,

    authentication: Vec<VerificationMethodId>,
    assertion_method: Vec<VerificationMethodId>,
    capability_invocation: Vec<VerificationMethodId>,
    capability_delegation: Vec<VerificationMethodId>,

    // TODO: We really want one-or-more, not zero-or-more
    pub(crate) service: Vec<Beacon>,
}

impl<T> TryFrom<(&Value, Option<Network>)> for DocumentFields<T>
where
    T: FromStr + TryNetworkExt,
    VerificationMethodId: FromStr,
    Error: From<<T as FromStr>::Err>,
    json_tools::JsonError: From<<T as FromStr>::Err> + From<<VerificationMethodId as FromStr>::Err>,
{
    type Error = Error;

    fn try_from((value, network): (&Value, Option<Network>)) -> Result<Self, Self::Error> {
        use json_tools::*;

        let id: T = string_from_object(value, "id")?.parse()?;
        let network = id.try_network().or(network).unwrap();

        // TODO: Might want to abstract this null-check for required keys.
        if value["@context"].is_null() {
            return Err(JsonError::JsonMissingKey("@context".into()))?;
        }
        let context = vec_from_object(value, "@context", |id| {
            string_from_value(id).map(ToString::to_string)
        })?;

        // TODO: All of these are optional. Only `vec_from_value` has been fixed
        let controller = vec_from_value(value, "controller")?;
        let verification_method = vec_from_object(value, "verificationMethod", |method| {
            Ok(VerificationMethod::new(
                string_from_object(method, "id")?.parse()?,
                string_from_object(method, "controller")?.parse()?,
                PublicKey::from_multikey(string_from_object(method, "publicKeyMultibase")?)?,
            ))
        })?;
        let authentication = vec_from_value(value, "authentication")?;
        let assertion_method = vec_from_value(value, "assertionMethod")?;
        let capability_invocation = vec_from_value(value, "capabilityInvocation")?;
        let capability_delegation = vec_from_value(value, "capabilityDelegation")?;
        // TODO: This will fail when the DID document contains non-Beacon services
        // https://github.com/dcdpr/did-btc1/issues/170
        let service = vec_from_object(value, "service", |service| {
            let id = string_from_object(service, "id")?.to_string();
            let ty = string_from_object(service, "type")?.parse()?;
            let descriptor =
                Address::from_bip21(string_from_object(service, "serviceEndpoint")?, network)?;

            Ok(Beacon::new(id, ty, descriptor))
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

/// DID document resolution options.
#[derive(Debug, Default)]
pub struct ResolutionOptions {
    /// The Media Type of the caller's preferred representation of the DID document
    pub accept: Option<String>,

    /// Flag which instructs a DID resolver to expand relative DID URLs
    pub expand_relative_urls: bool,

    /// The version of the identifier and/or DID document
    pub version_id: Option<NonZeroU64>,

    /// A timestamp used during resolution as a bound for when to stop resolving
    pub version_time: Option<DateTime<Utc>>,

    /// Data necessary for resolving a DID such as DID Update Payloads and SMT proofs
    pub sidecar_data: Option<SidecarData>,
}

#[derive(Debug, Default)]
pub struct SidecarData {
    pub initial_document: Option<InitialDocument>,

    pub signals_metadata: HashMap<Txid, SignalsMetadata>,

    // TODO: Using the `url` crate is probably better.
    /// Blockchain RPC URI.
    ///
    /// Must be provided as a full URI including schema and domain:
    /// `https://esplora.example/testnet`.
    ///
    /// This can be used to override the hostname used in `Request`s returned by the [`Traversal`]
    /// FSM.
    pub blockchain_rpc_uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SignalsMetadata {
    pub btc1_update: Option<Update>,
    pub proofs: SmtProofs,
}

// Placeholders
#[derive(Clone, Debug)]
pub struct SmtProofs;

/// Represents a JSON or JSON-LD document
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// All structural Document fields
    pub(crate) fields: DocumentFields<Did>,
    /// The document data as a JSON Value
    data: Map<String, Value>,
}

impl Document {
    // Spec section 7.1.1
    pub fn from_did_components(
        did_components: DidComponents,
        resolution_options: ResolutionOptions,
    ) -> Result<(Did, Traversal), Error> {
        let did = Did::from(did_components);
        let traversal = Self::read(&did, resolution_options)?;

        Ok((did, traversal))
    }

    // Spec section 7.2
    //
    // TODO: Sans-I/O: This needs to not bake any I/O into the implementation. Instead, this should
    // return a finite state machine that represents the protocol described in the spec. This allows
    // the caller to do their own I/O and drive the state machine forward to `Document` resolution.
    pub fn read(did: &Did, resolution_options: ResolutionOptions) -> Result<Traversal, Error> {
        let initial_document = InitialDocument::from_did(did, &resolution_options)?;

        Ok(Self::resolve(initial_document, &resolution_options))
    }

    // Spec section 7.3
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

    // Spec section 7.4
    //
    // TODO: Sans-I/O.
    pub fn deactivate(&mut self) -> Result<Self, Error> {
        todo!()
    }

    /// Spec section 7.2.2
    fn resolve(
        initial_document: InitialDocument,
        resolution_options: &ResolutionOptions,
    ) -> Traversal {
        // TODO: We need a way to capture Spec section 7.2.2, step 6
        // This will be resolved by identifying the expected default value for ResolutionOptions::version_id
        Traversal::new(initial_document, resolution_options)
    }
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
        let fields = DocumentFields::try_from((&value, None))?;

        match value {
            Value::Object(map) => Ok(Self { fields, data: map }),
            _ => unreachable!(), // todo: parse don't validate
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

impl From<InitialDocument> for Document {
    fn from(doc: InitialDocument) -> Self {
        Self {
            fields: doc.fields,
            data: match doc.json_data {
                Value::Object(map) => map,
                _ => unreachable!(),
            },
        }
    }
}

/// Representation of initial DID document, according to did::btc1 specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialDocument {
    pub(crate) fields: DocumentFields<Did>,
    json_data: Value,
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
            fields: doc.fields,
            json_data: Value::Object(doc.data),
        })
    }

    // Spec section 7.1.2
    /// Create a document from an external intermediate DID Document that has been prepared
    /// externally.
    pub fn from_external_intermediate(
        doc: IntermediateDocument,
        version: Option<DidVersion>,
        network: Option<Network>,
    ) -> Result<(Did, Self), Error> {
        let hash = doc.hash();

        let id_type = IdType::External(hash);

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

    // Spec section 7.2.1
    /// Create an initial document from an existing DID.
    pub fn from_did(did: &Did, resolution_options: &ResolutionOptions) -> Result<Self, Error> {
        match did.components().id_type() {
            IdType::Key(_) => Self::deterministically_generate(did, resolution_options),
            IdType::External(hash) => Self::resolve_external(hash, resolution_options),
        }
    }

    // Spec section 7.2.1.1
    fn deterministically_generate(
        did: &Did,
        resolution_options: &ResolutionOptions,
    ) -> Result<Self, Error> {
        let verification_method_id = format!("{}#initialKey", did.encode());
        let verification_method_ids = json!([verification_method_id]);
        let beacon = generate_beacons(did, resolution_options)?;

        Self::from_json_value(json!({
            "id": did.encode(),
            "@context": [DID_CORE_V1_1_CONTEXT, DID_BTC1_CONTEXT],
            "controller": [did.encode()],
            "verificationMethod": [{
                "id": verification_method_id,
                "type": "Multikey",
                "controller": did.encode(),
                "publicKeyMultibase": did.public_key_unchecked().to_multikey(),
            }],
            "authentication": verification_method_ids,
            "assertionMethod": verification_method_ids,
            "capabilityInvocation": verification_method_ids,
            "capabilityDelegation": verification_method_ids,
            "service": beacon.into_iter().map(Beacon::into_json).collect::<Vec<_>>(),
        }))
    }

    // Spec section 7.2.1.2
    fn resolve_external(
        hash: Sha256Hash,
        resolution_options: &ResolutionOptions,
    ) -> Result<Self, Error> {
        // Step 1
        let initial_document = resolution_options
            .sidecar_data
            .as_ref()
            .and_then(|data| {
                data.initial_document
                    .as_ref()
                    .map(|doc| doc.sidecar_initial_validation(hash))
            })
            .unwrap_or_else(|| todo!("Sans I/O CAS retrieval"))?;

        // Step 3: Validate conformant DID document according to the DID Core 1.1 specification

        // todo: call some simple validation function that checks for top-level "id" entry

        Ok(initial_document)
    }

    // Spec section 7.2.1.2.1
    fn sidecar_initial_validation(&self, hash: Sha256Hash) -> Result<Self, Error> {
        let intermediate_doc = IntermediateDocument::from_initial(self);

        // Canonicalize the JSON doc to get a hash
        // todo: need to use RDFC canonicalization instead
        let hash_bytes = intermediate_doc.hash();

        if hash_bytes != hash {
            Err(Btc1Error::InvalidDid(
                "TODO: description for sidecar_initial_validation() hash mismatch".to_string(),
            ))?
        } else {
            Ok(self.clone())
        }
    }

    // Spec Section 7.2.2.5
    pub(crate) fn apply_update(&mut self, update: &Update) -> Result<(), Btc1Error> {
        let capability_id = &update.proof.inner.capability;
        let did = dereference_root_capability(capability_id)?;

        if self.fields.id != did {
            return Err(Btc1Error::InvalidDidUpdate(
                "Proof root capability is not for this DID document".into(),
            ));
        }

        // TODO: Replace JCS asap
        let crypto_suite = CryptoSuite::Jcs;

        // Extract public key from the document
        let verification_method = &update.proof.inner.verification_method;
        let public_key = self
            .fields
            .verification_method
            .iter()
            .find_map(|method| (&method.id.0 == verification_method).then_some(method.public_key))
            .ok_or_else(|| {
                Btc1Error::ProofVerification(format!(
                    "verificationMethod `{verification_method}` not found in document "
                ))
            })?;

        let verification_result = crypto_suite.data_integrity_verify_proof(
            public_key,
            update,
            &ProofPurpose::CapabilityInvocation,
        )?;

        if verification_result.is_none() {
            // todo: we are supposedly to return list of warning and error ProblemDetails?
            return Err(Btc1Error::InvalidUpdateProof("Verification failed".into()));
        }

        // YOU ARE HERE
        // step 11... Use json-patch crate to apply the update.patch to self

        todo!()
    }
}

impl AsRef<Value> for InitialDocument {
    fn as_ref(&self) -> &Value {
        &self.json_data
    }
}

impl CanonicalHash for InitialDocument {}

/// Representation of intermediate DID document, according to did::btc1 specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntermediateDocument {
    // TODO: We really want one-or-more, not zero-or-more
    pub(crate) service: Vec<Beacon>,
    json_data: Value,
}

impl AsRef<Value> for IntermediateDocument {
    fn as_ref(&self) -> &Value {
        &self.json_data
    }
}

impl CanonicalHash for IntermediateDocument {}

impl IntermediateDocument {
    /// Load an intermediate document from a file
    pub fn from_file<P: AsRef<Path>>(path: P, network: Network) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        Self::from_json_string(&content, network)
    }

    /// Create an intermediate document from a JSON string
    pub fn from_json_string(json: &str, network: Network) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_json_value(value, network)
    }

    /// Create an intermediate document from a JSON Value
    pub fn from_json_value(value: Value, network: Network) -> Result<Self, Error> {
        // validate structural integrity
        let fields = DocumentFields::<String>::try_from((&value, Some(network)))?;

        Ok(Self {
            service: fields.service,
            json_data: value,
        })
    }

    fn into_initial(self, did: &Did) -> InitialDocument {
        // Find and replace all DID placeholder strings with the DID.
        let mut json_data = self.json_data.clone();
        find_and_replace(&mut json_data, DID_PLACEHOLDER, did.encode());

        InitialDocument::from_json_value(json_data).unwrap()
    }

    pub(crate) fn from_initial(initial_doc: &InitialDocument) -> Self {
        // Find and replace all DIDs with the DID placeholder string.
        let did = &initial_doc.fields.id;
        let mut json_data = initial_doc.json_data.clone();
        find_and_replace(&mut json_data, did.encode(), DID_PLACEHOLDER);

        Self {
            service: initial_doc.fields.service.clone(),
            json_data,
        }
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

// Spec section 7.2.1.1.1
fn generate_beacons(
    did: &Did,
    _resolution_options: &ResolutionOptions,
) -> Result<Vec<Beacon>, Error> {
    use crate::beacon::Type;

    let secp = secp256k1::Secp256k1::verification_only();
    let network = did.components().network().try_into()?;
    // TODO: After the `bitcoin` crate is updated, we can remove this extra public key constructor.
    let public_key = esploda::bitcoin::PublicKey::new(did.public_key_unchecked());

    let p2pkh_id = format!("{}#initialP2PKH", did.encode());
    let p2wpkh_id = format!("{}#initialP2WPKH", did.encode());
    let p2tr_id = format!("{}#initialP2TR", did.encode());

    let p2pkh_beacon = Address::p2pkh(&public_key, network);
    let p2wpkh_beacon = Address::p2wpkh(&public_key, network)?;
    let p2tr_beacon = Address::p2tr(&secp, public_key.inner.into(), None, network);

    // TODO: Allow overriding the default minimum confirmations required in `ResolutionOptions`?
    Ok(vec![
        Beacon::new(p2pkh_id, Type::Singleton, p2pkh_beacon),
        Beacon::new(p2wpkh_id, Type::Singleton, p2wpkh_beacon),
        Beacon::new(p2tr_id, Type::Singleton, p2tr_beacon),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::TraversalState;
    use esploda::esplora::Transaction;

    impl Did {
        fn hash_unchecked(&self) -> Sha256Hash {
            match self.components().id_type() {
                IdType::Key(_) => unreachable!(), // todo: parse don't validate
                IdType::External(hash) => hash,
            }
        }
    }

    impl ResolutionOptions {
        pub(crate) fn from_json_string(json: &str) -> Self {
            let json = serde_json::from_str::<Value>(json).unwrap();

            let signals_metadata = json["sidecarData"]["signalsMetadata"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(txid, metadata)| {
                    (
                        txid.parse().unwrap(),
                        SignalsMetadata {
                            btc1_update: Update::from_json_value(metadata["updatePayload"].clone())
                                .ok(),
                            proofs: SmtProofs,
                        },
                    )
                })
                .collect();

            ResolutionOptions {
                sidecar_data: Some(SidecarData {
                    signals_metadata,
                    ..Default::default()
                }),
                ..Default::default()
            }
        }
    }

    #[test]
    fn test_document_parse() {
        let doc = Document::from_json_string(include_str!(concat!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
            "/initialDidDoc.json",
        ))).unwrap();

        assert_eq!(doc.fields.service.len(), 3);
        assert_eq!(doc.fields.verification_method.len(), 1);
    }

    #[test]
    fn test_sidecar_initial_validation() {
        let initial_doc = InitialDocument::from_json_string(include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/initialDidDoc.json",
        )))
        .unwrap();

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(SidecarData {
                initial_document: Some(initial_doc),
                ..Default::default()
            }),
            ..Default::default()
        };

        let did: Did = "did:btc1:x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf"
            .parse()
            .unwrap();
        let hash = did.hash_unchecked();
        let initial_doc = InitialDocument::resolve_external(hash, &resolution_options).unwrap();
        assert_eq!(initial_doc.fields.id, did);
    }

    #[test]
    fn test_document_validation_missing_elements() {
        let path = "./fixtures/initialDidDoc-missing-verificationMethod-id.json";
        assert!(matches!(
            InitialDocument::from_file(path),
            Err(Error::JsonValue(json_tools::JsonError::JsonMissingKey(key))) if key == "id"
        ));
    }

    #[test]
    #[ignore = "blockchain traversal is incomplete"]
    fn test_document_from_did_components() {
        let id_type = IdType::from(
            PublicKey::from_slice(
                &hex::decode("03da2c07d2443fbf228aa773e5f685562158d39ee675b586b3ebdb897e7f1e56f5")
                    .unwrap(),
            )
            .unwrap(),
        );
        let did_components = DidComponents::new(DidVersion::One, Network::Signet, id_type).unwrap();

        let resolution_options = ResolutionOptions::from_json_string(include_str!(concat!(
            "../test-suite/signet/k1qypa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dagl0mgs4",
            "/resolutionOptions.json",
        )));

        let (did, fsm) = Document::from_did_components(did_components, resolution_options).unwrap();
        let TraversalState::Requests(next_state, requests) = fsm.traverse().unwrap() else {
            unreachable!()
        };

        let request_urls = requests
            .into_iter()
            .map(|req| req.uri().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            request_urls,
            [
                "https://blockstream.info/testnet/api/address/mtA1SshFsJtD2Di1KBSTmyuD23eBqUekQ3/txs",
                "https://blockstream.info/testnet/api/address/tb1q323c0l0fapjeg4ux9ayumnpqh8xzqgk3wg82dy/txs",
                "https://blockstream.info/testnet/api/address/tb1pecc8w64wdvn6x2np8yr8qvsz2pclydkd9t5jde2gf0hy0musfxxsn23q20/txs",
            ],
        );

        let json = include_str!(
            "../fixtures/k1qypa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dagl0mgs4-transactions.json"
        );
        let transactions: Vec<Transaction> = serde_json::from_str(json).unwrap();
        let fsm = next_state.process_responses(transactions);

        let TraversalState::Resolved(document) = fsm.traverse().unwrap() else {
            unreachable!()
        };
        assert_eq!(document.fields.id.encode(), did.encode());
    }

    #[test]
    fn test_from_external_intermediate() {
        let intermediate_doc = IntermediateDocument::from_json_string(
            include_str!(concat!(
                "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
                "/intermediateDidDoc.json",
            )),
            Network::Regtest,
        )
        .unwrap();
        let (did, initial_doc) = InitialDocument::from_external_intermediate(
            intermediate_doc,
            None,
            Some(Network::Regtest),
        )
        .unwrap();

        let expected_did = include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/did.txt",
        ));
        assert_eq!(did.encode(), expected_did.trim());

        let expected_doc = InitialDocument::from_json_string(include_str!(concat!(
            "../test-suite/regtest/x1qgcs38429dp7kyr5y90g3l94r6ky85pnppy9aggzgas2kdcldelrk3yfjrf",
            "/initialDidDoc.json",
        )))
        .unwrap();
        assert_eq!(initial_doc, expected_doc);
    }
}
