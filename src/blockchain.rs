use crate::document::{ContemporaryDocument, InitialDocument, ResolutionOptions, SignalsMetadata};
use crate::identifier::{Did, Sha256Hash};
use bitcoin::Txid;
use chrono::{DateTime, Utc};
use esploda::esplora::Transaction;
use esploda::http::{Request, Response};
use onlyerror::Error;
use std::collections::HashMap;

#[derive(Error, Debug)]
pub enum Error {
    /// Spec section 4.2.2.4
    UpdateNotDuplicate,
}

/// State machine for Bitcoin blockchain traversal.
#[derive(Debug)]
pub struct Traversal {
    did: Did,
    contemporary_doc: ContemporaryDocument,
    contemporary_block_height: u32,
    current_version_id: u64,
    target_condition: TargetCondition,
    // TODO: We don't need to keep all of the documents.
    // did_document_history: Vec<ContemporaryDocument>,
    update_hash_history: Vec<Sha256Hash>,
    // TODO: Use Txid instead of String
    signals_metadata: HashMap<String, SignalsMetadata>,

    fsm: TraversalFsm,
}

impl Traversal {
    pub(crate) fn new(
        initial_doc: InitialDocument,
        resolution_options: &ResolutionOptions,
    ) -> Self {
        Self {
            did: initial_doc.did.clone(),
            contemporary_doc: initial_doc.into(),
            contemporary_block_height: 0,
            current_version_id: 1,
            target_condition: TargetCondition::from(resolution_options),
            // did_document_history: vec![],
            update_hash_history: vec![],
            signals_metadata: resolution_options
                .sidecar_data
                .as_ref()
                .map(|sidecar_data| sidecar_data.signals_metadata.clone())
                .unwrap_or_default(),
            fsm: TraversalFsm::Init,
        }
    }

    // Spec section 4.2.2.1
    // TODO: Better name for this?
    pub fn traverse(&mut self) -> Result<TraversalFsm, Error> {
        // Step 1.
        let contemporary_hash = self.contemporary_doc.compute_hash(&self.did);

        // Step 2, 3: unnecessary

        // Step 4.
        Ok(TraversalFsm::Request(self.next_signals_requests()))
    }

    // Spec section 4.2.2.1
    pub fn process_responses(&mut self, responses: Vec<Transaction>) {
        // Step 4. (assign `nextSignals)
        todo!()
    }

    // Spec section 4.2.2.2
    fn find_next_signals(&self) -> Vec<NextSignal> {
        self.contemporary_doc
            .beacon
            .iter()
            .enumerate()
            .map(|(i, b)| NextSignal {
                beacon_id: i,
                beacon_type: b.ty,
                tx: todo!(),
                block_height: 0,
                block_time: Default::default(),
            })
            .collect()
    }

    fn next_signals_requests(&self) -> Vec<Request<()>> {
        let base_url = "https://blockstream.info/testnet/api".to_string();

        self.contemporary_doc
            .beacon
            .iter()
            .map(|b| {
                Request::builder()
                    .uri(format!("{}/address/{}/txs", base_url, b.descriptor))
                    .body(())
                    .unwrap()
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub enum TraversalFsm {
    Init,
    Request(Vec<Request<()>>),
    Resolved(ContemporaryDocument),
}

impl TraversalFsm {
    fn traverse(self, traversal: &Traversal) -> Result<Self, Error> {
        match self {
            Self::Init => Ok(Self::Request(traversal.next_signals_requests())),

            // TODO: There is a break condition between request/response...
            Self::Request(_) => Ok(todo!()),

            Self::Resolved(doc) => Ok(Self::Resolved(doc)),
        }
    }
}

struct NextSignal {
    beacon_id: usize,
    beacon_type: crate::beacon::Type,
    tx: Txid,
    block_height: u32,
    block_time: DateTime<Utc>,
}

#[derive(Debug)]
enum TargetCondition {
    VersionId(u64),
    Time(DateTime<Utc>),
}

impl From<&ResolutionOptions> for TargetCondition {
    fn from(resolution_options: &ResolutionOptions) -> Self {
        if let Some(version) = resolution_options.version_id {
            Self::VersionId(version)
        } else {
            Self::Time(resolution_options.version_time.unwrap_or_else(Utc::now))
        }
    }
}
