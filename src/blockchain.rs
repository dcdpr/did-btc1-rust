use crate::document::{InitialDocument, IntermediateDocument, ResolutionOptions, SignalsMetadata};
use crate::{document::Document, identifier::Sha256Hash};
use bitcoin::Txid;
use chrono::{DateTime, Utc};
use esploda::{Req, esplora::Transaction};
use onlyerror::Error;
use std::collections::HashMap;

const DEFAULT_RPC_BASE_URL: &str = "https://blockstream.info/testnet/api";

#[derive(Error, Debug)]
pub enum Error {
    /// Spec section 4.2.2.4
    UpdateNotDuplicate,
}

/// State machine for Bitcoin blockchain traversal.
#[derive(Debug)]
pub struct Traversal {
    contemporary_doc: InitialDocument,
    contemporary_block_height: u32,
    current_version_id: u64,
    target_condition: TargetCondition,
    update_hash_history: Vec<Sha256Hash>,
    // TODO: Use Txid instead of String
    signals_metadata: HashMap<String, SignalsMetadata>,
    rpc_host: String,
    fsm: TraversalFsm,
}

impl Traversal {
    pub(crate) fn new(
        initial_doc: InitialDocument,
        resolution_options: &ResolutionOptions,
    ) -> Self {
        let sidecar_data = resolution_options.sidecar_data.as_ref();

        Self {
            contemporary_doc: initial_doc,
            contemporary_block_height: 0,
            current_version_id: 1,
            target_condition: TargetCondition::from(resolution_options),
            update_hash_history: vec![],
            signals_metadata: sidecar_data
                .map(|data| data.signals_metadata.clone())
                .unwrap_or_default(),
            rpc_host: sidecar_data
                .and_then(|data| data.blockchain_rpc_uri.as_deref())
                .unwrap_or(DEFAULT_RPC_BASE_URL)
                .to_string(),
            fsm: TraversalFsm::Init,
        }
    }

    // Spec section 4.2.2.1
    // TODO: Better name for this?
    pub fn traverse(&mut self) -> Result<TraversalState, Error> {
        match &self.fsm {
            TraversalFsm::Init => {
                // Step 1.
                let contemporary_hash =
                    IntermediateDocument::from_initial(&self.contemporary_doc).compute_hash();

                // Step 2, 3: unnecessary

                // Step 4.
                self.fsm = TraversalFsm::Requests;

                Ok(self.next_signals_requests())
            }

            TraversalFsm::Requests => {
                todo!();
            }
        }
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

    fn next_signals_requests(&self) -> TraversalState {
        TraversalState::Requests(
            self.contemporary_doc
                .beacon
                .iter()
                .map(|b| {
                    Req::builder()
                        .uri(format!("{}/address/{}/txs", self.rpc_host, b.descriptor))
                        .body(())
                        .unwrap()
                })
                .collect(),
        )
    }
}

#[derive(Copy, Clone, Debug)]
enum TraversalFsm {
    /// FSM just initialized.
    Init,

    /// FSM is waiting for requests to be processed.
    Requests,
}

#[derive(Clone, Debug)]
pub enum TraversalState {
    /// Requests need to be sent to the blockchain.
    Requests(Vec<Req>),

    /// Document is fully resolved.
    Resolved(Box<Document>),
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
