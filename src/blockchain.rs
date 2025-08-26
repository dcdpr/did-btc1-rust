use crate::document::{InitialDocument, IntermediateDocument, ResolutionOptions, SignalsMetadata};
use crate::{document::Document, identifier::Sha256Hash};
use chrono::{DateTime, Utc};
use esploda::esplora::{Status, Transaction};
use esploda::{Req, bitcoin::Txid};
use onlyerror::Error;
use std::collections::HashMap;

const DEFAULT_RPC_BASE_URL: &str = "https://blockstream.info/testnet/api";

#[derive(Error, Debug)]
pub enum Error {
    /// FSM is waiting for RPC responses.
    ///
    /// This happens when the caller forgot to call [`Traversal::process_responses`].
    WaitingForResponses,

    /// Spec section 4.2.2.4
    UpdateNotDuplicate,
}

/// State machine for Bitcoin blockchain traversal.
#[derive(Debug)]
pub struct Traversal<T = ()> {
    contemporary_doc: InitialDocument,
    contemporary_block_height: u32,
    current_version_id: u64,
    target_condition: TargetCondition,
    update_hash_history: Vec<Sha256Hash>,
    // TODO: Use Txid instead of String
    signals_metadata: HashMap<String, SignalsMetadata>,
    rpc_host: String,

    // Finite State Machine
    fsm: TraversalFsm,
    _type_state: T,
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
            _type_state: (),
        }
    }

    fn from_waiting_for_responses(traversal: Traversal<WaitingForResponses>) -> Self {
        Self {
            contemporary_doc: traversal.contemporary_doc,
            contemporary_block_height: traversal.contemporary_block_height,
            current_version_id: traversal.current_version_id,
            target_condition: traversal.target_condition,
            update_hash_history: traversal.update_hash_history,
            signals_metadata: traversal.signals_metadata,
            rpc_host: traversal.rpc_host,
            fsm: traversal.fsm,
            _type_state: (),
        }
    }

    // Spec section 4.2.2.1
    // TODO: Better name for this?
    pub fn traverse(mut self) -> Result<TraversalState, Error> {
        // Take the FSM state, leaving the default in its place.
        let mut fsm = TraversalFsm::Init;
        std::mem::swap(&mut self.fsm, &mut fsm);

        match fsm {
            TraversalFsm::Init => {
                // Step 1.
                let contemporary_hash =
                    IntermediateDocument::from_initial(&self.contemporary_doc).compute_hash();

                // Step 2, 3: unnecessary

                // Step 4. (Create RPC requests)
                self.fsm = TraversalFsm::Requests;

                Ok(self.next_signals_requests())
            }

            TraversalFsm::FindNextSignals(responses) => {
                // Step 4. (Assignment)
                let next_signals = self.find_next_signals(responses);

                // Step 5.
                if next_signals.is_empty() {
                    return Ok(TraversalState::Resolved(self.contemporary_doc.into()));
                }

                // Step 6.
                if let TargetCondition::Time(time) = &self.target_condition
                    && &next_signals[0].block_time > time
                {
                    return Ok(TraversalState::Resolved(self.contemporary_doc.into()));
                }

                // Step 7.
                self.contemporary_block_height = next_signals[0].block_height;

                // Step 8.
                todo!()
            }

            TraversalFsm::Requests => Err(Error::WaitingForResponses),
        }
    }

    // Spec section 4.2.2.2
    fn find_next_signals(&self, transactions: Vec<Transaction>) -> Vec<NextSignal> {
        self.contemporary_doc
            .fields
            .beacon
            .iter()
            .zip(transactions)
            .enumerate()
            .map(|(i, (b, tx))| {
                let (block_height, block_time) = match tx.status {
                    Status::Unconfirmed => todo!("Unconfirmed transactions are not supported yet"),
                    Status::Confirmed {
                        block_height,
                        block_time,
                        ..
                    } => (block_height, block_time),
                };

                NextSignal {
                    beacon_id: i,
                    beacon_type: b.ty,
                    tx: tx.txid,
                    block_height,
                    block_time,
                }
            })
            .collect()
    }

    fn next_signals_requests(self) -> TraversalState {
        let requests = self
            .contemporary_doc
            .fields
            .beacon
            .iter()
            .map(|b| {
                // TODO: Move this to Esploda
                Req::builder()
                    .uri(format!("{}/address/{}/txs", self.rpc_host, b.descriptor))
                    .body(())
                    .unwrap()
            })
            .collect();

        TraversalState::Requests(Traversal::from_init(self), requests)
    }
}

impl Traversal<WaitingForResponses> {
    fn from_init(traversal: Traversal) -> Self {
        Self {
            contemporary_doc: traversal.contemporary_doc,
            contemporary_block_height: traversal.contemporary_block_height,
            current_version_id: traversal.current_version_id,
            target_condition: traversal.target_condition,
            update_hash_history: traversal.update_hash_history,
            signals_metadata: traversal.signals_metadata,
            rpc_host: traversal.rpc_host,
            fsm: traversal.fsm,
            _type_state: WaitingForResponses,
        }
    }

    pub fn process_responses(mut self, transactions: Vec<Transaction>) -> Traversal<()> {
        self.fsm = TraversalFsm::FindNextSignals(transactions);

        Traversal::from_waiting_for_responses(self)
    }
}

/// Marker type for FSM.
#[derive(Debug)]
pub struct WaitingForResponses;

#[derive(Debug)]
enum TraversalFsm {
    /// FSM just initialized.
    Init,

    /// FSM is waiting for requests to be processed.
    Requests,

    /// FSM is ready to find the next beacon signals.
    FindNextSignals(Vec<Transaction>),
}

#[derive(Debug)]
pub enum TraversalState {
    /// Requests need to be sent to the blockchain.
    Requests(Traversal<WaitingForResponses>, Vec<Req>),

    /// Document is fully resolved.
    Resolved(Document),
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
