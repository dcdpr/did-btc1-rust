use crate::beacon::BeaconType;
use crate::canonical_hash::CanonicalHash as _;
use crate::document::{Document, InitialDocument, ResolutionOptions, SignalsMetadata};
use crate::update::UnsecuredUpdate;
use crate::{error::Btc1Error, identifier::Sha256Hash, update::Update};
use chrono::{DateTime, Utc};
use esploda::bitcoin::{Txid, opcodes::all::OP_RETURN, script::Instruction};
use esploda::esplora::{Status, Transaction};
use onlyerror::Error;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;

const DEFAULT_RPC_BASE_URL: &str = "https://blockstream.info/testnet/api";

#[derive(Error, Debug)]
pub enum Error {
    /// FSM is waiting for RPC responses.
    ///
    /// This happens when the caller forgot to call [`Traversal::process_responses`].
    WaitingForResponses,

    /// Sidecar data not found
    SidecarDataNotFound,

    /// Update hash does not match
    UpdateHashMismatch,

    /// Late Publishing Error
    LatePublishingError,

    /// DID:BTC1 error
    Btc1Error(#[from] crate::error::Btc1Error),
}

/// State machine for Bitcoin blockchain traversal.
#[derive(Debug)]
pub struct Traversal<T = ()> {
    contemporary_doc: InitialDocument,
    current_version_id: NonZeroU64,
    target_condition: TargetCondition,
    update_hash_history: Vec<Sha256Hash>,
    signals_metadata: HashMap<Txid, SignalsMetadata>,
    rpc_host: String,
    request_cache: HashSet<esploda::http::Uri>,

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
            current_version_id: 1.try_into().unwrap(),
            target_condition: TargetCondition::from(resolution_options),
            update_hash_history: vec![],
            signals_metadata: sidecar_data
                .map(|data| data.signals_metadata.clone())
                .unwrap_or_default(),
            rpc_host: sidecar_data
                .and_then(|data| data.blockchain_rpc_uri.as_deref())
                .unwrap_or(DEFAULT_RPC_BASE_URL)
                .to_string(),
            request_cache: HashSet::new(),
            fsm: TraversalFsm::Init,
            _type_state: (),
        }
    }

    fn from_waiting_for_responses(traversal: Traversal<WaitingForResponses>) -> Self {
        Self {
            contemporary_doc: traversal.contemporary_doc,
            current_version_id: traversal.current_version_id,
            target_condition: traversal.target_condition,
            update_hash_history: traversal.update_hash_history,
            signals_metadata: traversal.signals_metadata,
            rpc_host: traversal.rpc_host,
            request_cache: traversal.request_cache,
            fsm: traversal.fsm,
            _type_state: (),
        }
    }

    // Spec section 7.2.2.1
    // TODO: Better name for this?
    pub fn traverse(mut self) -> Result<TraversalState, Error> {
        // Take the FSM state, leaving the default in its place.
        let mut fsm = TraversalFsm::Init;
        std::mem::swap(&mut self.fsm, &mut fsm);

        match fsm {
            TraversalFsm::Init => {
                // Step 1 is deferred to step 10.
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

                // Step 7: unnecessary

                // Step 8.
                let mut updates = self.process_beacon_signals(next_signals)?;

                // Step 9.
                updates
                    .as_mut_slice()
                    .sort_unstable_by_key(|update| update.target_version_id);

                // Step 10.
                let mut contemporary_hash = self.contemporary_doc.hash();

                for update in updates {
                    // Step 10.1.
                    if update.target_version_id <= self.current_version_id {
                        self.update_hash_history.push(contemporary_hash);

                        update.confirm_duplicate(&self.update_hash_history)?;
                    }

                    // Step 10.2.
                    let next_update_version_id = self.current_version_id.checked_add(1).unwrap();
                    if update.target_version_id == next_update_version_id {
                        // Step 10.2.1.
                        if update.source_hash != contemporary_hash {
                            return Err(Btc1Error::late_publishing(
                                update.source_hash,
                                contemporary_hash,
                            ))?;
                        }

                        // Step 10.2.2 - 10.2.3.
                        self.contemporary_doc.apply_update(&update)?;

                        // Step 10.2.4.
                        self.current_version_id = next_update_version_id;

                        // Step 13.
                        // Yes, we need to do 13 here: there is a bug in the spec.
                        if let TargetCondition::VersionId(version_id) = self.target_condition
                            && version_id == self.current_version_id
                        {
                            return Ok(TraversalState::Resolved(self.contemporary_doc.into()));
                        }

                        // Step 10.2.5 - 10.2.6.
                        let unsecured_update = UnsecuredUpdate::from(&update);

                        // Step 10.2.7 - 10.2.8.
                        self.update_hash_history.push(unsecured_update.hash());

                        // Step 10.2.9.
                        contemporary_hash = self.contemporary_doc.hash();
                    }

                    // Step 10.3.
                    if update.target_version_id > self.current_version_id.checked_add(1).unwrap() {
                        return Err(Error::LatePublishingError);
                    }
                }

                // Step 11: unnecessary

                // Step 12.
                let TraversalState::Requests(fsm, signals) = self.next_signals_requests() else {
                    unreachable!()
                };
                if signals.is_empty() {
                    Ok(TraversalState::Resolved(fsm.contemporary_doc.into()))
                } else {
                    Ok(TraversalState::Requests(fsm, signals))
                }
            }

            TraversalFsm::Requests => Err(Error::WaitingForResponses),
        }
    }

    // Spec section 7.2.2.2
    fn find_next_signals(
        &self,
        mut transactions: HashMap<BeaconType, Vec<Transaction>>,
    ) -> Vec<NextSignal> {
        // todo: we need to deal with other two BeaconTypes
        let entry = transactions.entry(BeaconType::Singleton).or_default();
        entry
            .into_iter()
            .filter_map(|tx| {
                let txout = tx.outputs.last().unwrap();
                let ops = txout
                    .script_pubkey
                    .instructions()
                    .flatten()
                    .collect::<Vec<_>>();

                // Extract the signal bytes
                let [Instruction::Op(OP_RETURN), Instruction::PushBytes(bytes)] = ops[..] else {
                    return None;
                };
                let signal_bytes = Sha256Hash(bytes.as_bytes().try_into().ok()?);

                let block_time = match tx.status {
                    Status::Unconfirmed => todo!("Unconfirmed transactions are not supported yet"),
                    Status::Confirmed { block_time, .. } => block_time,
                };

                Some(NextSignal {
                    beacon_type: BeaconType::Singleton,
                    txid: tx.txid,
                    signal_bytes,
                    block_time,
                })
            })
            .collect()
    }

    fn next_signals_requests(mut self) -> TraversalState {
        let mut map: HashMap<_, Vec<_>> = HashMap::new();

        for beacon in &self.contemporary_doc.fields.service {
            // TODO: Move this to Esploda
            let req = esploda::Req::builder()
                .uri(format!(
                    "{}/address/{}/txs",
                    self.rpc_host, beacon.descriptor
                ))
                .body(())
                .unwrap();

            if !self.request_cache.contains(req.uri()) {
                self.request_cache.insert(req.uri().clone());
                map.entry(beacon.ty).or_default().push(req);
            }
        }

        TraversalState::Requests(Traversal::from_init(self), map)
    }

    // Spec section 7.2.2.3
    fn process_beacon_signals(
        &self,
        beacon_signals: Vec<NextSignal>,
    ) -> Result<Vec<Update>, Error> {
        beacon_signals
            .into_iter()
            .map(|beacon_signal| {
                let signal_metadata = self
                    .signals_metadata
                    .get(&beacon_signal.txid)
                    .ok_or(Error::SidecarDataNotFound)?;

                let update = match beacon_signal.beacon_type {
                    BeaconType::Singleton => Self::process_singleton_beacon_signal(
                        beacon_signal.signal_bytes,
                        signal_metadata,
                    )?,
                    BeaconType::Map => todo!(),
                    BeaconType::SparseMerkleTree => todo!(),
                };

                Ok(update)
            })
            .collect()
    }

    fn process_singleton_beacon_signal(
        expected_hash: Sha256Hash,
        signal_metadata: &SignalsMetadata,
    ) -> Result<Update, Error> {
        if let Some(update) = &signal_metadata.btc1_update {
            if update.hash() != expected_hash {
                return Err(Error::UpdateHashMismatch);
            }
            Ok(update.clone())
        } else {
            Err(Error::SidecarDataNotFound)
        }
    }
}

impl Traversal<WaitingForResponses> {
    fn from_init(traversal: Traversal) -> Self {
        Self {
            contemporary_doc: traversal.contemporary_doc,
            current_version_id: traversal.current_version_id,
            target_condition: traversal.target_condition,
            update_hash_history: traversal.update_hash_history,
            signals_metadata: traversal.signals_metadata,
            rpc_host: traversal.rpc_host,
            request_cache: traversal.request_cache,
            fsm: traversal.fsm,
            _type_state: WaitingForResponses,
        }
    }

    pub fn process_responses(
        mut self,
        transactions: HashMap<BeaconType, Vec<Transaction>>,
    ) -> Traversal {
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
    FindNextSignals(HashMap<BeaconType, Vec<Transaction>>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TraversalState {
    /// Requests need to be sent to the blockchain.
    Requests(
        Traversal<WaitingForResponses>,
        HashMap<BeaconType, Vec<esploda::Req>>,
    ),

    /// Document is fully resolved.
    Resolved(Document),
}

#[derive(Debug)]
struct NextSignal {
    beacon_type: BeaconType,
    txid: Txid,
    signal_bytes: Sha256Hash,
    block_time: DateTime<Utc>,
}

#[derive(Debug)]
enum TargetCondition {
    VersionId(NonZeroU64),

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traversal() {
        let initial_document =
            InitialDocument::from_json_string(include_str!(concat!(
                "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
                "/initialDidDoc.json",
            ))).unwrap();

        let resolution_options = ResolutionOptions::from_json_string(include_str!(concat!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
            "/resolutionOptions.json",
        )));

        let fsm = Traversal::new(initial_document, &resolution_options);
        let TraversalState::Requests(next_state, requests) = fsm.traverse().unwrap() else {
            unreachable!()
        };

        let request_urls = requests[&BeaconType::Singleton]
            .iter()
            .map(|req| req.uri().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            request_urls,
            [
                "https://blockstream.info/testnet/api/address/mtA1SshFsJtD2Di1KBSTmyuD23eBqUekQ3/txs",
                "https://blockstream.info/testnet/api/address/tb1q323c0l0fapjeg4ux9ayumnpqh8xzqgk3wg82dy/txs",
                "https://blockstream.info/testnet/api/address/tb1pecc8w64wdvn6x2np8yr8qvsz2pclydkd9t5jde2gf0hy0musfxxsn23q20/txs",
            ]
        );

        let json = include_str!(
            "../fixtures/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp-transactions.json"
        );
        let transactions: HashMap<_, _> = serde_json::from_str(json).unwrap();
        let fsm = next_state.process_responses(transactions.clone());

        let TraversalState::Requests(next_state, requests) = fsm.traverse().unwrap() else {
            unreachable!()
        };

        let request_urls = requests[&BeaconType::Singleton]
            .iter()
            .map(|req| req.uri().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            request_urls,
            [
                "https://blockstream.info/testnet/api/address/tb1qcs60r4j6ema8x4gf07hgt83x45e650dr97q3qv/txs",
            ]
        );

        let fsm = next_state.process_responses(transactions);

        let TraversalState::Resolved(document) = fsm.traverse().unwrap() else {
            unreachable!()
        };

        assert_eq!(
            document.fields.id.encode(),
            "did:btc1:k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
        );

        let target_doc = Document::from_json_string(include_str!(concat!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
            "/targetDocument.json",
        )))
        .unwrap();
        assert_eq!(document.hash(), target_doc.hash());
    }
}
