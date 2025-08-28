use crate::beacon::Type as BeaconType;
use crate::canonical_hash::CanonicalHash as _;
use crate::document::{InitialDocument, IntermediateDocument, ResolutionOptions, SignalsMetadata};
use crate::identifier::Sha256Hash;
use crate::{document::Document, update::Update};
use chrono::{DateTime, Utc};
use esploda::bitcoin::{opcodes::all::OP_RETURN, script::Instruction};
use esploda::esplora::{Status, Transaction};
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

    /// Sidecar data not found
    SidecarDataNotFound,

    /// Update hash does not match
    UpdateHashMismatch,
}

/// State machine for Bitcoin blockchain traversal.
#[derive(Debug)]
pub struct Traversal<T = ()> {
    contemporary_doc: InitialDocument,
    contemporary_block_height: u32,
    current_version_id: u64,
    target_condition: TargetCondition,
    update_hash_history: Vec<Sha256Hash>,
    signals_metadata: HashMap<Sha256Hash, SignalsMetadata>,
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

    // Spec section 5.2.2.1
    // TODO: Better name for this?
    pub fn traverse(mut self) -> Result<TraversalState, Error> {
        // Take the FSM state, leaving the default in its place.
        let mut fsm = TraversalFsm::Init;
        std::mem::swap(&mut self.fsm, &mut fsm);

        match fsm {
            TraversalFsm::Init => {
                // Step 1.
                let contemporary_hash =
                    IntermediateDocument::from_initial(&self.contemporary_doc).hash();

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
                let updates = self.process_beacon_signals(next_signals)?;

                todo!()
            }

            TraversalFsm::Requests => Err(Error::WaitingForResponses),
        }
    }

    // Spec section 5.2.2.2
    fn find_next_signals(&self, transactions: Vec<Transaction>) -> Vec<NextSignal> {
        self.contemporary_doc
            .fields
            .beacon
            .iter()
            .zip(transactions)
            .enumerate()
            .filter_map(|(i, (b, tx))| {
                let txout = tx.outputs.last().unwrap();
                let mut ops = txout.script_pubkey.instructions();

                // First instruction must be `OP_RETURN`
                match ops.next() {
                    Some(Ok(Instruction::Op(OP_RETURN))) => (),
                    _ => return None,
                }

                // Second instruction must be `OP_PUSHBYTES_32`
                let hash = match ops.next() {
                    Some(Ok(Instruction::PushBytes(bytes))) if bytes.len() == 32 => {
                        Sha256Hash(bytes.as_bytes().try_into().unwrap())
                    }
                    _ => return None,
                };

                // Last iteration must be None
                match ops.next() {
                    None => (),
                    _ => return None,
                }

                let (block_height, block_time) = match tx.status {
                    Status::Unconfirmed => todo!("Unconfirmed transactions are not supported yet"),
                    Status::Confirmed {
                        block_height,
                        block_time,
                        ..
                    } => (block_height, block_time),
                };

                Some(NextSignal {
                    beacon_id: i,
                    beacon_type: b.ty,
                    hash,
                    block_height,
                    block_time,
                })
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
                esploda::Req::builder()
                    .uri(format!("{}/address/{}/txs", self.rpc_host, b.descriptor))
                    .body(())
                    .unwrap()
            })
            .collect();

        TraversalState::Requests(Traversal::from_init(self), requests)
    }

    // Spec section 7.2.2.3
    fn process_beacon_signals(
        &self,
        beacon_signals: Vec<NextSignal>,
    ) -> Result<Vec<Update>, Error> {
        for beacon_signal in beacon_signals {
            let expected_hash = beacon_signal.hash;
            let signal_metadata = self
                .signals_metadata
                .get(&expected_hash)
                .ok_or(Error::SidecarDataNotFound)?;

            let update = match beacon_signal.beacon_type {
                BeaconType::Singleton => {
                    Self::process_singleton_beacon_signal(expected_hash, signal_metadata)?
                }
                BeaconType::Map => todo!(),
                BeaconType::SparseMerkleTree => todo!(),
            };

            // YOU ARE HERE!
        }

        todo!()
    }

    fn process_singleton_beacon_signal(
        expected_hash: Sha256Hash,
        signal_metadata: &SignalsMetadata,
    ) -> Result<&Update, Error> {
        if let Some(update) = &signal_metadata.btc1_update {
            let hash = update.hash();

            if hash != expected_hash {
                return Err(Error::UpdateHashMismatch);
            }

            Ok(update)
        } else {
            Err(Error::SidecarDataNotFound)
        }
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

    pub fn process_responses(mut self, transactions: Vec<Transaction>) -> Traversal {
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
    Requests(Traversal<WaitingForResponses>, Vec<esploda::Req>),

    /// Document is fully resolved.
    Resolved(Document),
}

struct NextSignal {
    beacon_id: usize,
    beacon_type: crate::beacon::Type,
    hash: Sha256Hash,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{SidecarData, SmtProofs};
    use serde_json::Value;
    use std::{fs, path::PathBuf};

    #[test]
    #[ignore]
    fn test_traversal() {
        let path = "./fixtures/exampleTargetDocument.json";
        let initial_document = InitialDocument::from_file(path).unwrap();

        let updates_file_path = PathBuf::from(
            "./test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
        );

        // TODO: Seriously, fix this horrible setup code. Make some nice test fixtures
        let hash1 = include_str!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp/block2207945/update_hash_hex.txt"
        );
        let update1 = serde_json::from_str::<Value>(
            &fs::read_to_string(updates_file_path.join("block2207945").join("updates.json"))
                .unwrap(),
        )
        .unwrap()[0]
            .clone();

        let hash2 = include_str!(
            "../test-suite/mutinynet/k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp/block2219084/update_hash_hex.txt"
        );
        let update2 = serde_json::from_str::<Value>(
            &fs::read_to_string(updates_file_path.join("block2219084").join("updates.json"))
                .unwrap(),
        )
        .unwrap()[0]
            .clone();

        let resolution_options = ResolutionOptions {
            sidecar_data: Some(SidecarData {
                signals_metadata: HashMap::from_iter([
                    (
                        Sha256Hash(hex::decode(hash1).unwrap().try_into().unwrap()),
                        SignalsMetadata {
                            btc1_update: Update::from_json_value(update1).ok(),
                            proofs: SmtProofs,
                        },
                    ),
                    (
                        Sha256Hash(hex::decode(hash2).unwrap().try_into().unwrap()),
                        SignalsMetadata {
                            btc1_update: Update::from_json_value(update2).ok(),
                            proofs: SmtProofs,
                        },
                    ),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let fsm = Traversal::new(initial_document, &resolution_options);
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
                "https://blockstream.info/testnet/api/address/tb1qcs60r4j6ema8x4gf07hgt83x45e650dr97q3qv/txs"
            ]
        );

        let json = include_str!("../fixtures/exampleTargetDocument-transactions.json");
        let transactions: Vec<Transaction> = serde_json::from_str(json).unwrap();
        let fsm = next_state.process_responses(transactions);

        let TraversalState::Resolved(document) = fsm.traverse().unwrap() else {
            unreachable!()
        };
        assert_eq!(
            document.fields.id.encode(),
            "did:btc1:k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp",
        );
    }
}
