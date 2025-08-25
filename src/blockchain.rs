use crate::document::{ContemporaryDocument, InitialDocument, ResolutionOptions, SignalsMetadata};
use crate::identifier::{Did, Sha256Hash};
use chrono::{DateTime, Utc};
use onlyerror::Error;
use std::collections::HashMap;

#[derive(Error, Debug)]
pub enum Error {
    /// Spec section 4.2.2.4
    UpdateNotDuplicate,
}

/// State machine for Bitcoin blockchain traversal.
#[derive(Debug)]
pub(crate) struct Traversal {
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
        }
    }

    // Spec section 4.2.2.1
    fn traverse(&mut self) -> Result<ContemporaryDocument, Error> {
        // Step 1.
        let contemporary_hash = self.contemporary_doc.compute_hash(&self.did);

        // Step 2.
        todo!();
    }
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
