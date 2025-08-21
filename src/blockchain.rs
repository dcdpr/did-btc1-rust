use crate::document::{ContemporaryDocument, InitialDocument, ResolutionOptions, SignalsMetadata};
use crate::identifier::{Did, SHA256_HASH_LEN};
use onlyerror::Error;
use chrono::{DateTime, Utc};

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
    contemporary_block_height: u32, // ?
    current_version_id: u64,
    target_condition: TargetCondition, // TODO: This may need both (what is the default for version_id???)
    did_document_history: Vec<ContemporaryDocument>,
    update_hash_history: Vec<[u8; SHA256_HASH_LEN]>, // TODO: We need a type alias or something for hashes
    signals_metadata: Option<SignalsMetadata>,
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
            did_document_history: vec![],
            update_hash_history: vec![],
            signals_metadata: resolution_options
                .sidecar_data
                .as_ref()
                .and_then(|sidecar_data| sidecar_data.signals_metadata.clone()),
        }
    }

    // Spec section 4.2.2.1
    fn traverse(&mut self) -> Result<Self, Error> {
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
            Self::Time(
                resolution_options
                    .version_time
                    .unwrap_or_else(Utc::now),
            )
        }
    }
}
