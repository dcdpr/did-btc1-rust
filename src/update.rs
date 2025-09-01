use crate::zcap::proof::Proof;
use crate::{canonical_hash::CanonicalHash, error::Btc1Error, identifier::Sha256Hash, json_tools};
use onlyerror::Error;
use serde_json::Value;
use std::{fs, num::NonZeroU64, path::Path};

#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    Io(#[from] std::io::Error),

    /// JSON parse error
    Json(#[from] serde_json::Error),

    /// JSON value parse error
    JsonValue(#[from] json_tools::JsonError),

    /// Invalid SHA256 hash
    #[error("Invalid SHA256 hash: {0}")]
    InvalidHash(&'static str),

    /// Invalid targetVersionId
    InvalidTargetVersionId,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub(crate) source_hash: Sha256Hash,
    pub(crate) _target_hash: Sha256Hash,
    pub(crate) target_version_id: NonZeroU64,
    pub(crate) proof: Proof,

    pub(crate) json: Value,
}

impl Update {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let json = fs::read_to_string(path)?;

        Self::from_json_string(&json)
    }

    pub fn from_json_string(json: &str) -> Result<Self, Error> {
        let json = serde_json::from_str(json)?;

        Self::from_json_value(json)
    }

    pub fn from_json_value(json: Value) -> Result<Self, Error> {
        use json_tools::*;

        let source_hash = hash_from_object(&json, "sourceHash")?;
        let _target_hash = hash_from_object(&json, "targetHash")?;
        let target_version_id = u64::try_from(int_from_object(&json, "targetVersionId")?)
            .map_err(|_| Error::InvalidTargetVersionId)?
            .try_into()
            .map_err(|_| Error::InvalidTargetVersionId)?;
        // TODO: Check whether "proof" exists as a key.
        let proof = serde_json::from_value(json["proof"].clone())?;

        Ok(Self {
            source_hash,
            _target_hash,
            target_version_id,
            proof,
            json,
        })
    }

    // Spec section 7.2.2.4
    pub(crate) fn confirm_duplicate(&self, hash_history: &[Sha256Hash]) -> Result<(), Btc1Error> {
        let update_hash = UnsecuredUpdate::from(self).hash();
        let update_hash_index = usize::try_from(u64::from(self.target_version_id) - 2).unwrap();
        let historical_update_hash = hash_history[update_hash_index];

        if historical_update_hash != update_hash {
            Err(Btc1Error::late_publishing(
                update_hash,
                historical_update_hash,
            ))
        } else {
            Ok(())
        }
    }
}

impl AsRef<Value> for Update {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for Update {}

#[derive(Clone, Debug)]
pub(crate) struct UnsecuredUpdate {
    pub(crate) json: Value,
}

impl From<&Update> for UnsecuredUpdate {
    fn from(update: &Update) -> Self {
        let mut json = update.json.clone();
        if let Value::Object(map) = &mut json {
            map.remove("proof");
        }

        Self { json }
    }
}

impl AsRef<Value> for UnsecuredUpdate {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for UnsecuredUpdate {}

pub struct DocumentPatch;
