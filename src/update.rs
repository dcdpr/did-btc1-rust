use crate::{canonical_hash::CanonicalHash, json_tools};
use onlyerror::Error;
use serde_json::Value;
use std::{fs, path::Path};
use std::num::NonZeroU64;

#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    Io(#[from] std::io::Error),

    /// JSON parse error
    Json(#[from] serde_json::Error),

    /// JSON value parse error
    JsonValue(#[from] json_tools::Error),

    /// Zero found where non-Zero is required
    NonZero(#[from] std::num::TryFromIntError),
}

#[derive(Clone, Debug)]
pub struct Update {
    pub(crate) target_version_id: NonZeroU64,

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

    pub fn from_json_value(value: Value) -> Result<Self, Error> {
        let json = serde_json::from_value(value)?;

        // TODO: Use TryInto instead of `as` ... Correctly handle non-u64 numbers.
        let target_version_id =
            json_tools::int_from_object(&json, "targetVersionId").map(|id| id as u64)?.try_into()?;
        Ok(Self {
            target_version_id,
            json,
        })
    }
}

impl AsRef<Value> for Update {
    fn as_ref(&self) -> &Value {
        &self.json
    }
}

impl CanonicalHash for Update {}

pub struct DocumentPatch;
