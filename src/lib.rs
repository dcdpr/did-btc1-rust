pub mod beacon;
pub mod blockchain;
pub mod document;
pub mod error;
pub mod identifier;
pub mod key;
pub mod verification;

mod canonical_hash;
mod cryptosuite;
mod json_tools;
mod update;
mod zcap;

// Re-exports of key components
pub use document::{Document, ResolutionOptions};
pub use key::{KeyPair, PublicKey, SecretKey};
