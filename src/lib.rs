pub mod beacon;
pub mod blockchain;
pub mod cryptosuite;
pub mod document;
pub mod error;
pub mod identifier;
pub mod key;
pub mod proof;
//pub mod suites;
//pub mod transformation;
pub mod verification;
//pub mod zcap;

// Re-exports of key components
pub use cryptosuite::CryptoSuite;
pub use document::{Document, ResolutionOptions};
pub use error::Error;
pub use key::{KeyPair, PublicKey, SecretKey};
pub use proof::{Proof, ProofOptions, ProofPurpose, VerificationResult};
pub use verification::VerificationMethod;

//mod did;
mod canonical_hash;
mod json_tools;
mod update;
