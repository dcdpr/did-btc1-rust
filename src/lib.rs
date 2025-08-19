pub mod cryptosuite;
pub mod document;
pub mod error;
pub mod identifier;
pub mod key;
pub mod proof;
pub mod service;
//pub mod suites;
//pub mod transformation;
pub mod verification;
//pub mod zcap;

// Re-exports of key components
pub use cryptosuite::CryptoSuite;
pub use document::Document;
pub use error::Error;
pub use key::{KeyPair, PublicKey, SecretKey};
pub use proof::{Proof, ProofOptions, ProofPurpose, VerificationResult};
pub use verification::VerificationMethod;

//mod did;
