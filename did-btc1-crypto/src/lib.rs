//! # BIP340 Data Integrity
//!
//! This crate implements the Data Integrity BIP340 Cryptographic Suites,
//! providing functionality to create and verify cryptographic proofs for
//! JSON and JSON-LD documents using BIP340 Schnorr signatures over secp256k1.
//!
//! Two primary cryptographic suites are supported:
//! - `bip340-rdfc-2025`: Uses RDF Dataset Canonicalization
//! - `bip340-jcs-2025`: Uses JSON Canonicalization Scheme
//!
//! ## Example
//! ```rust,no_run
//! use did_btc1_crypto::{CryptoSuite, Document, ProofOptions};
//! use did_btc1_crypto::suites::bip340_jcs::Bip340JcsSuite;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load a document from a file
//! let document = Document::from_file("path/to/document.json")?;
//!
//! // Create proof options
//! let options = ProofOptions::new()
//!     .with_verification_method("did:example:123#key-0")
//!     .with_proof_purpose("assertionMethod");
//!
//! // Create a cryptographic suite
//! let suite = Bip340JcsSuite::new();
//!
//! // Create a proof for the document
//! let secured_document = suite.create_proof(&document, &options)?;
//!
//! // Save the secured document to a file
//! secured_document.to_file("path/to/secured_document.json")?;
//!
//! // Later, verify the proof
//! let verification_result = suite.verify_proof(&secured_document)?;
//! assert!(verification_result.verified);
//! # Ok(())
//! # }
//! ```

pub mod cryptosuite;
pub mod document;
pub mod document_management;
pub mod error;
pub mod key;
pub mod proof;
pub mod suites;
pub mod transformation;
pub mod verification;
pub mod zcap;

// Re-exports of key components
pub use cryptosuite::CryptoSuite;
pub use document::Document;
pub use error::Error;
pub use key::{KeyFormat, KeyPair, PublicKey, SecretKey};
pub use proof::{Proof, ProofOptions, ProofPurpose, VerificationResult};
pub use verification::VerificationMethod;

mod did;
