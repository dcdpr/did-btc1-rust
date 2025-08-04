use crate::document::Document;
use crate::error::Result;
use crate::proof::{Proof, ProofOptions, VerificationResult};

/// Trait defining the main interface for cryptographic suites
pub trait CryptoSuite {
    /// Name of the cryptographic suite
    fn name(&self) -> &'static str;

    /// Create a proof for a document with given options
    fn create_proof(&self, document: &Document, options: &ProofOptions) -> Result<Document>;

    /// Verify a document with a proof
    fn verify_proof(&self, document: &Document) -> Result<VerificationResult>;

    /// Transform a document for hashing
    fn transform(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>>;

    /// Hash transformed data
    fn hash(&self, transformed_data: &[u8], proof_config: &[u8]) -> Result<Vec<u8>>;

    /// Configure a proof from options
    fn configure_proof(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>>;

    /// Serialize a proof
    fn serialize_proof(&self, hash_data: &[u8], options: &ProofOptions) -> Result<Vec<u8>>;

    /// Verify a proof
    fn verify(&self, hash_data: &[u8], proof_bytes: &[u8], options: &Proof) -> Result<bool>;
}

/// Trait for instantiating a cryptographic suite
pub trait InstantiateCryptoSuite {
    /// The type of cryptographic suite this creates
    type Suite: CryptoSuite;

    /// Instantiate a new cryptographic suite
    fn instantiate(options: &ProofOptions) -> Result<Self::Suite>;
}

/// Factory function to instantiate a cryptosuite by name
pub fn instantiate_cryptosuite(
    cryptosuite: &str,
    _options: &ProofOptions,
) -> Result<Box<dyn CryptoSuite>> {
    match cryptosuite {
        "bip340-jcs-2025" => {
            use crate::suites::bip340_jcs::Bip340JcsSuite;
            Ok(Box::new(Bip340JcsSuite::new()))
        }
        "bip340-rdfc-2025" => {
            use crate::suites::bip340_rdfc::Bip340RdfcSuite;
            Ok(Box::new(Bip340RdfcSuite::new()))
        }
        _ => Err(crate::error::Error::UnsupportedCryptoSuite(
            cryptosuite.to_string(),
        )),
    }
}
