use super::Error;
use super::utils::{bip340_sign, bip340_verify, hash_sha256, multibase_decode, multibase_encode};
use crate::cryptosuite::CryptoSuite;
use crate::document::Document;
use crate::proof::{Proof, ProofOptions, VerificationResult};
use crate::transformation::{JcsTransformation, Transformation};
use serde_json::Value;

/// BIP340 JCS cryptographic suite implementation
pub struct Bip340JcsSuite {
    transformation: JcsTransformation,
}

impl Bip340JcsSuite {
    /// Create a new BIP340 JCS suite
    pub fn new() -> Self {
        Self {
            transformation: JcsTransformation::new(),
        }
    }
}

impl Default for Bip340JcsSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoSuite for Bip340JcsSuite {
    fn name(&self) -> &'static str {
        "bip340-jcs-2025"
    }

    fn create_proof(&self, document: &Document, options: &ProofOptions) -> Result<Document, Error> {
        // TODO: need strong types in here too

        // Clone proof options
        let mut proof_options = options.options.clone();

        // Ensure required fields are present
        if !proof_options.contains_key("type") {
            proof_options.insert(
                "type".to_string(),
                Value::String("DataIntegrityProof".to_string()),
            );
        }

        if !proof_options.contains_key("cryptosuite") {
            proof_options.insert(
                "cryptosuite".to_string(),
                Value::String(self.name().to_string()),
            );
        }

        // Add document context to proof if present
        // todo: commented since it wasn't working with new Document embedded types
        // proof_options.insert("@context".to_string(), Value::from_iter(document.get_context()));

        // Create proof config
        let proof_config = self.configure_proof(document, options)?;

        // Transform document
        let transformed_data = self.transform(document, options)?;

        // Hash the data
        let hash_data = self.hash(&transformed_data, &proof_config)?;

        // Generate proof value
        let proof_bytes = self.serialize_proof(&hash_data, options)?;

        // Encode proof value with Multibase
        let proof_value = multibase_encode(&proof_bytes);

        // Create final proof
        let proof_value_str = Value::String(proof_value);
        proof_options.insert("proofValue".to_string(), proof_value_str);

        // Convert to Proof struct
        let proof: Proof = serde_json::from_value(Value::Object(serde_json::Map::from_iter(
            proof_options.into_iter(),
        )))?;

        // Add proof to document
        Ok(document.with_proof(&proof)?)
    }

    fn verify_proof(&self, document: &Document) -> Result<VerificationResult, Error> {
        // Get proof from document
        let proof = document.get_proof().ok_or_else(|| {
            Error::ProofVerification("Document does not contain a proof".to_string())
        })?;

        // Check proof type and cryptosuite
        if proof.type_ != crate::proof::ProofType::DataIntegrityProof {
            return Err(Error::ProofVerification(format!(
                "Unsupported proof type: {:?}",
                proof.type_
            )));
        }

        if proof.cryptosuite != self.name() {
            return Err(Error::ProofVerification(format!(
                "Unsupported cryptosuite: {}",
                proof.cryptosuite
            )));
        }

        // Remove proof from document
        let unsecured_document = document.without_proof();

        // Create proof options
        let mut proof_options = ProofOptions::new();
        for (key, value) in document
            .get_proof()
            .unwrap()
            .context
            .iter()
            .flat_map(|c| match c {
                Value::Object(map) => map
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
                _ => vec![],
            })
        {
            proof_options.options.insert(key, value);
        }

        // Decode proof value
        let proof_bytes = multibase_decode(&proof.proof_value)?;

        // Transform document
        let transformed_data = self.transform(&unsecured_document, &proof_options)?;

        // Configure proof
        let proof_config = self.configure_proof(&unsecured_document, &proof_options)?;

        // Hash data
        let hash_data = self.hash(&transformed_data, &proof_config)?;

        // Verify proof
        let verified = self.verify(&hash_data, &proof_bytes, &proof)?;

        Ok(VerificationResult {
            verified,
            verified_document: if verified {
                Some(unsecured_document)
            } else {
                None
            },
        })
    }

    fn transform(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>, Error> {
        self.transformation.transform(document, options)
    }

    fn hash(&self, transformed_data: &[u8], proof_config: &[u8]) -> Result<Vec<u8>, Error> {
        // Concatenate proof config and transformed data
        let mut bytes_to_hash = Vec::with_capacity(proof_config.len() + transformed_data.len());
        bytes_to_hash.extend_from_slice(proof_config);
        bytes_to_hash.extend_from_slice(transformed_data);

        // Hash with SHA-256
        let hash = hash_sha256(&bytes_to_hash);
        Ok(hash.to_vec())
    }

    fn configure_proof(
        &self,
        _document: &Document,
        options: &ProofOptions,
    ) -> Result<Vec<u8>, Error> {
        // Clone proof options
        let proof_config = options.options.clone();

        // Validate required fields
        if let Some(Value::String(type_)) = proof_config.get("type") {
            if type_ != "DataIntegrityProof" {
                return Err(Error::InvalidProofConfig(format!(
                    "Unsupported proof type: {type_}"
                )));
            }
        } else {
            return Err(Error::InvalidProofConfig(
                "Proof config must include 'type'".to_string(),
            ));
        }

        if let Some(Value::String(suite)) = proof_config.get("cryptosuite") {
            if suite != "bip340-jcs-2025" {
                return Err(Error::InvalidProofConfig(format!(
                    "Unsupported cryptosuite: {suite}"
                )));
            }
        } else {
            return Err(Error::InvalidProofConfig(
                "Proof config must include 'cryptosuite'".to_string(),
            ));
        }

        // Validate created date if present
        if let Some(Value::String(created)) = proof_config.get("created") {
            // TODO: Validate datetime format
            // For now, we'll just check that it's not empty
            if created.is_empty() {
                return Err(Error::InvalidProofConfig(
                    "Invalid 'created' datetime".to_string(),
                ));
            }
        }

        // Add document context if present
        // todo: commented since it wasn't working with new Document embedded types
        // proof_options.insert("@context".to_string(), Value::from_iter(document.get_context()));

        // Apply JCS canonicalization to proof config
        let config_value = Value::Object(serde_json::Map::from_iter(proof_config));

        let canonical_config = serde_jcs::to_vec(&config_value)
            .map_err(|e| Error::Canonicalization(format!("JCS canonicalization failed: {e:?}")))?;

        Ok(canonical_config)
    }

    fn serialize_proof(&self, hash_data: &[u8], options: &ProofOptions) -> Result<Vec<u8>, Error> {
        // Get verification method
        let _verification_method = options
            .options
            .get("verificationMethod")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::ProofGeneration("Missing verificationMethod in proof options".to_string())
            })?;

        // In a real implementation, retrieve the private key associated with
        // the "verificationMethod"
        // For this stub, we'll just generate a dummy signature

        // TODO: Implement actual key retrieval
        let private_key_bytes = [0u8; 32]; // Placeholder

        // Ensure hash data is exactly 32 bytes
        let hash_array: [u8; 32] = if hash_data.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(hash_data);
            arr
        } else {
            return Err(Error::Cryptographic(format!(
                "Hash data must be 32 bytes, got {}",
                hash_data.len()
            )));
        };

        // Sign hash with BIP340
        let signature = bip340_sign(&hash_array, &private_key_bytes)?;

        Ok(signature.to_vec())
    }

    fn verify(&self, hash_data: &[u8], proof_bytes: &[u8], proof: &Proof) -> Result<bool, Error> {
        // Get verification method
        let _verification_method_id = &proof.verification_method;

        // TODO: Implement actual verification method resolution
        // For now, just create a mock public key

        // Convert hash data to 32-byte array
        let hash_array: [u8; 32] = if hash_data.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(hash_data);
            arr
        } else {
            return Err(Error::Cryptographic(format!(
                "Hash data must be 32 bytes, got {}",
                hash_data.len()
            )));
        };

        // Convert signature to 64-byte array
        let signature: [u8; 64] = if proof_bytes.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(proof_bytes);
            arr
        } else {
            return Err(Error::Cryptographic(format!(
                "Signature must be 64 bytes, got {}",
                proof_bytes.len()
            )));
        };

        // Mock public key for now
        let public_key_bytes = [0u8; 32]; // Placeholder
        // let public_key = XOnlyPublicKey::from_slice(&public_key_bytes)
        //     .map_err(|e| Error::Key(format!("Invalid public key: {e:?}")))?;
        let public_key = PublicKey::from_bytes(&public_key_bytes)?;

        // Verify signature
        bip340_verify(&hash_array, &signature, &public_key.key)
    }
}

// Re-export for external use
use crate::PublicKey;
pub use secp256k1::XOnlyPublicKey;
