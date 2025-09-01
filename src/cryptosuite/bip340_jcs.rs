use super::transformation::{JcsTransformation, RdfcTransformation, Transformation as _};
use super::utils::{bip340_sign, bip340_verify, hash_sha256, multibase_decode, multibase_encode};
use super::{CryptoSuite, Error};
use crate::zcap::proof::{CryptoSuiteName, Proof, ProofOptions, ProofType, VerificationResult};
use crate::{document::Document, error::Btc1Error, key::PublicKey};
use secp256k1::constants::{
    MESSAGE_SIZE, PUBLIC_KEY_SIZE, SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE,
};
use serde_json::Value;

impl CryptoSuite {
    fn name(&self) -> &'static str {
        match self {
            Self::Jsc => "bip340-jcs-2025",
            Self::Rdfc => "bip340-rdfc-2025",
        }
    }

    fn create_proof(&self, document: &Document, options: &ProofOptions) -> Result<Document, Error> {
        // TODO: need strong types in here too
        // TODO: Need to fix ProofOptions
        let mut proof_options = std::collections::HashMap::new();

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
            super::Error::ProofVerification("Document does not contain a proof".to_string())
        })?;

        // Check proof type and cryptosuite
        if proof.proof_type != ProofType::DataIntegrityProof {
            return Err(super::Error::ProofVerification(format!(
                "Unsupported proof type: {:?}",
                proof.proof_type
            )))?;
        }

        if proof.cryptosuite != self.name() {
            return Err(super::Error::ProofVerification(format!(
                "Unsupported cryptosuite: {}",
                proof.cryptosuite
            )))?;
        }

        // Remove proof from document
        let unsecured_document = document.without_proof();

        // TODO: Create proof options
        // let mut proof_options = ProofOptions::new();
        // for (key, value) in document
        //     .get_proof()
        //     .unwrap()
        //     .context
        //     .iter()
        //     .flat_map(|c| match c {
        //         Value::Object(map) => map
        //             .iter()
        //             .map(|(k, v)| (k.clone(), v.clone()))
        //             .collect::<Vec<_>>(),
        //         _ => vec![],
        //     })
        // {
        //     proof_options.options.insert(key, value);
        // }
        let proof_options = ProofOptions::default();

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

    // TODO: Why return `Vec<u8>`? What about `String`?
    fn transform(&self, document: &Document, options: &ProofOptions) -> Result<Vec<u8>, Error> {
        match self {
            Self::Jsc => JcsTransformation::new().transform(document, options),
            Self::Rdfc => RdfcTransformation::new().transform(document, options),
        }
    }

    fn hash(&self, transformed_data: &[u8], proof_config: &str) -> Result<Vec<u8>, Error> {
        // Concatenate proof config and transformed data
        let mut bytes_to_hash = Vec::with_capacity(proof_config.len() + transformed_data.len());
        bytes_to_hash.extend_from_slice(proof_config.as_bytes());
        bytes_to_hash.extend_from_slice(transformed_data);

        // Hash with SHA-256
        let hash = hash_sha256(&bytes_to_hash);
        Ok(hash.to_vec())
    }

    fn configure_proof(
        &self,
        document: &Document,
        options: &ProofOptions,
    ) -> Result<String, Error> {
        let canonical_config = match options.cryptosuite {
            CryptoSuiteName::Jcs => {
                // Apply JCS canonicalization to proof config
                let mut config_value = serde_json::json!({
                    "@context": document.fields.context,
                    "type": options.suite_type.to_string(),
                    "cryptosuite": options.cryptosuite.to_string(),
                    "verificationMethod": options.verification_method,
                });

                if let Some(created) = options.created.as_ref() {
                    // TODO: Is this the right time format? It's ISO 8601
                    config_value["created"] = created.format("%+").to_string().into();
                }

                serde_jcs::to_string(&config_value).map_err(|e| {
                    super::Error::Canonicalization(format!("JCS canonicalization failed: {e:?}"))
                })
            }
            CryptoSuiteName::Rdfc => {
                todo!()
            }
        }?;

        Ok(canonical_config)
    }

    // TODO: Why return `Vec<u8>`? What about `String`?
    fn serialize_proof(&self, hash_data: &[u8], _options: &ProofOptions) -> Result<Vec<u8>, Error> {
        // TODO: Check options.verificationMethod

        // In a real implementation, retrieve the private key associated with
        // the "verificationMethod"
        // For this stub, we'll just generate a dummy signature

        // TODO: Implement actual key retrieval
        let private_key_bytes = [0u8; SECRET_KEY_SIZE]; // Placeholder

        // Ensure hash data is exactly 32 bytes
        let hash_array: [u8; MESSAGE_SIZE] = if hash_data.len() == MESSAGE_SIZE {
            let mut arr = [0u8; MESSAGE_SIZE];
            arr.copy_from_slice(hash_data);
            arr
        } else {
            return Err(super::Error::Cryptographic(format!(
                "Hash data must be {MESSAGE_SIZE} bytes, got {}",
                hash_data.len()
            )))?;
        };

        // Sign hash with BIP340
        let signature = bip340_sign(&hash_array, &private_key_bytes)?;

        Ok(signature.to_vec())
    }

    // TODO: Why take `proof_bytes: &[u8]`? What about `&str`?
    fn verify(&self, hash_data: &[u8], proof_bytes: &[u8], proof: &Proof) -> Result<bool, Error> {
        // Get verification method
        let _verification_method_id = &proof.verification_method;

        // TODO: Implement actual verification method resolution
        // For now, just create a mock public key

        // Convert hash data to 32-byte array
        let hash_array: [u8; MESSAGE_SIZE] = if hash_data.len() == MESSAGE_SIZE {
            let mut arr = [0u8; MESSAGE_SIZE];
            arr.copy_from_slice(hash_data);
            arr
        } else {
            return Err(super::Error::Cryptographic(format!(
                "Hash data must be {MESSAGE_SIZE} bytes, got {}",
                hash_data.len()
            )))?;
        };

        // Convert signature to 64-byte array
        let signature: [u8; SCHNORR_SIGNATURE_SIZE] = if proof_bytes.len() == SCHNORR_SIGNATURE_SIZE
        {
            let mut arr = [0u8; SCHNORR_SIGNATURE_SIZE];
            arr.copy_from_slice(proof_bytes);
            arr
        } else {
            return Err(super::Error::Cryptographic(format!(
                "Signature must be {SCHNORR_SIGNATURE_SIZE} bytes, got {}",
                proof_bytes.len()
            )))?;
        };

        // Mock public key for now
        let public_key_bytes = [0u8; PUBLIC_KEY_SIZE]; // Placeholder
        // let public_key = XOnlyPublicKey::from_slice(&public_key_bytes)
        //     .map_err(|e| Error::Key(format!("Invalid public key: {e:?}")))?;
        let public_key = PublicKey::from_slice(&public_key_bytes)?;

        // Verify signature
        bip340_verify(&hash_array, &signature, &public_key.x_only_public_key().0)
    }

    // This is defined by https://www.w3.org/TR/vc-data-integrity/#verify-proof
    // And it calls Self::verify_proof()
    pub(crate) fn data_integrity_verify_proof(
        &self,
        _media_type: &str,
        _proof: &Proof,
        _expected_proof_purpose: &str,
    ) -> Result<VerificationResult, Btc1Error> {
        todo!()
    }
}
