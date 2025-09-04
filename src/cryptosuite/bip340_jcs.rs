#![allow(dead_code)] // todo

use super::CryptoSuite;
use super::transformation::{JcsTransformation, RdfcTransformation, Transformation as _};
use super::utils::{bip340_sign, bip340_verify, multibase_decode, multibase_encode};
use crate::identifier::Sha256Hash;
use crate::update::{UnsecuredUpdate, Update};
use crate::zcap::proof::{Proof, ProofInner, ProofPurpose};
use crate::{error::Btc1Error, key::PublicKey};
use secp256k1::constants::{SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE};
use serde_json::Value;
use sha2::{Digest, Sha256};

impl CryptoSuite {
    // bip340 cryptosuite spec Section 3.3.1
    pub(crate) fn create_proof(
        &self,
        unsecured_update: &UnsecuredUpdate,
        mut inner: ProofInner,
    ) -> Result<Proof, Btc1Error> {
        // Add document context to proof if present
        let context = &unsecured_update.as_ref()["@context"].as_array();
        if let Some(context) = context {
            inner.context = context
                .iter()
                .flat_map(|e| e.as_str())
                .map(|e| e.to_string())
                .collect();
        }

        // Create proof config
        let proof_config = self.configure_proof(&serde_json::to_value(&inner).unwrap());

        // Transform document
        let transformed_data = self.transform(unsecured_update)?;

        // Hash the data
        let hash_data = self.hash(&transformed_data, &proof_config);

        // Generate proof value
        let proof_bytes = self.serialize_proof(hash_data, &inner)?;

        // Encode proof value with Multibase
        let proof_value = multibase_encode(&proof_bytes);

        // Create final proof
        let proof = Proof::from_inner(inner, proof_value);

        Ok(proof)
    }

    // This is defined by https://www.w3.org/TR/vc-data-integrity/#verify-proof
    // And it calls Self::verify_proof()
    pub(crate) fn data_integrity_verify_proof(
        &self,
        public_key: PublicKey,
        update: &Update,
        expected_proof_purpose: &ProofPurpose,
    ) -> Result<Option<UnsecuredUpdate>, Btc1Error> {
        // Step 5
        if &update.proof.inner.proof_purpose != expected_proof_purpose {
            return Err(Btc1Error::ProofVerification(format!(
                "Proof purpose was expected to be {expected_proof_purpose}"
            )));
        }

        // Step 8
        self.verify_proof(public_key, update)
    }

    // bip340 cryptosuite spec Section 3.3.2
    pub(crate) fn verify_proof(
        &self,
        public_key: PublicKey,
        update: &Update,
    ) -> Result<Option<UnsecuredUpdate>, Btc1Error> {
        // Get proof from document
        let proof = &update.proof;

        // Remove proof from document
        let unsecured_document = UnsecuredUpdate::from(update);

        // Decode proof value
        let proof_bytes = multibase_decode(&proof.proof_value)?;

        let inner_context_size = proof.inner.context.len();
        let context = &update.as_ref()["@context"].as_array();
        if let Some(context) = context {
            let contexts_are_equal = context
                .iter()
                .take(inner_context_size)
                .zip(proof.inner.context.iter())
                .all(|(update_context_entry, proof_context_entry)| {
                    if let Some(update_context_entry) = update_context_entry.as_str() {
                        update_context_entry == proof_context_entry
                    } else {
                        false
                    }
                });
            if !contexts_are_equal {
                return Ok(None);
            }
        }

        // Transform document
        let transformed_data = self.transform(&unsecured_document)?;

        // Configure proof
        let proof_config = self.configure_proof(unsecured_document.as_ref());

        // Hash data
        let hash_data = self.hash(&transformed_data, &proof_config);

        // Verify proof
        let verified = self.proof_verify(hash_data, &proof_bytes, public_key);

        Ok(verified.then_some(unsecured_document))
    }

    // bip340 cryptosuite spec Section 3.3.3
    fn transform(&self, unsecured_update: &UnsecuredUpdate) -> Result<String, Btc1Error> {
        match self {
            Self::Jcs => JcsTransformation::new().transform(unsecured_update),
            Self::Rdfc => RdfcTransformation::new().transform(unsecured_update),
        }
    }

    // bip340 cryptosuite spec Section 3.3.4
    fn hash(&self, transformed_data: &str, proof_config: &str) -> Sha256Hash {
        let mut hasher = Sha256::new();
        // Concatenate proof config and transformed data
        hasher.update(proof_config);
        hasher.update(transformed_data);

        Sha256Hash(hasher.finalize().into())
    }

    // bip340 cryptosuite spec Section 3.3.5
    fn configure_proof(&self, options: &Value) -> String {
        match self {
            Self::Jcs => {
                // Apply JCS canonicalization to proof config
                serde_jcs::to_string(options).unwrap()
            }
            Self::Rdfc => {
                todo!()
            }
        }
    }

    // bip340 cryptosuite spec Section 3.3.6
    fn serialize_proof(
        &self,
        hash_data: Sha256Hash,
        proof: &ProofInner,
        // TODO: Make a newtype for Schnorr signatures
    ) -> Result<[u8; SCHNORR_SIGNATURE_SIZE], Btc1Error> {
        // Get verification method
        let _verification_method_id = &proof.verification_method;

        // In a real implementation, retrieve the private key associated with
        // the "verificationMethod"
        // For this stub, we'll just generate a dummy signature

        // TODO: Implement actual key retrieval
        let private_key_bytes = [0u8; SECRET_KEY_SIZE]; // todo: need to get a real key (using `versification_method`)

        // Sign hash with BIP340
        bip340_sign(hash_data.0, private_key_bytes)
    }

    // bip340 cryptosuite spec Section 3.3.7
    fn proof_verify(
        &self,
        hash_data: Sha256Hash,
        // TODO: Make a newtype for Schnorr signatures
        proof_bytes: &[u8; SCHNORR_SIGNATURE_SIZE],
        public_key: PublicKey,
    ) -> bool {
        // Verify signature
        bip340_verify(hash_data, proof_bytes, &public_key.x_only_public_key().0)
    }
}
