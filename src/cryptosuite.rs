#![allow(dead_code)] // todo

//! BIP340 cryptosuite implementation

use crate::update::{UnsecuredUpdate, Update};
use crate::zcap::proof::{Proof, ProofInner, ProofPurpose, ProofValue};
use crate::{error::Btc1Error, identifier::Sha256Hash, key::PublicKey};
use multibase::{Base, decode, encode};
use secp256k1::constants::{MESSAGE_SIZE, SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE};
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) enum CryptoSuite {
    Jcs, // TODO: Remove JCS asap

    #[allow(dead_code)]
    Rdfc,
}

impl CryptoSuite {
    // bip340 cryptosuite spec Section 3.3.1
    pub(crate) fn create_proof(
        &self,
        unsecured_update: &UnsecuredUpdate,
        mut inner: ProofInner,
    ) -> Result<Proof, Btc1Error> {
        // Add document context to proof if present
        let context = unsecured_update.as_ref()["@context"].as_array();
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
        let transformed_data = self.transform(unsecured_update);

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
        // Remove proof from update document
        let unsecured_update = UnsecuredUpdate::from(update);

        // Decode proof value
        let proof_bytes = multibase_decode(&update.proof.proof_value)?;

        // Compare @context
        let context = update.as_ref()["@context"].as_array();
        if let Some(context) = context {
            let contexts_are_equal = context.iter().zip(update.proof.inner.context.iter()).all(
                |(update_context_entry, proof_context_entry)| {
                    update_context_entry
                        .as_str()
                        .map(|update_context_entry| update_context_entry == proof_context_entry)
                        .unwrap_or_default()
                },
            );
            if !contexts_are_equal {
                return Ok(None);
            }
        }

        // Transform document
        let transformed_data = self.transform(&unsecured_update);

        // Configure proof
        let proof_options = serde_json::to_value(&update.proof.inner).unwrap();
        let proof_config = self.configure_proof(&proof_options);

        // Hash data
        let hash_data = self.hash(&transformed_data, &proof_config);

        // Verify proof
        let verified = self.proof_verify(hash_data, &proof_bytes, public_key);

        Ok(verified.then_some(unsecured_update))
    }

    // bip340 cryptosuite spec Section 3.3.3
    fn transform(&self, unsecured_update: &UnsecuredUpdate) -> String {
        match self {
            Self::Jcs => serde_jcs::to_string(unsecured_update.as_ref()).unwrap(),
            Self::Rdfc => todo!(),
        }
    }

    // bip340 cryptosuite spec Section 3.3.4
    fn hash(&self, transformed_data: &str, proof_config: &str) -> Sha256Hash {
        let mut hasher = Sha256::new();

        // Hash and concatenate proof config and transformed data
        hasher.update(Sha256::digest(proof_config));
        hasher.update(Sha256::digest(transformed_data));

        Sha256Hash(hasher.finalize().into())
    }

    // bip340 cryptosuite spec Section 3.3.5
    fn configure_proof(&self, options: &Value) -> String {
        match self {
            Self::Jcs => serde_jcs::to_string(options).unwrap(),
            Self::Rdfc => todo!(),
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
        let private_key_bytes = [0u8; SECRET_KEY_SIZE]; // todo: need to get a real key (using `verification_method`)

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

/// Sign data using BIP340 Schnorr signatures
fn bip340_sign(
    message_hash: [u8; MESSAGE_SIZE],
    private_key_bytes: [u8; SECRET_KEY_SIZE],
    // TODO: Make a newtype for Schnorr signatures
) -> Result<[u8; SCHNORR_SIGNATURE_SIZE], Btc1Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();

    // Create message object from hash
    let message = Message::from_slice(&message_hash).unwrap();

    // Sign with BIP340 Schnorr
    let keypair = KeyPair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    let mut signature_bytes = [0; SCHNORR_SIGNATURE_SIZE];
    signature_bytes.copy_from_slice(signature.as_ref());

    Ok(signature_bytes)
}

/// Verify a BIP340 Schnorr signature
fn bip340_verify(
    message_hash: Sha256Hash,
    signature: &[u8; SCHNORR_SIGNATURE_SIZE],
    public_key: &XOnlyPublicKey,
) -> bool {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(&message_hash.0).unwrap();

    // Create signature object
    let sig = Signature::from_slice(signature).unwrap();

    // Verify signature
    secp.verify_schnorr(&sig, &message, public_key).is_ok()
}

/// Encode binary data using Multibase (base58-btc)
fn multibase_encode(data: &[u8]) -> ProofValue {
    ProofValue(encode(Base::Base58Btc, data))
}

/// Decode multibase encoded string
fn multibase_decode(data: &ProofValue) -> Result<[u8; SCHNORR_SIGNATURE_SIZE], Btc1Error> {
    let decoded = decode(&data.0)
        .map(|(_, decoded)| decoded)
        .map_err(|_| Btc1Error::ProofVerification("Invalid proofValue encoding".into()))?;

    if decoded.len() != SCHNORR_SIGNATURE_SIZE {
        return Err(Btc1Error::ProofVerification(
            "Invalid proofValue encoding".into(),
        ));
    }

    Ok(decoded.try_into().unwrap())
}
