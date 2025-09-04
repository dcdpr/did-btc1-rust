#![allow(dead_code)] // todo

use crate::error::Btc1Error;
use crate::identifier::Sha256Hash;
use crate::zcap::proof::ProofValue;
use multibase::{Base, decode, encode};
use secp256k1::constants::{MESSAGE_SIZE, SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE};
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

/// Sign data using BIP340 Schnorr signatures
pub(crate) fn bip340_sign(
    message_hash: [u8; MESSAGE_SIZE],
    private_key_bytes: [u8; SECRET_KEY_SIZE],
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
pub(crate) fn bip340_verify(
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
pub(crate) fn multibase_encode(data: &[u8]) -> ProofValue {
    ProofValue(encode(Base::Base58Btc, data))
}

pub(crate) fn multibase_decode(
    data: &ProofValue,
) -> Result<[u8; SCHNORR_SIGNATURE_SIZE], Btc1Error> {
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
