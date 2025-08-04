use crate::error::{Error, Result};
use multibase::{Base, decode, encode};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// Hash data using SHA-256
pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Sign data using BIP340 Schnorr signatures
pub fn bip340_sign(message_hash: &[u8; 32], private_key_bytes: &[u8]) -> Result<[u8; 64]> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key_bytes)
        .map_err(|e| Error::Cryptographic(format!("Invalid secret key: {e:?}")))?;

    // Create message object from hash
    let message = Message::from_slice(message_hash)
        .map_err(|e| Error::Cryptographic(format!("Invalid message hash: {e:?}")))?;

    // Sign with BIP340 Schnorr
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(message.as_ref(), &keypair);

    Ok(signature.serialize())
}

/// Verify a BIP340 Schnorr signature
pub fn bip340_verify(
    message_hash: &[u8; 32],
    signature: &[u8; 64],
    public_key: &XOnlyPublicKey,
) -> Result<bool> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(message_hash)
        .map_err(|e| Error::Cryptographic(format!("Invalid message hash: {e:?}")))?;

    // Create signature object
    let sig = Signature::from_slice(signature)
        .map_err(|e| Error::Cryptographic(format!("Invalid signature: {e:?}")))?;

    // Verify signature
    Ok(secp
        .verify_schnorr(&sig, message.as_ref(), public_key)
        .is_ok())
}

/// Encode binary data using Multibase (base58-btc)
pub fn multibase_encode(data: &[u8]) -> String {
    encode(Base::Base58Btc, data)
}

/// Decode multibase encoded string
pub fn multibase_decode(encoded: &str) -> Result<Vec<u8>> {
    let (_, bytes) = decode(encoded)
        .map_err(|e| Error::Multibase(format!("Failed to decode multibase: {e:?}")))?;
    Ok(bytes)
}
