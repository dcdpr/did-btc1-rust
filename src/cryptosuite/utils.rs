use super::Error;
use multibase::{Base, decode, encode};
use secp256k1::constants::{MESSAGE_SIZE, SCHNORR_SIGNATURE_SIZE};
use secp256k1::schnorr::Signature;
use secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// Hash data using SHA-256
pub(crate) fn hash_sha256(data: &[u8]) -> [u8; MESSAGE_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Sign data using BIP340 Schnorr signatures
pub(crate) fn bip340_sign(
    message_hash: &[u8; MESSAGE_SIZE],
    private_key_bytes: &[u8],
) -> Result<[u8; SCHNORR_SIGNATURE_SIZE], Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key_bytes)
        .map_err(|e| super::Error::Cryptographic(format!("Invalid secret key: {e:?}")))?;

    // Create message object from hash
    let message = Message::from_slice(message_hash).unwrap();

    // Sign with BIP340 Schnorr
    let keypair = KeyPair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    let mut signature_bytes = [0; SCHNORR_SIGNATURE_SIZE];
    signature_bytes.copy_from_slice(signature.as_ref());

    Ok(signature_bytes)
}

/// Verify a BIP340 Schnorr signature
pub(crate) fn bip340_verify(
    message_hash: &[u8; MESSAGE_SIZE],
    signature: &[u8; SCHNORR_SIGNATURE_SIZE],
    public_key: &XOnlyPublicKey,
) -> Result<bool, Error> {
    let secp = Secp256k1::new();

    // Create message object from hash
    let message = Message::from_slice(message_hash).unwrap();

    // Create signature object
    let sig = Signature::from_slice(signature)
        .map_err(|e| super::Error::Cryptographic(format!("Invalid signature: {e:?}")))?;

    // Verify signature
    Ok(secp.verify_schnorr(&sig, &message, public_key).is_ok())
}

/// Encode binary data using Multibase (base58-btc)
pub(crate) fn multibase_encode(data: &[u8]) -> String {
    encode(Base::Base58Btc, data)
}

/// Decode multibase encoded string
pub(crate) fn multibase_decode(encoded: &str) -> Result<Vec<u8>, Error> {
    let (_, bytes) = decode(encoded)?;
    Ok(bytes)
}
