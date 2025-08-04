
use crate::{
    CryptoSuite, Document, ProofOptions,
    key::{KeyFormat, KeyPair},
    suites::{bip340_jcs::Bip340JcsSuite, bip340_rdfc::Bip340RdfcSuite},
};

// Helper function to create a test document
fn create_test_document() -> Document {
    let json = r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                {"myWebsite": "https://vocabulary.example/myWebsite"}
            ],
            "myWebsite": "https://hello.world.example/"
        }"#;

    Document::from_json_string(json).expect("Failed to create test document")
}

// Helper function to create test proof options
fn create_test_proof_options(key_pair: &KeyPair) -> ProofOptions {
    let public_key = &key_pair.public_key;
    let _public_key_multibase = public_key
        .encode(KeyFormat::Multikey)
        .expect("Failed to encode public key");

    let verification_method_id = "did:example:123#key-0".to_string();

    ProofOptions::new()
        .with_type("DataIntegrityProof")
        .with_verification_method(&verification_method_id)
        .with_proof_purpose("assertionMethod")
        .with_created("2025-03-10T15:00:00Z")
}

#[test]
fn test_document_serialization() {
    let doc = create_test_document();
    let json = doc.to_json_string().expect("Failed to serialize document");
    let doc2 = Document::from_json_string(&json).expect("Failed to deserialize document");

    assert_eq!(doc.data.get("myWebsite"), doc2.data.get("myWebsite"));
}

#[test]
fn test_key_generation() {
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let public_key_str = key_pair
        .public_key
        .encode(KeyFormat::Multikey)
        .expect("Failed to encode public key");

    assert!(
        public_key_str.starts_with('z'),
        "Public key should start with 'z'"
    );
}

#[test]
fn test_jcs_suite_instantiation() {
    let suite = Bip340JcsSuite::new();
    assert_eq!(suite.name(), "bip340-jcs-2025");
}

#[test]
fn test_rdfc_suite_instantiation() {
    let suite = Bip340RdfcSuite::new();
    assert_eq!(suite.name(), "bip340-rdfc-2025");
}

// This test is marked as ignored since the RDFC transformation is not yet implemented
#[test]
#[ignore]
fn test_create_and_verify_proof_rdfc() {
    let document = create_test_document();
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let options = create_test_proof_options(&key_pair).with_cryptosuite("bip340-rdfc-2025");

    let suite = Bip340RdfcSuite::new();

    // Create proof
    let secured_document = suite
        .create_proof(&document, &options)
        .expect("Failed to create proof");

    // Verify proof
    let verification_result = suite
        .verify_proof(&secured_document)
        .expect("Failed to verify proof");

    assert!(
        verification_result.verified,
        "Proof verification should succeed"
    );
}

// This test will fail until we implement proper key handling
#[test]
#[ignore]
fn test_create_and_verify_proof_jcs() {
    let document = create_test_document();
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let options = create_test_proof_options(&key_pair).with_cryptosuite("bip340-jcs-2025");

    let suite = Bip340JcsSuite::new();

    // Create proof
    let secured_document = suite
        .create_proof(&document, &options)
        .expect("Failed to create proof");

    // Verify proof exists
    assert!(
        secured_document.get_proof().is_some(),
        "Secured document should have a proof"
    );

    // Verify proof cryptosuite
    let proof = secured_document.get_proof().unwrap();
    assert_eq!(
        proof.cryptosuite, "bip340-jcs-2025",
        "Proof should use bip340-jcs-2025 cryptosuite"
    );

    // Verify proof (this will likely fail until we implement proper key handling)
    let verification_result = suite
        .verify_proof(&secured_document)
        .expect("Failed to verify proof");

    assert!(
        verification_result.verified,
        "Proof verification should succeed"
    );
}

#[test]
fn test_document_io() {
    let document = create_test_document();

    // Create a temporary file
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test_document.json");

    // Save document
    document
        .to_file(&file_path)
        .expect("Failed to save document");

    // Load document
    let loaded_document = Document::from_file(&file_path).expect("Failed to load document");

    // Compare
    assert_eq!(
        document.data.get("myWebsite"),
        loaded_document.data.get("myWebsite")
    );
}
