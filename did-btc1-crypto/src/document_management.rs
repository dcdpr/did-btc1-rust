use crate::Document;
use did_btc1_encoding::{IdType, Network};

impl Document {
    pub fn generate_deterministic_initial_document(
        pub_key_bytes: &[u8],
        version: Option<u8>,
        network: Option<Network>,
    ) -> Self {
        // spec section 4.1.1
        let version = version.unwrap_or(1);
        let network = network.unwrap_or(Network::Mainnet);
        let did =
            did_btc1_encoding::encode_did_identifier(version, network, IdType::Key, pub_key_bytes)
                .unwrap();

        let mut doc = Self::new();
        doc.data.insert("id".to_string(), did.into());
        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_deterministic_initial_did_document() {
        let pub_key_bytes =
            hex::decode("034bf8b0c32b0482c2eda88d10e56c091c01e16aa7c8438ac6e22926f3ae6ce1f3")
                .unwrap();

        let doc = Document::generate_deterministic_initial_document(
            &pub_key_bytes,
            None,
            Some(Network::Regtest),
        );
        assert_eq!(
            doc.get_data().get("id").unwrap(),
            "did:btc1:k1qgp5h79scv4sfqkzak5g6y89dsy3cq0pd2nussu2cm3zjfhn4ekwrucc4q7t7"
        );
    }
}
