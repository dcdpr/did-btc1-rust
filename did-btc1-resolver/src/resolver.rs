use did_btc1_crypto::Document;
use did_btc1_identifier::{DidComponents, IdType, Network};
use onlyerror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// DID encoding error
    DidEncoding(#[from] did_btc1_identifier::DidEncodingError),

    /// Document generation error
    DocumentGeneration(#[from] did_btc1_crypto::error::Error),
}

pub struct Resolver;

#[derive(Debug, Default)]
pub struct ResolutionOptions {
    version_id: Option<u8>,
    version_time: Option<u64>,
}

impl Resolver {
    // TODO: Strongly type `Did` instead of strings.
    pub fn resolve(did: &str, resolution_options: ResolutionOptions) -> Result<Document, Error> {
        let did_components = did_btc1_identifier::parse_did_identifier(did)?;

        let initial_document = resolve_initial_document(did, &did_components, &resolution_options)?;
        resolve_target_document(
            initial_document,
            &resolution_options,
            did_components.network(),
        )
    }
}

fn resolve_initial_document(
    did: &str,
    did_components: &DidComponents,
    resolution_options: &ResolutionOptions,
) -> Result<Document, Error> {
    // Spec section 4.2.1
    match did_components.id_type() {
        IdType::Key => Ok(Document::deterministically_generate_initial_did_document(
            did,
            did_components,
        )?),
        IdType::External => todo!(),
    }
}

fn resolve_target_document(
    mut initial_document: Document,
    resolution_options: &ResolutionOptions,
    network: Network,
) -> Result<Document, Error> {
    // Spec section 4.2.2
    if let Some(version_id) = resolution_options.version_id.as_ref() {
        todo!("Set version ID");
    }

    // TODO: faking so the tests pass
    Ok(initial_document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve() {
        let did = "did:btc1:k1qgp5h79scv4sfqkzak5g6y89dsy3cq0pd2nussu2cm3zjfhn4ekwrucc4q7t7";
        let document = Resolver::resolve(did, ResolutionOptions::default()).unwrap();
        assert_eq!(document.data["id"], did);
        assert_eq!(
            document.data["service"].as_array().unwrap()[0]["type"],
            "SingletonBeacon"
        );
    }
}
