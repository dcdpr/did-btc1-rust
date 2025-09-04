use anyhow::Result;
use did_btc1::blockchain::TraversalState;
use did_btc1::{Document, ResolutionOptions, document::SidecarData};
use std::collections::HashMap;

fn main() -> Result<()> {
    // TODO: Need all of the sidecar data to resolve the given DID (because it has updates).
    let resolution_options = ResolutionOptions {
        sidecar_data: Some(SidecarData {
            blockchain_rpc_uri: Some("https://mutinynet.com/api".into()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let agent = ureq::agent();
    let did = "did:btc1:k1q5pa5tq86fzrl0ez32nh8e0ks4tzzkxnnmn8tdvxk04ahzt70u09dag02h0cp".parse()?;
    let mut fsm = Document::read(&did, resolution_options)?;

    // Drive the blockchain traversal state machine forward.
    loop {
        match fsm.traverse()? {
            TraversalState::Requests(next_state, requests) => {
                let mut responses = HashMap::new();

                for (beacon_type, requests) in requests {
                    for req in requests {
                        let mut resp = agent.run(req)?;

                        let transactions: Vec<_> = resp.body_mut().read_json()?;

                        let entry: &mut Vec<_> = responses.entry(beacon_type).or_default();
                        entry.extend(transactions);
                    }
                }

                fsm = next_state.process_responses(responses);
            }

            TraversalState::Resolved(document) => {
                println!("Resolved document: {document:#?}");
                break;
            }
        }
    }

    Ok(())
}
