use anyhow::Result;
use did_btc1::blockchain::TraversalState;
use did_btc1::{Document, ResolutionOptions};

fn main() -> Result<()> {
    let agent = ureq::agent();
    let did = "did:btc1:k1qgp5h79scv4sfqkzak5g6y89dsy3cq0pd2nussu2cm3zjfhn4ekwrucc4q7t7".parse()?;
    let mut fsm = Document::read(&did, ResolutionOptions::default())?;

    // Drive the blockchain traversal state machine forward.
    loop {
        match fsm.traverse()? {
            TraversalState::Requests(next_state, requests) => {
                let responses = requests
                    .into_iter()
                    .map(|req| {
                        let mut resp = agent.run(req)?;

                        Ok(resp.body_mut().read_json()?)
                    })
                    .collect::<Result<Vec<_>>>()?;

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
