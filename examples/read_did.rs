use did_btc1::blockchain::TraversalFsm;
use did_btc1::document::{Document, ResolutionOptions};

fn main() {
    let did = "did:btc1:k1qgp5h79scv4sfqkzak5g6y89dsy3cq0pd2nussu2cm3zjfhn4ekwrucc4q7t7"
        .parse()
        .unwrap();

    let mut traversal = Document::read(&did, ResolutionOptions::default()).unwrap();

    let agent = ureq::agent();

    // Drive the blockchain traversal state machine forward.
    loop {
        match traversal.traverse() {
            Ok(TraversalFsm::Init) => unreachable!(),

            Ok(TraversalFsm::Request(requests)) => {
                let responses = requests
                    .into_iter()
                    .map(|req| {
                        let mut resp = agent.run(req).expect("request failed");

                        resp.body_mut().read_json().expect("JSON parse error")
                    })
                    .collect();

                traversal.process_responses(responses);
            }

            Ok(TraversalFsm::Resolved(contemporary_document)) => {
                println!("Resolved document: {contemporary_document:#?}");
                break;
            }

            Err(err) => {
                eprintln!("{err:?}");
                break;
            }
        }
    }
}
