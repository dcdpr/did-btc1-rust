
2025-08-11:

- added url crate, then got rid of it
- continued making real types for embedded Document items

for next time:

- analyze existing tests, see if we can improve or remove any


2025-08-12

- Major refactor on error types
- Removed many stub crates
- Added `services` field to `Document`, and the `Service` type.
- Added some actual tests

for next time:

- Tightening up `Did::public_key()` -- should be infallible, because if we have a `Did`, we have
  already parsed and validated the genesis bytes.
- Plus any caller changes for that.
- Start testing `Document` in preparation for creating and resolving.

2025-08-13

missed it (did work, but forgot to record here)


2025-08-14

- Continued work on DID related types
- Removed serde operations for DID related types in favor of our own read/save functions
- Started working through the Create and Read DID operations.
- Added new InitialDocument type
- added lots of todo!() ...


for next time:

- finish up sidecar_initial_validation()
- continue with 4.2.2, Resolve Target Document


2025-08-15

- Refactor of error types (added `ProblemDetails` trait for DID specification errors)
- Removed error handling from some infallible code paths
- implemented the JSON hash function with JCS

for next time:

- Implement section 4.1.1
- Implement section 4.1.2


2025-08-18:

- Implemented 4.1.1 with function from_did_components()
- Tried to start 4.1.2, but got side-tracked by creating IntermediateDocument, to go along with InitialDocument and Document
- Worked on some problems we had importing JSON-LD from our test files and checking structural integrity of the documents

for next time:

- May want to think about proptesting our structual concerns
- Continue to implement section 4.1.2
- Then 4.2 (read/resolve)


2025-08-19:

- Finished 4.1.2 (From External Intermediate DID Document)
- Parameterized DocumentFields so that we could parse the included DIDs or leave them as strings (so we can deal with intermediate docs with xxxxxx placeholders)
- stared 4.2 and beginning of blockchain traversal.

for next time:

- Hopefully get some answers to my six issues I filed today
- continue with blockchain traversal
- some sprinkled todos around that we might want to deal with
- Need to get into Sans-IO thinking (reading: https://www.firezone.dev/blog/sans-io)

2025-08-21:

- Cleaned up lots of todos
- Finalized a few tests
- Created blockchain.rs module
- Renamed some of our JSON extraction functions for be nicer and more consistent
- Added a bunch of documentation comments for functions
- Added chrono crate

for next time:

- figure out the confusing blockchain traversal part of the spec


2025-08-22:

- We simplified From impl for Service
- Added several todo comments



2025-08-24

- Switched service to beacon
- Beacon type is an enum
- Beacon descriptor is a bitcoin::Address
- Updated local tests documents (copied from `did-btc1` repo)

for next time:

- Add conversions for `crate::identifier::Network` <--> `bitcoin::Network`
- Fix tests
- More blockchain traversal


2025-08-25 (part 1)

- Added conversions for `bitcoin::Network`
- Fixed the tests that now take `Beacon`
- Added a macro for DRY document parsing and structural validation
- Added some convenience methods for `ContemporaryDocument` required by `blockchain::Traversal`

for next time:

- Continue with blockchain Traversal. Section 4.2.2.1, Step 2.


2025-08-25 (part 2)

- Added to the Sans-I/O story, by drafting a FSM and an example that drives it.
- Added Beacon to various document types.
- `generate_beacon()` returns a strict `Vec<Beacon>` instead of json::Value

for next time:

- Continue with blockchain Traversal. Section 4.2.2.1, Step 4/5.

2025-08-25 (part 3)

Jay worked a bit on his own and accomplished the following:

- Remove unused dependencies.
- Remove the unused workspace.
- Group dependencies and sort by name.
- Remove the unwraps in our example with anyhow.
- Split blockchain traversal FSM into public TraversalState and private TraversalFsm.
- Remove the Did argument from Document constructors.
- Replace the macro for DocumentFields with a single From impl that uses an extension trait for Did/String.
- Add Blockchain RPC host to ResolutionOptions::sidecar_data.
- Remove ContemporaryDocument. It's identical to InitialDocument, but it was causing some friction to use.
- Remove more unneeded Did method arguments where the DID is available on self.
- Pull all parsed document fields into InitialDocument.
- Move the FSM in and out of the traversal API using type-state. Resolves API misuse before it can ever happen.


2025-08-26

We started mobbing today, but hit some confusing blockchain traveral
algorithm steps due to a huge Beacons chapter refactoring that got
merged into the spec. We asked for clarification over signal and will
continue tomorrow.

