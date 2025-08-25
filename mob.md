
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
