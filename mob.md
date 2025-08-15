
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

