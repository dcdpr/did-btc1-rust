
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
