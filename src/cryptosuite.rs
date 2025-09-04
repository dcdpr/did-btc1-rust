/// BIP340 cryptosuite implementation
pub(crate) mod bip340;

/// Shared utilities for cryptosuites
pub(crate) mod utils;

pub(crate) enum CryptoSuite {
    Jcs, // TODO: Remove JCS asap

    #[allow(dead_code)]
    Rdfc,
}
