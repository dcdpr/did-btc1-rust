/// BIP340 JCS cryptosuite implementation
pub(crate) mod bip340_jcs;

// /// BIP340 RDFC cryptosuite implementation
// pub(crate) mod bip340_rdfc;

/// Shared utilities for cryptosuites
pub(crate) mod utils;

pub(crate) mod transformation;

pub(crate) enum CryptoSuite {
    Jcs, // TODO: Remove JCS asap

    #[allow(dead_code)]
    Rdfc,
}
