use crate::identifier::Network;
use esploda::bitcoin::address::Address;
use onlyerror::Error;
use serde_json::{Value, json};
use std::{fmt, str::FromStr};

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid beacon type
    InvalidBeaconType,

    /// Invalid BIP21 address.
    InvalidBip21,

    /// Bitcoin Address Parse error
    AddressParse(#[from] esploda::bitcoin::address::Error),

    /// Identifier Parse Error
    IdentifierParse(#[from] crate::identifier::Error),
}

/// Extension trait for [`Address`]. Allows parsing from [BIP21] URI.
///
/// [BIP21]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
pub trait AddressExt {
    fn from_bip21(uri: &str, network: Network) -> Result<Self, Error>
    where
        Self: Sized;
}

impl AddressExt for Address {
    fn from_bip21(uri: &str, network: Network) -> Result<Self, Error> {
        let address = uri.strip_prefix("bitcoin:").ok_or(Error::InvalidBip21)?;
        let address = address
            .split_once('?')
            .map(|(addr, _params)| addr)
            .unwrap_or(address);

        Ok(address
            .parse::<Address<_>>()?
            .require_network(network.try_into()?)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub(crate) ty: Type,
    pub(crate) descriptor: Address,
    pub(crate) min_confirmations_required: u32, // todo: need to figure out how to make this optional in the json @context
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Singleton,
    Map,
    SparseMerkleTree,
}

impl FromStr for Type {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self, Self::Err> {
        match ty {
            "SingletonBeacon" => Ok(Self::Singleton),
            "MapBeacon" => Ok(Self::Map),
            "SMTBeacon" => Ok(Self::SparseMerkleTree),
            _ => Err(Error::InvalidBeaconType),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Singleton => f.write_str("SingletonBeacon"),
            Self::Map => f.write_str("MapBeacon"),
            Self::SparseMerkleTree => f.write_str("SMTBeacon"),
        }
    }
}

impl Beacon {
    pub(crate) fn new(ty: Type, descriptor: Address, min_confirmations_required: u32) -> Self {
        Self {
            ty,
            descriptor,
            min_confirmations_required,
        }
    }

    pub(crate) fn into_json(self) -> Value {
        json!({
            "type": self.ty.to_string(),
            "descriptor": format!("bitcoin:{}", self.descriptor),
            "minimumConfirmationsRequired": self.min_confirmations_required,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_beacon_address_uri() {
        let address =
            Address::from_bip21("foo:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU", Network::Regtest);

        assert!(matches!(address, Err(Error::InvalidBip21)));
    }
}
