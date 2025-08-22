use onlyerror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Missing or empty 'type' attribute
    MissingTypeAttribute,

    /// Missing or empty 'serviceEndpoint' attribute
    MissingServiceEndpointAttribute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    id: Option<String>,
    ty: Vec<String>,
    endpoint: Vec<String>,
}

impl Service {
    pub fn new<T, E>(id: Option<String>, ty: T, endpoint: E) -> Result<Self, Error>
    where
        T: IntoIterator<Item: ToString>,
        E: IntoIterator<Item: ToString>,
    {
        let ty: Vec<_> = ty.into_iter().map(|s| s.to_string()).collect();
        if ty.is_empty() {
            return Err(Error::MissingTypeAttribute);
        }

        let endpoint: Vec<_> = endpoint.into_iter().map(|s| s.to_string()).collect();
        if endpoint.is_empty() {
            return Err(Error::MissingServiceEndpointAttribute);
        }

        Ok(Self { id, ty, endpoint })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let service = Service::new(
            None,
            ["SingletonBeacon"],
            ["bitcoin:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU"],
        );
        assert!(service.is_ok());
    }

    #[test]
    fn test_missing_type() {
        let service = Service::new(None, [0; 0], ["bitcoin:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU"]);
        assert_eq!(service.unwrap_err(), Error::MissingTypeAttribute);
    }

    #[test]
    fn test_missing_service_endpoint() {
        let service = Service::new(None, ["SingletonBeacon"], [0; 0]);
        assert_eq!(service.unwrap_err(), Error::MissingServiceEndpointAttribute);
    }
}
