use onlyerror::Error;
use serde_json::Value;
use std::{fmt::Display, str::FromStr};

#[derive(Error, Debug)]
pub enum Error {
    /// Error converting JSON Value to str
    #[error("Object key `{0}` was expected to be type `{1}`")]
    UnexpectedJsonType(String, ExpectedType),

    /// Missing object key
    #[error("Object key `{0}` does not exist")]
    JsonMissingElement(String),

    /// Invalid number in JSON
    #[error("Invalid number in JSON. expected `{0}`")]
    InvalidNumber(ExpectedInt),

    /// Expected a JSON string
    ExpectedJsonStr,

    /// Error with key operations
    Key(#[from] crate::key::Error),

    /// DID Encoding error
    DidEncoding(#[from] crate::identifier::Error),

    /// Verification Error
    Verification(#[from] crate::verification::Error),

    /// Document beacon endpoints error
    Beacon(#[from] crate::beacon::Error),

    /// This should not happen: Only needed to satisfy `String: FromStr` trait bound
    Infallible(#[from] std::convert::Infallible),
}

#[derive(Debug)]
pub enum ExpectedType {
    Number,
    String,
    Boolean,
    Array,
    Object,
}

impl Display for ExpectedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedType::Number => write!(f, "Number"),
            ExpectedType::String => write!(f, "String"),
            ExpectedType::Boolean => write!(f, "Boolean"),
            ExpectedType::Array => write!(f, "Array"),
            ExpectedType::Object => write!(f, "Object"),
        }
    }
}

#[derive(Debug)]
pub enum ExpectedInt {
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
}

impl Display for ExpectedInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedInt::I8 => write!(f, "i8"),
            ExpectedInt::I16 => write!(f, "i16"),
            ExpectedInt::I32 => write!(f, "i32"),
            ExpectedInt::I64 => write!(f, "i64"),
            ExpectedInt::I128 => write!(f, "i128"),
            ExpectedInt::U8 => write!(f, "u8"),
            ExpectedInt::U16 => write!(f, "u16"),
            ExpectedInt::U32 => write!(f, "u32"),
            ExpectedInt::U64 => write!(f, "u64"),
            ExpectedInt::U128 => write!(f, "u128"),
        }
    }
}

pub(crate) trait ExpectedIntExt {
    fn from_num() -> ExpectedInt;
}

macro_rules! expected_int_ext {
    ($in:ty, $out:ident) => {
        impl ExpectedIntExt for $in {
            fn from_num() -> ExpectedInt {
                ExpectedInt::$out
            }
        }
    };
}

expected_int_ext!(i8, I8);
expected_int_ext!(i16, I16);
expected_int_ext!(i32, I32);
expected_int_ext!(i64, I64);
expected_int_ext!(i128, I128);
expected_int_ext!(u8, U8);
expected_int_ext!(u16, U16);
expected_int_ext!(u32, U32);
expected_int_ext!(u64, U64);
expected_int_ext!(u128, U128);

pub(crate) fn expected_int_error<T: ExpectedIntExt>() -> Error {
    Error::InvalidNumber(T::from_num())
}

/// Returns value[key] as a str if it is a JSON string.
pub(crate) fn string_from_object<'value>(
    value: &'value Value,
    key: &str,
) -> Result<&'value str, Error> {
    optional_string_from_object(value, key)
        .map(|maybe_int| maybe_int.ok_or_else(|| Error::JsonMissingElement(key.into())))?
}

/// Returns value[key] as a str if it is a JSON string, or `None` if the key is missing.
pub(crate) fn optional_string_from_object<'value>(
    value: &'value Value,
    key: &str,
) -> Result<Option<&'value str>, Error> {
    let obj = &value[key];

    if obj.is_null() {
        Ok(None)
    } else {
        obj.as_str()
            .map(Option::Some)
            .ok_or_else(|| Error::UnexpectedJsonType(key.into(), ExpectedType::String))
    }
}

/// Returns value[key] as an int if it is a JSON number.
pub(crate) fn int_from_object(value: &Value, key: &str) -> Result<i64, Error> {
    optional_int_from_object(value, key)
        .map(|maybe_int| maybe_int.ok_or_else(|| Error::JsonMissingElement(key.into())))?
}

/// Returns value[key] as an int if it is a JSON number, or `None` if the key is missing.
pub(crate) fn optional_int_from_object(value: &Value, key: &str) -> Result<Option<i64>, Error> {
    let obj = &value[key];

    if obj.is_null() {
        Ok(None)
    } else {
        obj.as_i64()
            .map(Option::Some)
            .ok_or_else(|| Error::UnexpectedJsonType(key.into(), ExpectedType::Number))
    }
}

/// Create a vector of any type from `value[key]` using a map function.
pub(crate) fn vec_from_object<T, F>(value: &Value, key: &str, map_fn: F) -> Result<Vec<T>, Error>
where
    F: Fn(&Value) -> Result<T, Error>,
{
    let obj = &value[key];

    if obj.is_null() {
        Ok(Vec::new())
    } else {
        obj.as_array()
            .ok_or_else(|| Error::UnexpectedJsonType(key.into(), ExpectedType::Array))?
            .iter()
            .map(map_fn)
            .collect::<Result<Vec<_>, Error>>()
    }
}

/// Returns a string if the JSON value is a string type.
pub(crate) fn string_from_value(value: &Value) -> Result<&str, Error> {
    value.as_str().ok_or(Error::ExpectedJsonStr)
}

/// Create a vector of any type from `value[key]` if it can be parsed from a string.
pub(crate) fn vec_from_value<T>(value: &Value, key: &str) -> Result<Vec<T>, Error>
where
    T: FromStr,
    Error: From<<T as FromStr>::Err>,
{
    vec_from_object(value, key, |v| Ok(string_from_value(v)?.parse()?))
}
