pub use self::sqlite::SmtSqlite;
pub use monotree::Hash;
use monotree::database::{rocksdb::RocksDB, sled::Sled};
use monotree::{Monotree, hasher::Sha2};
use std::cell::RefCell;

mod sqlite;

pub struct SmtRocks(RefCell<Monotree<RocksDB, Sha2>>);
pub struct SmtSled(RefCell<Monotree<Sled, Sha2>>);

pub trait Smt {
    const EXT: &str;
    type Proof;
    type Error;

    fn new(db_path: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn prepare(&self);

    fn commit(&self);

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error>;

    fn get_proof(
        &self,
        root: Option<&Hash>,
        key: &Hash,
    ) -> Result<Option<Self::Proof>, Self::Error>;
}

impl Smt for SmtRocks {
    const EXT: &str = "rocksdb";
    type Proof = Vec<(bool, Vec<u8>)>;
    type Error = monotree::Errors;

    fn new(db_path: &str) -> Result<Self, Self::Error> {
        Ok(Self(RefCell::new(Monotree::new(db_path))))
    }

    fn prepare(&self) {
        self.0.borrow_mut().prepare();
    }

    fn commit(&self) {
        self.0.borrow_mut().commit();
    }

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error> {
        self.0.borrow_mut().insert(root, key, value)
    }

    fn get_proof(
        &self,
        root: Option<&Hash>,
        key: &Hash,
    ) -> Result<Option<Self::Proof>, Self::Error> {
        self.0.borrow_mut().get_merkle_proof(root, key)
    }
}

impl Smt for SmtSled {
    const EXT: &str = "sled";
    type Proof = Vec<(bool, Vec<u8>)>;
    type Error = monotree::Errors;

    fn new(db_path: &str) -> Result<Self, Self::Error> {
        Ok(Self(RefCell::new(Monotree::new(db_path))))
    }

    fn prepare(&self) {
        self.0.borrow_mut().prepare();
    }

    fn commit(&self) {
        self.0.borrow_mut().commit();
    }

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error> {
        self.0.borrow_mut().insert(root, key, value)
    }

    fn get_proof(
        &self,
        root: Option<&Hash>,
        key: &Hash,
    ) -> Result<Option<Self::Proof>, Self::Error> {
        self.0.borrow_mut().get_merkle_proof(root, key)
    }
}
