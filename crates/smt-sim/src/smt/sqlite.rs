//! Sparse Merkle Tree SQLite backend.
//!
//! Stores tree state in a local SQLite database. This backend is currently the slowest of all
//! supported backends. It is second in disk usage behind `SmtNih`, requiring around 69% more disk
//! space.
//!
//! Durability properties have been weakened in attempt to gain more performance. Higher durability
//! makes it on the order of another 3x slower. Which is not good for what is already the slowest
//! backend.

use super::Smt;
use super::tree::{Arrow, Prefix, Proof, SmtBackend, SmtNode, get_nth_bit, hash_concat};
use monotree::Hash;
use onlyerror::Error;
use rusqlite::{Connection, OptionalExtension as _, Row, named_params, types::ValueRef};

#[derive(Debug, Error)]
pub enum Error {
    /// Sqlite Error
    Sqlite(#[from] rusqlite::Error),

    /// SMT error
    Smt(#[from] super::tree::Error),
}

pub struct SmtSqlite {
    db: Connection,
}

impl Smt for SmtSqlite {
    const EXT: &str = "sqlite";
    type Proof = Proof;
    type Error = Error;

    fn new(db_path: &str) -> Result<Self, Self::Error> {
        let db = Connection::open(db_path)?;

        // // Settings for high durability (at the expense of performance)
        // db.pragma_update(None, "journal_mode", "WAL")?;
        // db.pragma_update(None, "synchronous", "NORMAL")?;
        // db.pragma_update(None, "locking_mode", "EXCLUSIVE")?;

        // // Settings for high performance (at the expect of durability)
        db.pragma_update(None, "journal_mode", "MEMORY")?;
        db.pragma_update(None, "synchronous", "OFF")?;
        db.pragma_update(None, "trusted_schema", "OFF")?;
        db.pragma_update(None, "locking_mode", "EXCLUSIVE")?;

        db.execute(include_str!("../../sql/smt.sql"), ())?;

        Ok(Self { db })
    }

    fn prepare(&self) {}

    fn commit(&self) {}

    fn insert(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
    ) -> Result<Option<Hash>, Self::Error> {
        let mut tx = self.db.unchecked_transaction()?;
        tx.set_drop_behavior(rusqlite::DropBehavior::Commit);

        let (root, _) = self.insert_inner(root, key, value, 0)?;

        Ok(root)
    }

    fn get_proof(&self, root: &Hash, key: &Hash) -> Result<Self::Proof, Self::Error> {
        let mut proof = Proof::new();

        self.build_proof(&mut proof, root, key, 0)?;

        Ok(proof)
    }

    fn render(&self, root: &Hash) -> Option<String> {
        <Self as SmtBackend>::render(self, root)
    }
}

impl SmtBackend for SmtSqlite {
    type Error = Error;

    fn get_node(&self, id: &Hash) -> Option<SmtNode> {
        self.db
            .query_one(
                "SELECT path, key_value, left_child, right_child FROM smt WHERE id = :id",
                named_params! {
                    ":id": id,
                },
                SmtNode::from_sql,
            )
            .optional()
            .unwrap()
    }

    fn insert_leaf(&self, key: &Hash, value: &Hash) -> Hash {
        let key_value = hash_concat(key, value);
        let id = Arrow::leaf_hash(key, &key_value);

        self.db
            .execute(
                "INSERT INTO smt (id, path, key_value) VALUES (:id, :path, :key_value)",
                named_params! {
                    ":id": id,
                    ":path": key,
                    ":key_value": key_value,
                },
            )
            .unwrap();

        id
    }

    fn insert_node(
        &self,
        root: &Hash,
        key: &Hash,
        value: &Hash,
        prefix: Prefix,
    ) -> (Option<Hash>, Option<Prefix>) {
        let new_node = self.insert_leaf(key, value);
        let (left, right) = if get_nth_bit(key, prefix.bit_count) {
            (root, &new_node)
        } else {
            (&new_node, root)
        };
        let id = hash_concat(left, right);

        self.db.execute(
            "INSERT INTO smt (id, path, left_child, right_child) VALUES (:id, :path, :left, :right)",
            named_params! {
                ":id": id,
                ":path": prefix.to_bytes(),
                ":left": left,
                ":right": right,
            },
        ).unwrap();

        (Some(id), Some(prefix))
    }

    fn update(&self, id: &Hash, prefix: &Prefix, left: &Hash, right: &Hash) -> Hash {
        let new_id = hash_concat(left, right);

        self.db
            .execute(
                "UPDATE smt SET id = :new_id, path = :path, left_child = :left, right_child = :right WHERE id = :id",
                named_params! {
                    ":new_id": new_id,
                    ":path": prefix.to_bytes(),
                    ":left": left,
                    ":right": right,
                    ":id": id,
                },
            )
            .unwrap();

        new_id
    }
}

impl SmtNode {
    fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let left = row.get_ref(2)?;
        let right = row.get_ref(3)?;

        match (left, right) {
            (ValueRef::Blob(left), ValueRef::Blob(right)) => {
                let mut bytes: Vec<u8> = row.get(0)?;

                // Decode first two bytes into a u16
                let bit_count = u16::from_le_bytes(bytes[..2].try_into().unwrap());

                bytes.resize_with(2 + 32, u8::default);
                let prefix = Prefix::new(bit_count, &bytes[2..].try_into().unwrap());

                Ok(Self::Node {
                    prefix,
                    left: left.try_into().unwrap(),
                    right: right.try_into().unwrap(),
                })
            }

            (ValueRef::Null, ValueRef::Null) => Ok(Self::Leaf {
                key: row.get(0)?,
                key_value: row.get(1)?,
            }),

            _ => Err(rusqlite::Error::ExecuteReturnedResults),
        }
    }
}
