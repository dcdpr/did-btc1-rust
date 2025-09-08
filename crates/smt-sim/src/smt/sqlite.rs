use super::Smt;
use monotree::Hash;
use onlyerror::Error;
use rusqlite::{Connection, OptionalExtension as _, Row, named_params, types::ValueRef};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Error)]
pub enum Error {
    /// Sqlite Error
    Sqlite(#[from] rusqlite::Error),

    /// Invalid Merkle root
    InvalidRoot,

    /// Sparse Merkle Tree depth exceeded maximum
    TooDeep,
}

pub struct SmtSqlite {
    db: Connection,
}

impl Smt for SmtSqlite {
    const EXT: &str = "sqlite";
    type Proof = ();
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

        self.insert_inner(root, key, value, 0)
    }

    fn get_proof(
        &self,
        root: Option<&Hash>,
        key: &Hash,
    ) -> Result<Option<Self::Proof>, Self::Error> {
        // TODO
        Ok(Some(()))
    }
}

impl SmtSqlite {
    fn insert_inner(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
        depth: u16,
    ) -> Result<Option<Hash>, Error> {
        // Keep track of depth, ensure it never exceeds 257 (256 levels + the root)
        if depth > (u8::MAX as u16) + 1 {
            return Err(Error::TooDeep);
        }

        if let Some(root) = root {
            let row = self.get_node(root)?;

            match row.ok_or(Error::InvalidRoot)? {
                SmtNode::Leaf { key: old_key } => {
                    // When the root is a leaf node, create a new root and sibling leaf node.
                    let new_node = self.insert_leaf(key, value)?;

                    Ok(Some(if new_node < old_key {
                        self.insert_node(&new_node, root)
                    } else {
                        self.insert_node(root, &new_node)
                    }?))
                }

                SmtNode::Node { left, right } => {
                    // When the root is a full node, traverse the tree to find the insert location.
                    let insert_on_right = get_nth_bit(key, depth.into());
                    let new_node = if insert_on_right {
                        self.insert_inner(Some(&right), key, value, depth + 1)
                    } else {
                        self.insert_inner(Some(&left), key, value, depth + 1)
                    }?
                    .unwrap();

                    // Update the existing node to point at the new node.
                    Ok(Some(if insert_on_right {
                        self.update_right(root, &left, &new_node)
                    } else {
                        self.update_left(root, &new_node, &right)
                    }?))
                }
            }
        } else {
            let leaf = self.insert_leaf(key, value)?;

            Ok(Some(leaf))
        }
    }

    fn get_node(&self, id: &Hash) -> rusqlite::Result<Option<SmtNode>> {
        self.db
            .query_one(
                "SELECT path, left_child, right_child FROM smt WHERE id = :id",
                named_params! {
                    ":id": id,
                },
                SmtNode::from_sql,
            )
            .optional()
    }

    fn insert_leaf(&self, key: &Hash, value: &Hash) -> rusqlite::Result<Hash> {
        let id = hash_concat(key, value);

        self.db.execute(
            "INSERT INTO smt (id, path) VALUES (:id, :path)",
            named_params! {
                ":id": id,
                ":path": key,
            },
        )?;

        Ok(id)
    }

    fn insert_node(&self, left: &Hash, right: &Hash) -> rusqlite::Result<Hash> {
        let id = hash_concat(left, right);

        self.db.execute(
            "INSERT INTO smt (id, left_child, right_child) VALUES (:id, :left, :right)",
            named_params! {
                ":id": id,
                ":left": left,
                ":right": right,
            },
        )?;

        Ok(id)
    }

    fn update_left(&self, id: &Hash, left: &Hash, right: &Hash) -> rusqlite::Result<Hash> {
        let new_id = hash_concat(left, right);

        self.db.execute(
            "UPDATE smt SET id = :new_id, left_child = :left WHERE id = :id",
            named_params! {
                ":new_id": new_id,
                ":left": left,
                ":id": id,
            },
        )?;

        Ok(new_id)
    }

    fn update_right(&self, id: &Hash, left: &Hash, right: &Hash) -> rusqlite::Result<Hash> {
        let new_id = hash_concat(left, right);

        self.db.execute(
            "UPDATE smt SET id = :new_id, right_child = :right WHERE id = :id",
            named_params! {
                ":new_id": new_id,
                ":right": right,
                ":id": id,
            },
        )?;

        Ok(new_id)
    }
}

#[derive(Clone, Debug)]
enum SmtNode {
    Leaf { key: Hash },
    Node { left: Hash, right: Hash },
}

impl SmtNode {
    fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let key = row.get_ref(0)?;
        let left = row.get_ref(1)?;
        let right = row.get_ref(2)?;

        match (left, right) {
            (ValueRef::Blob(left), ValueRef::Blob(right)) => Ok(Self::Node {
                left: left.try_into().unwrap(),
                right: right.try_into().unwrap(),
            }),

            (ValueRef::Null, ValueRef::Null) => match key {
                ValueRef::Blob(key) => Ok(Self::Leaf {
                    key: key.try_into().unwrap(),
                }),
                _ => unreachable!(),
            },

            _ => Err(rusqlite::Error::ExecuteReturnedResults),
        }
    }
}

fn hash_concat(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().as_slice().try_into().unwrap()
}

fn get_nth_bit(hash: &Hash, n: usize) -> bool {
    let i = n / 8;
    let shift = 7 - (n % 8);

    (hash[i] & (1 << shift)) != 0
}
