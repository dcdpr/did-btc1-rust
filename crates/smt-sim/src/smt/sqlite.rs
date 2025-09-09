use super::Smt;
use monotree::Hash;
use onlyerror::Error;
use rusqlite::{Connection, OptionalExtension as _, Row, named_params, types::ValueRef};
use sha2::{Digest as _, Sha256};
use std::fmt::{self, Write as _};

#[derive(Debug, Error)]
pub enum Error {
    /// Sqlite Error
    Sqlite(#[from] rusqlite::Error),

    /// Invalid Merkle root
    InvalidRoot,

    /// Bad Path
    BadPath,

    /// Invalid Proof
    InvalidProof,

    /// Sparse Merkle Tree depth exceeded maximum
    TooDeep,
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

        self.insert_inner(root, key, value, 0)
    }

    fn get_proof(
        &self,
        root: Option<&Hash>,
        key: &Hash,
    ) -> Result<Option<Self::Proof>, Self::Error> {
        let mut proof = Proof { path: Vec::new() };
        let root = root.ok_or(Error::InvalidRoot)?;

        self.build_proof(&mut proof, root, root, key, 0)?;
        Ok(Some(proof))
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
            let node = self.get_node(root)?;

            match dbg!(node.ok_or(Error::InvalidRoot)?) {
                SmtNode::Leaf { key: old_key } => {
                    // When the root is a leaf node, create a new root and sibling leaf node.
                    let new_node = self.insert_leaf(key, value)?;
                    let prefix = Prefix::longest_matching(key, &old_key);

                    eprintln!("insert key (leaf): {}", hex::encode(key));
                    Ok(Some(if dbg!(get_nth_bit(key, dbg!(&prefix).bit_count)) {
                        self.insert_node(prefix, root, &new_node)
                    } else {
                        self.insert_node(prefix, &new_node, root)
                    }?))
                }

                SmtNode::Node { left, right, .. } => {
                    // When the root is a full node, traverse the tree to find the insert location.
                    eprintln!("insert key (node): {}", hex::encode(key));
                    let insert_on_right = dbg!(get_nth_bit(key, dbg!(depth)));
                    let new_node = if insert_on_right {
                        self.insert_inner(Some(&right), key, value, depth + 1)
                    } else {
                        self.insert_inner(Some(&left), key, value, depth + 1)
                    }?
                    .unwrap();

                    // Update the existing node to point at the new node.
                    Ok(Some(if insert_on_right {
                        // Get the sibling node's key
                        let sibling_node = self.get_node(&left)?.unwrap();
                        // TODO: handle getting the key when the sibling is an intermediate node
                        let SmtNode::Leaf { key: sibling_key } = sibling_node else {
                            panic!("TODO: Get key at some depth");
                        };

                        eprintln!("sibling key (right): {}", hex::encode(sibling_key));
                        let prefix = dbg!(Prefix::longest_matching(&sibling_key, key));

                        self.update_right(root, prefix, &left, &new_node)
                    } else {
                        // Get the sibling node's key
                        let sibling_node = self.get_node(&right)?.unwrap();
                        // TODO: handle getting the key when the sibling is an intermediate node
                        let SmtNode::Leaf { key: sibling_key } = sibling_node else {
                            panic!("TODO: Get key at some depth");
                        };

                        eprintln!("sibling key (left): {}", hex::encode(sibling_key));
                        let prefix = dbg!(Prefix::longest_matching(key, &new_node));

                        self.update_left(root, prefix, &new_node, &right)
                    }?))
                }
            }
        } else {
            eprintln!("key (root): {}", hex::encode(key));
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

    fn insert_node(&self, prefix: Prefix, left: &Hash, right: &Hash) -> rusqlite::Result<Hash> {
        let id = hash_concat(left, right);

        self.db.execute(
            "INSERT INTO smt (id, path, left_child, right_child) VALUES (:id, :path, :left, :right)",
            named_params! {
                ":id": id,
                ":path": prefix.to_bytes(),
                ":left": left,
                ":right": right,
            },
        )?;

        Ok(id)
    }

    fn update_left(
        &self,
        id: &Hash,
        prefix: Prefix,
        left: &Hash,
        right: &Hash,
    ) -> rusqlite::Result<Hash> {
        let new_id = hash_concat(left, right);

        self.db.execute(
            "UPDATE smt SET id = :new_id, path = :path, left_child = :left WHERE id = :id",
            named_params! {
                ":new_id": new_id,
                ":path": prefix.to_bytes(),
                ":left": left,
                ":id": id,
            },
        )?;

        Ok(new_id)
    }

    fn update_right(
        &self,
        id: &Hash,
        prefix: Prefix,
        left: &Hash,
        right: &Hash,
    ) -> rusqlite::Result<Hash> {
        let new_id = hash_concat(left, right);

        self.db.execute(
            "UPDATE smt SET id = :new_id, path = :path, right_child = :right WHERE id = :id",
            named_params! {
                ":new_id": new_id,
                ":path": prefix.to_bytes(),
                ":right": right,
                ":id": id,
            },
        )?;

        Ok(new_id)
    }

    fn build_proof(
        &self,
        proof: &mut Proof,
        root: &Hash,
        sibling: &Hash,
        key: &Hash,
        depth: u16,
    ) -> Result<(), Error> {
        println!("root: {}", hex::encode(root));
        let node = self.get_node(root)?;

        proof.path.push(*sibling);

        match dbg!(node.ok_or(Error::InvalidRoot)?) {
            SmtNode::Leaf { .. } => {
                proof.path.push(*root);

                Ok(())
            }

            SmtNode::Node {
                left,
                right,
                prefix,
            } => {
                dbg!(prefix);
                if get_nth_bit(key, depth) {
                    self.build_proof(proof, &right, &left, key, depth + 1)
                } else {
                    self.build_proof(proof, &left, &right, key, depth + 1)
                }
            }
        }
    }

    pub fn render(&self, root: &Hash) -> Option<String> {
        let mut mermaid = String::new();
        writeln!(&mut mermaid, "graph TD").unwrap();
        self.render_inner(&mut mermaid, root);
        Some(mermaid)
    }

    fn render_inner(&self, mermaid: &mut String, hash: &Hash) {
        match self.get_node(hash).unwrap().unwrap() {
            SmtNode::Leaf { key } => {
                writeln!(
                    mermaid,
                    "  {}[\"hash: {}\nkey: {}\"]",
                    hex::encode(&hash[..4]),
                    hex::encode(&hash[..4]),
                    hex::encode(&key[..4]),
                )
                .unwrap();
            }

            SmtNode::Node { left, right, .. } => {
                writeln!(
                    mermaid,
                    "  {} --> {}",
                    hex::encode(&hash[..4]),
                    hex::encode(&left[..4]),
                )
                .unwrap();
                self.render_inner(mermaid, &left);

                writeln!(
                    mermaid,
                    "  {} --> {}",
                    hex::encode(&hash[..4]),
                    hex::encode(&right[..4]),
                )
                .unwrap();
                self.render_inner(mermaid, &right);
            }
        }
    }
}

#[derive(Clone)]
enum SmtNode {
    Leaf {
        key: Hash,
    },
    Node {
        // TODO: May not need to store the prefix at all!
        prefix: Prefix,
        left: Hash,
        right: Hash,
    },
}

impl SmtNode {
    fn from_sql(row: &Row<'_>) -> rusqlite::Result<Self> {
        let left = row.get_ref(1)?;
        let right = row.get_ref(2)?;

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

            (ValueRef::Null, ValueRef::Null) => Ok(Self::Leaf { key: row.get(0)? }),

            _ => Err(rusqlite::Error::ExecuteReturnedResults),
        }
    }
}

impl fmt::Debug for SmtNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SmtNode::")?;
        match self {
            Self::Leaf { key } => f
                .debug_struct("Leaf")
                .field("key", &hex::encode(key))
                .finish(),

            Self::Node {
                prefix,
                left,
                right,
            } => f
                .debug_struct("Node")
                .field("prefix", &prefix)
                .field("left", &hex::encode(left))
                .field("right", &hex::encode(right))
                .finish(),
        }
    }
}

pub fn hash_concat(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().as_slice().try_into().unwrap()
}

fn get_nth_bit(hash: &Hash, n: u16) -> bool {
    let i = usize::from(n / 8);
    let shift = 7 - (n % 8);

    (hash[i] & (1 << shift)) != 0
}

#[derive(Clone)]
struct Prefix {
    bit_count: u16,
    path: Hash,
}

impl Prefix {
    fn new(bit_count: u16, bytes: &Hash) -> Self {
        let byte_count = Self::byte_count(bit_count);

        let mut path = [0; 32];
        path[..byte_count].copy_from_slice(&bytes[..byte_count]);

        // Mask bits between bit_count up to (byte_count * 8)
        let leading_bits = bit_count % 8;
        if leading_bits > 0 {
            let mask = 0xff << (8 - leading_bits);
            let i = byte_count - 1;
            path[i] &= mask;
        }

        Self { bit_count, path }
    }

    fn longest_matching(a: &Hash, b: &Hash) -> Self {
        for i in 0..32 {
            if a[i] != b[i] {
                for j in (0..8).rev() {
                    if a[i] >> j != b[i] >> j {
                        return Self::new((i * 8 + (7 - j)).try_into().unwrap(), a);
                    }
                }
            }
        }

        Self::new(256, a)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let byte_count = Self::byte_count(self.bit_count);
        let mut bytes = Vec::with_capacity(byte_count + 2);

        // Encode the bit count into the first two bytes
        bytes.extend(self.bit_count.to_le_bytes());
        bytes.extend(&self.path[..byte_count]);

        bytes
    }

    fn byte_count(bit_count: u16) -> usize {
        (bit_count as f32 / 8.0).ceil() as usize
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prefix")
            .field("bit_count", &self.bit_count)
            .field(
                "bytes",
                &hex::encode(&self.path[..Prefix::byte_count(self.bit_count)]),
            )
            .finish()
    }
}

pub struct Proof {
    path: Vec<Hash>, // 0th: root hash; path hashes; nth: hash(key || value);
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proof [\n")?;
        for segment in &self.path {
            writeln!(f, "    {},", hex::encode(segment))?;
        }
        f.write_str("]")
    }
}

impl Proof {
    pub fn verify(&self, root: &Hash, key: &Hash, value: &Hash) -> Result<(), Error> {
        let leaf = hash_concat(key, value);

        // TODO: These checks can be implied by the final hash comparison
        // (these hashes are not needed in the path)
        if root != &self.path[0] {
            return Err(Error::InvalidRoot);
        }
        if &leaf != self.path.last().ok_or(Error::BadPath)? {
            return Err(Error::BadPath);
        }

        let mut hash = leaf;

        // TODO: The order of hash updates matters
        for (i, node) in self.path[..self.path.len() - 1]
            .iter()
            .skip(1)
            .enumerate()
            .rev()
        {
            hash = if get_nth_bit(key, dbg!(i.try_into().unwrap())) {
                hash_concat(node, &hash)
            } else {
                hash_concat(&hash, node)
            };
        }

        let possible_root = hash;

        println!("possible_root: {}", hex::encode(possible_root.as_slice()));

        if possible_root.as_slice() != root {
            return Err(Error::InvalidProof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_new() {
        let actual = Prefix::new(3, &[0xff; 32]).to_bytes();
        assert_eq!(actual, [3, 0, 0b1110_0000]);

        let actual = Prefix::new(17, &[0xff; 32]).to_bytes();
        assert_eq!(actual, [17, 0, 0b1111_1111, 0b1111_1111, 0b1000_0000]);

        let actual = Prefix::new(22, &[0xa5; 32]).to_bytes();
        assert_eq!(actual, [22, 0, 0b1010_0101, 0b1010_0101, 0b1010_0100]);
    }

    #[test]
    fn test_prefix_longest_matching() {
        let actual = Prefix::longest_matching(&[0; 32], &[0; 32]).to_bytes();
        let mut expected = [0; 2 + 32];
        expected[..2].copy_from_slice(&256_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);

        let actual = Prefix::longest_matching(&[0xff; 32], &[0; 32]).to_bytes();
        assert_eq!(actual, [0, 0]);

        let mut a = [0; 32];
        a[8..].copy_from_slice(&[0xff; 32 - 8]);
        let actual = Prefix::longest_matching(&a, &[0; 32]).to_bytes();
        let mut expected = [0; 2 + 8];
        expected[..2].copy_from_slice(&64_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);

        let actual = Prefix::longest_matching(&[6; 32], &[0; 32]).to_bytes();
        let mut expected = [0; 3];
        expected[..2].copy_from_slice(&5_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);
    }
}
