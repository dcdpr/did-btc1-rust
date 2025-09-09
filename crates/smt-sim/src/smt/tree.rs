//! Optimized Sparse Merkle Tree implementation.
//!
//! This is the core of the implementation that is shared across supported backends. It implements
//! the major algorithms for node insertion, proof construction, and Mermaid diagram rendering.
//! Supporting types and functions are also found here.

use bincode::{Encode, enc, error::EncodeError};
use monotree::Hash;
use onlyerror::Error;
use sha2::{Digest as _, Sha256};
use std::fmt::{self, Write as _};

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid Merkle root
    InvalidRoot,

    /// Invalid Proof
    InvalidProof,

    /// Sparse Merkle Tree depth exceeded maximum
    TooDeep,
}

/// This trait is an implementation detail. It provides the shared algorithms as default
/// implementations and leaves the Read/Write operations to be defined by implementers.
pub(crate) trait SmtBackend {
    type Error: From<Error>;

    fn insert_inner(
        &self,
        root: Option<&Hash>,
        key: &Hash,
        value: &Hash,
        depth: u16,
    ) -> Result<(Option<Hash>, Prefix), Self::Error> {
        // Keep track of depth, ensure it never exceeds 257 (256 levels + the root)
        if depth > (u8::MAX as u16) + 1 {
            return Err(Error::TooDeep.into());
        }

        if let Some(root) = root {
            match self.get_node(root).ok_or(Error::InvalidRoot)? {
                SmtNode::Leaf { key: old_key } => {
                    // When the root is a leaf node, create a new root and sibling leaf node.
                    let prefix = Prefix::longest_matching(key, &old_key);

                    Ok(self.insert_node(root, key, value, prefix))
                }

                SmtNode::Node {
                    prefix,
                    left,
                    right,
                } => {
                    // When the root is a full node, compare against the prefix to determine whether
                    // the new node will be internal or external.
                    //
                    // It's internal if the prefix matches: traverse the tree to find the insert
                    // location. Otherwise it's external and the new node needs to point to the
                    // existing node.
                    let matching = Prefix::longest_matching(&prefix.path, key);
                    if matching.bit_count < prefix.bit_count {
                        // Create external node.
                        Ok(self.insert_node(root, key, value, matching))
                    } else {
                        // Insert internal node.
                        let depth = depth.max(prefix.bit_count);
                        let insert_on_right = get_nth_bit(key, depth);
                        let target_root = if insert_on_right { &right } else { &left };
                        let (new_node, child_prefix) =
                            self.insert_inner(Some(target_root), key, value, depth + 1)?;
                        let new_node = new_node.unwrap();
                        let new_prefix = Prefix::new(child_prefix.bit_count.min(depth), key);

                        // Update the existing node to point at the new node.
                        let new_root = if insert_on_right {
                            self.update(root, &new_prefix, &left, &new_node)
                        } else {
                            self.update(root, &new_prefix, &new_node, &right)
                        };

                        Ok((Some(new_root), new_prefix))
                    }
                }
            }
        } else {
            let leaf = self.insert_leaf(key, value);

            Ok((Some(leaf), Prefix::new(256, key)))
        }
    }

    /// Get a node by its [`type@Hash`] identifier.
    fn get_node(&self, id: &Hash) -> Option<SmtNode>;

    /// Insert a key-value pair as a leaf node, returning its [`type@Hash`] identifier.
    fn insert_leaf(&self, key: &Hash, value: &Hash) -> Hash;

    /// Insert a new parent node that will point to the previous `root` and to a new leaf node using
    /// the key-value pair.
    ///
    /// The [`Prefix`] must be the longest matching key prefix between both subtrees.
    fn insert_node(
        &self,
        root: &Hash,
        key: &Hash,
        value: &Hash,
        prefix: Prefix,
    ) -> (Option<Hash>, Prefix);

    /// Update the links and prefix in an existing intermediate node identified by its [`type@Hash`]
    /// identifier.
    ///
    /// The [`Prefix`] must be the longest matching key prefix between both subtrees.
    fn update(&self, id: &Hash, prefix: &Prefix, left: &Hash, right: &Hash) -> Hash;

    fn build_proof(
        &self,
        proof: &mut Proof,
        root: &Hash,
        key: &Hash,
        depth: u16,
    ) -> Result<(), Self::Error> {
        // TODO: Only return `InvalidRoot` when depth == 0.
        // When deeper, return a proof-of-non-inclusion.
        match self.get_node(root).ok_or(Error::InvalidRoot)? {
            SmtNode::Leaf { .. } => Ok(()),

            SmtNode::Node {
                prefix,
                left,
                right,
            } => {
                let depth = depth.max(prefix.bit_count);
                if get_nth_bit(key, depth) {
                    // Sibling is on the left.
                    proof.path.push((Arrow::Left, left));

                    self.build_proof(proof, &right, key, depth + 1)
                } else {
                    // Sibling is on the right.
                    proof.path.push((Arrow::Right, right));

                    self.build_proof(proof, &left, key, depth + 1)
                }
            }
        }
    }

    fn render(&self, root: &Hash) -> Option<String> {
        let mut mermaid = String::new();
        writeln!(&mut mermaid, "graph TD").unwrap();
        self.render_inner(&mut mermaid, root)?;

        Some(mermaid)
    }

    fn render_inner(&self, mermaid: &mut String, hash: &Hash) -> Option<()> {
        match self.get_node(hash)? {
            SmtNode::Leaf { key } => {
                writeln!(
                    mermaid,
                    r#"  {}["Leaf<br />hash: {}<br />key: {}"]"#,
                    hex::encode(&hash[..4]),
                    hex::encode(&hash[..4]),
                    hex::encode(&key[..4]),
                )
                .unwrap();
            }

            SmtNode::Node {
                prefix,
                left,
                right,
            } => {
                self.render_node(mermaid, hash, &prefix, &left);
                self.render_node(mermaid, hash, &prefix, &right);
            }
        }

        Some(())
    }

    fn render_node(&self, mermaid: &mut String, hash: &Hash, prefix: &Prefix, next: &Hash) {
        let prefix_bytes = prefix.to_bytes();

        writeln!(
            mermaid,
            r#"  {}["Node<br />hash: {}<br />prefix: (bit_count {}) {}"] --> {}"#,
            hex::encode(&hash[..4]),
            hex::encode(&hash[..4]),
            prefix.bit_count,
            hex::encode(&prefix_bytes[2..6.min(prefix_bytes.len())]),
            hex::encode(&next[..4]),
        )
        .unwrap();
        self.render_inner(mermaid, next);
    }
}

#[derive(Clone, Encode)]
pub(crate) enum SmtNode {
    Leaf {
        key: Hash,
    },
    Node {
        prefix: Prefix,
        left: Hash,
        right: Hash,
    },
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

pub(crate) fn get_nth_bit(hash: &Hash, n: u16) -> bool {
    let i = usize::from(n / 8);
    let shift = 7 - (n % 8);

    (hash[i] & (1 << shift)) != 0
}

#[derive(Clone)]
pub(crate) struct Prefix {
    pub(crate) bit_count: u16,
    pub(crate) path: Hash,
}

impl Prefix {
    pub(crate) fn new(bit_count: u16, bytes: &Hash) -> Self {
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

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let byte_count = Self::byte_count(self.bit_count);
        let mut bytes = Vec::with_capacity(byte_count + 2);

        // Encode the bit count into the first two bytes
        bytes.extend(self.bit_count.to_le_bytes());
        bytes.extend(&self.path[..byte_count]);

        bytes
    }

    pub(crate) fn byte_count(bit_count: u16) -> usize {
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

// // TODO: Implement decode to allow loading from disk.
// impl<'de, Context> de::BorrowDecode<'de, Context> for Prefix {
//     fn borrow_decode<D: de::BorrowDecoder<'de, Context = Context>>(
//         decoder: &mut D,
//     ) -> Result<Self, DecodeError> {
//         todo!()
//     }
// }

// impl<Context> de::Decode<Context> for Prefix {
//     fn decode<D: de::Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
//         todo!()
//     }
// }

impl enc::Encode for Prefix {
    fn encode<E: enc::Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // Encode the bit count.
        bincode::Encode::encode(&self.bit_count, encoder)?;

        // Encode the prefix bytes as a variable-length slice.
        let byte_count = Self::byte_count(self.bit_count);
        bincode::Encode::encode(&self.path[..byte_count], encoder)?;

        Ok(())
    }
}

/// A cryptographic proof of inclusion (or non-inclusion) of a key-value pair within a Sparse Merkle
/// tree.
///
/// Constructed by [`Smt::get_proof`].
///
/// [`Smt::get_proof`]: crate::smt::Smt::get_proof
pub struct Proof {
    // TODO: Probably want to reverse the order to be compatible with the spec. VecDeque can do that
    // cheaply.
    /// Stores sibling hashes along the tree traversal path, ordered root -> leaf (omitting both).
    ///
    /// [`Self::verify`] requires the root and leaf to be provided as arguments.
    path: Vec<(Arrow, Hash)>,
}

impl Proof {
    pub(crate) fn new() -> Self {
        Self { path: Vec::new() }
    }

    /// Verify the proof against a known `root` and key-value pair.
    ///
    /// The key-value pair is hashed to create the initial leaf hash: `hash(key | value)`.
    pub fn verify(&self, root: &Hash, key: &Hash, value: &Hash) -> Result<(), Error> {
        let mut hash = hash_concat(key, value);

        for (arrow, sibling) in self.path.iter().rev() {
            hash = match arrow {
                Arrow::Left => hash_concat(sibling, &hash),
                Arrow::Right => hash_concat(&hash, sibling),
            };
        }

        if hash.as_slice() == root {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proof [\n")?;
        for (arrow, sibling) in &self.path {
            writeln!(f, "    {arrow} {},", hex::encode(sibling))?;
        }
        f.write_str("]")
    }
}

/// The sibling direction in relation to the traversal path.
enum Arrow {
    Left,
    Right,
}

impl fmt::Display for Arrow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Left => f.write_str("<--"),
            Self::Right => f.write_str("-->"),
        }
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

        let actual = Prefix::longest_matching(&[0x66; 32], &[0; 32]).to_bytes();
        let mut expected = [0; 3];
        expected[..2].copy_from_slice(&1_u16.to_le_bytes()[..2]);
        assert_eq!(actual, expected);
    }
}
