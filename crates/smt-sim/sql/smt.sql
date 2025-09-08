-- SQL schema for Sparse Merkle Tree

CREATE TABLE IF NOT EXISTS smt (
    id BLOB NOT NULL PRIMARY KEY,
    path BLOB,
    left_child BLOB,
    right_child BLOB
) STRICT;
