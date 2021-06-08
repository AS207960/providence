use std::convert::TryFrom;

fn count_bits_set(i: u64) -> usize {
    i.count_ones() as usize
}

fn lowest_bit_set(i: u64) -> usize {
    (i.trailing_zeros() + 1) as usize
}

fn compute_sha256_hash(data: &[u8]) -> Result<[u8; 32], String> {
    let digest = match openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &data) {
        Ok(v) => v.to_vec(),
        Err(_) => return Err("Failed to make digest".to_string())
    };
    Ok(<[u8; 32]>::try_from(digest).unwrap())
}

fn computer_merkle_node_hash(left: &[u8], right: &[u8]) -> Result<[u8; 32], String> {
    let mut out = vec![0x01];
    out.extend_from_slice(left);
    out.extend_from_slice(right);
    compute_sha256_hash(&out)
}

fn computer_merkle_node_hash_one(entry: &[u8]) -> Result<[u8; 32], String> {
    let mut out = vec![0x00];
    out.extend_from_slice(entry);
    compute_sha256_hash(&out)
}

#[derive(Debug)]
pub struct CompactMerkleTree {
    tree_size: u64,
    hashes: Vec<[u8; 32]>,
    min_tree_height: usize,
    root_hash: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
pub struct CompactMerkleTreeSave {
    tree_size: u64,
    hashes: Vec<[u8; 32]>,
}

impl CompactMerkleTree {
    pub fn new() -> Self {
        CompactMerkleTree {
            tree_size: 0,
            hashes: vec![],
            min_tree_height: 0,
            root_hash: None,
        }
    }

    pub fn load(&mut self, save: &CompactMerkleTreeSave) {
        self.update(save.tree_size, save.hashes.to_vec());
    }

    pub fn save(&self) -> CompactMerkleTreeSave {
        CompactMerkleTreeSave {
            tree_size: self.tree_size,
            hashes: self.hashes.clone()
        }
    }

    fn update(&mut self, tree_size: u64, hashes: Vec<[u8; 32]>) {
        let bits_set = count_bits_set(tree_size);
        let num_hashes = hashes.len();
        if num_hashes != bits_set {
            return;
        }
        self.tree_size = tree_size;
        self.hashes = hashes;
        self.min_tree_height = lowest_bit_set(tree_size);
        self.root_hash = None;
    }

    fn hash_full(&self, leaves: &[&[u8]], left: usize, right: usize) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
        let width = right - left;
        if right > leaves.len() {
            Err(format!("{},{} is not a valid range over [0..{}]", left, right, leaves.len()))
        } else if width == 0 {
            Ok((compute_sha256_hash(&[])?, vec![]))
        } else if width == 1 {
            let leaf_hash = computer_merkle_node_hash_one(&leaves[left])?;
            Ok((leaf_hash, vec![leaf_hash]))
        } else {
            let k = 2_usize.pow((((width - 1) as f64).log(2.0).floor()) as u32);
            assert!(k < width as usize);
            assert!(width as usize <= 2 * k);
            let (left_root, mut left_hashes) = self.hash_full(leaves, left, left + k)?;
            assert_eq!(left_hashes.len(), 1);
            let (right_root, mut right_hashes) = self.hash_full(leaves, left + k, right)?;
            let root_hash = computer_merkle_node_hash(&left_root, &right_root)?;
            let out_hashes = match k * 2 == width {
                true => vec![root_hash],
                false => {
                    left_hashes.append(&mut right_hashes);
                    left_hashes
                }
            };
            Ok((root_hash, out_hashes))
        }
    }

    fn hash_fold(&self, hashes: &[[u8; 32]]) -> Result<[u8; 32], String> {
        let mut hashes = hashes.to_vec();
        hashes.reverse();
        let mut rev_hashes = hashes.into_iter();
        let mut accum = rev_hashes.next().unwrap();
        for cur in rev_hashes {
            accum = computer_merkle_node_hash(&cur, &accum)?;
        }
        Ok(accum)
    }

    fn push_subtree(&mut self, leaves: &[&[u8]]) -> Result<(), String> {
        let size = leaves.len();
        if count_bits_set(size as u64) != 1 {
            return Err(format!("Invalid subtree size: {}", size));
        }
        let subtree_h = lowest_bit_set(size as u64);
        if self.min_tree_height > 0 && subtree_h > self.min_tree_height {
            return Err(format!("Subtree {} greater than current smallest subtree {}", subtree_h, self.min_tree_height));
        }
        let (root_hash, hashes) = self.hash_full(leaves, 0, size)?;
        assert_eq!(hashes.len(), 1);
        self.push_subtree_hash(subtree_h, root_hash)?;
        Ok(())
    }

    fn push_subtree_hash(&mut self, subtree_h: usize, sub_hash: [u8; 32]) -> Result<(), String> {
        let size: u64 = 1 << (subtree_h - 1);
        let min_tree_height = self.min_tree_height;
        if subtree_h < min_tree_height || min_tree_height == 0 {
            let mut new_hashes = self.hashes.clone();
            new_hashes.push(sub_hash);
            self.update(self.tree_size + size, new_hashes);
            Ok(())
        } else {
            assert_eq!(subtree_h, min_tree_height);
            let prev_hash = self.hashes.pop().unwrap();
            self.update(self.tree_size - size, self.hashes.clone());
            assert!(min_tree_height < self.min_tree_height || self.min_tree_height == 0);
            let next_hash = computer_merkle_node_hash(&prev_hash, &sub_hash)?;
            self.push_subtree_hash(subtree_h + 1, next_hash)
        }
    }

    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    pub fn root_hash(&mut self) -> Result<[u8; 32], String> {
        match &self.root_hash {
            Some(h) => Ok(h.clone()),
            None => {
                let new_hash = if self.hashes.len() != 0 {
                    self.hash_fold(&self.hashes)?
                } else {
                    compute_sha256_hash(&[])?
                };
                self.root_hash.replace(new_hash.clone());
                Ok(new_hash)
            }
        }
    }

    #[allow(dead_code)]
    pub fn append(&mut self, leaf: &[u8]) -> Result<(), String> {
        self.push_subtree(&[leaf])
    }

    #[allow(dead_code)]
    pub fn extend(&mut self, leaves: &[&[u8]]) -> Result<(), String> {
        let size = leaves.len();
        let final_size = self.tree_size + size as u64;
        let mut idx = 0;
        loop {
            let max_size = if self.min_tree_height > 0 {
                1 << (self.min_tree_height - 1)
            } else {
                0
            };
            if self.min_tree_height > 0 && size - idx >= max_size {
                self.push_subtree(&leaves[idx..idx + max_size])?;
                idx += max_size;
            } else {
                break;
            }
        }
        if idx < size {
            let (_root_hash, mut hashes) = self.hash_full(leaves, idx, size)?;
            let mut new_hashes = self.hashes.clone();
            new_hashes.append(&mut hashes);
            self.update(final_size, new_hashes);
        }
        assert_eq!(self.tree_size, final_size);
        Ok(())
    }
}