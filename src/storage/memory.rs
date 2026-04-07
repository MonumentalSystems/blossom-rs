//! In-memory blob storage (for testing and embedded use).

use std::collections::HashMap;

use super::{make_descriptor, make_descriptor_from_hash, BlobBackend};
use crate::protocol::BlobDescriptor;

/// In-memory blob storage backed by a HashMap.
///
/// Suitable for testing and lightweight embedded use. Not persistent.
pub struct MemoryBackend {
    blobs: HashMap<String, Vec<u8>>,
    index: HashMap<String, u64>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            blobs: HashMap::new(),
            index: HashMap::new(),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobBackend for MemoryBackend {
    fn insert(&mut self, data: Vec<u8>, base_url: &str) -> BlobDescriptor {
        let desc = make_descriptor(&data, base_url);
        self.index.insert(desc.sha256.clone(), desc.size);
        self.blobs.insert(desc.sha256.clone(), data);
        desc
    }

    fn insert_with_hash(
        &mut self,
        data: Vec<u8>,
        hash: &str,
        original_size: u64,
        base_url: &str,
    ) -> BlobDescriptor {
        let desc = make_descriptor_from_hash(hash, original_size, base_url);
        self.index.insert(desc.sha256.clone(), desc.size);
        self.blobs.insert(desc.sha256.clone(), data);
        desc
    }

    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        self.blobs.get(sha256).cloned()
    }

    fn exists(&self, sha256: &str) -> bool {
        self.index.contains_key(sha256)
    }

    fn delete(&mut self, sha256: &str) -> bool {
        self.blobs.remove(sha256);
        self.index.remove(sha256).is_some()
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn total_bytes(&self) -> u64 {
        self.index.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crud() {
        let mut store = MemoryBackend::new();
        let data = vec![1u8, 2, 3, 4, 5];

        let desc = store.insert(data.clone(), "http://test");
        assert_eq!(desc.size, 5);
        assert_eq!(store.len(), 1);
        assert!(store.exists(&desc.sha256));

        let retrieved = store.get(&desc.sha256).unwrap();
        assert_eq!(retrieved, data);

        assert!(store.delete(&desc.sha256));
        assert!(!store.exists(&desc.sha256));
        assert!(store.get(&desc.sha256).is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_deduplication() {
        let mut store = MemoryBackend::new();
        let data = b"deterministic content";
        let desc1 = store.insert(data.to_vec(), "http://test");
        let desc2 = store.insert(data.to_vec(), "http://test");
        assert_eq!(desc1.sha256, desc2.sha256);
        assert_eq!(store.len(), 1);
    }
}
