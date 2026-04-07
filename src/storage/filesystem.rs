//! Filesystem blob storage with hash-bucketed directories.

use std::collections::HashMap;
use std::path::PathBuf;

use tracing::{info, instrument, warn};

use super::{make_descriptor, make_descriptor_from_hash, BlobBackend};
use crate::protocol::{BlobDescriptor, STREAM_CHUNK_SIZE};

/// Filesystem blob storage.
///
/// Blobs are stored as `<data_dir>/<sha256>.blob` files. On creation,
/// the directory is scanned for existing blobs to rebuild the index.
pub struct FilesystemBackend {
    data_dir: PathBuf,
    index: HashMap<String, u64>,
}

impl FilesystemBackend {
    /// Create a new filesystem backend. Creates the directory if it doesn't exist.
    /// Scans for existing blobs on startup.
    #[instrument(name = "blossom.storage.fs.init", skip_all, fields(
        storage.backend = "filesystem",
        storage.data_dir = %data_dir,
        storage.existing_blobs,
    ))]
    pub fn new(data_dir: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(data_dir);
        std::fs::create_dir_all(&path)?;

        let mut index = HashMap::new();
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".blob") {
                let hash = name.trim_end_matches(".blob").to_string();
                if hash.len() == 64 {
                    let size = entry.metadata()?.len();
                    index.insert(hash, size);
                }
            }
        }

        tracing::Span::current().record("storage.existing_blobs", index.len());
        info!(
            storage.backend = "filesystem",
            storage.data_dir = %path.display(),
            storage.existing_blobs = index.len(),
            "initialized filesystem blob storage"
        );

        Ok(Self {
            data_dir: path,
            index,
        })
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        self.data_dir.join(format!("{}.blob", sha256))
    }
}

impl BlobBackend for FilesystemBackend {
    fn insert(&mut self, data: Vec<u8>, base_url: &str) -> BlobDescriptor {
        let desc = make_descriptor(&data, base_url);
        let path = self.blob_path(&desc.sha256);
        if let Err(e) = std::fs::write(&path, &data) {
            warn!(
                storage.backend = "filesystem",
                blob.sha256 = %desc.sha256,
                error.message = %e,
                "failed to write blob to disk"
            );
        }
        self.index.insert(desc.sha256.clone(), desc.size);
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
        let path = self.blob_path(&desc.sha256);
        if let Err(e) = std::fs::write(&path, &data) {
            warn!(
                storage.backend = "filesystem",
                blob.sha256 = %desc.sha256,
                error.message = %e,
                "failed to write blob to disk"
            );
        }
        self.index.insert(desc.sha256.clone(), desc.size);
        desc
    }

    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        let path = self.blob_path(sha256);
        if path.exists() {
            std::fs::read(&path).ok()
        } else {
            None
        }
    }

    fn exists(&self, sha256: &str) -> bool {
        self.index.contains_key(sha256) || self.blob_path(sha256).exists()
    }

    fn delete(&mut self, sha256: &str) -> bool {
        let removed = self.index.remove(sha256).is_some();
        let _ = std::fs::remove_file(self.blob_path(sha256));
        removed
    }

    fn len(&self) -> usize {
        self.index.len()
    }

    fn total_bytes(&self) -> u64 {
        self.index.values().sum()
    }

    fn insert_stream(
        &mut self,
        reader: &mut dyn std::io::Read,
        _size: u64,
        base_url: &str,
    ) -> Result<BlobDescriptor, String> {
        use sha2::{Digest, Sha256};
        use std::io::Write;

        // Write to a temp file while computing SHA256 incrementally.
        let tmp_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_name = format!(".tmp_{}", tmp_id);
        let tmp_path = self.data_dir.join(&tmp_name);

        let result = (|| -> Result<BlobDescriptor, String> {
            let mut file =
                std::fs::File::create(&tmp_path).map_err(|e| format!("create temp: {e}"))?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; STREAM_CHUNK_SIZE];
            let mut total = 0u64;

            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| format!("read stream: {e}"))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n])
                    .map_err(|e| format!("write temp: {e}"))?;
                total += n as u64;
            }
            file.flush().map_err(|e| format!("flush temp: {e}"))?;

            let hash = hex::encode(hasher.finalize());
            let final_path = self.blob_path(&hash);
            std::fs::rename(&tmp_path, &final_path)
                .map_err(|e| format!("rename temp to blob: {e}"))?;

            self.index.insert(hash.clone(), total);

            info!(
                storage.backend = "filesystem",
                blob.sha256 = %hash,
                blob.size = total,
                "blob stored via streaming insert"
            );

            Ok(make_descriptor_from_hash(&hash, total, base_url))
        })();

        // Clean up temp file on error.
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_crud() {
        let tmp_dir =
            std::env::temp_dir().join(format!("blossom_fs_test_{}", rand::random::<u32>()));
        let mut store = FilesystemBackend::new(tmp_dir.to_str().unwrap()).unwrap();

        let data = vec![10u8, 20, 30, 40, 50];
        let desc = store.insert(data.clone(), "http://test");

        let blob_path = tmp_dir.join(format!("{}.blob", desc.sha256));
        assert!(blob_path.exists());

        let retrieved = store.get(&desc.sha256).unwrap();
        assert_eq!(retrieved, data);

        assert!(store.delete(&desc.sha256));
        assert!(!blob_path.exists());
        assert!(store.get(&desc.sha256).is_none());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_survives_restart() {
        let tmp_dir =
            std::env::temp_dir().join(format!("blossom_restart_{}", rand::random::<u32>()));

        let hash;
        {
            let mut store = FilesystemBackend::new(tmp_dir.to_str().unwrap()).unwrap();
            let desc = store.insert(vec![99u8; 100], "http://test");
            hash = desc.sha256.clone();
            assert_eq!(store.len(), 1);
        }

        {
            let store = FilesystemBackend::new(tmp_dir.to_str().unwrap()).unwrap();
            assert_eq!(store.len(), 1);
            assert!(store.exists(&hash));
            let data = store.get(&hash).unwrap();
            assert_eq!(data.len(), 100);
            assert!(data.iter().all(|&b| b == 99));
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_insert_stream() {
        let tmp_dir =
            std::env::temp_dir().join(format!("blossom_stream_{}", rand::random::<u32>()));
        let mut store = FilesystemBackend::new(tmp_dir.to_str().unwrap()).unwrap();

        let data = vec![42u8; 1_000_000]; // 1MB
        let expected_hash = crate::protocol::sha256_hex(&data);

        let mut cursor = std::io::Cursor::new(&data);
        let desc = store
            .insert_stream(&mut cursor, data.len() as u64, "http://test")
            .unwrap();

        assert_eq!(desc.sha256, expected_hash);
        assert_eq!(desc.size, 1_000_000);

        // Verify file on disk matches.
        let retrieved = store.get(&desc.sha256).unwrap();
        assert_eq!(retrieved.len(), 1_000_000);
        assert_eq!(crate::protocol::sha256_hex(&retrieved), expected_hash);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
