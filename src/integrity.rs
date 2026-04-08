//! Build integrity and release verification.
//!
//! Provides deterministic source-build manifests, signed release manifests,
//! and Merkle tree attestation for zero-knowledge selective file disclosure.
//!
//! ## Build-time
//!
//! The `blossom-server` build.rs hashes all workspace source files and embeds
//! the aggregate hash as `BLOSSOM_SOURCE_BUILD_HASH`. This enables runtime
//! verification that the binary matches a known source state.
//!
//! ## Release signing
//!
//! Use `cargo xtask sign-release-manifest` to sign release binaries with a
//! Nostr BIP-340 key. The signed manifest can be verified at startup.
//!
//! ## Merkle attestation
//!
//! `cargo xtask source-merkle-tree` builds a Merkle tree of source files.
//! Individual files can be proved as members without revealing other files.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{BlossomSigner, Signer};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Integrity verification status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    Verified,
    Mismatch,
    Unsigned,
    Unavailable,
}

impl IntegrityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::Unsigned => "unsigned",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A file path + SHA256 hash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityEntry {
    pub path: String,
    pub sha256: String,
}

/// Source-build manifest generated at compile time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceBuildManifest {
    pub manifest_version: u32,
    pub manifest_kind: String,
    pub hash_algorithm: String,
    pub target: String,
    pub aggregate_hash: String,
    pub entries: Vec<IntegrityEntry>,
}

/// Signed release manifest for deployed binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub manifest_version: u32,
    pub manifest_kind: String,
    pub hash_algorithm: String,
    pub package_name: String,
    pub target: String,
    pub aggregate_hash: String,
    pub signer_npub: String,
    pub signature: String,
    pub entries: Vec<IntegrityEntry>,
}

/// Runtime integrity information exposed via API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeIntegrityInfo {
    pub integrity_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_manifest_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_signer_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_build_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_target: Option<String>,
}

/// Signing configuration for release manifests.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Hex-encoded nsec for release signing.
    pub nsec_hex: Option<String>,
}

// ---------------------------------------------------------------------------
// Runtime integrity
// ---------------------------------------------------------------------------

/// Get cached runtime integrity info. Call from status endpoints.
pub fn runtime_integrity_info(
    source_build_hash: Option<&str>,
    build_target: Option<&str>,
) -> RuntimeIntegrityInfo {
    static CACHE: OnceLock<RuntimeIntegrityInfo> = OnceLock::new();
    CACHE
        .get_or_init(|| build_runtime_integrity_info(source_build_hash, build_target))
        .clone()
}

fn build_runtime_integrity_info(
    source_build_hash: Option<&str>,
    build_target: Option<&str>,
) -> RuntimeIntegrityInfo {
    let verified = load_and_verify_release_manifest();
    match verified {
        Some((manifest, status)) => RuntimeIntegrityInfo {
            integrity_status: status.as_str().to_string(),
            release_manifest_hash: Some(manifest.aggregate_hash),
            release_signer_npub: npub_hex_to_bech32(&manifest.signer_npub),
            source_build_hash: source_build_hash.map(String::from),
            build_target: build_target.map(String::from),
        },
        None => RuntimeIntegrityInfo {
            integrity_status: IntegrityStatus::Unsigned.as_str().to_string(),
            release_manifest_hash: None,
            release_signer_npub: None,
            source_build_hash: source_build_hash.map(String::from),
            build_target: build_target.map(String::from),
        },
    }
}

fn load_and_verify_release_manifest() -> Option<(ReleaseManifest, IntegrityStatus)> {
    let manifest_path = release_manifest_path()?;
    let manifest_bytes = std::fs::read(&manifest_path).ok()?;
    let manifest = serde_json::from_slice::<ReleaseManifest>(&manifest_bytes).ok()?;
    let status = verify_release_manifest(&manifest, &manifest_path);
    Some((manifest, status))
}

/// Verify a release manifest: check aggregate hash, signature, and file hashes.
pub fn verify_release_manifest(
    manifest: &ReleaseManifest,
    manifest_path: &Path,
) -> IntegrityStatus {
    if manifest.hash_algorithm != "sha256" || manifest.manifest_kind != "release-package" {
        return IntegrityStatus::Mismatch;
    }

    let computed = aggregate_hash("release-package", &manifest.target, &manifest.entries);
    if computed != manifest.aggregate_hash {
        return IntegrityStatus::Mismatch;
    }

    let digest = match decode_hash(&manifest.aggregate_hash) {
        Some(bytes) => bytes,
        None => return IntegrityStatus::Mismatch,
    };
    if !Signer::verify(&manifest.signer_npub, &digest, &manifest.signature) {
        return IntegrityStatus::Mismatch;
    }

    let root = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    for entry in &manifest.entries {
        let path = root.join(&entry.path);
        let hash = match hash_file(&path) {
            Ok(hash) => hash,
            Err(_) => return IntegrityStatus::Mismatch,
        };
        if hash != entry.sha256 {
            return IntegrityStatus::Mismatch;
        }
    }

    IntegrityStatus::Verified
}

// ---------------------------------------------------------------------------
// Manifest generation
// ---------------------------------------------------------------------------

/// Generate a source-build manifest for the workspace.
pub fn generate_source_build_manifest(
    workspace_root: &Path,
    target: &str,
) -> Result<SourceBuildManifest, String> {
    let mut entries = discover_workspace_files(workspace_root)?
        .into_iter()
        .map(|relative| {
            let absolute = workspace_root.join(&relative);
            let hash = hash_file(&absolute)?;
            Ok(IntegrityEntry {
                path: relative.to_string_lossy().replace('\\', "/"),
                sha256: hash,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let agg = aggregate_hash("source-build", target, &entries);
    Ok(SourceBuildManifest {
        manifest_version: 1,
        manifest_kind: "source-build".to_string(),
        hash_algorithm: "sha256".to_string(),
        target: target.to_string(),
        aggregate_hash: agg,
        entries,
    })
}

/// Generate a signed release manifest for a package directory.
pub fn generate_release_manifest(
    package_root: &Path,
    target: &str,
    signing: &SigningConfig,
) -> Result<ReleaseManifest, String> {
    let paths = discover_release_files(package_root)?;
    generate_release_manifest_for_entries(package_root, paths, target, signing)
}

/// Generate a signed release manifest for specific files.
pub fn generate_release_manifest_for_entries(
    package_root: &Path,
    paths: Vec<PathBuf>,
    target: &str,
    signing: &SigningConfig,
) -> Result<ReleaseManifest, String> {
    let signer = signing_identity(signing)?;
    let mut entries = paths
        .into_iter()
        .map(|relative| {
            let absolute = package_root.join(&relative);
            let hash = hash_file(&absolute)?;
            Ok(IntegrityEntry {
                path: relative.to_string_lossy().replace('\\', "/"),
                sha256: hash,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let agg = aggregate_hash("release-package", target, &entries);
    let digest = decode_hash(&agg).ok_or("invalid aggregate hash")?;
    let sig = signer.sign_schnorr(&digest);
    Ok(ReleaseManifest {
        manifest_version: 1,
        manifest_kind: "release-package".to_string(),
        hash_algorithm: "sha256".to_string(),
        package_name: "blossom-server".to_string(),
        target: target.to_string(),
        aggregate_hash: agg,
        signer_npub: signer.public_key_hex(),
        signature: sig,
        entries,
    })
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Source Merkle tree for zero-knowledge file attestation.
///
/// Leaves are SHA-256 hashes of individual files. The tree structure
/// (paths + hashes, NOT contents) can be published for selective disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMerkleTree {
    pub version: u32,
    pub hash_algorithm: String,
    pub root: String,
    pub file_count: usize,
    pub leaves: Vec<IntegrityEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Merkle inclusion proof for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path: String,
    pub leaf_hash: String,
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root. `bool` = sibling is on the right.
    pub proof: Vec<(String, bool)>,
    pub root: String,
}

impl SourceMerkleTree {
    /// Build from workspace source files.
    pub fn build(workspace_root: &Path) -> Result<Self, String> {
        let files = discover_workspace_files(workspace_root)?;
        let mut leaves: Vec<IntegrityEntry> = files
            .iter()
            .map(|relative| {
                let absolute = workspace_root.join(relative);
                let hash = hash_file(&absolute)?;
                Ok(IntegrityEntry {
                    path: relative.to_string_lossy().replace('\\', "/"),
                    sha256: hash,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        leaves.sort_by(|a, b| a.path.cmp(&b.path));
        let root = compute_merkle_root(&leaves);
        Ok(Self {
            version: 1,
            hash_algorithm: "sha256".to_string(),
            root,
            file_count: leaves.len(),
            leaves,
            signer_npub: None,
            signature: None,
        })
    }

    /// Sign the Merkle root.
    pub fn sign(&mut self, signing: &SigningConfig) -> Result<(), String> {
        let signer = signing_identity(signing)?;
        let digest = decode_hash(&self.root).ok_or("invalid merkle root hash")?;
        self.signature = Some(signer.sign_schnorr(&digest));
        self.signer_npub = Some(
            npub_hex_to_bech32(&signer.public_key_hex()).unwrap_or_else(|| signer.public_key_hex()),
        );
        Ok(())
    }

    /// Generate an inclusion proof for a specific file.
    pub fn proof_for(&self, path: &str) -> Option<MerkleProof> {
        let leaf_index = self.leaves.iter().position(|e| e.path == path)?;
        let leaf_hashes: Vec<[u8; 32]> = self
            .leaves
            .iter()
            .map(|e| decode_hash(&e.sha256).unwrap_or([0u8; 32]))
            .collect();
        let proof = merkle_proof(&leaf_hashes, leaf_index);
        Some(MerkleProof {
            path: path.to_string(),
            leaf_hash: self.leaves[leaf_index].sha256.clone(),
            leaf_index,
            proof: proof
                .iter()
                .map(|(hash, is_right)| (hex::encode(hash), *is_right))
                .collect(),
            root: self.root.clone(),
        })
    }

    /// Verify a file's content matches its leaf.
    pub fn verify_file(&self, path: &str, content: &[u8]) -> Result<bool, String> {
        let entry = self
            .leaves
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| format!("file '{}' not in tree", path))?;
        let actual = crate::protocol::sha256_hex(content);
        Ok(actual == entry.sha256)
    }

    /// Verify a Merkle proof against the tree root.
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        verify_merkle_proof(&proof.leaf_hash, &proof.proof, &self.root)
    }
}

/// Verify a Merkle proof: recompute root from leaf hash and siblings.
pub fn verify_merkle_proof(leaf_hash: &str, proof: &[(String, bool)], expected_root: &str) -> bool {
    let mut current = match decode_hash(leaf_hash) {
        Some(h) => h,
        None => return false,
    };
    for (sibling_hex, is_right) in proof {
        let sibling = match decode_hash(sibling_hex) {
            Some(h) => h,
            None => return false,
        };
        if *is_right {
            current = hash_pair(&current, &sibling);
        } else {
            current = hash_pair(&sibling, &current);
        }
    }
    hex::encode(current) == expected_root
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn aggregate_hash(kind: &str, target: &str, entries: &[IntegrityEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(target.as_bytes());
    hasher.update(b"\n");
    for entry in entries {
        hasher.update(entry.path.as_bytes());
        hasher.update(b"\t");
        hasher.update(entry.sha256.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("serialize json: {e}"))?;
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

pub fn workspace_root_from_manifest_dir(manifest_dir: &Path) -> PathBuf {
    manifest_dir.parent().unwrap_or(manifest_dir).to_path_buf()
}

fn signing_identity(signing: &SigningConfig) -> Result<Signer, String> {
    let nsec = signing.nsec_hex.as_deref().ok_or("missing signing nsec")?;
    Signer::from_secret_hex(nsec)
}

fn release_manifest_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BLOSSOM_RELEASE_MANIFEST_PATH") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let exe_name = exe.file_stem()?.to_string_lossy();

    // Try <binary-name>.manifest.json first (supports multiple binaries in same dir)
    let named = exe_dir.join(format!("{}.manifest.json", exe_name));
    if named.exists() {
        return Some(named);
    }

    // Fall back to generic name
    let generic = exe_dir.join("release-manifest.json");
    generic.exists().then_some(generic)
}

fn npub_hex_to_bech32(npub_hex: &str) -> Option<String> {
    let bytes = hex::decode(npub_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let hrp = bech32::Hrp::parse("npub").ok()?;
    bech32::encode::<bech32::Bech32>(hrp, &bytes).ok()
}

fn discover_workspace_files(workspace_root: &Path) -> Result<Vec<PathBuf>, String> {
    match std::process::Command::new("git")
        .arg("ls-files")
        .arg("-z")
        .current_dir(workspace_root)
        .output()
    {
        Ok(output) if output.status.success() => {
            let mut files = output
                .stdout
                .split(|b| *b == 0)
                .filter(|chunk| !chunk.is_empty())
                .filter_map(|chunk| std::str::from_utf8(chunk).ok().map(PathBuf::from))
                .filter(|path| include_workspace_file(path))
                .collect::<Vec<_>>();
            files.sort();
            Ok(files)
        }
        _ => {
            let mut files = Vec::new();
            walk_files(
                workspace_root,
                workspace_root,
                &mut files,
                include_workspace_file,
            )?;
            files.sort();
            Ok(files)
        }
    }
}

fn discover_release_files(package_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    walk_files(package_root, package_root, &mut files, include_release_file)?;
    files.sort();
    Ok(files)
}

fn include_workspace_file(path: &Path) -> bool {
    !is_ignored_component(path)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| !name.ends_with(".db") && !name.ends_with(".log"))
            .unwrap_or(true)
}

fn include_release_file(path: &Path) -> bool {
    !is_ignored_component(path)
        && path.file_name().and_then(|name| name.to_str()) != Some("release-manifest.json")
        && path.file_name().and_then(|name| name.to_str()) != Some("source-build-manifest.json")
}

fn is_ignored_component(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name == ".git" || name == "target" || name == ".idea" || name == ".vscode" || name == ".zed"
    })
}

fn walk_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
    include: fn(&Path) -> bool,
) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("dir entry {}: {e}", dir.display()))?;
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if is_ignored_component(&relative) {
            continue;
        }
        if path.is_dir() {
            walk_files(root, &path, files, include)?;
        } else if path.is_file() && include(&relative) {
            files.push(relative);
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(crate::protocol::sha256_hex(&bytes))
}

fn decode_hash(hash: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hash).ok()?;
    bytes.try_into().ok()
}

fn compute_merkle_root(leaves: &[IntegrityEntry]) -> String {
    if leaves.is_empty() {
        return hex::encode([0u8; 32]);
    }
    let mut hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|e| decode_hash(&e.sha256).unwrap_or([0u8; 32]))
        .collect();
    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        hashes = next;
    }
    hex::encode(hashes[0])
}

fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<([u8; 32], bool)> {
    if leaves.len() <= 1 {
        return vec![];
    }
    let mut proof = Vec::new();
    let mut hashes = leaves.to_vec();
    let mut idx = index;
    while hashes.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling = if sibling_idx < hashes.len() {
            hashes[sibling_idx]
        } else {
            hashes[idx]
        };
        let is_right = idx % 2 == 0;
        proof.push((sibling, is_right));
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        hashes = next;
        idx /= 2;
    }
    proof
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_hash_is_deterministic() {
        let entries = vec![
            IntegrityEntry {
                path: "a.txt".into(),
                sha256: "11".repeat(32),
            },
            IntegrityEntry {
                path: "b.txt".into(),
                sha256: "22".repeat(32),
            },
        ];
        let left = aggregate_hash("source-build", "x86_64-apple-darwin", &entries);
        let right = aggregate_hash("source-build", "x86_64-apple-darwin", &entries);
        assert_eq!(left, right);
    }

    #[test]
    fn release_manifest_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "blossom_integrity_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blossom-server"), b"binary").unwrap();

        let signer = Signer::generate();
        let signing = SigningConfig {
            nsec_hex: Some(signer.secret_key_hex()),
        };
        let manifest = generate_release_manifest(&dir, "test-target", &signing).unwrap();
        let manifest_path = dir.join("release-manifest.json");
        write_json_pretty(&manifest_path, &manifest).unwrap();

        assert_eq!(
            verify_release_manifest(&manifest, &manifest_path),
            IntegrityStatus::Verified
        );

        // Tamper and verify fails.
        std::fs::write(dir.join("blossom-server"), b"tampered").unwrap();
        assert_eq!(
            verify_release_manifest(&manifest, &manifest_path),
            IntegrityStatus::Mismatch
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merkle_tree_build_and_verify() {
        let dir = std::env::temp_dir().join(format!(
            "blossom_merkle_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.toml"), b"[package]\nname = \"test\"").unwrap();
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").unwrap();

        let tree = SourceMerkleTree::build(&dir).unwrap();
        assert_eq!(tree.file_count, 2);
        assert!(tree
            .verify_file("Cargo.toml", b"[package]\nname = \"test\"")
            .unwrap());
        assert!(!tree.verify_file("Cargo.toml", b"tampered").unwrap());

        // Merkle proof roundtrip.
        for leaf in &tree.leaves {
            let proof = tree.proof_for(&leaf.path).unwrap();
            assert!(tree.verify_proof(&proof));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merkle_tree_sign() {
        let dir = std::env::temp_dir().join(format!(
            "blossom_merkle_sign_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("file.txt"), b"content").unwrap();

        let signer = Signer::generate();
        let mut tree = SourceMerkleTree::build(&dir).unwrap();
        tree.sign(&SigningConfig {
            nsec_hex: Some(signer.secret_key_hex()),
        })
        .unwrap();

        assert!(tree.signer_npub.is_some());
        assert!(tree.signature.is_some());
        assert!(tree.signer_npub.as_ref().unwrap().starts_with("npub1"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
