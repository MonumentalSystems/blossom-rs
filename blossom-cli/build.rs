use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let workspace_root = manifest_dir
        .parent()
        .expect("blossom-server should live in workspace")
        .to_path_buf();
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());

    let files = discover_source_files(&workspace_root).expect("source file discovery should work");
    for relative in &files {
        println!(
            "cargo:rerun-if-changed={}",
            workspace_root.join(relative).display()
        );
    }

    let entries = files
        .iter()
        .map(|relative| {
            let absolute = workspace_root.join(relative);
            let hash = hash_file(&absolute).expect("source file should hash");
            serde_json::json!({
                "path": relative.to_string_lossy().replace('\\', "/"),
                "sha256": hash,
            })
        })
        .collect::<Vec<_>>();

    let aggregate_hash = aggregate_hash("source-build", &target, &entries);
    let manifest = serde_json::json!({
        "manifest_version": 1u32,
        "manifest_kind": "source-build",
        "hash_algorithm": "sha256",
        "target": target,
        "aggregate_hash": aggregate_hash,
        "entries": entries,
    });

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let manifest_path = out_dir.join("source-build-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest json"),
    )
    .expect("build manifest should write");

    let cargo_toml_hash = hash_file(&manifest_dir.join("Cargo.toml")).expect("hash Cargo.toml");
    println!("cargo:rustc-env=BLOSSOM_CARGO_TOML_HASH={cargo_toml_hash}");
    println!("cargo:rustc-env=BLOSSOM_SOURCE_BUILD_HASH={aggregate_hash}");
    println!("cargo:rustc-env=BLOSSOM_BUILD_TARGET={target}");
    println!(
        "cargo:rustc-env=BLOSSOM_SOURCE_BUILD_MANIFEST_PATH={}",
        manifest_path.display()
    );
}

fn discover_source_files(workspace_root: &Path) -> io::Result<Vec<PathBuf>> {
    if let Some(files) = git_ls_files(workspace_root)? {
        return Ok(files);
    }
    let mut files = Vec::new();
    walk_files(workspace_root, workspace_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn git_ls_files(workspace_root: &Path) -> io::Result<Option<Vec<PathBuf>>> {
    let output = Command::new("git")
        .arg("ls-files")
        .arg("-z")
        .current_dir(workspace_root)
        .output();

    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(_) => return Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let mut files = output
        .stdout
        .split(|b| *b == 0)
        .filter(|chunk| !chunk.is_empty())
        .filter_map(|chunk| std::str::from_utf8(chunk).ok().map(PathBuf::from))
        .filter(|path| include_source_file(path))
        .collect::<Vec<_>>();
    files.sort();
    Ok(Some(files))
}

fn walk_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if should_skip(relative) {
            continue;
        }
        if path.is_dir() {
            walk_files(root, &path, files)?;
        } else if path.is_file() && include_source_file(relative) {
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn should_skip(path: &Path) -> bool {
    matches!(
        path.components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy()),
        Some(first)
            if first == ".git"
                || first == "target"
                || first == ".idea"
                || first == ".vscode"
                || first == ".zed"
    )
}

fn include_source_file(path: &Path) -> bool {
    !should_skip(path)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| !name.ends_with(".db") && !name.ends_with(".log"))
            .unwrap_or(true)
}

fn hash_file(path: &Path) -> io::Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn aggregate_hash(kind: &str, target: &str, entries: &[serde_json::Value]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(target.as_bytes());
    hasher.update(b"\n");
    for entry in entries {
        let path = entry
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let sha = entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        hasher.update(path.as_bytes());
        hasher.update(b"\t");
        hasher.update(sha.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}
