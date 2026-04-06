use std::path::{Path, PathBuf};
use std::process::Command;

use blossom_rs::integrity::{
    generate_release_manifest, generate_release_manifest_for_entries,
    generate_source_build_manifest, verify_merkle_proof, workspace_root_from_manifest_dir,
    write_json_pretty, SigningConfig, SourceMerkleTree,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("xtask: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("sign-release-manifest") => sign_release_manifest(&args[1..]),
        Some("source-build-manifest") => source_build_manifest(&args[1..]),
        Some("source-merkle-tree") => source_merkle_tree(&args[1..]),
        Some("verify-source-file") => verify_source_file(&args[1..]),
        _ => Err(usage()),
    }
}

fn sign_release_manifest(args: &[String]) -> Result<(), String> {
    let root = workspace_root();
    let target = take_flag_value(args, "--target").unwrap_or_else(detect_target);
    let maybe_bin = take_flag_path(args, "--bin");
    let maybe_package_root = take_flag_path(args, "--package-root");
    let nsec = std::env::var("BLOSSOM_RELEASE_NSEC")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let signing = SigningConfig { nsec_hex: nsec };

    if signing.nsec_hex.is_none() {
        return Err("missing BLOSSOM_RELEASE_NSEC environment variable".into());
    }

    match (maybe_bin, maybe_package_root) {
        (Some(bin_path), _) => {
            let package_root = bin_path
                .parent()
                .ok_or_else(|| format!("missing parent for {}", bin_path.display()))?
                .to_path_buf();
            let bin_name = bin_path
                .file_name()
                .ok_or_else(|| format!("missing filename for {}", bin_path.display()))?
                .to_os_string();
            let output = take_flag_path(args, "--output")
                .unwrap_or_else(|| package_root.join("release-manifest.json"));
            let manifest = generate_release_manifest_for_entries(
                &package_root,
                vec![PathBuf::from(bin_name)],
                &target,
                &signing,
            )?;
            write_json_pretty(&output, &manifest)?;
            println!("{}", output.display());
            Ok(())
        }
        (None, Some(package_root)) => {
            let output = take_flag_path(args, "--output")
                .unwrap_or_else(|| package_root.join("release-manifest.json"));
            let manifest = generate_release_manifest(&package_root, &target, &signing)?;
            write_json_pretty(&output, &manifest)?;
            println!("{}", output.display());
            Ok(())
        }
        (None, None) => {
            let bin_path = root.join("target").join("release").join("blossom-server");
            sign_release_manifest(&inject_flag(args, "--bin", &bin_path.display().to_string()))
        }
    }
}

fn source_build_manifest(args: &[String]) -> Result<(), String> {
    let root = workspace_root();
    let target = take_flag_value(args, "--target").unwrap_or_else(detect_target);
    let default_output = root
        .join("target")
        .join("dist")
        .join(format!("blossom-server-{target}"))
        .join("source-build-manifest.json");
    let output = take_flag_path(args, "--output").unwrap_or(default_output);
    let manifest = generate_source_build_manifest(&root, &target)?;
    write_json_pretty(&output, &manifest)?;
    println!("{}", output.display());
    Ok(())
}

fn source_merkle_tree(args: &[String]) -> Result<(), String> {
    let root = workspace_root();
    let default_output = root.join("source-merkle-tree.json");
    let output = take_flag_path(args, "--output").unwrap_or(default_output);

    let mut tree = SourceMerkleTree::build(&root)?;
    eprintln!(
        "  Merkle tree: {} files, root = {}",
        tree.file_count,
        &tree.root[..16]
    );

    let nsec = std::env::var("BLOSSOM_RELEASE_NSEC")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let signing = SigningConfig { nsec_hex: nsec };
    match tree.sign(&signing) {
        Ok(()) => eprintln!(
            "  Signed by: {}",
            tree.signer_npub.as_deref().unwrap_or("?")
        ),
        Err(_) => eprintln!("  Unsigned (no BLOSSOM_RELEASE_NSEC)"),
    }

    write_json_pretty(&output, &tree)?;
    println!("{}", output.display());
    Ok(())
}

fn verify_source_file(args: &[String]) -> Result<(), String> {
    let root = workspace_root();
    let tree_path =
        take_flag_path(args, "--tree").unwrap_or_else(|| root.join("source-merkle-tree.json"));
    let file_path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("usage: cargo xtask verify-source-file <path> [--tree <tree.json>]")?;

    let tree_bytes =
        std::fs::read(&tree_path).map_err(|e| format!("read {}: {e}", tree_path.display()))?;
    let tree: SourceMerkleTree =
        serde_json::from_slice(&tree_bytes).map_err(|e| format!("parse tree: {e}"))?;

    let abs_path = if Path::new(file_path).is_absolute() {
        PathBuf::from(file_path)
    } else {
        root.join(file_path)
    };
    let relative = abs_path
        .strip_prefix(&root)
        .unwrap_or(&abs_path)
        .to_string_lossy()
        .replace('\\', "/");

    let content =
        std::fs::read(&abs_path).map_err(|e| format!("read {}: {e}", abs_path.display()))?;

    let hash_matches = tree
        .verify_file(&relative, &content)
        .map_err(|e| format!("verify: {e}"))?;

    if !hash_matches {
        eprintln!("FAIL: file hash mismatch for '{}'", relative);
        std::process::exit(1);
    }

    let proof = tree
        .proof_for(&relative)
        .ok_or_else(|| format!("file '{}' not found in tree", relative))?;
    let proof_valid = verify_merkle_proof(&proof.leaf_hash, &proof.proof, &proof.root);

    if !proof_valid {
        eprintln!("FAIL: Merkle proof invalid for '{}'", relative);
        std::process::exit(1);
    }

    println!(
        "OK: '{}' verified against Merkle root {}",
        relative,
        &tree.root[..16]
    );
    println!("  leaf hash:  {}", proof.leaf_hash);
    println!("  leaf index: {}/{}", proof.leaf_index, tree.file_count);
    println!("  proof size: {} siblings", proof.proof.len());
    if let Some(ref npub) = tree.signer_npub {
        println!("  signed by:  {}", npub);
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    workspace_root_from_manifest_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
}

fn detect_target() -> String {
    if let Ok(target) = std::env::var("TARGET") {
        if !target.trim().is_empty() {
            return target;
        }
    }
    let output = Command::new("rustc").arg("-vV").output();
    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(target) = stdout.lines().find_map(|line| line.strip_prefix("host: ")) {
                return target.trim().to_string();
            }
        }
    }
    "unknown-target".to_string()
}

fn inject_flag(args: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut merged = args.to_vec();
    merged.push(flag.to_string());
    merged.push(value.to_string());
    merged
}

fn take_flag_path(args: &[String], flag: &str) -> Option<PathBuf> {
    take_flag_value(args, flag).map(PathBuf::from)
}

fn take_flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn usage() -> String {
    [
        "usage:",
        "  cargo xtask sign-release-manifest [--bin <path> | --package-root <dir>] [--output <path>] [--target <triple>]",
        "  cargo xtask source-build-manifest [--output <path>] [--target <triple>]",
        "  cargo xtask source-merkle-tree [--output <path>]",
        "  cargo xtask verify-source-file <path> [--tree <tree.json>]",
    ]
    .join("\n")
}
