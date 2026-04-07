//! build.rs — blossom-rs build script.
//!
//! Embeds a short git commit hash as the `BLOSSOM_GIT_HASH` env var, available
//! inside the crate via `env!("BLOSSOM_GIT_HASH")`.
//!
//! Note: TLS is provided by `rustls` (pure Rust) so no system OpenSSL is needed.
//!
//! Reference: <https://github.com/gnostr-org/gnostr/blob/master/build.rs>

use std::{env, process::Command};

fn main() {
    // Re-run this script when git state or the script itself changes.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=BUILD_GIT_COMMIT_ID");

    // Embed a short git hash so binaries can report their build provenance.
    let git_hash = git_short_hash();
    println!("cargo:rustc-env=BLOSSOM_GIT_HASH={}", git_hash);
}

// ---------------------------------------------------------------------------
// Git hash
// ---------------------------------------------------------------------------

fn git_short_hash() -> String {
    // Allow overriding from `git archive` tarballs (set BUILD_GIT_COMMIT_ID).
    if let Ok(commit) = env::var("BUILD_GIT_COMMIT_ID") {
        return commit.chars().take(7).collect();
    }
    Command::new("git")
        .args(["rev-parse", "--short=7", "--verify", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
