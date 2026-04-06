//! build.rs — blossom-rs build script.
//!
//! Follows the pattern from gnostr/build.rs to:
//! 1. Detect and install missing system build dependencies (OpenSSL, pkg-config)
//!    at build time so cross-compilation works without pre-configuring the host.
//! 2. Embed a short git commit hash as the `BLOSSOM_GIT_HASH` env var, available
//!    inside the crate via `env!("BLOSSOM_GIT_HASH")`.
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

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    match target_os.as_str() {
        "linux" => ensure_openssl_linux(&target_env),
        "macos" => ensure_openssl_macos(),
        "windows" => ensure_openssl_windows(),
        _ => {}
    }
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

// ---------------------------------------------------------------------------
// System dependency helpers
// ---------------------------------------------------------------------------

fn command_exists(cmd: &str) -> bool {
    let checker = if env::var("CARGO_CFG_TARGET_OS")
        .unwrap_or_default()
        .eq("windows")
    {
        "where"
    } else {
        "which"
    };
    Command::new(checker)
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Returns true if OpenSSL headers are locatable via pkg-config.
fn openssl_available() -> bool {
    Command::new("pkg-config")
        .args(["--exists", "openssl"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

/// Ensure OpenSSL development headers are present on Linux build hosts
/// (including inside `cross` Docker containers).  Mirrors the pattern used
/// in gnostr/build.rs for installing missing system dependencies.
fn ensure_openssl_linux(target_env: &str) {
    if openssl_available() {
        return;
    }

    println!(
        "cargo:warning=OpenSSL not found via pkg-config. \
         Attempting to install system packages."
    );

    let installer = if command_exists("apt-get") {
        "apt-get"
    } else if command_exists("yum") {
        "yum"
    } else if command_exists("dnf") {
        "dnf"
    } else {
        println!(
            "cargo:warning=No supported package manager found \
             (apt-get / yum / dnf). \
             Install libssl-dev (or equivalent) manually, \
             or set OPENSSL_DIR to point at your OpenSSL installation."
        );
        return;
    };

    // Refresh package lists for apt-get.
    if installer == "apt-get" {
        match Command::new(installer).args(["update", "-qq"]).status() {
            Ok(s) if !s.success() => {
                println!("cargo:warning=apt-get update failed (exit {}); proceeding with possibly stale index.", s);
            }
            Err(e) => {
                println!(
                    "cargo:warning=apt-get update error: {}; proceeding anyway.",
                    e
                );
            }
            _ => {}
        }
    }

    let mut pkgs: Vec<&str> = vec!["libssl-dev", "pkg-config"];
    if target_env == "musl" {
        // musl targets need the musl toolchain and static OpenSSL.
        pkgs.push("musl-tools");
    }

    println!("cargo:warning=Installing {:?} via {}", pkgs, installer);

    match Command::new(installer)
        .arg("install")
        .arg("-y")
        .args(&pkgs)
        .status()
    {
        Ok(s) if s.success() => {
            println!("cargo:warning=System OpenSSL packages installed successfully.");
        }
        Ok(s) => {
            println!(
                "cargo:warning=Package installation exited with status {}. \
                 Set OPENSSL_DIR if OpenSSL is installed in a non-standard location.",
                s
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=Failed to run package manager '{}': {}. \
                 Set OPENSSL_DIR or install libssl-dev manually.",
                installer, e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

/// On macOS the default TLS is SecureTransport (no system OpenSSL needed).
/// However, if a crate explicitly requires OpenSSL headers, attempt a
/// Homebrew install following the gnostr/build.rs pattern.
fn ensure_openssl_macos() {
    if openssl_available() {
        return;
    }

    if !command_exists("brew") {
        println!(
            "cargo:warning=Homebrew not found. \
             Install OpenSSL manually if build errors mention openssl-sys."
        );
        return;
    }

    println!("cargo:warning=OpenSSL not found via pkg-config on macOS. Trying Homebrew…");

    let result = Command::new("brew").args(["install", "openssl@3"]).status();

    match result {
        Ok(s) if s.success() => {
            println!("cargo:warning=Installed openssl@3 via Homebrew.");

            // Expose the Homebrew prefix so pkg-config can find openssl.pc
            // during subsequent build steps in the same cargo invocation.
            if let Ok(output) = Command::new("brew")
                .args(["--prefix", "openssl@3"])
                .output()
            {
                if let Ok(prefix) = String::from_utf8(output.stdout) {
                    let prefix = prefix.trim();
                    // Set the variable for the current build process so that
                    // pkg-config launched by other build scripts can find it.
                    let pkg_config_path = format!("{}/lib/pkgconfig", prefix);
                    env::set_var("PKG_CONFIG_PATH", &pkg_config_path);
                    println!("cargo:warning=Set PKG_CONFIG_PATH={}", pkg_config_path);
                }
            }
        }
        Ok(s) => {
            println!(
                "cargo:warning=brew install openssl@3 failed (exit {}). \
                 Install OpenSSL manually.",
                s
            );
        }
        Err(e) => {
            println!("cargo:warning=Failed to run Homebrew: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// On Windows, attempt to install OpenSSL via Scoop or Winget if it is
/// not already available, following the gnostr/build.rs pattern.
fn ensure_openssl_windows() {
    if openssl_available() {
        return;
    }

    if command_exists("scoop") {
        install_windows_dep("scoop", &["install", "openssl"]);
    } else if command_exists("winget") {
        install_windows_dep("winget", &["install", "--id=ShiningLight.OpenSSL", "-e"]);
    } else {
        println!(
            "cargo:warning=OpenSSL not found and neither Scoop nor Winget \
             is available. Install OpenSSL manually and set OPENSSL_DIR."
        );
    }
}

fn install_windows_dep(tool: &str, args: &[&str]) {
    println!(
        "cargo:warning=OpenSSL not found on Windows. Attempting: {} {}",
        tool,
        args.join(" ")
    );
    match Command::new(tool).args(args).status() {
        Ok(s) if s.success() => {
            println!("cargo:warning=OpenSSL installed successfully.");
        }
        Ok(s) => {
            println!(
                "cargo:warning=Installer exited with status {}. \
                 Set OPENSSL_DIR if OpenSSL is installed.",
                s
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=Failed to run '{}': {}. \
                 Install OpenSSL manually and set OPENSSL_DIR.",
                tool, e
            );
        }
    }
}
