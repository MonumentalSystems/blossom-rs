//! Git command wrapper for stateless-rpc operations.
//!
//! Spawns `git upload-pack` and `git receive-pack` as child processes,
//! piping request/response bodies through stdin/stdout.

use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Semaphore;

const MAX_GIT_OUTPUT: usize = 64 * 1024 * 1024;
const MAX_GIT_STDERR: usize = 64 * 1024;
const GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
static GIT_PROCESS_LIMIT: Semaphore = Semaphore::const_new(8);

/// Wrapper around the git CLI for HTTP smart protocol operations.
pub struct GitCommand<'a> {
    git_path: &'a str,
    repo_path: &'a Path,
}

impl<'a> GitCommand<'a> {
    pub fn new(git_path: &'a str, repo_path: &'a Path) -> Self {
        Self {
            git_path,
            repo_path,
        }
    }

    /// Advertise refs for a service (git-upload-pack or git-receive-pack).
    pub async fn refs(&self, service: &str, v2: bool) -> Result<Vec<u8>, &'static str> {
        let service_cmd = match service {
            "git-upload-pack" => "upload-pack",
            "git-receive-pack" => "receive-pack",
            _ => return Err("unsupported git service"),
        };

        let mut cmd = self.build_command(service_cmd, v2);
        cmd.arg("--advertise-refs").arg(".");

        let (success, stdout, stderr) = run_bounded(cmd, None).await?;

        if success {
            Ok(stdout)
        } else {
            tracing::error!(
                stderr = %String::from_utf8_lossy(&stderr),
                "git --advertise-refs failed"
            );
            Err("git advertise-refs failed")
        }
    }

    /// Execute git-upload-pack (fetch/clone).
    pub async fn upload_pack(&self, body: &[u8], v2: bool) -> Result<Vec<u8>, &'static str> {
        self.run_stateless_rpc("upload-pack", body, v2).await
    }

    /// Execute git-receive-pack (push).
    pub async fn receive_pack(&self, body: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.run_stateless_rpc("receive-pack", body, false).await
    }

    async fn run_stateless_rpc(
        &self,
        service: &str,
        body: &[u8],
        v2: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let mut cmd = self.build_command(service, v2);
        cmd.arg("--stateless-rpc")
            .arg(".")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let (success, stdout, stderr) = run_bounded(cmd, Some(body)).await?;

        if success {
            Ok(stdout)
        } else {
            tracing::error!(
                service = service,
                stderr = %String::from_utf8_lossy(&stderr),
                "git stateless-rpc failed"
            );
            Err("git command failed")
        }
    }

    fn build_command(&self, service: &str, v2: bool) -> Command {
        let mut cmd = Command::new(self.git_path);
        cmd.current_dir(self.repo_path);
        cmd.kill_on_drop(true)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_COUNT", "0")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_PROTOCOL_FROM_USER")
            .env_remove("GIT_ASKPASS")
            .env_remove("SSH_ASKPASS")
            .env_remove("LD_PRELOAD")
            .env_remove("DYLD_INSERT_LIBRARIES");

        cmd.arg("-c")
            .arg("uploadpack.allowTipSHA1InWant=true")
            .arg("-c")
            .arg("uploadpack.allowReachableSHA1InWant=true");

        cmd.arg(service);

        if v2 {
            cmd.env("GIT_PROTOCOL", "version=2");
        }

        cmd
    }
}

async fn read_limited(
    reader: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut output = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut output)
        .await
        .map_err(|_| "failed to read git output")?;
    if output.len() > limit {
        return Err("git output limit exceeded");
    }
    Ok(output)
}

async fn run_bounded(
    mut cmd: Command,
    input: Option<&[u8]>,
) -> Result<(bool, Vec<u8>, Vec<u8>), &'static str> {
    let _permit = GIT_PROCESS_LIMIT
        .acquire()
        .await
        .map_err(|_| "git process limiter closed")?;
    cmd.stdin(if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    })
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| "failed to spawn git")?;
    let stdout = child.stdout.take().ok_or("missing git stdout")?;
    let stderr = child.stderr.take().ok_or("missing git stderr")?;
    let mut stdin = child.stdin.take();

    tokio::time::timeout(GIT_TIMEOUT, async move {
        let write_input = async move {
            if let (Some(data), Some(mut writer)) = (input, stdin.take()) {
                writer
                    .write_all(data)
                    .await
                    .map_err(|_| "failed to write to git stdin")?;
            }
            Ok::<(), &'static str>(())
        };
        let (status, stdout, stderr, written) = tokio::join!(
            child.wait(),
            read_limited(stdout, MAX_GIT_OUTPUT),
            read_limited(stderr, MAX_GIT_STDERR),
            write_input,
        );
        written?;
        let status = status.map_err(|_| "failed to wait for git")?;
        Ok::<_, &'static str>((status.success(), stdout?, stderr?))
    })
    .await
    .map_err(|_| "git command timed out")?
}
