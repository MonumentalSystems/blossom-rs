//! Iroh QUIC client for Blossom blob operations.
//!
//! Connects to a Blossom peer by node ID and performs blob operations
//! over the `/blossom/1` ALPN protocol.

use std::collections::HashMap;
use std::sync::Mutex;

use iroh::endpoint::{Connection, Endpoint};
use iroh::{EndpointAddr, EndpointId};
use tracing::{info, instrument};

use super::iroh_transport::BLOSSOM_ALPN;
use super::wire::{self, Op, Request, Response, Status};
use crate::auth::{
    auth_header_value, build_blossom_auth, build_blossom_auth_with_extra_tags, BlossomSigner,
};
use crate::locks::LockRecord;
use crate::protocol::{sha256_hex, BlobDescriptor};

/// Iroh-based Blossom client.
///
/// Connects to peers by iroh node ID over QUIC. Caches connections
/// per node ID for reuse across operations.
pub struct IrohBlossomClient {
    endpoint: Endpoint,
    signer: Box<dyn BlossomSigner>,
    /// Cached connections by node endpoint ID.
    connections: Mutex<HashMap<EndpointId, Connection>>,
}

impl IrohBlossomClient {
    /// Create a new iroh client with the given endpoint and signer.
    pub fn new(endpoint: Endpoint, signer: impl BlossomSigner + 'static) -> Self {
        Self {
            endpoint,
            signer: Box::new(signer),
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Connect to a remote Blossom peer, reusing cached connections.
    async fn connect(&self, addr: EndpointAddr) -> Result<Connection, String> {
        let node_id = addr.id;

        // Check cache.
        if let Some(conn) = self.connections.lock().unwrap().get(&node_id) {
            // Verify connection is still alive.
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }

        // New connection.
        let conn = self
            .endpoint
            .connect(addr, BLOSSOM_ALPN)
            .await
            .map_err(|e| format!("iroh connect: {e}"))?;

        self.connections
            .lock()
            .unwrap()
            .insert(node_id, conn.clone());

        Ok(conn)
    }

    /// Upload a blob to a remote peer.
    #[instrument(name = "blossom.iroh.client.upload", skip_all, fields(blob.size = data.len()))]
    pub async fn upload(&self, addr: EndpointAddr, data: &[u8]) -> Result<BlobDescriptor, String> {
        self.upload_with_type(addr, data, "application/octet-stream")
            .await
    }

    /// Upload a blob with an explicit content type.
    #[instrument(name = "blossom.iroh.client.upload", skip_all, fields(blob.size = data.len()))]
    pub async fn upload_with_type(
        &self,
        addr: EndpointAddr,
        data: &[u8],
        content_type: &str,
    ) -> Result<BlobDescriptor, String> {
        let our_sha256 = sha256_hex(data);
        let auth_event =
            build_blossom_auth(self.signer.as_ref(), "upload", Some(&our_sha256), None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        // Send request.
        let req = Request {
            op: Op::Upload,
            sha256: String::new(),
            pubkey: String::new(),
            auth: auth_header,
            content_type: content_type.to_string(),
            body_len: data.len() as u64,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write request: {e}"))?;
        send.write_all(data)
            .await
            .map_err(|e| format!("write body: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        // Read response.
        let (resp, _leftover) = read_response(&mut recv).await?;
        if resp.status != Status::Ok {
            return Err(format!("upload failed: {}", resp.error));
        }

        let desc: BlobDescriptor =
            serde_json::from_value(resp.descriptor.ok_or("no descriptor in upload response")?)
                .map_err(|e| format!("parse descriptor: {e}"))?;

        if desc.sha256 != our_sha256 {
            return Err(format!(
                "SHA256 mismatch: server={}, ours={}",
                desc.sha256, our_sha256
            ));
        }

        info!(blob.sha256 = %desc.sha256, blob.size = desc.size, "blob uploaded via iroh");
        Ok(desc)
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(name = "blossom.iroh.client.upload_lfs", skip_all, fields(
        blob.size = data.len(),
        blob.sha256,
        lfs.path = path,
        lfs.repo = repo,
    ))]
    pub async fn upload_lfs(
        &self,
        addr: EndpointAddr,
        data: &[u8],
        content_type: &str,
        path: &str,
        repo: &str,
        base_sha256: Option<&str>,
        is_manifest: bool,
    ) -> Result<BlobDescriptor, String> {
        let our_sha256 = sha256_hex(data);
        tracing::Span::current().record("blob.sha256", our_sha256.as_str());

        let mut extra_tags = vec![
            vec!["t".into(), "lfs".into()],
            vec!["path".into(), path.into()],
            vec!["repo".into(), repo.into()],
        ];
        if let Some(base) = base_sha256 {
            extra_tags.push(vec!["base".into(), base.into()]);
        }
        if is_manifest {
            extra_tags.push(vec!["manifest".into()]);
        }

        let auth_event = build_blossom_auth_with_extra_tags(
            self.signer.as_ref(),
            "upload",
            Some(&our_sha256),
            None,
            "",
            &extra_tags,
        );
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        let req = Request {
            op: Op::Upload,
            auth: auth_header,
            content_type: content_type.to_string(),
            body_len: data.len() as u64,
            lfs_path: path.to_string(),
            lfs_repo: repo.to_string(),
            lfs_base: base_sha256.unwrap_or("").to_string(),
            lfs_manifest: is_manifest,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write request: {e}"))?;
        send.write_all(data)
            .await
            .map_err(|e| format!("write body: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _) = read_response(&mut recv).await?;
        if resp.status != Status::Ok {
            return Err(format!("upload_lfs failed: {}", resp.error));
        }

        let desc: BlobDescriptor = serde_json::from_value(
            resp.descriptor
                .ok_or("no descriptor in upload_lfs response")?,
        )
        .map_err(|e| format!("parse descriptor: {e}"))?;

        if desc.sha256 != our_sha256 {
            return Err(format!(
                "SHA256 mismatch: server={}, ours={}",
                desc.sha256, our_sha256
            ));
        }

        info!(
            blob.sha256 = %desc.sha256,
            blob.size = desc.size,
            lfs.path = %path,
            "LFS blob uploaded via iroh"
        );
        Ok(desc)
    }

    /// Download a blob from a remote peer.
    #[instrument(name = "blossom.iroh.client.download", skip_all, fields(blob.sha256 = %sha256))]
    pub async fn download(&self, addr: EndpointAddr, sha256: &str) -> Result<Vec<u8>, String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "get", None, None, "");
        let _auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        let req = Request {
            op: Op::Get,
            sha256: sha256.to_string(),
            pubkey: String::new(),
            auth: String::new(),
            content_type: String::new(),
            body_len: 0,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, leftover) = read_response(&mut recv).await?;
        if resp.status != Status::Ok {
            return Err(format!("download failed: {}", resp.error));
        }

        // Combine leftover bytes (read past newline) with remaining body.
        let mut data = leftover;
        let remaining = (resp.body_len as usize).saturating_sub(data.len());
        if remaining > 0 {
            let mut rest = vec![0u8; remaining];
            recv.read_exact(&mut rest)
                .await
                .map_err(|e| format!("read body: {e}"))?;
            data.extend_from_slice(&rest);
        }
        data.truncate(resp.body_len as usize);

        // Verify integrity.
        let actual = sha256_hex(&data);
        if actual != sha256 {
            return Err(format!(
                "SHA256 mismatch: expected={}, actual={}",
                sha256, actual
            ));
        }

        info!(blob.sha256 = %sha256, blob.size = data.len(), "blob downloaded via iroh");
        Ok(data)
    }

    /// Check if a blob exists on a remote peer.
    #[instrument(name = "blossom.iroh.client.exists", skip_all, fields(blob.sha256 = %sha256))]
    pub async fn exists(&self, addr: EndpointAddr, sha256: &str) -> Result<bool, String> {
        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        let req = Request {
            op: Op::Head,
            sha256: sha256.to_string(),
            pubkey: String::new(),
            auth: String::new(),
            content_type: String::new(),
            body_len: 0,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _leftover) = read_response(&mut recv).await?;
        Ok(resp.status == Status::Ok)
    }

    /// Delete a blob on a remote peer (requires auth).
    #[instrument(name = "blossom.iroh.client.delete", skip_all, fields(blob.sha256 = %sha256))]
    pub async fn delete(&self, addr: EndpointAddr, sha256: &str) -> Result<bool, String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "delete", None, None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        let req = Request {
            op: Op::Delete,
            sha256: sha256.to_string(),
            pubkey: String::new(),
            auth: auth_header,
            content_type: String::new(),
            body_len: 0,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _leftover) = read_response(&mut recv).await?;
        Ok(resp.status == Status::Ok)
    }

    /// List blobs uploaded by a pubkey on a remote peer.
    #[instrument(name = "blossom.iroh.client.list", skip_all, fields(list.pubkey = %pubkey))]
    pub async fn list(
        &self,
        addr: EndpointAddr,
        pubkey: &str,
    ) -> Result<Vec<BlobDescriptor>, String> {
        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        let req = Request {
            op: Op::List,
            sha256: String::new(),
            pubkey: pubkey.to_string(),
            auth: String::new(),
            content_type: String::new(),
            body_len: 0,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, leftover) = read_response(&mut recv).await?;
        if resp.status != Status::Ok {
            return Err(format!("list failed: {}", resp.error));
        }

        let mut data = leftover;
        let remaining = (resp.body_len as usize).saturating_sub(data.len());
        if remaining > 0 {
            let mut rest = vec![0u8; remaining];
            recv.read_exact(&mut rest)
                .await
                .map_err(|e| format!("read body: {e}"))?;
            data.extend_from_slice(&rest);
        }
        data.truncate(resp.body_len as usize);

        info!(list.pubkey = %pubkey, "list via iroh");
        serde_json::from_slice(&data).map_err(|e| format!("parse list: {e}"))
    }

    /// Upload a file from disk without buffering in memory.
    ///
    /// First pass computes SHA256. Second pass streams file to QUIC
    /// in 256KB chunks.
    #[instrument(name = "blossom.iroh.client.upload_file", skip_all, fields(
        file.path = %path.display(),
        blob.sha256,
        blob.size,
    ))]
    pub async fn upload_file(
        &self,
        addr: EndpointAddr,
        path: &std::path::Path,
        content_type: &str,
    ) -> Result<BlobDescriptor, String> {
        use crate::protocol::STREAM_CHUNK_SIZE;
        use tokio::io::AsyncReadExt;

        let file_meta = tokio::fs::metadata(path)
            .await
            .map_err(|e| format!("stat file: {e}"))?;
        let file_size = file_meta.len();

        // First pass: compute SHA256.
        let our_sha256 = tokio::task::block_in_place(|| {
            let mut f = std::fs::File::open(path).map_err(|e| format!("open file: {e}"))?;
            let (hash, _) =
                crate::protocol::sha256_stream(&mut f).map_err(|e| format!("hash file: {e}"))?;
            Ok::<_, String>(hash)
        })?;

        tracing::Span::current().record("blob.sha256", our_sha256.as_str());
        tracing::Span::current().record("blob.size", file_size);

        let auth_event =
            build_blossom_auth(self.signer.as_ref(), "upload", Some(&our_sha256), None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        // Send request header.
        let req = Request {
            op: Op::Upload,
            sha256: String::new(),
            pubkey: String::new(),
            auth: auth_header,
            content_type: content_type.to_string(),
            body_len: file_size,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("write request: {e}"))?;

        // Second pass: stream file in chunks.
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| format!("open file: {e}"))?;
        let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
        loop {
            let n = file
                .read(&mut buf)
                .await
                .map_err(|e| format!("read file: {e}"))?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n])
                .await
                .map_err(|e| format!("write body: {e}"))?;
        }
        send.finish().map_err(|e| format!("finish: {e}"))?;

        // Read response.
        let (resp, _leftover) = read_response(&mut recv).await?;
        if resp.status != Status::Ok {
            return Err(format!("upload failed: {}", resp.error));
        }

        let desc: BlobDescriptor =
            serde_json::from_value(resp.descriptor.ok_or("no descriptor in upload response")?)
                .map_err(|e| format!("parse descriptor: {e}"))?;

        if desc.sha256 != our_sha256 {
            return Err(format!(
                "SHA256 mismatch: server={}, ours={}",
                desc.sha256, our_sha256
            ));
        }

        info!(blob.sha256 = %desc.sha256, blob.size = desc.size, "file uploaded via iroh (streaming)");
        Ok(desc)
    }
}

impl crate::traits::BlobClient for IrohBlossomClient {
    type Address = EndpointAddr;

    async fn upload(
        &self,
        addr: &EndpointAddr,
        data: &[u8],
        content_type: &str,
    ) -> Result<BlobDescriptor, String> {
        self.upload_with_type(addr.clone(), data, content_type)
            .await
    }

    async fn download(&self, addr: &EndpointAddr, sha256: &str) -> Result<Vec<u8>, String> {
        self.download(addr.clone(), sha256).await
    }

    async fn exists(&self, addr: &EndpointAddr, sha256: &str) -> Result<bool, String> {
        self.exists(addr.clone(), sha256).await
    }

    async fn delete(&self, addr: &EndpointAddr, sha256: &str) -> Result<bool, String> {
        self.delete(addr.clone(), sha256).await
    }

    async fn list(&self, addr: &EndpointAddr, pubkey: &str) -> Result<Vec<BlobDescriptor>, String> {
        self.list(addr.clone(), pubkey).await
    }

    async fn upload_file(
        &self,
        addr: &EndpointAddr,
        path: &std::path::Path,
        content_type: &str,
    ) -> Result<BlobDescriptor, String> {
        self.upload_file(addr.clone(), path, content_type).await
    }
}

impl IrohBlossomClient {
    pub async fn create_lock(
        &self,
        addr: &EndpointAddr,
        repo_id: &str,
        path: &str,
    ) -> Result<LockRecord, String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "lock", None, None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr.clone()).await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;

        let req = Request {
            op: Op::LockCreate,
            auth: auth_header,
            repo_id: repo_id.to_string(),
            lock_path: path.to_string(),
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("send: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _) = read_response(&mut recv).await?;
        match resp.status {
            Status::Ok => resp
                .descriptor
                .ok_or_else(|| "missing descriptor".to_string())
                .and_then(|v| {
                    serde_json::from_value::<LockRecord>(v).map_err(|e| format!("parse lock: {e}"))
                }),
            Status::Conflict => Err("path already locked".to_string()),
            Status::Unauthorized => Err("unauthorized".to_string()),
            Status::Forbidden => Err("forbidden".to_string()),
            Status::NotFound => Err("lock support not configured".to_string()),
            Status::Error => Err(resp.error.clone()),
        }
    }

    pub async fn delete_lock(
        &self,
        addr: &EndpointAddr,
        repo_id: &str,
        lock_id: &str,
        force: bool,
    ) -> Result<LockRecord, String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "lock", None, None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr.clone()).await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;

        let req = Request {
            op: Op::LockDelete,
            auth: auth_header,
            repo_id: repo_id.to_string(),
            lock_id: lock_id.to_string(),
            force,
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("send: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _) = read_response(&mut recv).await?;
        match resp.status {
            Status::Ok => resp
                .descriptor
                .ok_or_else(|| "missing descriptor".to_string())
                .and_then(|v| {
                    serde_json::from_value::<LockRecord>(v).map_err(|e| format!("parse lock: {e}"))
                }),
            Status::NotFound => Err("lock not found".to_string()),
            Status::Forbidden => Err(resp.error.clone()),
            Status::Unauthorized => Err("unauthorized".to_string()),
            Status::Error => Err(resp.error.clone()),
            _ => Err(format!("unexpected status: {:?}", resp.status)),
        }
    }

    pub async fn list_locks(
        &self,
        addr: &EndpointAddr,
        repo_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<(Vec<LockRecord>, Option<String>), String> {
        let req = Request {
            op: Op::LockList,
            repo_id: repo_id.to_string(),
            cursor: cursor.unwrap_or("").to_string(),
            limit: limit.unwrap_or(0),
            ..Default::default()
        };

        let conn = self.connect(addr.clone()).await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;

        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("send: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _) = read_response(&mut recv).await?;
        match resp.status {
            Status::Ok => {
                let desc = resp
                    .descriptor
                    .ok_or_else(|| "missing descriptor".to_string())?;
                let locks: Vec<LockRecord> = desc
                    .get("locks")
                    .ok_or_else(|| "missing locks field".to_string())
                    .and_then(|v| {
                        serde_json::from_value(v.clone()).map_err(|e| format!("parse: {e}"))
                    })?;
                let next_cursor = desc
                    .get("next_cursor")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok((locks, next_cursor))
            }
            Status::NotFound => Err("lock support not configured".to_string()),
            Status::Error => Err(resp.error.clone()),
            _ => Err(format!("unexpected status: {:?}", resp.status)),
        }
    }

    pub async fn verify_locks(
        &self,
        addr: &EndpointAddr,
        repo_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<(Vec<LockRecord>, Vec<LockRecord>, Option<String>), String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "lock", None, None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr.clone()).await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;

        let req = Request {
            op: Op::LockVerify,
            auth: auth_header,
            repo_id: repo_id.to_string(),
            cursor: cursor.unwrap_or("").to_string(),
            limit: limit.unwrap_or(0),
            ..Default::default()
        };
        send.write_all(&wire::encode_request(&req))
            .await
            .map_err(|e| format!("send: {e}"))?;
        send.finish().map_err(|e| format!("finish: {e}"))?;

        let (resp, _) = read_response(&mut recv).await?;
        match resp.status {
            Status::Ok => {
                let desc = resp
                    .descriptor
                    .ok_or_else(|| "missing descriptor".to_string())?;
                let ours: Vec<LockRecord> = desc
                    .get("ours")
                    .ok_or_else(|| "missing ours field".to_string())
                    .and_then(|v| {
                        serde_json::from_value(v.clone()).map_err(|e| format!("parse ours: {e}"))
                    })?;
                let theirs: Vec<LockRecord> = desc
                    .get("theirs")
                    .ok_or_else(|| "missing theirs field".to_string())
                    .and_then(|v| {
                        serde_json::from_value(v.clone()).map_err(|e| format!("parse theirs: {e}"))
                    })?;
                let next_cursor = desc
                    .get("next_cursor")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok((ours, theirs, next_cursor))
            }
            Status::NotFound => Err("lock support not configured".to_string()),
            Status::Unauthorized => Err("unauthorized".to_string()),
            Status::Error => Err(resp.error.clone()),
            _ => Err(format!("unexpected status: {:?}", resp.status)),
        }
    }
}

/// Read a response from a QUIC recv stream.
/// Returns the parsed response and any leftover bytes (body data read past the newline).
async fn read_response(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<(Response, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        match recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => return Err(format!("read response: {e}")),
        }
    }

    let (resp, consumed) = wire::decode_line::<Response>(&buf)?;
    let leftover = buf[consumed..].to_vec();
    Ok((resp, leftover))
}
