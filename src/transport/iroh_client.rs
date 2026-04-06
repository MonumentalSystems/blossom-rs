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
use crate::auth::{auth_header_value, build_blossom_auth, BlossomSigner};
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
            content_type: "application/octet-stream".into(),
            body_len: data.len() as u64,
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

    /// Download a blob from a remote peer.
    #[instrument(name = "blossom.iroh.client.download", skip_all, fields(blob.sha256 = %sha256))]
    pub async fn download(&self, addr: EndpointAddr, sha256: &str) -> Result<Vec<u8>, String> {
        let auth_event = build_blossom_auth(self.signer.as_ref(), "get", None, None, "");
        let auth_header = auth_header_value(&auth_event);

        let conn = self.connect(addr).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open stream: {e}"))?;

        let req = Request {
            op: Op::Get,
            sha256: sha256.to_string(),
            pubkey: String::new(),
            auth: auth_header,
            content_type: String::new(),
            body_len: 0,
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
