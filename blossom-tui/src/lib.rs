//! blossom-tui — gitui-inspired Terminal User Interface for Blossom blob storage.
//!
//! Multi-tab keyboard-driven TUI for managing blobs on a Blossom server.
//!
//! # Tabs
//! - **Blobs** — list, navigate, delete blobs
//! - **Upload** — upload a local file
//! - **Status** — fetch and display `/status` JSON
//! - **Keygen** — generate a fresh BIP-340 keypair

use std::cmp::Reverse;
use std::io::Stdout;
use std::path::PathBuf;
use std::time::Duration;

use blossom_rs::{BlobDescriptor, BlossomClient, BlossomSigner, Signer};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Frame, Terminal,
};
use tokio::sync::mpsc;

// ── Constants ────────────────────────────────────────────────────────────────

pub const APP_TITLE: &str = "blossom-tui";
pub const TAB_NAMES: &[&str] = &[" Blobs ", " Upload ", " Batch ", " Admin ", " Status ", " Keygen "];

pub const COLOR_ACCENT: Color = Color::Cyan;
pub const COLOR_OK: Color = Color::Green;
pub const COLOR_ERR: Color = Color::Red;
pub const COLOR_DIM: Color = Color::DarkGray;
pub const COLOR_SELECTED_BG: Color = Color::Blue;
pub const COLOR_TITLE_BG: Color = Color::DarkGray;

// ── Sort/Filter ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortField {
    #[default]
    Date,
    Size,
    Hash,
    ContentType,
}

impl SortField {
    pub fn next(self) -> Self {
        match self {
            Self::Date => Self::Size,
            Self::Size => Self::Hash,
            Self::Hash => Self::ContentType,
            Self::ContentType => Self::Date,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Date => "Date",
            Self::Size => "Size",
            Self::Hash => "Hash",
            Self::ContentType => "Type",
        }
    }
}

// ── Modal ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// Prompt for local save path to download selected blob.
    Download { sha256: String },
    /// Prompt for remote URL to mirror onto the server.
    Mirror,
}

// ── Async messages ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AppMsg {
    BlobsLoaded(Vec<BlobDescriptor>),
    BlobsError(String),
    UploadDone(BlobDescriptor),
    UploadError(String),
    StatusLoaded(serde_json::Value),
    StatusError(String),
    DeleteDone(String),
    DeleteError(String),
    DownloadDone(PathBuf),
    DownloadError(String),
    MirrorDone(BlobDescriptor),
    MirrorError(String),
    BatchItemDone(usize, BlobDescriptor), // (index, descriptor)
    BatchItemError(usize, String),        // (index, error)
    AdminStatsLoaded(serde_json::Value),
    AdminStatsError(String),
    AdminUsersLoaded(serde_json::Value),
    AdminUsersError(String),
}

// ── Batch upload ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum BatchStatus {
    Pending,
    Running,
    Done(BlobDescriptor),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct BatchItem {
    pub path: String,
    pub status: BatchStatus,
}

// ── App state ─────────────────────────────────────────────────────────────────

pub struct KeygenResult {
    pub hex_secret: String,
    pub nsec: String,
    pub pubkey: String,
}

pub struct App {
    // Config
    pub server: String,
    pub secret_key: Option<String>,
    pub pubkey: Option<String>,

    // Navigation
    pub tab: usize,

    // Blobs tab
    pub blobs: Vec<BlobDescriptor>,
    pub blobs_table: TableState,
    pub blobs_loading: bool,
    pub blobs_error: Option<String>,
    pub sort_field: SortField,
    pub filter_str: String,
    pub filter_mode: bool,

    // Upload tab
    pub upload_path: String,
    pub upload_loading: bool,
    pub upload_msg: Option<String>,
    pub upload_ok: bool,
    pub input_mode: bool,

    // Status tab
    pub status_data: Option<serde_json::Value>,
    pub status_loading: bool,
    pub status_error: Option<String>,

    // Keygen tab
    pub keygen_data: Option<KeygenResult>,

    // Batch upload tab
    pub batch_items: Vec<BatchItem>,
    pub batch_input: String,
    pub batch_input_mode: bool,
    pub batch_running: bool,

    // Admin tab
    pub admin_stats: Option<serde_json::Value>,
    pub admin_stats_loading: bool,
    pub admin_stats_error: Option<String>,
    pub admin_users: Option<serde_json::Value>,
    pub admin_users_loading: bool,
    pub admin_users_error: Option<String>,

    // UI state
    pub show_help: bool,
    pub notification: Option<(String, bool)>, // (message, is_error)
    pub modal: Option<Modal>,
    pub modal_input: String,

    // Channel sender for async results
    pub tx: mpsc::UnboundedSender<AppMsg>,
}

impl App {
    pub fn new(server: String, secret_key: Option<String>, tx: mpsc::UnboundedSender<AppMsg>) -> Self {
        let pubkey = secret_key
            .as_deref()
            .and_then(|k| Signer::from_secret_hex(k).ok().map(|s| s.public_key_hex()));

        let mut blobs_table = TableState::default();
        blobs_table.select(Some(0));

        Self {
            server,
            secret_key,
            pubkey,
            tab: 0,
            blobs: Vec::new(),
            blobs_table,
            blobs_loading: false,
            blobs_error: None,
            sort_field: SortField::default(),
            filter_str: String::new(),
            filter_mode: false,
            upload_path: String::new(),
            upload_loading: false,
            upload_msg: None,
            upload_ok: false,
            input_mode: false,
            status_data: None,
            status_loading: false,
            status_error: None,
            keygen_data: None,
            batch_items: Vec::new(),
            batch_input: String::new(),
            batch_input_mode: false,
            batch_running: false,
            admin_stats: None,
            admin_stats_loading: false,
            admin_stats_error: None,
            admin_users: None,
            admin_users_loading: false,
            admin_users_error: None,
            show_help: false,
            notification: None,
            modal: None,
            modal_input: String::new(),
            tx,
        }
    }

    pub fn apply(&mut self, msg: AppMsg) {
        match msg {
            AppMsg::BlobsLoaded(blobs) => {
                self.blobs_loading = false;
                self.blobs_error = None;
                let sel = if blobs.is_empty() {
                    None
                } else {
                    Some(
                        self.blobs_table
                            .selected()
                            .unwrap_or(0)
                            .min(blobs.len() - 1),
                    )
                };
                self.blobs = blobs;
                self.blobs_table.select(sel);
            }
            AppMsg::BlobsError(e) => {
                self.blobs_loading = false;
                self.blobs_error = Some(e);
            }
            AppMsg::UploadDone(desc) => {
                self.upload_loading = false;
                self.upload_ok = true;
                self.upload_msg = Some(format!(
                    "✓  {}  ({} bytes)",
                    &desc.sha256[..16.min(desc.sha256.len())],
                    desc.size
                ));
                self.notification = Some(("Upload successful!".into(), false));
                self.refresh_blobs();
            }
            AppMsg::UploadError(e) => {
                self.upload_loading = false;
                self.upload_ok = false;
                self.upload_msg = Some(format!("✗  {e}"));
            }
            AppMsg::StatusLoaded(data) => {
                self.status_loading = false;
                self.status_error = None;
                self.status_data = Some(data);
            }
            AppMsg::StatusError(e) => {
                self.status_loading = false;
                self.status_error = Some(e);
            }
            AppMsg::DeleteDone(sha256) => {
                self.blobs.retain(|b| b.sha256 != sha256);
                let sel = if self.blobs.is_empty() {
                    None
                } else {
                    Some(
                        self.blobs_table
                            .selected()
                            .unwrap_or(0)
                            .min(self.blobs.len() - 1),
                    )
                };
                self.blobs_table.select(sel);
                self.notification = Some(("Blob deleted.".into(), false));
            }
            AppMsg::DeleteError(e) => {
                self.notification = Some((format!("Delete failed: {e}"), true));
            }
            AppMsg::DownloadDone(path) => {
                self.notification = Some((format!("Downloaded → {}", path.display()), false));
            }
            AppMsg::DownloadError(e) => {
                self.notification = Some((format!("Download failed: {e}"), true));
            }
            AppMsg::MirrorDone(desc) => {
                self.notification = Some((
                    format!("Mirrored: {}", &desc.sha256[..16.min(desc.sha256.len())]),
                    false,
                ));
                self.refresh_blobs();
            }
            AppMsg::MirrorError(e) => {
                self.notification = Some((format!("Mirror failed: {e}"), true));
            }
            AppMsg::BatchItemDone(idx, desc) => {
                if let Some(item) = self.batch_items.get_mut(idx) {
                    item.status = BatchStatus::Done(desc);
                }
                let all_done = self.batch_items.iter().all(|i| {
                    matches!(i.status, BatchStatus::Done(_) | BatchStatus::Failed(_))
                });
                if all_done {
                    self.batch_running = false;
                }
            }
            AppMsg::BatchItemError(idx, e) => {
                if let Some(item) = self.batch_items.get_mut(idx) {
                    item.status = BatchStatus::Failed(e);
                }
                let all_done = self.batch_items.iter().all(|i| {
                    matches!(i.status, BatchStatus::Done(_) | BatchStatus::Failed(_))
                });
                if all_done {
                    self.batch_running = false;
                }
            }
            AppMsg::AdminStatsLoaded(data) => {
                self.admin_stats_loading = false;
                self.admin_stats = Some(data);
                self.admin_stats_error = None;
            }
            AppMsg::AdminStatsError(e) => {
                self.admin_stats_loading = false;
                self.admin_stats_error = Some(e);
            }
            AppMsg::AdminUsersLoaded(data) => {
                self.admin_users_loading = false;
                self.admin_users = Some(data);
                self.admin_users_error = None;
            }
            AppMsg::AdminUsersError(e) => {
                self.admin_users_loading = false;
                self.admin_users_error = Some(e);
            }
        }
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    pub fn refresh_blobs(&mut self) {
        if self.blobs_loading {
            return;
        }
        self.blobs_loading = true;
        self.blobs_error = None;

        let server = self.server.clone();
        let pubkey = self.pubkey.clone().unwrap_or_default();
        let secret_key = self.secret_key.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let signer = secret_key
                .as_deref()
                .and_then(|k| Signer::from_secret_hex(k).ok())
                .unwrap_or_else(Signer::generate);
            let client = BlossomClient::new(vec![server], signer);
            match client.list(&pubkey).await {
                Ok(blobs) => {
                    tx.send(AppMsg::BlobsLoaded(blobs)).ok();
                }
                Err(e) => {
                    tx.send(AppMsg::BlobsError(e)).ok();
                }
            }
        });
    }

    pub fn start_upload(&mut self) {
        let path_str = self.upload_path.trim().to_string();
        if path_str.is_empty() {
            self.upload_msg = Some("Enter a file path first (press i to edit).".into());
            self.upload_ok = false;
            return;
        }
        if self.secret_key.is_none() {
            self.upload_msg = Some("A secret key (--key / BLOSSOM_SECRET_KEY) is required.".into());
            self.upload_ok = false;
            return;
        }
        if self.upload_loading {
            return;
        }
        self.upload_loading = true;
        self.upload_msg = None;

        let server = self.server.clone();
        let key = self.secret_key.clone().unwrap();
        let path = std::path::PathBuf::from(path_str);
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let signer = match Signer::from_secret_hex(&key) {
                Ok(s) => s,
                Err(e) => {
                    tx.send(AppMsg::UploadError(format!("invalid key: {e}")))
                        .ok();
                    return;
                }
            };
            let client = BlossomClient::new(vec![server], signer);
            let mime = mime_from_path(&path);
            match client.upload_file(&path, &mime).await {
                Ok(desc) => {
                    tx.send(AppMsg::UploadDone(desc)).ok();
                }
                Err(e) => {
                    tx.send(AppMsg::UploadError(e)).ok();
                }
            }
        });
    }

    pub fn delete_selected(&mut self) {
        if self.secret_key.is_none() {
            self.notification = Some((
                "A secret key (--key / BLOSSOM_SECRET_KEY) is required for delete.".into(),
                true,
            ));
            return;
        }
        let Some(idx) = self.blobs_table.selected() else {
            return;
        };
        let Some(blob) = self.blobs.get(idx) else {
            return;
        };
        let server = self.server.clone();
        let key = self.secret_key.clone().unwrap();
        let sha256 = blob.sha256.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let signer = match Signer::from_secret_hex(&key) {
                Ok(s) => s,
                Err(e) => {
                    tx.send(AppMsg::DeleteError(format!("invalid key: {e}")))
                        .ok();
                    return;
                }
            };
            let client = BlossomClient::new(vec![server], signer);
            match client.delete(&sha256).await {
                Ok(true) => {
                    tx.send(AppMsg::DeleteDone(sha256)).ok();
                }
                Ok(false) => {
                    tx.send(AppMsg::DeleteError("not found".into())).ok();
                }
                Err(e) => {
                    tx.send(AppMsg::DeleteError(e)).ok();
                }
            }
        });
    }

    pub fn refresh_status(&mut self) {
        if self.status_loading {
            return;
        }
        self.status_loading = true;
        self.status_error = None;

        let server = self.server.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let url = format!("{}/status", server.trim_end_matches('/'));
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(data) => {
                            tx.send(AppMsg::StatusLoaded(data)).ok();
                        }
                        Err(e) => {
                            tx.send(AppMsg::StatusError(format!("parse: {e}"))).ok();
                        }
                    }
                }
                Ok(resp) => {
                    tx.send(AppMsg::StatusError(format!("HTTP {}", resp.status())))
                        .ok();
                }
                Err(e) => {
                    tx.send(AppMsg::StatusError(format!("request: {e}"))).ok();
                }
            }
        });
    }

    pub fn generate_keypair(&mut self) {
        let signer = Signer::generate();
        let hex_secret = signer.secret_key_hex();
        let nsec = encode_nsec(&hex_secret).unwrap_or_else(|_| "?".into());
        let pubkey = signer.public_key_hex();
        self.keygen_data = Some(KeygenResult {
            hex_secret,
            nsec,
            pubkey,
        });
    }

    pub fn next_tab(&mut self) {
        self.tab = (self.tab + 1) % TAB_NAMES.len();
        self.on_tab_enter();
    }

    pub fn prev_tab(&mut self) {
        self.tab = self.tab.checked_sub(1).unwrap_or(TAB_NAMES.len() - 1);
        self.on_tab_enter();
    }

    pub fn on_tab_enter(&mut self) {
        match self.tab {
            0 if self.blobs.is_empty() && !self.blobs_loading => self.refresh_blobs(),
            2 if self.status_data.is_none() && !self.status_loading => self.refresh_status(),
            _ => {}
        }
    }

    pub fn scroll_up(&mut self) {
        if self.tab == 0 {
            let i = self
                .blobs_table
                .selected()
                .map(|i| i.saturating_sub(1))
                .unwrap_or(0);
            self.blobs_table.select(Some(i));
        }
    }

    pub fn scroll_down(&mut self) {
        if self.tab == 0 && !self.blobs.is_empty() {
            let max = self.blobs.len() - 1;
            let i = self
                .blobs_table
                .selected()
                .map(|i| (i + 1).min(max))
                .unwrap_or(0);
            self.blobs_table.select(Some(i));
        }
    }

    /// Cycle sort field.
    pub fn cycle_sort(&mut self) {
        self.sort_field = self.sort_field.next();
        self.blobs_table.select(Some(0));
    }

    /// Enter filter mode.
    pub fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
        self.blobs_table.select(Some(0));
    }

    /// Exit filter mode.
    pub fn exit_filter_mode(&mut self) {
        self.filter_mode = false;
    }

    /// Clear the current filter.
    pub fn clear_filter(&mut self) {
        self.filter_str.clear();
        self.filter_mode = false;
        self.blobs_table.select(Some(0));
    }

    /// Open the download path prompt for the selected blob.
    pub fn prompt_download(&mut self) {
        let Some(idx) = self.blobs_table.selected() else { return };
        let Some(blob) = self.blobs.get(idx) else { return };
        let sha256 = blob.sha256.clone();
        self.modal_input = sha256[..16.min(sha256.len())].to_string();
        self.modal = Some(Modal::Download { sha256 });
    }

    /// Execute the download using the path in `modal_input`.
    pub fn confirm_download(&mut self) {
        let Some(Modal::Download { sha256 }) = self.modal.take() else { return };
        let path_str = self.modal_input.trim().to_string();
        self.modal_input.clear();
        if path_str.is_empty() {
            self.notification = Some(("Enter a file path.".into(), true));
            return;
        }
        let server = self.server.clone();
        let secret_key = self.secret_key.clone();
        let tx = self.tx.clone();
        let path = PathBuf::from(&path_str);

        tokio::spawn(async move {
            let signer = secret_key
                .as_deref()
                .and_then(|k| Signer::from_secret_hex(k).ok())
                .unwrap_or_else(Signer::generate);
            let client = BlossomClient::new(vec![server], signer);
            match client.download(&sha256).await {
                Ok(data) => match tokio::fs::write(&path, &data).await {
                    Ok(()) => tx.send(AppMsg::DownloadDone(path)).ok(),
                    Err(e) => tx.send(AppMsg::DownloadError(format!("write: {e}"))).ok(),
                },
                Err(e) => tx.send(AppMsg::DownloadError(e)).ok(),
            };
        });
    }

    /// Open the mirror URL prompt.
    pub fn prompt_mirror(&mut self) {
        if self.secret_key.is_none() {
            self.notification = Some(("A secret key is required to mirror.".into(), true));
            return;
        }
        self.modal_input.clear();
        self.modal = Some(Modal::Mirror);
    }

    /// Execute mirroring using the URL in `modal_input`.
    pub fn confirm_mirror(&mut self) {
        self.modal = None;
        let url = self.modal_input.trim().to_string();
        self.modal_input.clear();
        if url.is_empty() {
            self.notification = Some(("Enter a URL.".into(), true));
            return;
        }
        let server = self.server.clone();
        let secret_key = self.secret_key.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let signer = secret_key
                .as_deref()
                .and_then(|k| Signer::from_secret_hex(k).ok())
                .unwrap_or_else(Signer::generate);
            let auth_event = blossom_rs::auth::build_blossom_auth(&signer, "upload", None, None, "");
            let auth_header = blossom_rs::auth::auth_header_value(&auth_event);
            let endpoint = format!("{}/mirror", server.trim_end_matches('/'));
            let http = reqwest::Client::new();
            match http
                .put(&endpoint)
                .header("Authorization", auth_header)
                .json(&serde_json::json!({"url": url}))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<BlobDescriptor>().await {
                        Ok(desc) => tx.send(AppMsg::MirrorDone(desc)).ok(),
                        Err(e) => tx.send(AppMsg::MirrorError(format!("parse: {e}"))).ok(),
                    }
                }
                Ok(resp) => {
                    let text = resp.text().await.unwrap_or_default();
                    tx.send(AppMsg::MirrorError(format!("server: {text}"))).ok()
                }
                Err(e) => tx.send(AppMsg::MirrorError(format!("request: {e}"))).ok(),
            };
        });
    }

    /// Fetch admin stats and users.
    pub fn refresh_admin(&mut self) {
        let server = self.server.clone();
        let tx = self.tx.clone();

        if !self.admin_stats_loading {
            self.admin_stats_loading = true;
            let server2 = server.clone();
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let url = format!("{}/admin/stats", server2.trim_end_matches('/'));
                match reqwest::get(&url).await {
                    Ok(r) if r.status().is_success() => {
                        match r.json::<serde_json::Value>().await {
                            Ok(v) => tx2.send(AppMsg::AdminStatsLoaded(v)).ok(),
                            Err(e) => tx2.send(AppMsg::AdminStatsError(format!("parse: {e}"))).ok(),
                        }
                    }
                    Ok(r) => {
                        let t = r.text().await.unwrap_or_default();
                        tx2.send(AppMsg::AdminStatsError(format!("server: {t}"))).ok()
                    }
                    Err(e) => tx2.send(AppMsg::AdminStatsError(format!("request: {e}"))).ok(),
                };
            });
        }

        if !self.admin_users_loading {
            self.admin_users_loading = true;
            tokio::spawn(async move {
                let url = format!("{}/admin/users", server.trim_end_matches('/'));
                match reqwest::get(&url).await {
                    Ok(r) if r.status().is_success() => {
                        match r.json::<serde_json::Value>().await {
                            Ok(v) => tx.send(AppMsg::AdminUsersLoaded(v)).ok(),
                            Err(e) => tx.send(AppMsg::AdminUsersError(format!("parse: {e}"))).ok(),
                        }
                    }
                    Ok(r) => {
                        let t = r.text().await.unwrap_or_default();
                        tx.send(AppMsg::AdminUsersError(format!("server: {t}"))).ok()
                    }
                    Err(e) => tx.send(AppMsg::AdminUsersError(format!("request: {e}"))).ok(),
                };
            });
        }
    }

    /// Add a path to the batch queue.
    pub fn add_batch_path(&mut self) {
        let path = self.batch_input.trim().to_string();
        if path.is_empty() {
            return;
        }
        self.batch_items.push(BatchItem { path, status: BatchStatus::Pending });
        self.batch_input.clear();
    }

    /// Remove the last batch item.
    pub fn remove_last_batch_item(&mut self) {
        if !self.batch_running {
            self.batch_items.pop();
        }
    }

    /// Start uploading all pending items with concurrency limit 4.
    pub fn start_batch_upload(&mut self) {
        if self.batch_running || self.batch_items.is_empty() {
            return;
        }
        if self.secret_key.is_none() {
            self.notification = Some(("A secret key is required to upload.".into(), true));
            return;
        }
        self.batch_running = true;
        // Mark all pending
        for item in &mut self.batch_items {
            if matches!(item.status, BatchStatus::Pending | BatchStatus::Failed(_)) {
                item.status = BatchStatus::Running;
            }
        }

        let server = self.server.clone();
        let secret_key = self.secret_key.clone().unwrap();
        let tx = self.tx.clone();
        let paths: Vec<(usize, String)> = self
            .batch_items
            .iter()
            .enumerate()
            .map(|(i, item)| (i, item.path.clone()))
            .collect();

        tokio::spawn(async move {
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
            let mut handles = Vec::new();

            for (idx, path) in paths {
                let permit = sem.clone().acquire_owned().await.ok();
                let server = server.clone();
                let secret_key = secret_key.clone();
                let tx = tx.clone();
                let path = path.clone();

                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let signer = match Signer::from_secret_hex(&secret_key) {
                        Ok(s) => s,
                        Err(e) => {
                            tx.send(AppMsg::BatchItemError(idx, e)).ok();
                            return;
                        }
                    };
                    let client = BlossomClient::new(vec![server], signer);
                    let p = std::path::Path::new(&path);
                    let mime = crate::mime_from_path(p);
                    match client.upload_file(p, &mime).await {
                        Ok(desc) => tx.send(AppMsg::BatchItemDone(idx, desc)).ok(),
                        Err(e) => tx.send(AppMsg::BatchItemError(idx, e)).ok(),
                    };
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        });
    }
}

// ── Drawing ───────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // content
            Constraint::Length(1), // status bar
        ])
        .split(area);

    draw_title_bar(f, app, chunks[0]);
    draw_tabs(f, app, chunks[1]);

    match app.tab {
        0 => draw_blobs_tab(f, app, chunks[2]),
        1 => draw_upload_tab(f, app, chunks[2]),
        2 => draw_batch_tab(f, app, chunks[2]),
        3 => draw_admin_tab(f, app, chunks[2]),
        4 => draw_status_tab(f, app, chunks[2]),
        5 => draw_keygen_tab(f, app, chunks[2]),
        _ => {}
    }

    draw_status_bar(f, app, chunks[3]);

    if app.show_help {
        draw_help_popup(f, area);
    }

    if app.modal.is_some() {
        draw_modal_input(f, app, area);
    }
}

pub fn draw_title_bar(f: &mut Frame, app: &App, area: Rect) {
    let pubkey_info = match &app.pubkey {
        Some(pk) => format!("  pubkey: {}…", &pk[..16]),
        None => "  no key set".into(),
    };
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", APP_TITLE),
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD)
                .bg(COLOR_TITLE_BG),
        ),
        Span::styled(
            format!(" {}", app.server),
            Style::default().fg(Color::White).bg(COLOR_TITLE_BG),
        ),
        Span::styled(
            pubkey_info,
            Style::default().fg(COLOR_DIM).bg(COLOR_TITLE_BG),
        ),
    ]))
    .style(Style::default().bg(COLOR_TITLE_BG));
    f.render_widget(title, area);
}

pub fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = TAB_NAMES.iter().map(|&t| Line::from(t)).collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" blossom-tui "),
        )
        .select(app.tab)
        .highlight_style(
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

pub fn draw_blobs_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let loading_suffix = if app.blobs_loading {
        " (loading…)"
    } else {
        ""
    };
    let pubkey_label = app
        .pubkey
        .as_deref()
        .map(|pk| format!(" — {}", &pk[..16.min(pk.len())]))
        .unwrap_or_default();
    let sort_label = app.sort_field.label();
    let filter_label = if app.filter_str.is_empty() {
        String::new()
    } else {
        format!(" [filter: {}]", app.filter_str)
    };
    let title = format!(" Blobs{pubkey_label}{loading_suffix} │ sort:{sort_label}{filter_label} ");

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(COLOR_ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.filter_mode {
        let filter_area = Rect {
            x: inner.x,
            y: inner.y + inner.height.saturating_sub(1),
            width: inner.width,
            height: 1,
        };
        let filter_bar = Paragraph::new(format!("/{}", app.filter_str))
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(filter_bar, filter_area);
    }

    if let Some(err) = app.blobs_error.clone() {
        let msg = Paragraph::new(Span::styled(
            format!("Error: {err}\n\nPress 'r' to retry."),
            Style::default().fg(COLOR_ERR),
        ))
        .wrap(Wrap { trim: false });
        f.render_widget(msg, inner);
        return;
    }

    if app.blobs.is_empty() && !app.blobs_loading {
        let msg = Paragraph::new(Line::from(vec![
            Span::styled("No blobs found. Press ", Style::default().fg(COLOR_DIM)),
            Span::styled(
                "r",
                Style::default()
                    .fg(COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" to refresh.", Style::default().fg(COLOR_DIM)),
        ]));
        f.render_widget(msg, inner);
        return;
    }

    // Apply filter
    let filter_lc = app.filter_str.to_lowercase();
    let mut visible: Vec<&BlobDescriptor> = app
        .blobs
        .iter()
        .filter(|b| {
            if filter_lc.is_empty() {
                return true;
            }
            b.sha256.to_lowercase().contains(&filter_lc)
                || b.content_type
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&filter_lc)
        })
        .collect();

    // Apply sort
    match app.sort_field {
        SortField::Date => visible.sort_by_key(|b| Reverse(b.uploaded.unwrap_or(0))),
        SortField::Size => visible.sort_by_key(|b| Reverse(b.size)),
        SortField::Hash => visible.sort_by(|a, b| a.sha256.cmp(&b.sha256)),
        SortField::ContentType => visible.sort_by(|a, b| {
            a.content_type
                .as_deref()
                .unwrap_or("")
                .cmp(b.content_type.as_deref().unwrap_or(""))
        }),
    }

    let sha_header_label = format!("SHA256");
    let size_header_label = if app.sort_field == SortField::Size {
        "Size ▲".to_string()
    } else {
        "Size".to_string()
    };
    let type_header_label = if app.sort_field == SortField::ContentType {
        "Content-Type ▲".to_string()
    } else {
        "Content-Type".to_string()
    };
    let date_header_label = if app.sort_field == SortField::Date {
        "Uploaded ▼".to_string()
    } else {
        "Uploaded".to_string()
    };

    let header = Row::new(vec![
        Cell::from(sha_header_label).style(Style::default().add_modifier(Modifier::BOLD).fg(COLOR_ACCENT)),
        Cell::from(size_header_label).style(Style::default().add_modifier(Modifier::BOLD).fg(COLOR_ACCENT)),
        Cell::from(type_header_label).style(Style::default().add_modifier(Modifier::BOLD).fg(COLOR_ACCENT)),
        Cell::from(date_header_label).style(Style::default().add_modifier(Modifier::BOLD).fg(COLOR_ACCENT)),
    ])
    .bottom_margin(1);

    let rows: Vec<Row> = visible
        .iter()
        .map(|b| {
            let sha = if b.sha256.len() > 20 {
                format!("{}…{}", &b.sha256[..16], &b.sha256[b.sha256.len() - 4..])
            } else {
                b.sha256.clone()
            };
            let size = format_size(b.size);
            let ctype = b.content_type.clone().unwrap_or_else(|| "—".into());
            let uploaded = b.uploaded.map(format_unix_ts).unwrap_or_else(|| "—".into());

            Row::new(vec![
                Cell::from(sha),
                Cell::from(size),
                Cell::from(ctype),
                Cell::from(uploaded),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(24),
        Constraint::Length(10),
        Constraint::Min(20),
        Constraint::Length(19),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(
            Style::default()
                .bg(COLOR_SELECTED_BG)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, inner, &mut app.blobs_table);
}

pub fn draw_upload_tab(f: &mut Frame, app: &App, area: Rect) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" Upload File ")
        .border_style(Style::default().fg(COLOR_ACCENT));
    let outer_inner = outer.inner(area);
    f.render_widget(outer, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // file path input
            Constraint::Length(3), // controls hint
            Constraint::Min(3),    // result
        ])
        .split(outer_inner);

    let input_border_style = if app.input_mode {
        Style::default()
            .fg(COLOR_ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let input_title = if app.input_mode {
        " File Path [editing] "
    } else {
        " File Path "
    };
    let input_block = Block::default()
        .borders(Borders::ALL)
        .title(input_title)
        .border_style(input_border_style);
    let input_para = Paragraph::new(app.upload_path.as_str())
        .block(input_block)
        .style(Style::default().fg(Color::White));
    f.render_widget(input_para, chunks[0]);

    if app.input_mode {
        f.set_cursor_position((
            chunks[0].x + app.upload_path.len() as u16 + 1,
            chunks[0].y + 1,
        ));
    }

    let hints = if app.input_mode {
        Line::from(vec![
            Span::styled(
                "Enter",
                Style::default()
                    .fg(COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(": upload    "),
            Span::styled(
                "Esc",
                Style::default()
                    .fg(COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(": stop editing"),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "i",
                Style::default()
                    .fg(COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(": edit path    "),
            Span::styled(
                "Enter",
                Style::default()
                    .fg(COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(": upload    "),
            Span::styled(
                "Esc",
                Style::default()
                    .fg(COLOR_ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(": clear"),
        ])
    };
    let hints_para =
        Paragraph::new(hints).block(Block::default().borders(Borders::ALL).title(" Controls "));
    f.render_widget(hints_para, chunks[1]);

    if app.upload_loading {
        let loading = Paragraph::new("Uploading…")
            .block(Block::default().borders(Borders::ALL).title(" Result "))
            .style(Style::default().fg(COLOR_DIM));
        f.render_widget(loading, chunks[2]);
    } else if let Some(msg) = &app.upload_msg {
        let style = if app.upload_ok {
            Style::default().fg(COLOR_OK)
        } else {
            Style::default().fg(COLOR_ERR)
        };
        let result_para = Paragraph::new(msg.as_str())
            .block(Block::default().borders(Borders::ALL).title(" Result "))
            .style(style)
            .wrap(Wrap { trim: false });
        f.render_widget(result_para, chunks[2]);
    } else {
        let placeholder = Paragraph::new("No upload yet.")
            .block(Block::default().borders(Borders::ALL).title(" Result "))
            .style(Style::default().fg(COLOR_DIM));
        f.render_widget(placeholder, chunks[2]);
    }
}

pub fn draw_batch_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let running = if app.batch_running { " (running…)" } else { "" };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Batch Upload{running} "))
        .border_style(Style::default().fg(COLOR_ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // path input
            Constraint::Length(1), // hints
            Constraint::Min(1),    // queue
        ])
        .split(inner);

    // Path input
    let input_style = if app.batch_input_mode {
        Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(COLOR_DIM)
    };
    let input_title = if app.batch_input_mode { " Path (Esc: cancel) " } else { " Path (i: edit, Enter: add) " };
    let input = Paragraph::new(app.batch_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(input_title).border_style(input_style))
        .style(Style::default().fg(Color::White));
    f.render_widget(input, chunks[0]);

    if app.batch_input_mode {
        f.set_cursor_position((chunks[0].x + app.batch_input.len() as u16 + 1, chunks[0].y + 1));
    }

    // Hints
    let done = app.batch_items.iter().filter(|i| matches!(i.status, BatchStatus::Done(_))).count();
    let failed = app.batch_items.iter().filter(|i| matches!(i.status, BatchStatus::Failed(_))).count();
    let hint = format!(
        " {} queued  {} done  {} failed  │  Enter: start upload  x: remove last",
        app.batch_items.len(),
        done,
        failed,
    );
    f.render_widget(
        Paragraph::new(hint.as_str()).style(Style::default().fg(COLOR_DIM)),
        chunks[1],
    );

    // Queue list
    let rows: Vec<Row> = app.batch_items.iter().map(|item| {
        let (status_text, status_style) = match &item.status {
            BatchStatus::Pending => ("pending", Style::default().fg(COLOR_DIM)),
            BatchStatus::Running => ("running…", Style::default().fg(Color::Yellow)),
            BatchStatus::Done(_) => ("✓ done", Style::default().fg(COLOR_OK)),
            BatchStatus::Failed(e) => {
                let _ = e;
                ("✗ failed", Style::default().fg(COLOR_ERR))
            }
        };
        let path_display = if item.path.len() > 60 {
            format!("…{}", &item.path[item.path.len() - 57..])
        } else {
            item.path.clone()
        };
        Row::new(vec![
            Cell::from(path_display),
            Cell::from(status_text).style(status_style),
        ])
    }).collect();

    let widths = [Constraint::Min(40), Constraint::Length(12)];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                Cell::from("Path").style(Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD)),
                Cell::from("Status").style(Style::default().fg(COLOR_ACCENT).add_modifier(Modifier::BOLD)),
            ])
            .bottom_margin(1),
        );
    f.render_widget(table, chunks[2]);
}

pub fn draw_admin_tab(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Admin ")
        .border_style(Style::default().fg(COLOR_ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);

    // Stats panel
    let stats_text = if app.admin_stats_loading {
        "Loading stats…".to_string()
    } else if let Some(e) = &app.admin_stats_error {
        format!("Error: {e}\n\nPress 'r' to retry.")
    } else if let Some(stats) = &app.admin_stats {
        serde_json::to_string_pretty(stats).unwrap_or_else(|_| stats.to_string())
    } else {
        "Press 'r' to load admin stats.".to_string()
    };

    let stats_block = Block::default()
        .borders(Borders::ALL)
        .title(" Stats ")
        .border_style(Style::default().fg(COLOR_DIM));
    f.render_widget(
        Paragraph::new(stats_text.as_str())
            .block(stats_block)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(Color::White)),
        chunks[0],
    );

    // Users panel
    let users_text = if app.admin_users_loading {
        "Loading users…".to_string()
    } else if let Some(e) = &app.admin_users_error {
        format!("Error: {e}")
    } else if let Some(users) = &app.admin_users {
        serde_json::to_string_pretty(users).unwrap_or_else(|_| users.to_string())
    } else {
        "Press 'r' to load users.".to_string()
    };

    let users_block = Block::default()
        .borders(Borders::ALL)
        .title(" Users ")
        .border_style(Style::default().fg(COLOR_DIM));
    f.render_widget(
        Paragraph::new(users_text.as_str())
            .block(users_block)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(Color::White)),
        chunks[1],
    );
}

pub fn draw_status_tab(f: &mut Frame, app: &App, area: Rect) {
    let loading_suffix = if app.status_loading {
        " (loading…)"
    } else {
        ""
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Status — {}{loading_suffix} ", app.server))
        .border_style(Style::default().fg(COLOR_ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(err) = &app.status_error {
        let msg = Paragraph::new(Span::styled(
            format!("Error: {err}\n\nPress 'r' to retry."),
            Style::default().fg(COLOR_ERR),
        ))
        .wrap(Wrap { trim: false });
        f.render_widget(msg, inner);
        return;
    }

    if let Some(data) = &app.status_data {
        let text = serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string());
        let para = Paragraph::new(text)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: false });
        f.render_widget(para, inner);
    } else if !app.status_loading {
        let msg = Paragraph::new(Span::styled(
            "Press 'r' to fetch server status.",
            Style::default().fg(COLOR_DIM),
        ));
        f.render_widget(msg, inner);
    }
}

pub fn draw_keygen_tab(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Key Generation ")
        .border_style(Style::default().fg(COLOR_ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // hint
            Constraint::Length(2), // secret hex
            Constraint::Length(2), // nsec
            Constraint::Length(2), // pubkey
            Constraint::Min(0),    // warning / padding
        ])
        .split(inner);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled(
            "g",
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(": generate a new BIP-340 keypair"),
    ]));
    f.render_widget(hint, chunks[0]);

    if let Some(kp) = &app.keygen_data {
        let label = Style::default()
            .fg(COLOR_ACCENT)
            .add_modifier(Modifier::BOLD);
        let val = Style::default().fg(Color::White);

        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Secret (hex):  ", label),
                Span::styled(&kp.hex_secret, val),
            ])),
            chunks[1],
        );
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Secret (nsec): ", label),
                Span::styled(&kp.nsec, val),
            ])),
            chunks[2],
        );
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Public key:    ", label),
                Span::styled(&kp.pubkey, val),
            ])),
            chunks[3],
        );
        f.render_widget(
            Paragraph::new(Span::styled(
                "⚠  Keep the secret key safe — it is not stored anywhere.",
                Style::default().fg(Color::Yellow),
            )),
            chunks[4],
        );
    }
}

pub fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let content = if let Some((msg, is_err)) = &app.notification {
        Line::from(Span::styled(
            format!(" {msg}"),
            Style::default()
                .fg(if *is_err { COLOR_ERR } else { COLOR_OK })
                .bg(COLOR_TITLE_BG),
        ))
    } else if app.show_help {
        Line::from(Span::styled(
            " ?:close  Tab/S-Tab:switch-tabs  q:quit",
            Style::default().fg(Color::White).bg(COLOR_TITLE_BG),
        ))
    } else {
        let hints = match app.tab {
            0 => " r:refresh  d:delete  o:download  m:mirror  s:sort  /:filter  ↑↓/jk  Tab  ?  q",
            1 => " i:edit-path  Enter:upload  Esc:clear  Tab:next  ?:help  q:quit",
            2 => " i:edit  Enter:add/start  x:remove-last  Tab:next  ?:help  q:quit",
            3 => " r:refresh  Tab:next  ?:help  q:quit",
            4 => " r:refresh  Tab:next  ?:help  q:quit",
            5 => " g:generate  Tab:next  ?:help  q:quit",
            _ => " Tab:next  ?:help  q:quit",
        };
        Line::from(Span::styled(
            hints,
            Style::default().fg(Color::White).bg(COLOR_TITLE_BG),
        ))
    };
    f.render_widget(
        Paragraph::new(content).style(Style::default().bg(COLOR_TITLE_BG)),
        area,
    );
}

pub fn draw_modal_input(f: &mut Frame, app: &App, area: Rect) {
    let (title, label) = match &app.modal {
        Some(Modal::Download { sha256 }) => (
            " Download Blob ",
            format!("Save path for {}…{}:", &sha256[..8.min(sha256.len())], &sha256[sha256.len().saturating_sub(4)..]),
        ),
        Some(Modal::Mirror) => (
            " Mirror Blob ",
            "Remote URL to mirror:".to_string(),
        ),
        None => return,
    };

    let popup_w = 60u16.min(area.width.saturating_sub(4));
    let popup_h = 7u16;
    let popup_x = (area.width.saturating_sub(popup_w)) / 2;
    let popup_y = (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_w, popup_h);

    f.render_widget(Clear, popup_area);

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(3), Constraint::Length(1)])
        .margin(1)
        .split(popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(COLOR_ACCENT));
    f.render_widget(block, popup_area);

    f.render_widget(
        Paragraph::new(label.as_str()).style(Style::default().fg(COLOR_DIM)),
        inner_chunks[0],
    );

    let input = Paragraph::new(app.modal_input.as_str())
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(COLOR_ACCENT)))
        .style(Style::default().fg(Color::White));
    f.render_widget(input, inner_chunks[1]);

    f.set_cursor_position((
        inner_chunks[1].x + app.modal_input.len() as u16 + 1,
        inner_chunks[1].y + 1,
    ));

    f.render_widget(
        Paragraph::new("Enter: confirm   Esc: cancel").style(Style::default().fg(COLOR_DIM)),
        inner_chunks[2],
    );
}

pub fn draw_help_popup(f: &mut Frame, area: Rect) {
    let popup_w = 62u16.min(area.width.saturating_sub(4));
    let popup_h = 26u16.min(area.height.saturating_sub(4));
    let popup_x = (area.width.saturating_sub(popup_w)) / 2;
    let popup_y = (area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(popup_x, popup_y, popup_w, popup_h);

    f.render_widget(Clear, popup_area);

    let y = Style::default().fg(Color::Yellow);
    let h = Style::default()
        .fg(COLOR_ACCENT)
        .add_modifier(Modifier::BOLD);

    let lines = vec![
        Line::from(Span::styled("  Global", h)),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tab / Shift+Tab  ", y),
            Span::raw("Switch tabs"),
        ]),
        Line::from(vec![
            Span::styled("  q / Ctrl+C       ", y),
            Span::raw("Quit"),
        ]),
        Line::from(vec![
            Span::styled("  ?                ", y),
            Span::raw("Toggle this help"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Blobs tab", h)),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ↑ / k            ", y),
            Span::raw("Navigate up"),
        ]),
        Line::from(vec![
            Span::styled("  ↓ / j            ", y),
            Span::raw("Navigate down"),
        ]),
        Line::from(vec![
            Span::styled("  r                ", y),
            Span::raw("Refresh blob list"),
        ]),
        Line::from(vec![
            Span::styled("  d                ", y),
            Span::raw("Delete selected blob"),
        ]),
        Line::from(vec![
            Span::styled("  o                ", y),
            Span::raw("Download selected blob"),
        ]),
        Line::from(vec![
            Span::styled("  m                ", y),
            Span::raw("Mirror blob from URL"),
        ]),
        Line::from(vec![
            Span::styled("  s                ", y),
            Span::raw("Cycle sort (Date/Size/Hash/Type)"),
        ]),
        Line::from(vec![
            Span::styled("  /                ", y),
            Span::raw("Filter blobs (Enter confirm, Esc clear)"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Upload tab", h)),
        Line::from(""),
        Line::from(vec![
            Span::styled("  i                ", y),
            Span::raw("Enter file-path edit mode"),
        ]),
        Line::from(vec![
            Span::styled("  Enter            ", y),
            Span::raw("Start upload"),
        ]),
        Line::from(vec![
            Span::styled("  Esc              ", y),
            Span::raw("Exit edit mode / clear path"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Status tab", h)),
        Line::from(""),
        Line::from(vec![
            Span::styled("  r                ", y),
            Span::raw("Refresh server status"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Keygen tab", h)),
        Line::from(""),
        Line::from(vec![
            Span::styled("  g                ", y),
            Span::raw("Generate new keypair"),
        ]),
    ];

    let help = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help — press ? to close ")
                .border_style(Style::default().fg(COLOR_ACCENT)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(help, popup_area);
}

// ── Main event loop ───────────────────────────────────────────────────────────

pub async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<AppMsg>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        while let Ok(msg) = rx.try_recv() {
            app.apply(msg);
        }

        terminal.draw(|f| draw(f, app))?;

        let has_event = tokio::task::block_in_place(|| event::poll(Duration::from_millis(100)))?;
        if !has_event {
            continue;
        }

        let evt = tokio::task::block_in_place(event::read)?;

        match evt {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // Modal input intercepts all keys when active
                if app.modal.is_some() {
                    match key.code {
                        KeyCode::Esc => {
                            app.modal = None;
                            app.modal_input.clear();
                        }
                        KeyCode::Enter => {
                            match &app.modal {
                                Some(Modal::Download { .. }) => app.confirm_download(),
                                Some(Modal::Mirror) => app.confirm_mirror(),
                                None => {}
                            }
                        }
                        KeyCode::Backspace => { app.modal_input.pop(); }
                        KeyCode::Char(c) => app.modal_input.push(c),
                        _ => {}
                    }
                    continue;
                }

                // Filter mode intercepts keys in Blobs tab
                if app.filter_mode && app.tab == 0 {
                    match key.code {
                        KeyCode::Esc => app.clear_filter(),
                        KeyCode::Enter => app.exit_filter_mode(),
                        KeyCode::Backspace => { app.filter_str.pop(); }
                        KeyCode::Char(c) => {
                            app.filter_str.push(c);
                            app.blobs_table.select(Some(0));
                        }
                        _ => {}
                    }
                    continue;
                }

                if (!app.input_mode && key.code == KeyCode::Char('q'))
                    || (key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c'))
                {
                    return Ok(());
                }

                if !app.input_mode && key.code == KeyCode::Char('?') {
                    app.show_help = !app.show_help;
                    app.notification = None;
                    continue;
                }

                if app.show_help {
                    app.show_help = false;
                    continue;
                }

                app.notification = None;

                if !app.input_mode {
                    match key.code {
                        KeyCode::Tab => {
                            app.next_tab();
                            continue;
                        }
                        KeyCode::BackTab => {
                            app.prev_tab();
                            continue;
                        }
                        _ => {}
                    }
                }

                if app.input_mode {
                    match key.code {
                        KeyCode::Esc => app.input_mode = false,
                        KeyCode::Enter => {
                            app.input_mode = false;
                            app.start_upload();
                        }
                        KeyCode::Backspace => {
                            app.upload_path.pop();
                        }
                        KeyCode::Char(c) => app.upload_path.push(c),
                        _ => {}
                    }
                    continue;
                }

                if app.batch_input_mode {
                    match key.code {
                        KeyCode::Esc => app.batch_input_mode = false,
                        KeyCode::Enter => {
                            app.add_batch_path();
                            app.batch_input_mode = false;
                        }
                        KeyCode::Backspace => { app.batch_input.pop(); }
                        KeyCode::Char(c) => app.batch_input.push(c),
                        _ => {}
                    }
                    continue;
                }

                match app.tab {
                    0 => match key.code {
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::Char('r') => app.refresh_blobs(),
                        KeyCode::Char('d') => app.delete_selected(),
                        KeyCode::Char('o') => app.prompt_download(),
                        KeyCode::Char('m') => app.prompt_mirror(),
                        KeyCode::Char('s') => app.cycle_sort(),
                        KeyCode::Char('/') => app.enter_filter_mode(),
                        _ => {}
                    },
                    1 => match key.code {
                        KeyCode::Char('i') => app.input_mode = true,
                        KeyCode::Enter => app.start_upload(),
                        KeyCode::Esc => {
                            app.upload_path.clear();
                            app.upload_msg = None;
                        }
                        _ => {}
                    },
                    2 => match key.code {
                        KeyCode::Char('i') => app.batch_input_mode = true,
                        KeyCode::Enter => app.start_batch_upload(),
                        KeyCode::Char('x') => app.remove_last_batch_item(),
                        _ => {}
                    },
                    3 => {
                        if key.code == KeyCode::Char('r') {
                            app.refresh_admin();
                        }
                    }
                    4 => {
                        if key.code == KeyCode::Char('r') {
                            app.refresh_status();
                        }
                    }
                    5 => {
                        if key.code == KeyCode::Char('g') {
                            app.generate_keypair();
                        }
                    }
                    _ => {}
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Guess a MIME type from the file extension.
pub fn mime_from_path(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        Some("ogg") => "audio/ogg",
        Some("pdf") => "application/pdf",
        Some("txt") | Some("md") => "text/plain",
        Some("json") => "application/json",
        Some("html") | Some("htm") => "text/html",
        _ => "application/octet-stream",
    }
    .into()
}

/// Human-readable byte size.
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM`.
pub fn format_unix_ts(ts: u64) -> String {
    let secs = ts;
    let mins = secs / 60;
    let hours = mins / 60;
    let days_total = hours / 24;

    let minute = mins % 60;
    let hour = hours % 24;

    let (year, month, day) = days_to_ymd(days_total);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

/// Convert days since 1970-01-01 to (year, month, day).
pub fn days_to_ymd(d: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = d + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

/// Encode a hex secret key as `nsec1` bech32.
pub fn encode_nsec(hex_key: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid hex: {e}"))?;
    let hrp = bech32::Hrp::parse("nsec").map_err(|e| format!("hrp: {e}"))?;
    bech32::encode::<bech32::Bech32>(hrp, &bytes).map_err(|e| format!("bech32: {e}"))
}

/// Decode a secret key from hex or `nsec1` bech32.
pub fn decode_secret_key(input: &str) -> Result<String, String> {
    if input.starts_with("nsec1") {
        let (hrp, data) = bech32::decode(input).map_err(|e| format!("invalid nsec1: {e}"))?;
        if hrp.as_str() != "nsec" {
            return Err(format!("expected nsec hrp, got {hrp}"));
        }
        Ok(hex::encode(data))
    } else {
        if input.len() != 64 || !input.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid hex key: expected 64 hex characters".into());
        }
        Ok(input.to_string())
    }
}

