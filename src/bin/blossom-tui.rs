//! blossom-tui — gitui-inspired Terminal User Interface for Blossom blob storage.
//!
//! Multi-tab keyboard-driven TUI for managing blobs on a Blossom server.
//!
//! # Tabs
//! - **Blobs** — list, navigate, delete blobs
//! - **Upload** — upload a local file
//! - **Status** — fetch and display `/status` JSON
//! - **Keygen** — generate a fresh BIP-340 keypair
//!
//! # Usage
//! ```text
//! cargo run --bin blossom-tui --features tui -- [OPTIONS]
//!
//! OPTIONS:
//!   -s, --server <URL>   Blossom server URL [default: http://localhost:3000]
//!   -k, --key    <KEY>   Secret key (hex or nsec1 bech32)
//!
//! ENV:
//!   BLOSSOM_SERVER       Server URL
//!   BLOSSOM_SECRET_KEY   Secret key
//! ```

use std::io::{self, Stdout};
use std::time::Duration;

use blossom_rs::{BlobDescriptor, BlossomClient, BlossomSigner, Signer};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
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

const APP_TITLE: &str = "blossom-tui";
const TAB_NAMES: &[&str] = &[" Blobs ", " Upload ", " Status ", " Keygen "];

const COLOR_ACCENT: Color = Color::Cyan;
const COLOR_OK: Color = Color::Green;
const COLOR_ERR: Color = Color::Red;
const COLOR_DIM: Color = Color::DarkGray;
const COLOR_SELECTED_BG: Color = Color::Blue;
const COLOR_TITLE_BG: Color = Color::DarkGray;

// ── Async messages ────────────────────────────────────────────────────────────

#[derive(Debug)]
enum AppMsg {
    BlobsLoaded(Vec<BlobDescriptor>),
    BlobsError(String),
    UploadDone(BlobDescriptor),
    UploadError(String),
    StatusLoaded(serde_json::Value),
    StatusError(String),
    DeleteDone(String),
    DeleteError(String),
}

// ── App state ─────────────────────────────────────────────────────────────────

struct KeygenResult {
    hex_secret: String,
    nsec: String,
    pubkey: String,
}

struct App {
    // Config
    server: String,
    secret_key: Option<String>,
    pubkey: Option<String>,

    // Navigation
    tab: usize,

    // Blobs tab
    blobs: Vec<BlobDescriptor>,
    blobs_table: TableState,
    blobs_loading: bool,
    blobs_error: Option<String>,

    // Upload tab
    upload_path: String,
    upload_loading: bool,
    upload_msg: Option<String>,
    upload_ok: bool,
    input_mode: bool,

    // Status tab
    status_data: Option<serde_json::Value>,
    status_loading: bool,
    status_error: Option<String>,

    // Keygen tab
    keygen_data: Option<KeygenResult>,

    // UI state
    show_help: bool,
    notification: Option<(String, bool)>, // (message, is_error)

    // Channel sender for async results
    tx: mpsc::UnboundedSender<AppMsg>,
}

impl App {
    fn new(server: String, secret_key: Option<String>, tx: mpsc::UnboundedSender<AppMsg>) -> Self {
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
            upload_path: String::new(),
            upload_loading: false,
            upload_msg: None,
            upload_ok: false,
            input_mode: false,
            status_data: None,
            status_loading: false,
            status_error: None,
            keygen_data: None,
            show_help: false,
            notification: None,
            tx,
        }
    }

    fn apply(&mut self, msg: AppMsg) {
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
                // Refresh blob list after upload
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
        }
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    fn refresh_blobs(&mut self) {
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

    fn start_upload(&mut self) {
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

    fn delete_selected(&mut self) {
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

    fn refresh_status(&mut self) {
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

    fn generate_keypair(&mut self) {
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

    fn next_tab(&mut self) {
        self.tab = (self.tab + 1) % TAB_NAMES.len();
        self.on_tab_enter();
    }

    fn prev_tab(&mut self) {
        self.tab = self.tab.checked_sub(1).unwrap_or(TAB_NAMES.len() - 1);
        self.on_tab_enter();
    }

    fn on_tab_enter(&mut self) {
        match self.tab {
            0 if self.blobs.is_empty() && !self.blobs_loading => self.refresh_blobs(),
            2 if self.status_data.is_none() && !self.status_loading => self.refresh_status(),
            _ => {}
        }
    }

    fn scroll_up(&mut self) {
        if self.tab == 0 {
            let i = self
                .blobs_table
                .selected()
                .map(|i| i.saturating_sub(1))
                .unwrap_or(0);
            self.blobs_table.select(Some(i));
        }
    }

    fn scroll_down(&mut self) {
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
}

// ── Drawing ───────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
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
        2 => draw_status_tab(f, app, chunks[2]),
        3 => draw_keygen_tab(f, app, chunks[2]),
        _ => {}
    }

    draw_status_bar(f, app, chunks[3]);

    if app.show_help {
        draw_help_popup(f, area);
    }
}

fn draw_title_bar(f: &mut Frame, app: &App, area: Rect) {
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

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
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

fn draw_blobs_tab(f: &mut Frame, app: &mut App, area: Rect) {
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
    let title = format!(" Blobs{pubkey_label}{loading_suffix} ");

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(COLOR_ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

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

    let header = Row::new(vec![
        Cell::from("SHA256").style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(COLOR_ACCENT),
        ),
        Cell::from("Size").style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(COLOR_ACCENT),
        ),
        Cell::from("Content-Type").style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(COLOR_ACCENT),
        ),
        Cell::from("Uploaded").style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(COLOR_ACCENT),
        ),
    ])
    .bottom_margin(1);

    let rows: Vec<Row> = app
        .blobs
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

fn draw_upload_tab(f: &mut Frame, app: &App, area: Rect) {
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

    // File path input field
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

    // Controls hint
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

    // Result panel
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

fn draw_status_tab(f: &mut Frame, app: &App, area: Rect) {
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

fn draw_keygen_tab(f: &mut Frame, app: &App, area: Rect) {
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

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
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
            0 => " r:refresh  d:delete  ↑↓/jk:navigate  Tab:next  ?:help  q:quit",
            1 => " i:edit-path  Enter:upload  Esc:clear  Tab:next  ?:help  q:quit",
            2 => " r:refresh  Tab:next  ?:help  q:quit",
            3 => " g:generate  Tab:next  ?:help  q:quit",
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

fn draw_help_popup(f: &mut Frame, area: Rect) {
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

// ── Main loop ─────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (server, secret_key) = parse_args()?;

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, mut rx) = mpsc::unbounded_channel::<AppMsg>();
    let mut app = App::new(server, secret_key, tx);

    // Kick off initial data loads
    app.refresh_blobs();
    app.refresh_status();

    let result = run_loop(&mut terminal, &mut app, &mut rx).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<AppMsg>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Drain async messages without blocking
        while let Ok(msg) = rx.try_recv() {
            app.apply(msg);
        }

        terminal.draw(|f| draw(f, app))?;

        // Poll for terminal input without blocking the tokio executor
        let has_event = tokio::task::block_in_place(|| event::poll(Duration::from_millis(100)))?;
        if !has_event {
            continue;
        }

        let evt = tokio::task::block_in_place(event::read)?;

        match evt {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // Global: quit
                if (!app.input_mode && key.code == KeyCode::Char('q'))
                    || (key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c'))
                {
                    return Ok(());
                }

                // Global: toggle help (? not captured in input mode)
                if !app.input_mode && key.code == KeyCode::Char('?') {
                    app.show_help = !app.show_help;
                    app.notification = None;
                    continue;
                }

                // Any key closes the help overlay
                if app.show_help {
                    app.show_help = false;
                    continue;
                }

                // Clear notification on any non-meta key
                app.notification = None;

                // Tab navigation (not in input mode)
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

                // Input mode (Upload tab file-path field)
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

                // Tab-specific key handlers
                match app.tab {
                    0 => match key.code {
                        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                        KeyCode::Char('r') => app.refresh_blobs(),
                        KeyCode::Char('d') => app.delete_selected(),
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
                    2 => {
                        if key.code == KeyCode::Char('r') {
                            app.refresh_status();
                        }
                    }
                    3 => {
                        if key.code == KeyCode::Char('g') {
                            app.generate_keypair();
                        }
                    }
                    _ => {}
                }
            }
            Event::Resize(_, _) => {
                // ratatui re-renders automatically; just continue
            }
            _ => {}
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Guess a MIME type from the file extension.
fn mime_from_path(path: &std::path::Path) -> String {
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
fn format_size(bytes: u64) -> String {
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
fn format_unix_ts(ts: u64) -> String {
    // Simple manual UTC conversion without pulling in chrono.
    let secs = ts;
    let mins = secs / 60;
    let hours = mins / 60;
    let days_total = hours / 24;

    let second = secs % 60;
    let minute = mins % 60;
    let hour = hours % 24;

    // Days since Unix epoch → Gregorian date (Zeller-like algo)
    let (year, month, day) = days_to_ymd(days_total);
    let _ = second; // seconds not shown in display

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

/// Convert days since 1970-01-01 to (year, month, day).
fn days_to_ymd(d: u64) -> (u64, u64, u64) {
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
fn encode_nsec(hex_key: &str) -> Result<String, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid hex: {e}"))?;
    let hrp = bech32::Hrp::parse("nsec").map_err(|e| format!("hrp: {e}"))?;
    bech32::encode::<bech32::Bech32>(hrp, &bytes).map_err(|e| format!("bech32: {e}"))
}

/// Decode a secret key from hex or `nsec1` bech32.
fn decode_secret_key(input: &str) -> Result<String, String> {
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

/// Parse CLI arguments: returns `(server_url, secret_key_hex_opt)`.
fn parse_args() -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let mut server =
        std::env::var("BLOSSOM_SERVER").unwrap_or_else(|_| "http://localhost:3000".into());
    let mut secret_key: Option<String> = std::env::var("BLOSSOM_SECRET_KEY").ok();

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--server" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    server = v.clone();
                }
            }
            "-k" | "--key" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    secret_key = Some(decode_secret_key(v)?);
                }
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("blossom-tui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    Ok((server, secret_key))
}

fn print_usage() {
    println!("blossom-tui — Terminal UI for Blossom blob storage\n");
    println!("USAGE:");
    println!("  blossom-tui [OPTIONS]\n");
    println!("OPTIONS:");
    println!("  -s, --server <URL>   Blossom server URL [default: http://localhost:3000]");
    println!("  -k, --key <KEY>      Secret key (hex or nsec1 bech32)");
    println!("  -h, --help           Print this help");
    println!("  -V, --version        Print version info\n");
    println!("ENV:");
    println!("  BLOSSOM_SERVER       Server URL (fallback when --server not set)");
    println!("  BLOSSOM_SECRET_KEY   Secret key (fallback when --key not set)");
}
