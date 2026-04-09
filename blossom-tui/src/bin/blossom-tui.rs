//! blossom-tui binary entry point.

use std::io;

use blossom_tui::{App, AppMsg, run_loop};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (server, secret_key) = parse_args()?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, mut rx) = mpsc::unbounded_channel::<AppMsg>();
    let mut app = App::new(server, secret_key, tx);

    app.refresh_blobs();
    app.refresh_status();

    let result = run_loop(&mut terminal, &mut app, &mut rx).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

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
                    secret_key = Some(blossom_tui::decode_secret_key(v)?);
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
