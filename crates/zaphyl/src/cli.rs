//! Command-line interface: run the server, or manage sites.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zaphyl", version, about = "Reverse proxy and web server")]
pub struct Cli {
    /// Config file to run with (default mode).
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the server (this is also the default with --config).
    Run,
    /// Manage sites.
    #[command(subcommand)]
    Site(SiteCmd),
    /// Apply config changes to the running server.
    Reload,
}

#[derive(Subcommand)]
pub enum SiteCmd {
    /// Add a site for a domain.
    Add {
        domain: String,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        php: bool,
        #[arg(long)]
        r#static: bool,
        #[arg(long)]
        no_tls: bool,
    },
    /// List configured sites.
    List,
    /// Remove a site.
    Remove { domain: String },
    /// Enable a previously disabled site.
    Enable { domain: String },
    /// Disable a site without deleting it.
    Disable { domain: String },
}

pub fn run_site(_cmd: SiteCmd) -> std::process::ExitCode {
    eprintln!("not yet implemented");
    std::process::ExitCode::FAILURE
}

pub fn run_reload() -> std::process::ExitCode {
    eprintln!("not yet implemented");
    std::process::ExitCode::FAILURE
}
