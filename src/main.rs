mod connect;
mod nat;
mod proxy;
mod session;
mod share;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "localshare", about = "Simple P2P port sharing")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Share a local port over P2P. Prints connection info to send to your peer.
    Share {
        /// Local port to share (e.g. 8080)
        port: u16,
        /// Port to listen on for incoming peer connections (default: random)
        #[arg(short, long)]
        listen_port: Option<u16>,
    },
    /// Connect to a peer using their connection info
    Connect {
        /// Connection string from the sharing peer
        info: String,
        /// Local port to expose the tunneled service on (default: random)
        #[arg(short, long)]
        local_port: Option<u16>,
    },
    /// Detect your NAT type and report P2P connectivity
    Nat,
    /// List all active port shares
    List,
    /// Stop sharing a port
    Remove {
        /// The local port to stop sharing
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Share { port, listen_port } => {
            share::run(port, listen_port).await?;
        }
        Commands::Connect { info, local_port } => {
            connect::run(&info, local_port).await?;
        }
        Commands::Nat => {
            nat::run().await?;
        }
        Commands::List => {
            let sessions = session::list_active()?;
            if sessions.is_empty() {
                println!("No active shares.");
            } else {
                println!("{:<10} {:<14} {:<24} {}", "PORT", "LISTEN PORT", "PUBLIC ADDRESS", "STARTED");
                println!("{}", "-".repeat(70));
                for s in &sessions {
                    println!("{:<10} {:<14} {:<24} {}", s.target_port, s.listen_port, s.public_addr, s.started_at);
                }
                println!("\n{} active share(s)", sessions.len());
            }
        }
        Commands::Remove { port } => {
            match session::find_by_port(port)? {
                Some(s) => {
                    // Kill the sharing process
                    unsafe { libc::kill(s.pid as i32, libc::SIGTERM); }
                    session::remove(port)?;
                    println!("Stopped sharing port {}.", port);
                }
                None => {
                    println!("No active share found for port {}.", port);
                }
            }
        }
    }

    Ok(())
}
