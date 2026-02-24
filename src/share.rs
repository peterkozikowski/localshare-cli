use crate::proxy;
use crate::session;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

#[derive(Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub host: String,
    pub port: u16,
    pub token: String,
}

impl ConnectionInfo {
    pub fn encode(&self) -> anyhow::Result<String> {
        let json = serde_json::to_string(self)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    pub fn decode(s: &str) -> anyhow::Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        let info: ConnectionInfo = serde_json::from_slice(&bytes)?;
        Ok(info)
    }
}

fn discover_public_addr(local_port: u16) -> anyhow::Result<SocketAddr> {
    let stun_servers = [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
    ];

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", local_port))?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    for server in &stun_servers {
        use std::net::ToSocketAddrs;
        let addr = match server.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => continue,
            },
            Err(_) => continue,
        };

        let mut tid = [0u8; 12];
        rand::thread_rng().fill(&mut tid);

        let mut packet = Vec::with_capacity(20);
        packet.extend_from_slice(&0x0001u16.to_be_bytes());
        packet.extend_from_slice(&0x0000u16.to_be_bytes());
        packet.extend_from_slice(&0x2112A442u32.to_be_bytes());
        packet.extend_from_slice(&tid);

        if socket.send_to(&packet, addr).is_err() {
            continue;
        }

        let mut buf = [0u8; 512];
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            if let Some(mapped) = parse_mapped_address(&buf[..n]) {
                return Ok(mapped);
            }
        }
    }

    anyhow::bail!("Could not discover public address via STUN. You may need to specify your public IP manually or check your network.")
}

fn parse_mapped_address(response: &[u8]) -> Option<SocketAddr> {
    if response.len() < 20 {
        return None;
    }
    let msg_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    let mut offset = 20;
    while offset + 4 <= 20 + msg_len && offset + 4 <= response.len() {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > response.len() {
            break;
        }
        if (attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 && response[offset + 1] == 0x01 {
            let port = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
            let ip = &response[offset + 4..offset + 8];
            if attr_type == 0x0020 {
                let cookie = 0x2112A442u32.to_be_bytes();
                return Some(SocketAddr::new(
                    std::net::Ipv4Addr::new(ip[0] ^ cookie[0], ip[1] ^ cookie[1], ip[2] ^ cookie[2], ip[3] ^ cookie[3]).into(),
                    port ^ 0x2112,
                ));
            } else {
                return Some(SocketAddr::new(
                    std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).into(),
                    port,
                ));
            }
        }
        offset += (attr_len + 3) & !3;
    }
    None
}

fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    hex::encode(&bytes)
}

pub async fn run(target_port: u16, listen_port: Option<u16>) -> anyhow::Result<()> {
    let listen_port = listen_port.unwrap_or(0);

    // Bind the TCP listener first
    let listener = TcpListener::bind(format!("0.0.0.0:{}", listen_port)).await?;
    let actual_port = listener.local_addr()?.port();

    // Discover public address
    print!("Discovering public address... ");
    let public_addr = match discover_public_addr(0) {
        Ok(addr) => {
            println!("{}", addr.ip());
            addr
        }
        Err(e) => {
            println!("failed");
            eprintln!("Warning: {}", e);
            eprintln!("Using local address instead. Remote peers may not be able to connect.");
            let local = listener.local_addr()?;
            local
        }
    };

    let token = generate_token();

    let info = ConnectionInfo {
        host: public_addr.ip().to_string(),
        port: actual_port,
        token: token.clone(),
    };

    let connection_string = info.encode()?;

    // Save session for list/remove commands
    let sess = session::Session {
        pid: std::process::id(),
        target_port,
        listen_port: actual_port,
        public_addr: format!("{}:{}", public_addr.ip(), actual_port),
        connection_string: connection_string.clone(),
        started_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    };
    session::save(&sess)?;

    // Clean up session file on Ctrl+C
    let cleanup_port = target_port;
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = session::remove(cleanup_port);
        std::process::exit(0);
    });

    println!();
    println!("Sharing localhost:{} on port {}", target_port, actual_port);
    println!();
    println!("--- Send this to your peer ---");
    println!("{}", connection_string);
    println!("------------------------------");
    println!();
    println!("Waiting for connections... (Ctrl+C to stop)");

    loop {
        let (mut peer_stream, peer_addr) = listener.accept().await?;
        let token = token.clone();
        let target_port = target_port;

        println!("Incoming connection from {}", peer_addr);

        tokio::spawn(async move {
            // Read auth token
            match proxy::read_msg(&mut peer_stream).await {
                Ok(msg) => {
                    let received_token = String::from_utf8_lossy(&msg);
                    if received_token != token {
                        eprintln!("  {} - invalid token, rejecting", peer_addr);
                        let _ = proxy::write_msg(&mut peer_stream, b"REJECT").await;
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("  {} - failed to read auth: {}", peer_addr, e);
                    return;
                }
            }

            // Send OK
            if let Err(e) = proxy::write_msg(&mut peer_stream, b"OK").await {
                eprintln!("  {} - failed to send OK: {}", peer_addr, e);
                return;
            }

            println!("  {} - authenticated, proxying to localhost:{}", peer_addr, target_port);

            // Connect to local service
            match TcpStream::connect(format!("127.0.0.1:{}", target_port)).await {
                Ok(local_stream) => {
                    if let Err(e) = proxy::bridge(peer_stream, local_stream).await {
                        eprintln!("  {} - proxy error: {}", peer_addr, e);
                    } else {
                        println!("  {} - disconnected", peer_addr);
                    }
                }
                Err(e) => {
                    eprintln!("  {} - could not connect to localhost:{}: {}", peer_addr, target_port, e);
                }
            }
        });
    }
}
