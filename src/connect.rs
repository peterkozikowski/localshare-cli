use crate::proxy;
use crate::share::ConnectionInfo;
use tokio::net::{TcpListener, TcpStream};

pub async fn run(info_str: &str, local_port: Option<u16>) -> anyhow::Result<()> {
    let info = ConnectionInfo::decode(info_str)
        .map_err(|_| anyhow::anyhow!("Invalid connection string. Make sure you copied it correctly."))?;

    println!("Connecting to {}:{}...", info.host, info.port);

    // Connect to the peer
    let mut peer_stream = TcpStream::connect(format!("{}:{}", info.host, info.port)).await
        .map_err(|e| anyhow::anyhow!("Could not connect to peer at {}:{}: {}\nMake sure the peer is online and the port is reachable.", info.host, info.port, e))?;

    // Send auth token
    proxy::write_msg(&mut peer_stream, info.token.as_bytes()).await?;

    // Read response
    let response = proxy::read_msg(&mut peer_stream).await?;
    let response_str = String::from_utf8_lossy(&response);

    if response_str != "OK" {
        anyhow::bail!("Authentication failed. The connection was rejected by the peer.");
    }

    println!("Connected and authenticated!");

    // If a local port is specified, start a local listener and proxy connections
    // Otherwise, just proxy this single connection to stdout (for piping)
    let local_port = local_port.unwrap_or(0);
    let local_listener = TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;
    let actual_port = local_listener.local_addr()?.port();

    println!();
    println!("Service available at: 127.0.0.1:{}", actual_port);
    println!("(Ctrl+C to disconnect)");

    // Accept the first local connection and bridge it to the peer
    // For subsequent connections, we'd need to reconnect to the peer
    let (local_stream, _) = local_listener.accept().await?;

    println!("Local client connected, proxying traffic...");

    proxy::bridge(peer_stream, local_stream).await?;

    println!("Connection closed.");

    Ok(())
}
