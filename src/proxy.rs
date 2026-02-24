use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bidirectional proxy between two TCP streams.
/// Copies data in both directions until either side closes.
pub async fn bridge(mut a: TcpStream, mut b: TcpStream) -> anyhow::Result<()> {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();

    let a_to_b = tokio::io::copy(&mut ar, &mut bw);
    let b_to_a = tokio::io::copy(&mut br, &mut aw);

    tokio::select! {
        r = a_to_b => { r?; }
        r = b_to_a => { r?; }
    }

    Ok(())
}

/// Read exactly `n` bytes from a stream.
pub async fn read_exact(stream: &mut TcpStream, n: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed message (4-byte big-endian length + payload).
pub async fn write_msg(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed message.
pub async fn read_msg(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let len_bytes = read_exact(stream, 4).await?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len > 1024 * 1024 {
        anyhow::bail!("message too large: {} bytes", len);
    }
    read_exact(stream, len).await
}
