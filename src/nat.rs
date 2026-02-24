use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
];

/// STUN Binding Request magic cookie and header
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20);
    // Message type: Binding Request (0x0001)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    // Message length: 0 (no attributes)
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Magic cookie
    packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    packet.extend_from_slice(transaction_id);
    packet
}

fn parse_xor_mapped_address(response: &[u8], _transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if response.len() < 20 {
        return None;
    }

    let msg_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    if response.len() < 20 + msg_len {
        return None;
    }

    let mut offset = 20;
    while offset + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > response.len() {
            break;
        }

        // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
        if (attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 {
            let family = response[offset + 1];
            if family == 0x01 {
                // IPv4
                let port = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
                let ip_bytes = &response[offset + 4..offset + 8];

                if attr_type == 0x0020 {
                    // XOR with magic cookie
                    let xor_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
                    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                    let xor_ip = std::net::Ipv4Addr::new(
                        ip_bytes[0] ^ cookie_bytes[0],
                        ip_bytes[1] ^ cookie_bytes[1],
                        ip_bytes[2] ^ cookie_bytes[2],
                        ip_bytes[3] ^ cookie_bytes[3],
                    );
                    return Some(SocketAddr::new(xor_ip.into(), xor_port));
                } else {
                    let ip = std::net::Ipv4Addr::new(
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                    );
                    return Some(SocketAddr::new(ip.into(), port));
                }
            }
        }

        // Pad to 4-byte boundary
        offset += (attr_len + 3) & !3;
    }
    None
}

fn stun_query(socket: &UdpSocket, server: &str) -> Option<SocketAddr> {
    let addr: SocketAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => {
            // Resolve hostname
            use std::net::ToSocketAddrs;
            match server.to_socket_addrs() {
                Ok(mut addrs) => addrs.next()?,
                Err(_) => return None,
            }
        }
    };

    let mut tid = [0u8; 12];
    for b in tid.iter_mut() {
        *b = rand::random();
    }

    let request = build_binding_request(&tid);
    socket.send_to(&request, addr).ok()?;

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => parse_xor_mapped_address(&buf[..n], &tid),
        Err(_) => None,
    }
}

pub async fn run() -> anyhow::Result<()> {
    println!("Detecting NAT type...\n");

    // Test 1: Query from a single socket to multiple STUN servers
    let socket1 = UdpSocket::bind("0.0.0.0:0")?;
    socket1.set_read_timeout(Some(Duration::from_secs(3)))?;
    let local_addr = socket1.local_addr()?;

    println!("Local address: {}", local_addr);

    let mut mapped_addresses: Vec<SocketAddr> = Vec::new();

    for server in STUN_SERVERS.iter().take(3) {
        print!("Querying {}... ", server);
        match stun_query(&socket1, server) {
            Some(addr) => {
                println!("{}", addr);
                mapped_addresses.push(addr);
            }
            None => {
                println!("no response");
            }
        }
    }

    if mapped_addresses.is_empty() {
        println!("\n--- NAT Detection Result ---");
        println!("Type: BLOCKED");
        println!("Could not reach any STUN servers.");
        println!("P2P connections: NOT POSSIBLE");
        println!("\nYou may be behind a strict firewall that blocks UDP traffic.");
        return Ok(());
    }

    // Test 2: Query from a second socket to see if we get a different mapping
    let socket2 = UdpSocket::bind("0.0.0.0:0")?;
    socket2.set_read_timeout(Some(Duration::from_secs(3)))?;

    let mapped2 = stun_query(&socket2, STUN_SERVERS[0]);

    let public_ip = mapped_addresses[0].ip();

    // Check if our mapped address matches local (no NAT)
    let local_ip_check = local_addr.ip();
    let is_public = mapped_addresses[0].ip() == local_ip_check
        || local_ip_check.to_string() == "0.0.0.0";

    // Check if all mapped addresses have the same IP and port
    let all_same_port = mapped_addresses.windows(2).all(|w| w[0].port() == w[1].port());
    let all_same_ip = mapped_addresses.windows(2).all(|w| w[0].ip() == w[1].ip());

    println!("\n--- NAT Detection Result ---");
    println!("Public IP: {}", public_ip);

    if mapped_addresses.len() >= 2 && all_same_ip && all_same_port {
        // Same mapping for different destinations = Cone NAT or no NAT
        if is_public || (mapped_addresses[0].port() == local_addr.port()) {
            println!("Type: OPEN / NO NAT");
            println!("P2P connections: EASY");
            println!("\nYour port is directly reachable. Sharing will work great.");
        } else {
            // Check if different source ports get different mappings
            match mapped2 {
                Some(m2) if m2.ip() == public_ip => {
                    println!("Type: FULL CONE NAT");
                    println!("P2P connections: EASY");
                    println!("\nOnce a port is mapped, anyone can reach it. Sharing will work.");
                }
                _ => {
                    println!("Type: RESTRICTED CONE NAT");
                    println!("P2P connections: POSSIBLE");
                    println!("\nDirect connections work if both peers initiate. Sharing should work");
                    println!("if the connecting peer can reach your public IP.");
                }
            }
        }
    } else if mapped_addresses.len() >= 2 && all_same_ip && !all_same_port {
        println!("Type: SYMMETRIC NAT");
        println!("P2P connections: DIFFICULT");
        println!("\nEach destination gets a different port mapping.");
        println!("Direct P2P is unreliable. You may need to use port forwarding");
        println!("or ensure the connecting peer is on an open/cone NAT.");
    } else {
        println!("Type: UNKNOWN");
        println!("P2P connections: UNCERTAIN");
        println!("\nCould not determine NAT type reliably. Try port forwarding if sharing fails.");
    }

    Ok(())
}
