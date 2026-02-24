# LocalShare

Simple P2P port sharing CLI. Share any local port directly with another person, no servers in between.

## Install

```bash
cargo install --path .
```

## Usage

### Check your NAT type

```bash
localshare nat
```

Reports your NAT type and whether direct P2P connections will work.

### Share a port

```bash
# Share localhost:8080
localshare share 8080

# Share on a specific listen port
localshare share 8080 --listen-port 9000
```

Prints a connection string. Send it to your peer.

### Connect to a peer

```bash
# Connect using the connection string
localshare connect <CONNECTION_STRING>

# Specify local port
localshare connect <CONNECTION_STRING> --local-port 3000
```

Opens a local port that tunnels traffic to the peer's shared service.

## How it works

1. `share` discovers your public IP via STUN, opens a TCP listener, and prints a base64 connection string
2. You send that string to your peer (chat, email, whatever)
3. `connect` decodes the string and opens a direct TCP connection to you
4. Traffic is proxied bidirectionally - your peer accesses the service on their local port

No relay servers. No accounts. No signup. Just direct P2P.

## Limitations

- Both peers need to be reachable (run `localshare nat` to check)
- Symmetric NAT makes direct connections difficult
- If you're behind a firewall, you may need to port forward the listen port

## License

MIT
