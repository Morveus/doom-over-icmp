# DOOM Over ICMP

**Can it ping DOOM?** Yes. Yes it can.

Inspired by [Doom Over DNS](https://github.com/resumex/doom-over-dns), this project delivers the entirety of DOOM's shareware WAD through ICMP Echo Request/Reply packets (aka `ping`). A server splits the compressed WAD into ~2,800 chunks and serves each one as the payload of an ICMP Echo Reply. The client pings its way to a fully playable copy of DOOM.

```
 ┌──────────┐                              ┌──────────┐
 │  Client  │  ICMP Echo Request (seq=N)   │  Server  │
 │          │ ───────────────────────────►  │          │
 │          │                              │  Has the  │
 │          │  ICMP Echo Reply             │  WAD     │
 │          │  ◄─── payload: chunk N ────  │          │
 │          │                              │          │
 │  x ~2800 │                              │          │
 │          │                              │          │
 │ reassemble + decompress + launch DOOM   │          │
 └──────────┘                              └──────────┘
```

## How It Works

1. **`prepare.py`** takes a DOOM WAD file, compresses it with zlib, splits it into 1400-byte chunks, and writes a `.doom-icmp` bundle
2. **`server.py`** loads the bundle and listens for ICMP Echo Requests with a magic ID (`0xD00D`). Each request's sequence number maps to a chunk index
3. **`client.py`** pings the server sequentially (seq 0 = metadata, seq 1..N = chunks), reassembles the WAD in memory, verifies SHA-256, and launches the game

## Requirements

- Python 3.10+
- [scapy](https://scapy.net/) (`pip install scapy`)
- Root/sudo (raw sockets require elevated privileges)
- A DOOM engine for the client machine (e.g., [chocolate-doom](https://www.chocolate-doom.org/))
- `DOOM1.WAD` (shareware, freely available)

**PowerShell client only:**
- PowerShell 7+ (cross-platform) or Windows PowerShell 5.1
- Administrator privileges (raw sockets)

## Quick Start

### Server

```bash
# Prepare the WAD bundle
sudo python3 prepare.py DOOM1.WAD

# Serve it over ICMP
sudo python3 server.py DOOM1.doom-icmp
```

### Client

```bash
# Fetch DOOM over ICMP and play it
sudo python3 client.py <server-ip>

# Or just save the WAD without launching
sudo python3 client.py <server-ip> --output doom1.wad

# Use a different DOOM engine
sudo python3 client.py <server-ip> --launcher crispy-doom
```

### Client (PowerShell - Windows)

```powershell
# Run as Administrator
.\client.ps1 -Server <server-ip>

# Save WAD without launching
.\client.ps1 -Server <server-ip> -OutputPath doom1.wad

# Use a different DOOM engine
.\client.ps1 -Server <server-ip> -Launcher crispy-doom
```

## Protocol

| Packet | ICMP ID | Sequence | Payload |
|--------|---------|----------|---------|
| Request metadata | `0xD00D` | `0` | *(empty)* |
| Reply metadata | `0xD00D` | `0` | JSON: `{filename, chunks, sha256, ...}` |
| Request chunk N | `0xD00D` | `N` (1-indexed) | *(empty)* |
| Reply chunk N | `0xD00D` | `N` | 1400 bytes of zlib-compressed WAD |

## Numbers

| Metric | Value |
|--------|-------|
| DOOM1.WAD (shareware) | ~4.2 MB |
| Compressed (zlib level 9) | ~2.8 MB |
| Chunk size | 1,400 bytes |
| Total chunks | ~2,000 |
| Transfer time (LAN) | ~10-30 seconds |
| Transfer time (Internet) | 1-5 minutes |

## Why?

Because someone put DOOM in 2,000 DNS records and we thought: what if we put it in 2,000 pings instead?

## Credits

- Inspired by [Andrew Rice's Doom Over DNS](https://blog.rice.is/post/doom-over-dns/)
- DOOM by id Software (1993)
- Built with [scapy](https://scapy.net/)

## License

MIT
