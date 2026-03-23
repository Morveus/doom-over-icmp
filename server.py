#!/usr/bin/env python3
"""
Doom Over ICMP - Server

Serves a prepared .doom-icmp bundle over ICMP echo replies.
Listens for ICMP Echo Requests and responds with WAD chunks in the payload.

Protocol:
    - ICMP ID field = 0xD00M (0xD00D) to identify Doom requests
    - Sequence 0       -> metadata JSON chunk
    - Sequence 1..N    -> compressed WAD data chunks (1-indexed)

Usage:
    sudo python3 server.py doom1.doom-icmp
    sudo python3 server.py doom1.doom-icmp --interface eth0
"""

import argparse
import json
import struct
import sys
from pathlib import Path

from scapy.all import (
    ICMP,
    IP,
    Raw,
    send,
    sniff,
)

MAGIC = b"DOOMICMP"
DOOM_ICMP_ID = 0xD00D  # Magic ICMP identifier for Doom requests


def load_bundle(bundle_path: str) -> tuple[dict, list[bytes]]:
    """Load a .doom-icmp bundle file, return (metadata, chunks)."""
    data = Path(bundle_path).read_bytes()
    offset = 0

    # Verify magic
    if data[offset : offset + 8] != MAGIC:
        print("Error: Invalid bundle file (bad magic)")
        sys.exit(1)
    offset += 8

    # Version
    (version,) = struct.unpack("!H", data[offset : offset + 2])
    offset += 2

    # Metadata
    (meta_len,) = struct.unpack("!I", data[offset : offset + 4])
    offset += 4
    metadata = json.loads(data[offset : offset + meta_len].decode("utf-8"))
    offset += meta_len

    # Chunks
    chunks = []
    while offset < len(data):
        (chunk_len,) = struct.unpack("!H", data[offset : offset + 2])
        offset += 2
        chunks.append(data[offset : offset + chunk_len])
        offset += chunk_len

    assert len(chunks) == metadata["chunks"], (
        f"Chunk count mismatch: expected {metadata['chunks']}, got {len(chunks)}"
    )

    return metadata, chunks


def handle_packet(packet, metadata_bytes: bytes, chunks: list[bytes], verbose: bool) -> None:
    """Handle an incoming ICMP Echo Request."""
    if not packet.haslayer(ICMP) or packet[ICMP].type != 8:  # Echo Request
        return

    icmp = packet[ICMP]

    # Only respond to packets with our magic ICMP ID
    if icmp.id != DOOM_ICMP_ID:
        return

    seq = icmp.seq
    src_ip = packet[IP].src

    if seq == 0:
        # Metadata request
        payload = metadata_bytes
        if verbose:
            print(f"[{src_ip}] META request -> {len(payload)} bytes")
    elif 1 <= seq <= len(chunks):
        # Chunk request (1-indexed)
        payload = chunks[seq - 1]
        if verbose and seq % 100 == 0:
            print(f"[{src_ip}] Chunk {seq}/{len(chunks)} -> {len(payload)} bytes")
    else:
        if verbose:
            print(f"[{src_ip}] Invalid seq {seq}, ignoring")
        return

    # Build ICMP Echo Reply
    reply = (
        IP(dst=src_ip)
        / ICMP(type=0, id=DOOM_ICMP_ID, seq=seq)
        / Raw(load=payload)
    )
    send(reply, verbose=False)


def serve(bundle_path: str, interface: str | None = None, verbose: bool = True) -> None:
    """Main server loop."""
    print(f"Loading bundle: {bundle_path}")
    metadata, chunks = load_bundle(bundle_path)

    metadata_bytes = json.dumps(metadata).encode("utf-8")

    print(f"\n{'=' * 50}")
    print(f"  DOOM Over ICMP Server")
    print(f"{'=' * 50}")
    print(f"  WAD:        {metadata['filename']}")
    print(f"  Original:   {metadata['original_size']:,} bytes")
    print(f"  Compressed: {metadata['compressed_size']:,} bytes")
    print(f"  Chunks:     {metadata['chunks']} x {metadata['chunk_size']} bytes")
    print(f"  SHA-256:    {metadata['sha256'][:16]}...")
    print(f"{'=' * 50}")
    print(f"\nListening for ICMP Echo Requests (ID=0x{DOOM_ICMP_ID:04X})...")
    print(f"Clients can connect from any IP.\n")

    # Sniff ICMP packets and handle them
    filter_str = "icmp[icmptype] == 8"  # Echo Request only
    sniff_kwargs = {"filter": filter_str, "prn": lambda p: handle_packet(p, metadata_bytes, chunks, verbose), "store": 0}
    if interface:
        sniff_kwargs["iface"] = interface

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nServer stopped.")


def main():
    parser = argparse.ArgumentParser(description="Serve DOOM over ICMP echo replies")
    parser.add_argument("bundle", help="Path to the .doom-icmp bundle file")
    parser.add_argument("--interface", "-i", help="Network interface to listen on")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress per-chunk logging")
    args = parser.parse_args()
    serve(args.bundle, args.interface, verbose=not args.quiet)


if __name__ == "__main__":
    main()
