#!/usr/bin/env python3
"""
Doom Over ICMP - Client

Fetches a DOOM WAD from a Doom Over ICMP server by sending ICMP Echo Requests
and reassembling the WAD from the payloads. Then launches the game.

Protocol:
    - ICMP ID field = 0xD00D to identify Doom requests
    - Sequence 0       -> request metadata
    - Sequence 1..N    -> request compressed WAD chunks (1-indexed)

Usage:
    sudo python3 client.py <server-ip>
    sudo python3 client.py <server-ip> --launcher chocolate-doom
    sudo python3 client.py <server-ip> --output doom1.wad  # save to disk instead of launching
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import zlib

from scapy.all import (
    ICMP,
    IP,
    Raw,
    sr1,
)

DOOM_ICMP_ID = 0xD00D
TIMEOUT = 5        # seconds per packet
MAX_RETRIES = 5    # retries per chunk
PARALLEL_BATCH = 1 # sequential by default (ICMP is unreliable)


def request_chunk(server: str, seq: int, timeout: float = TIMEOUT) -> bytes | None:
    """Send an ICMP Echo Request and return the payload of the reply."""
    pkt = IP(dst=server) / ICMP(type=8, id=DOOM_ICMP_ID, seq=seq)
    reply = sr1(pkt, timeout=timeout, verbose=False)

    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
        if reply.haslayer(Raw):
            return bytes(reply[Raw].load)
    return None


def fetch_with_retry(server: str, seq: int, label: str = "") -> bytes:
    """Fetch a chunk with retries."""
    for attempt in range(MAX_RETRIES):
        data = request_chunk(server, seq)
        if data is not None:
            return data
        if attempt < MAX_RETRIES - 1:
            wait = 0.5 * (attempt + 1)
            print(f"  Retry {attempt + 1}/{MAX_RETRIES} for {label or f'seq {seq}'}...")
            time.sleep(wait)
    print(f"Error: Failed to fetch {label or f'seq {seq}'} after {MAX_RETRIES} attempts")
    sys.exit(1)


def print_progress(current: int, total: int, start_time: float) -> None:
    """Print a progress bar."""
    elapsed = time.time() - start_time
    pct = current / total * 100
    bar_len = 40
    filled = int(bar_len * current // total)
    bar = "#" * filled + "-" * (bar_len - filled)

    if current > 0:
        eta = elapsed / current * (total - current)
        speed = current / elapsed if elapsed > 0 else 0
        print(f"\r  [{bar}] {pct:5.1f}% | {current}/{total} | {speed:.0f} chunks/s | ETA {eta:.0f}s", end="", flush=True)
    else:
        print(f"\r  [{bar}] {pct:5.1f}% | {current}/{total}", end="", flush=True)


def fetch_doom(server: str) -> tuple[bytes, str]:
    """Fetch the full WAD from the server. Returns (wad_bytes, filename)."""

    print(f"\n{'=' * 50}")
    print(f"  DOOM Over ICMP Client")
    print(f"{'=' * 50}")
    print(f"  Server: {server}")
    print(f"{'=' * 50}\n")

    # Step 1: Fetch metadata
    print("[1/3] Fetching metadata...")
    meta_raw = fetch_with_retry(server, 0, "metadata")
    metadata = json.loads(meta_raw.decode("utf-8"))

    filename = metadata["filename"]
    num_chunks = metadata["chunks"]
    chunk_size = metadata["chunk_size"]
    original_size = metadata["original_size"]
    compressed_size = metadata["compressed_size"]
    expected_sha256 = metadata["sha256"]

    print(f"       WAD:        {filename}")
    print(f"       Original:   {original_size:,} bytes")
    print(f"       Compressed: {compressed_size:,} bytes")
    print(f"       Chunks:     {num_chunks} x {chunk_size} bytes")
    print()

    # Step 2: Fetch all chunks
    print(f"[2/3] Fetching {num_chunks} chunks over ICMP...")
    chunks = [None] * num_chunks
    start_time = time.time()

    for i in range(num_chunks):
        chunk_data = fetch_with_retry(server, i + 1, f"chunk {i + 1}/{num_chunks}")
        chunks[i] = chunk_data
        print_progress(i + 1, num_chunks, start_time)

    elapsed = time.time() - start_time
    print(f"\n       Done in {elapsed:.1f}s ({num_chunks / elapsed:.0f} chunks/s)")
    print()

    # Step 3: Reassemble and verify
    print("[3/3] Reassembling WAD...")
    compressed = b"".join(chunks)
    print(f"       Compressed payload: {len(compressed):,} bytes")

    wad = zlib.decompress(compressed)
    print(f"       Decompressed WAD:   {len(wad):,} bytes")

    actual_sha256 = hashlib.sha256(wad).hexdigest()
    if actual_sha256 != expected_sha256:
        print(f"\n  ERROR: SHA-256 mismatch!")
        print(f"    Expected: {expected_sha256}")
        print(f"    Got:      {actual_sha256}")
        sys.exit(1)

    print(f"       SHA-256 verified:   {actual_sha256[:16]}...")
    print()

    return wad, filename


def launch_doom(wad_bytes: bytes, filename: str, launcher: str) -> None:
    """Write WAD to a temp file and launch the game."""
    with tempfile.NamedTemporaryFile(suffix=f"_{filename}", delete=False) as f:
        f.write(wad_bytes)
        temp_path = f.name

    print(f"  WAD written to: {temp_path}")
    print(f"  Launching: {launcher} -iwad {temp_path}")
    print()

    try:
        subprocess.run([launcher, "-iwad", temp_path], check=True)
    except FileNotFoundError:
        print(f"Error: '{launcher}' not found. Install it or specify --launcher.")
        print(f"  The WAD is saved at: {temp_path}")
    except subprocess.CalledProcessError as e:
        print(f"Game exited with code {e.returncode}")
    finally:
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Fetch DOOM over ICMP and play it")
    parser.add_argument("server", help="IP address of the Doom Over ICMP server")
    parser.add_argument(
        "--launcher", "-l", default="chocolate-doom",
        help="Doom engine to launch (default: chocolate-doom)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Save WAD to file instead of launching the game",
    )
    parser.add_argument(
        "--timeout", "-t", type=float, default=TIMEOUT,
        help=f"Timeout per packet in seconds (default: {TIMEOUT})",
    )
    args = parser.parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    wad_bytes, filename = fetch_doom(args.server)

    if args.output:
        out_path = args.output
        with open(out_path, "wb") as f:
            f.write(wad_bytes)
        print(f"  WAD saved to: {out_path}")
    else:
        launch_doom(wad_bytes, filename, args.launcher)


if __name__ == "__main__":
    main()
