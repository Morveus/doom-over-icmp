#!/usr/bin/env python3
"""
Doom Over ICMP - WAD Preparation Tool

Compresses a DOOM WAD file and splits it into chunks ready to be served
over ICMP echo replies. Produces a .doom-icmp bundle file containing
metadata and all chunks.

Usage:
    sudo python3 prepare.py DOOM1.WAD
    sudo python3 prepare.py DOOM1.WAD -o doom1.doom-icmp -c 1400
"""

import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path


MAGIC = b"DOOMICMP"
VERSION = 1
DEFAULT_CHUNK_SIZE = 1400  # bytes per ICMP payload chunk (safe under MTU)


def prepare_wad(wad_path: str, output_path: str | None = None, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    wad_file = Path(wad_path)
    if not wad_file.exists():
        print(f"Error: {wad_path} not found")
        sys.exit(1)

    raw = wad_file.read_bytes()
    original_size = len(raw)
    original_sha256 = hashlib.sha256(raw).hexdigest()

    print(f"Original WAD: {original_size:,} bytes")
    print(f"SHA-256:      {original_sha256}")

    compressed = zlib.compress(raw, level=9)
    compressed_size = len(compressed)
    ratio = (1 - compressed_size / original_size) * 100
    print(f"Compressed:   {compressed_size:,} bytes ({ratio:.1f}% reduction)")

    # Split into chunks
    chunks = []
    for i in range(0, len(compressed), chunk_size):
        chunks.append(compressed[i : i + chunk_size])

    num_chunks = len(chunks)
    print(f"Chunks:       {num_chunks} x {chunk_size} bytes")

    # Build metadata
    metadata = {
        "filename": wad_file.name,
        "original_size": original_size,
        "compressed_size": compressed_size,
        "sha256": original_sha256,
        "chunks": num_chunks,
        "chunk_size": chunk_size,
        "version": VERSION,
    }
    meta_json = json.dumps(metadata).encode("utf-8")

    # Write bundle: MAGIC | VERSION(u16) | meta_len(u32) | meta_json | chunk0 | chunk1 | ...
    out = Path(output_path) if output_path else wad_file.with_suffix(".doom-icmp")

    with open(out, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("!H", VERSION))
        f.write(struct.pack("!I", len(meta_json)))
        f.write(meta_json)
        for chunk in chunks:
            f.write(struct.pack("!H", len(chunk)))
            f.write(chunk)

    bundle_size = out.stat().st_size
    print(f"\nBundle written to: {out}")
    print(f"Bundle size:       {bundle_size:,} bytes")
    print(f"\nReady to serve with: sudo python3 server.py {out}")


def main():
    parser = argparse.ArgumentParser(description="Prepare a DOOM WAD for serving over ICMP")
    parser.add_argument("wad", help="Path to the WAD file (e.g., DOOM1.WAD)")
    parser.add_argument("-o", "--output", help="Output bundle path (default: <wad>.doom-icmp)")
    parser.add_argument(
        "-c", "--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
        help=f"Chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})",
    )
    args = parser.parse_args()
    prepare_wad(args.wad, args.output, args.chunk_size)


if __name__ == "__main__":
    main()
