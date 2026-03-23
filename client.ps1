<#
.SYNOPSIS
    DOOM Over ICMP - PowerShell Client

.DESCRIPTION
    Fetches a DOOM WAD from a Doom Over ICMP server by sending ICMP Echo Requests
    and reassembling the WAD from the payloads. Then launches the game.

    Protocol:
        - ICMP ID field = 0xD00D to identify Doom requests
        - Sequence 0       -> request metadata
        - Sequence 1..N    -> request compressed WAD chunks (1-indexed)

.EXAMPLE
    # Run as Administrator
    .\client.ps1 -Server 192.168.1.100
    .\client.ps1 -Server 192.168.1.100 -Launcher "crispy-doom"
    .\client.ps1 -Server 192.168.1.100 -OutputPath doom1.wad

.NOTES
    Requires: PowerShell 7+, Administrator privileges (raw sockets)
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [string]$Launcher = "chocolate-doom",

    [string]$OutputPath,

    [int]$Timeout = 5000,

    [int]$MaxRetries = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DOOM_ICMP_ID = 0xD00D

# --- ICMP Packet Construction ---

function Get-ICMPChecksum([byte[]]$Data) {
    [uint32]$sum = 0
    for ($i = 0; $i -lt $Data.Length - 1; $i += 2) {
        $sum += [BitConverter]::ToUInt16($Data, $i)
    }
    if ($Data.Length % 2 -ne 0) {
        $sum += $Data[$Data.Length - 1]
    }
    while (($sum -shr 16) -ne 0) {
        $sum = ($sum -band 0xFFFF) + ($sum -shr 16)
    }
    return [uint16]((-bnot $sum) -band 0xFFFF)
}

function New-ICMPEchoRequest([uint16]$Id, [uint16]$Seq, [byte[]]$Payload = @()) {
    $packetLen = 8 + $Payload.Length
    $packet = [byte[]]::new($packetLen)

    # Type 8 = Echo Request, Code 0
    $packet[0] = 8
    $packet[1] = 0
    # Checksum placeholder (bytes 2-3)
    $packet[2] = 0
    $packet[3] = 0
    # Identifier (big-endian)
    $packet[4] = [byte](($Id -shr 8) -band 0xFF)
    $packet[5] = [byte]($Id -band 0xFF)
    # Sequence (big-endian)
    $packet[6] = [byte](($Seq -shr 8) -band 0xFF)
    $packet[7] = [byte]($Seq -band 0xFF)

    # Copy payload
    if ($Payload.Length -gt 0) {
        [Array]::Copy($Payload, 0, $packet, 8, $Payload.Length)
    }

    # Calculate checksum
    $cksum = Get-ICMPChecksum $packet
    $packet[2] = [byte]($cksum -band 0xFF)
    $packet[3] = [byte](($cksum -shr 8) -band 0xFF)

    return $packet
}

function Send-ICMPRequest([System.Net.Sockets.Socket]$Socket,
                          [System.Net.IPEndPoint]$EndPoint,
                          [uint16]$Seq,
                          [int]$TimeoutMs) {
    $request = New-ICMPEchoRequest -Id $DOOM_ICMP_ID -Seq $Seq

    # Drain any stale packets from the buffer before sending
    $Socket.ReceiveTimeout = 1
    $drainBuf = [byte[]]::new(65535)
    try { while ($Socket.Available -gt 0) { [void]$Socket.Receive($drainBuf) } }
    catch [System.Net.Sockets.SocketException] { }

    [void]$Socket.SendTo($request, $EndPoint)

    $recvBuf = [byte[]]::new(65535)
    $deadline = [System.Diagnostics.Stopwatch]::StartNew()

    # Loop until we get our matching reply or timeout
    while ($deadline.ElapsedMilliseconds -lt $TimeoutMs) {
        $remaining = $TimeoutMs - [int]$deadline.ElapsedMilliseconds
        if ($remaining -le 0) { break }
        $Socket.ReceiveTimeout = $remaining

        try {
            $received = $Socket.Receive($recvBuf)
            if ($received -lt 28) { continue }  # IP header (20) + ICMP header (8) min

            # Parse IP header to find ICMP offset (IHL field)
            $ihl = ($recvBuf[0] -band 0x0F) * 4

            # Verify ICMP type=0 (Echo Reply)
            if ($recvBuf[$ihl] -ne 0) { continue }

            # Verify ICMP ID matches
            $replyId = ([uint16]$recvBuf[$ihl + 4] -shl 8) -bor $recvBuf[$ihl + 5]
            if ($replyId -ne $DOOM_ICMP_ID) { continue }

            # Verify sequence matches
            $replySeq = ([uint16]$recvBuf[$ihl + 6] -shl 8) -bor $recvBuf[$ihl + 7]
            if ($replySeq -ne $Seq) { continue }

            # Extract payload (after ICMP 8-byte header)
            $payloadOffset = $ihl + 8
            $payloadLen = $received - $payloadOffset
            if ($payloadLen -le 0) { continue }

            $payload = [byte[]]::new($payloadLen)
            [Array]::Copy($recvBuf, $payloadOffset, $payload, 0, $payloadLen)
            return $payload
        }
        catch [System.Net.Sockets.SocketException] {
            break  # Timeout
        }
    }
    return $null
}

function Send-ICMPRequestWithRetry([System.Net.Sockets.Socket]$Socket,
                                    [System.Net.IPEndPoint]$EndPoint,
                                    [uint16]$Seq,
                                    [string]$Label,
                                    [int]$TimeoutMs,
                                    [int]$Retries) {
    for ($attempt = 0; $attempt -lt $Retries; $attempt++) {
        $data = Send-ICMPRequest -Socket $Socket -EndPoint $EndPoint -Seq $Seq -TimeoutMs $TimeoutMs
        if ($null -ne $data) { return $data }
        if ($attempt -lt $Retries - 1) {
            $wait = 500 * ($attempt + 1)
            Write-Host "  Retry $($attempt + 1)/$Retries for $Label..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds $wait
        }
    }
    Write-Host "Error: Failed to fetch $Label after $Retries attempts" -ForegroundColor Red
    exit 1
}

# --- Progress Display ---

function Write-Progress2([int]$Current, [int]$Total, [System.Diagnostics.Stopwatch]$Timer) {
    $pct = [math]::Round($Current / $Total * 100, 1)
    $barLen = 40
    $filled = [math]::Floor($barLen * $Current / $Total)
    $bar = ("#" * $filled) + ("-" * ($barLen - $filled))

    $elapsed = $Timer.Elapsed.TotalSeconds
    if ($Current -gt 0 -and $elapsed -gt 0) {
        $speed = [math]::Round($Current / $elapsed, 0)
        $eta = [math]::Round($elapsed / $Current * ($Total - $Current), 0)
        Write-Host "`r  [$bar] $($pct.ToString("0.0"))% | $Current/$Total | ${speed} chunks/s | ETA ${eta}s" -NoNewline
    }
    else {
        Write-Host "`r  [$bar] $($pct.ToString("0.0"))% | $Current/$Total" -NoNewline
    }
}

# --- Main ---

Write-Host ""
Write-Host ("=" * 50)
Write-Host "  DOOM Over ICMP Client (PowerShell)"
Write-Host ("=" * 50)
Write-Host "  Server: $Server"
Write-Host ("=" * 50)
Write-Host ""

# Resolve server IP
$ip = [System.Net.Dns]::GetHostAddresses($Server) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -First 1
if ($null -eq $ip) {
    Write-Host "Error: Could not resolve $Server" -ForegroundColor Red
    exit 1
}
$endPoint = [System.Net.IPEndPoint]::new($ip, 0)

# Create raw ICMP socket
$socket = [System.Net.Sockets.Socket]::new(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Raw,
    [System.Net.Sockets.ProtocolType]::Icmp
)

try {
    # Step 1: Fetch metadata
    Write-Host "[1/3] Fetching metadata..."
    $metaRaw = Send-ICMPRequestWithRetry -Socket $socket -EndPoint $endPoint -Seq 0 `
        -Label "metadata" -TimeoutMs $Timeout -Retries $MaxRetries

    $metaJson = [System.Text.Encoding]::UTF8.GetString($metaRaw)
    $metadata = $metaJson | ConvertFrom-Json

    $filename     = $metadata.filename
    $numChunks    = [int]$metadata.chunks
    $chunkSize    = [int]$metadata.chunk_size
    $originalSize = [long]$metadata.original_size
    $compressedSz = [long]$metadata.compressed_size
    $expectedHash = $metadata.sha256

    Write-Host "       WAD:        $filename"
    Write-Host "       Original:   $($originalSize.ToString('N0')) bytes"
    Write-Host "       Compressed: $($compressedSz.ToString('N0')) bytes"
    Write-Host "       Chunks:     $numChunks x $chunkSize bytes"
    Write-Host ""

    # Step 2: Fetch all chunks
    Write-Host "[2/3] Fetching $numChunks chunks over ICMP..."
    $chunks = [System.Collections.Generic.List[byte[]]]::new($numChunks)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    for ($i = 0; $i -lt $numChunks; $i++) {
        $seq = $i + 1  # 1-indexed
        $chunkData = Send-ICMPRequestWithRetry -Socket $socket -EndPoint $endPoint `
            -Seq ([uint16]$seq) -Label "chunk $seq/$numChunks" `
            -TimeoutMs $Timeout -Retries $MaxRetries
        $chunks.Add($chunkData)
        Write-Progress2 -Current ($i + 1) -Total $numChunks -Timer $timer
    }

    $timer.Stop()
    $elapsed = [math]::Round($timer.Elapsed.TotalSeconds, 1)
    $speed = [math]::Round($numChunks / $timer.Elapsed.TotalSeconds, 0)
    Write-Host ""
    Write-Host "       Done in ${elapsed}s ($speed chunks/s)"
    Write-Host ""

    # Step 3: Reassemble and verify
    Write-Host "[3/3] Reassembling WAD..."

    # Concatenate all chunks
    $totalCompressed = 0
    foreach ($c in $chunks) { $totalCompressed += $c.Length }
    $compressed = [byte[]]::new($totalCompressed)
    $offset = 0
    foreach ($c in $chunks) {
        [Array]::Copy($c, 0, $compressed, $offset, $c.Length)
        $offset += $c.Length
    }
    Write-Host "       Compressed payload: $($totalCompressed.ToString('N0')) bytes"

    # Decompress (zlib = deflate with 2-byte header)
    $inputStream = [System.IO.MemoryStream]::new($compressed)
    # Skip zlib header (2 bytes)
    [void]$inputStream.ReadByte()
    [void]$inputStream.ReadByte()
    $deflateStream = [System.IO.Compression.DeflateStream]::new(
        $inputStream,
        [System.IO.Compression.CompressionMode]::Decompress
    )
    $outputStream = [System.IO.MemoryStream]::new()
    $deflateStream.CopyTo($outputStream)
    $deflateStream.Close()
    $inputStream.Close()

    $wadBytes = $outputStream.ToArray()
    $outputStream.Close()
    Write-Host "       Decompressed WAD:   $($wadBytes.Length.ToString('N0')) bytes"

    # SHA-256 verification
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($wadBytes)
    $actualHash = -join ($hashBytes | ForEach-Object { $_.ToString("x2") })

    if ($actualHash -ne $expectedHash) {
        Write-Host ""
        Write-Host "  ERROR: SHA-256 mismatch!" -ForegroundColor Red
        Write-Host "    Expected: $expectedHash" -ForegroundColor Red
        Write-Host "    Got:      $actualHash" -ForegroundColor Red
        exit 1
    }
    Write-Host "       SHA-256 verified:   $($actualHash.Substring(0, 16))..."
    Write-Host ""

    # Step 4: Save or launch
    if ($OutputPath) {
        [System.IO.File]::WriteAllBytes($OutputPath, $wadBytes)
        Write-Host "  WAD saved to: $OutputPath" -ForegroundColor Green
    }
    else {
        $tempPath = [System.IO.Path]::Combine(
            [System.IO.Path]::GetTempPath(),
            "doom_icmp_$filename"
        )
        [System.IO.File]::WriteAllBytes($tempPath, $wadBytes)
        Write-Host "  WAD written to: $tempPath"
        Write-Host "  Launching: $Launcher -iwad $tempPath"
        Write-Host ""

        try {
            & $Launcher -iwad $tempPath
        }
        catch {
            Write-Host "Error: '$Launcher' not found. Install it or specify -Launcher." -ForegroundColor Red
            Write-Host "  The WAD is saved at: $tempPath" -ForegroundColor Yellow
        }
        finally {
            if (Test-Path $tempPath) { Remove-Item $tempPath -ErrorAction SilentlyContinue }
        }
    }
}
finally {
    $socket.Close()
}
