# airsink

[![CI](https://github.com/imadal1n/airsink/actions/workflows/ci.yml/badge.svg)](https://github.com/imadal1n/airsink/actions/workflows/ci.yml)
[![Built with Nix](https://img.shields.io/static/v1?logo=nixos&logoColor=white&label=&message=Built%20with%20Nix&color=4278ed)](https://builtwithnix.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AirPlay 2 audio streaming from Linux to Apple devices.

airsink creates a virtual PipeWire sink on your Linux desktop, captures system audio, encodes it as ALAC, and streams it to AirPlay 2 receivers like HomePod Mini. It includes a terminal UI for device discovery, pairing, and session control.

## Features

- AirPlay 2 protocol with HAP pairing (transient, pair-setup, pair-verify)
- Apple HomePod Mini compatibility
- Virtual PipeWire sink (44.1 kHz / 16-bit stereo)
- ALAC (Apple Lossless) audio encoding
- Real-time RTP/UDP streaming with ChaCha20-Poly1305 encryption
- IEEE 1588v2 PTP clock follower for receiver synchronisation
- NTP-like timing server for AirPlay 2 session negotiation
- mDNS device discovery via Avahi
- Terminal UI with ratatui (catppuccin-mocha theme)
- Automatic reconnection with exponential backoff
- Volume control (linear 0.0–1.0 → logarithmic −144 dB … 0 dB)

## Requirements

- NixOS or Linux with PipeWire
- Avahi daemon (mDNS / DNS-SD device discovery)
- Nix with flakes enabled
- AirPlay 2 receiver (HomePod Mini, Apple TV 4K, etc.)
- `cap_net_bind_service` on the binary to bind PTP ports 319/320 (see NixOS setup)

## Installation

### NixOS (recommended)

Add airsink as a flake input and import the shared module, which installs the
binary, grants the required Linux capability, and opens the firewall for
HomePod-initiated PTP traffic:

```nix
# flake.nix
inputs.airsink.url = "git+https://github.com/imadal1n/airsink";
```

```nix
# nixos/configuration.nix or a shared module
{ inputs, pkgs, ... }:
let airsinkPkg = inputs.airsink.packages.${pkgs.system}.default; in {
  environment.systemPackages = [ airsinkPkg ];
  security.wrappers.airsink = {
    source = "${airsinkPkg}/bin/airsink";
    capabilities = "cap_net_bind_service=+ep";
    owner = "root"; group = "users";
  };
  # UDP 319 (PTP event) and 320 (PTP general): HomePod initiates inbound,
  # so conntrack alone is not sufficient — these must be opened explicitly.
  networking.firewall.allowedUDPPorts = [ 319 320 ];
}
```

Avahi must be running for device discovery:

```nix
services.avahi = { enable = true; nssmdns4 = true; openFirewall = true; };
```

### Development Shell

```bash
nix develop
```

Provides a shell with the Rust toolchain, PipeWire headers, Avahi, and all
build dependencies.

### Build

```bash
nix build
# binary at ./result/bin/airsink
```

### Run from Source

```bash
nix run
```

## Usage

```bash
airsink [OPTIONS]
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--host-name` | `"airsink"` | Human-readable sender name shown to receivers |
| `--bind-ip` | auto | Local interface IP to bind sockets |
| `--latency` | `2000` | Target latency in milliseconds |
| `--sink-name` | `"airsink"` | Name of the virtual PipeWire sink |

### Example

```bash
airsink --host-name "Living Room" --latency 1500
```

### TUI Keybindings

| Key | Action |
|-----|--------|
| `q` / `Ctrl-C` | Quit |
| `j` / `k` / `↑` / `↓` | Navigate device list |
| `Enter` / `Space` | Connect to selected device |
| `s` | Stop streaming |
| `+` / `-` | Increase / decrease volume |
| `p` | Enter PIN during pair-setup |
| `Esc` | Cancel PIN entry |

## Architecture

### Module Structure

```
src/
  main.rs          — CLI bootstrap, tokio runtime, TUI launch
  lib.rs           — Crate exports
  error.rs         — Error enum, Recoverability trait
  app/mod.rs       — Supervisor, state machine, session lifecycle
  core/
    device.rs      — Device, DeviceId, DeviceFeatures
    audio.rs       — PcmFormat, PcmChunk, EncodedFrame, SampleFormat
    state.rs       — ConnState enum, AppModel
  config/mod.rs    — Config, PairingCredentials, FilePairingStore
  discovery/mod.rs — mDNS browse, DeviceEvent broadcast
  hap/
    mod.rs         — HapClient: pair_setup, pair_setup_transient, pair_verify
    tlv.rs         — TLV8 encode/decode
    srp.rs         — SRP-6a (RFC 5054 3072-bit group, SHA-512)
  crypto/mod.rs    — SessionKeys, AeadContext, NonceStrategy
  rtsp/mod.rs      — RtspClient: SETUP, RECORD, SET_PARAMETER, TEARDOWN
  timing/
    mod.rs         — TimingServer (NTP-like AirPlay timing responder)
    ptp.rs         — PtpMaster (IEEE 1588v2 follower), PtpSockets, PtpConfig
  pipewire/mod.rs  — Virtual PipeWire sink, PCM capture thread
  codec/mod.rs     — ALAC encoder (alac-encoder crate)
  rtp/mod.rs       — RtpPacket, RtpSender, SyncSender, StreamPipeline
  ui/mod.rs        — ratatui TUI
```

### Task Hierarchy

```
main thread (TUI render loop)
  └── tokio runtime
        ├── discovery_task       — mDNS browse → DeviceEvent broadcast
        ├── app_task             — Command rx → state transitions → session
        └── session_task
              ├── rtsp_reader_task
              ├── timing_task    — NTP timing server
              ├── ptp_task       — IEEE 1588v2 PTP follower
              └── audio_pipeline_task
                    capture → encode → encrypt → sync → send
```

### State Machine

```
Idle → Discovering → Selected → Pairing/Verifying → Connecting → Connected → Streaming
                              ↓                                          ↓
                           Failed ←────────────────────── Reconnecting (backoff)
```

## Protocol

### HAP Pairing

airsink tries three pairing paths in order:

**1. Pair-Verify** (stored credentials — fastest): Ephemeral X25519 key
exchange + stored Ed25519 long-term signature verification. Key derivation:
- RTSP write key: `HKDF-SHA512(shared_secret, salt="Control-Salt", info="Control-Write-Encryption-Key")`
- RTSP read key: `HKDF-SHA512(shared_secret, salt="Control-Salt", info="Control-Read-Encryption-Key")`
- Audio `shk`: raw 32-byte X25519 `shared_secret` (no HKDF)

**2. Transient pair-setup** (no stored credentials): SRP-6a with fixed PIN
`3939`, `Flags=0x10`, `X-Apple-HKP: 4` header. No credentials stored. Key
derivation:
- RTSP write/read keys: HKDF-SHA512 over SRP session key (same salts/infos as above)
- Audio `shk`: first 32 bytes of SRP session key (`SHA-512(SRP_S)[0..32]`)

**3. Full pair-setup** (user PIN entry): SRP-6a with user-entered PIN,
followed by Ed25519 long-term key exchange. Credentials stored for future
pair-verify reconnects.

### RTSP Session

After pairing, these RTSP methods are sent over the same TCP connection:

| Method | Purpose |
|--------|---------|
| `GET /info` | Fetch receiver capabilities |
| `SETUP` (session) | Negotiate timing protocol (PTP or NTP) and advertise PTP clock |
| `SETUP` (audio stream) | Configure codec, `shk`, ports, latency |
| `SETPEERS` | Advertise PTP peer IP addresses to HomePod |
| `RECORD` | Start playout with initial seq/rtptime |
| `SET_PARAMETER` | Adjust playback volume |
| `FLUSH` | Reset decoder state |
| `TEARDOWN` | End session |

**Encrypted framing** (post-pairing): Messages are chunked at 1024 bytes. Each
chunk is sealed with ChaCha20-Poly1305:

```
Wire per chunk: [2-byte LE plaintext length (AAD)] [ciphertext] [16-byte Poly1305 tag]
```

- Nonce: 12 bytes = `[0 × 8][write_counter as u32 LE]`
- Write counter increments per chunk; read counter is tracked separately

### Audio Streaming

PCM audio flows: PipeWire capture → ALAC encode → ChaCha20-Poly1305 seal → RTP → UDP.

**Fixed stream parameters:**

| Parameter | Value |
|-----------|-------|
| Codec | ALAC (Apple Lossless) |
| Sample rate | 44 100 Hz |
| Bit depth | 16-bit |
| Channels | Stereo |
| Frames per RTP packet | 352 |
| RTP payload type | `0x60` (96) |
| Minimum latency | 11 025 samples (0.25 s) |
| Maximum latency | 88 200 samples (2 s) |

**RTP wire packet layout:**

```
[RTP header — 12 B] [ciphertext + Poly1305 tag — N+16 B] [nonce suffix — 8 B]
```

**Per-packet encryption:**
- Algorithm: ChaCha20-Poly1305
- Key: 32-byte audio session key (`shk` — see pairing section)
- Nonce (12 bytes): `[0 0 0 0  seq_le[0] seq_le[1]  0 0 0 0 0 0]`
  — sequence number in little-endian at bytes 4–5, all other bytes zero
- AAD: `rtp_header[4..12]` — 8 bytes covering the RTP timestamp and SSRC fields
- The 8 trailing nonce bytes (`nonce[4..12]`) are appended after the
  ciphertext+tag so the receiver can reconstruct the nonce without counter state

**RTP sync packets** (payload type `0xD7`, 28 bytes): sent on the control
socket once at stream start (`sync_type=0x90`) and every 125 RTP packets
thereafter (`sync_type=0x80`, ≈1 s at 125 pkt/s). Each packet carries the
current PTP master time and the RTP position offset by `LATENCY_SAMPLES`
(11 025) so the receiver can schedule playout correctly.

### Timing Protocols

Two timing mechanisms run concurrently:

**NTP-like timing server** (`TimingServer`): Listens on an ephemeral UDP port.
Responds to AirPlay timing requests (payload type `0x52 / 82`) with
receive + transmit timestamps (payload type `0xD3 / 211`). Used when the
receiver negotiates `timingProtocol: NTP` in session SETUP.

**PTP follower** (`PtpMaster`): Tracks the HomePod's IEEE 1588v2 grandmaster.
Binds UDP 319 (event) and 320 (general); requires `cap_net_bind_service` — without
it `try_bind()` falls back to ephemeral ports and HomePod PTP may not function.
Sends an awakening sequence (Signaling + Announce) to prompt `Follow_Up` from
the HomePod, then computes a one-way clock offset using a sliding window of 8
samples. Lock is acquired once all 8 samples show < 50 ms peak-to-peak jitter.

### Network Ports

| Port | Proto | Direction | Purpose |
|------|-------|-----------|---------|
| device mDNS port (typically 7000) | TCP | Outbound | RTSP/HAP control |
| 319 | UDP | **Inbound** | PTP event (HomePod-initiated) |
| 320 | UDP | **Inbound** | PTP general (HomePod-initiated) |
| ephemeral | UDP | Both | NTP timing server |
| ephemeral | UDP | Outbound | RTP audio packets |
| ephemeral | UDP | Both | RTP control / sync |
| device eventPort | TCP | Outbound | HomePod event channel |
| 5353 | UDP | Both | mDNS (Avahi) |

> UDP 319 and 320 must be opened explicitly. The HomePod initiates these
> connections inbound, so Linux connection tracking alone will not allow them.

### Volume Control

`SET_PARAMETER` with `Content-Type: text/parameters`, body: `volume: <dB>\r\n`.
UI value 0.0–1.0 is mapped as `dB = clamp(20 × log₁₀(v) × 1.5, −144, 0)`.
Value −144.0 dB signals mute.

## Development

### Build Commands

```bash
cargo check            # type-check only
cargo build --release
RUST_LOG=debug cargo run   # logs to stderr and /tmp/airsink.log
cargo test
```

### Nix

```bash
nix develop   # dev shell with all dependencies
nix build     # release build → ./result/bin/airsink
nix run       # build and run directly
```

## License

MIT
