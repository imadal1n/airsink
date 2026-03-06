# airsink

[![CI](https://github.com/imadal1n/airsink/actions/workflows/ci.yml/badge.svg)](https://github.com/imadal1n/airsink/actions/workflows/ci.yml)
[![Built with Nix](https://img.shields.io/static/v1?logo=nixos&logoColor=white&label=&message=Built%20with%20Nix&color=4278ed)](https://builtwithnix.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AirPlay 2 audio streaming from Linux to Apple devices.

airsink creates a virtual PipeWire sink on your Linux desktop, captures system audio, encodes it as ALAC, and streams it to AirPlay 2 receivers like HomePod Mini. It includes a terminal UI for device discovery, pairing, and session control.

## Features

- AirPlay 2 protocol support with HAP pairing
- Apple HomePod Mini compatibility
- Virtual PipeWire sink creation (44.1kHz/16-bit stereo)
- ALAC audio encoding
- Real-time RTP/UDP streaming with ChaCha20-Poly1305 encryption
- mDNS device discovery
- Terminal UI with ratatui (catppuccin-mocha colors)
- Automatic reconnection with exponential backoff
- Volume control (UI 0.0-1.0 mapped to -144dB to 0dB)

## Requirements

- NixOS or Linux with PipeWire
- Avahi/mDNS support on the local network
- Nix with flakes enabled
- AirPlay 2 receiver (HomePod Mini, Apple TV, etc.)

## Installation

### Development Shell

```bash
nix develop
```

This provides a shell with Rust toolchain, PipeWire, Avahi, and all build dependencies.

### Build

```bash
nix build
```

The binary is available at `./result/bin/airsink`.

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
| `--host-name` | "airsink" | Human-readable sender name shown to receivers |
| `--bind-ip` | auto | Local interface address to bind sockets |
| `--latency` | 2000 | Target latency in milliseconds |
| `--sink-name` | "airsink" | Name of the virtual PipeWire sink |

### Example

```bash
airsink --host-name "Living Room" --latency 1500 --sink-name "myairplay"
```

### TUI Keybindings

| Key | Action |
|-----|--------|
| `q` or `Ctrl-C` | Quit |
| `j` / `k` or `↑` / `↓` | Navigate device list |
| `Enter` or `Space` | Select/connect to device |
| `s` | Stop streaming |
| `+` / `-` | Increase/decrease volume |
| `p` | Enter PIN during pairing |
| `Esc` | Cancel PIN entry |

## Architecture

### Module Structure

```
src/
  main.rs         # CLI bootstrap, starts tokio runtime, launches TUI
  lib.rs          # Crate exports
  error.rs        # Error enum and Recoverability trait
  app/            # Supervisor and state machine runner
    mod.rs
  core/           # Pure domain types
    mod.rs
    device.rs     # Device, DeviceId, DeviceFeatures
    audio.rs      # PcmFormat, PcmChunk, EncodedFrame, SampleFormat
    state.rs      # ConnState enum, AppModel
  config/         # Persistent config and credential storage
    mod.rs
  discovery/      # mDNS device discovery
    mod.rs
  hap/            # HomeKit Accessory Protocol pairing
    mod.rs
    tlv.rs        # TLV8 encode/decode
    srp.rs        # SRP-6a with Apple's 3072-bit group
  crypto/         # Encryption contexts
    mod.rs
  rtsp/           # RTSP client and encrypted transport
    mod.rs
  timing/         # NTP timing socket and clock sync
    mod.rs
  pipewire/       # Virtual sink and audio capture
    mod.rs
  codec/          # ALAC encoding
    mod.rs
  rtp/            # RTP packetization and UDP streaming
    mod.rs
  ui/             # TUI interface
    mod.rs
```

### Task Hierarchy

```
main thread (TUI render loop)
  └── tokio runtime
        ├── discovery_task (always-on)
        │     mDNS browse → DeviceEvent broadcast
        ├── app_task (supervisor)
        │     Command rx → state transitions → spawn/cancel session
        └── session_task (per active device, owned by supervisor)
              ├── rtsp_reader_task
              ├── timing_task (NTP sync)
              └── audio_pipeline_task
                    capture → encode → encrypt → pace → send
```

### State Machine

```
Idle → Discovering → Selected → Pairing/Verifying → Connecting → Connected → Streaming
                              ↓                                          ↓
                           Failed ←─────────────────────────── Reconnecting (with backoff)
```

## Protocol

### HAP Pairing

airsink implements HomeKit Accessory Protocol pairing with SRP-6a authentication:

**Pair-Setup Flow** (first connection):
1. Exchange SRP public keys and salt
2. Verify PIN-derived proof
3. Exchange Ed25519 long-term keys
4. Store credentials for future sessions

**Pair-Verify Flow** (subsequent connections):
1. Ephemeral X25519 key exchange
2. Verify stored long-term keys
3. Derive session keys via HKDF-SHA512

### RTSP Session

After pairing, airsink establishes an RTSP control channel:

- `SETUP` - Configure timing and audio streams
- `RECORD` - Start streaming with initial sequence/timestamp
- `SET_PARAMETER` - Volume control
- `FLUSH` - Reset decoder state
- `TEARDOWN` - End session

All RTSP frames after pair-verify are encrypted with ChaCha20-Poly1305 using per-direction keys derived from the shared secret.

### Audio Streaming

Audio flows over UDP as encrypted RTP packets:

- **Codec**: ALAC (Apple Lossless)
- **Sample Rate**: 44.1 kHz
- **Bit Depth**: 16-bit
- **Channels**: Stereo
- **Frames per Packet**: 352 (RTP timestamp increment)
- **Payload Type**: 96
- **Encryption**: ChaCha20-Poly1305 per packet

**RTP Packet Layout**:
```
[RTP Header - 12 bytes] [Encrypted ALAC Frame - N bytes] [Poly1305 Tag - 16 bytes]
```

### Timing Protocol

NTP-like UDP protocol (payload types 82/83) for clock synchronization between sender and receiver. Used to compute clock offset and round-trip time.

## Development

### Project Structure

The codebase follows a modular architecture with clear separation:

- `core/` - Pure data types, no IO
- `app/` - State machine and supervisor
- `discovery/`, `hap/`, `rtsp/`, `timing/` - Protocol implementations
- `pipewire/`, `codec/`, `rtp/` - Audio pipeline
- `ui/` - TUI frontend
- `crypto/` - Shared encryption utilities

### Build Commands

```bash
# Check compilation
cargo check

# Build release
cargo build --release

# Run with logging
RUST_LOG=debug cargo run

# Run tests
cargo test
```

### Nix Development

```bash
# Enter dev shell
nix develop

# Build with nix
nix build

# Run directly
nix run
```

### Adding a New Device

Devices are discovered via mDNS. airsink browses for `_airplay._tcp` and `_raop._tcp` services. Features are extracted from the `features` TXT record bitmask.

## License

MIT
