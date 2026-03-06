//! Audio-format, PCM transport, and encoded-frame contracts.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Supported PCM sample representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SampleFormat {
    /// Signed 16-bit little-endian interleaved PCM samples.
    S16LE,
}

/// PCM stream format descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcmFormat {
    /// Sample rate in Hertz.
    pub rate_hz: u32,
    /// Number of interleaved channels.
    pub channels: u16,
    /// Sample representation for each channel sample.
    pub sample: SampleFormat,
}

/// Zero-copy chunk of captured interleaved PCM data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcmChunk {
    /// PCM format metadata for this chunk.
    pub format: PcmFormat,
    /// Number of audio frames in this chunk.
    pub frames: u32,
    /// Monotonic host timestamp in nanoseconds at capture time.
    pub pts_host_ns: u64,
    /// Interleaved PCM bytes in native sender layout.
    pub data: Bytes,
}

/// Encoded audio payload prepared for RTP packetization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// RTP timestamp assigned to this encoded frame.
    pub rtp_timestamp: u32,
    /// Encoded ALAC payload bytes before transport encryption.
    pub payload: Bytes,
    /// ALAC magic cookie (decoder config) needed for receiver initialization.
    pub magic_cookie: Option<Bytes>,
}
