//! Shared error types and recoverability classification for `airsink`.

use thiserror::Error;

/// Convenient result alias for all library modules.
pub type Result<T> = std::result::Result<T, Error>;

/// Indicates whether an error can be retried without user intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recoverability {
    /// The operation can typically be retried automatically.
    Recoverable,
    /// The operation requires explicit user action or process restart.
    Fatal,
}

/// Top-level error type used across all foundational modules.
#[derive(Debug, Error)]
pub enum Error {
    /// Discovery subsystem failure.
    #[error("discovery: {0}")]
    Discovery(String),
    /// Pairing is required before the requested action can proceed.
    #[error("pairing required")]
    PairingRequired,
    /// HomeKit Accessory Protocol failure.
    #[error("hap: {0}")]
    Hap(String),
    /// RTSP protocol or transport failure.
    #[error("rtsp: {0}")]
    Rtsp(String),
    /// PipeWire integration failure.
    #[error("pipewire: {0}")]
    PipeWire(String),
    /// Audio codec failure.
    #[error("codec: {0}")]
    Codec(String),
    /// Network I/O or socket-level failure.
    #[error("network: {0}")]
    Network(String),
    /// Configuration or persistent-store failure.
    #[error("config: {0}")]
    Config(String),
    /// Cryptographic operation failure.
    #[error("crypto: {0}")]
    Crypto(String),
    /// Invalid state transition or unsupported input.
    #[error("invalid state: {0}")]
    InvalidState(String),
    /// Filesystem or OS I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization/deserialization failure.
    #[error("serde json: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

impl Error {
    /// Returns the recoverability classification for this error.
    pub fn recoverability(&self) -> Recoverability {
        match self {
            Self::Discovery(_)
            | Self::Rtsp(_)
            | Self::PipeWire(_)
            | Self::Network(_)
            | Self::Io(_) => Recoverability::Recoverable,
            Self::PairingRequired
            | Self::Hap(_)
            | Self::Codec(_)
            | Self::Config(_)
            | Self::Crypto(_)
            | Self::InvalidState(_)
            | Self::SerdeJson(_) => Recoverability::Fatal,
        }
    }
}
