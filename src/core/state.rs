//! Application-level connection state machine and UI-visible model state.

use serde::{Deserialize, Serialize};

use crate::core::device::Device;

/// Connection and session lifecycle states for the application.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnState {
    /// No active operation is running.
    Idle,
    /// Device discovery is active.
    Discovering,
    /// A receiver has been selected by the user.
    Selected {
        /// The currently selected device.
        device: Device,
    },
    /// Pair-setup is in progress.
    Pairing {
        /// The device currently being paired.
        device: Device,
    },
    /// Pair-verify is in progress.
    Verifying {
        /// The device currently being verified.
        device: Device,
    },
    /// RTSP/session transport setup is in progress.
    Connecting {
        /// The device currently being connected.
        device: Device,
    },
    /// Control session is established but media may not be flowing yet.
    Connected {
        /// The device currently connected.
        device: Device,
    },
    /// Audio streaming is active.
    Streaming {
        /// The device currently receiving stream data.
        device: Device,
    },
    /// Automatic reconnect is in progress after a transient failure.
    Reconnecting {
        /// The target device being retried.
        device: Device,
        /// Monotonic reconnect attempt number.
        attempt: u32,
    },
    /// The session failed and requires user attention.
    Failed {
        /// Optional associated device for the failure.
        device: Option<Device>,
        /// Human-readable failure context.
        message: String,
    },
}

/// UI-facing aggregate state shared across application components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppModel {
    /// Last known discovered devices.
    pub devices: Vec<Device>,
    /// Current connection lifecycle state.
    pub state: ConnState,
    /// User volume in the normalized range `0.0..=1.0`.
    pub volume: f32,
    /// Last surfaced human-readable error, if any.
    pub last_error: Option<String>,
}

impl Default for AppModel {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            state: ConnState::Idle,
            volume: 1.0,
            last_error: None,
        }
    }
}
