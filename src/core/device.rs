//! AirPlay receiver device identity, capabilities, and addressing types.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Stable logical identifier for a discovered receiver device.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(
    /// Opaque identifier string used for selection and persistence.
    pub String,
);

/// Describes one discoverable AirPlay receiver endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Stable identifier used across discovery and persistence layers.
    pub id: DeviceId,
    /// Human-readable display name shown to users.
    pub name: String,
    /// IPv4 or IPv6 address for direct transport connections.
    pub host: IpAddr,
    /// RTSP control port exposed by the receiver.
    pub port_rtsp: u16,
    /// Optional timing socket port, if announced.
    pub port_timing: Option<u16>,
    /// Optional control socket port, if announced.
    pub port_control: Option<u16>,
    /// Capability flags extracted from discovery metadata.
    pub features: DeviceFeatures,
}

/// Capability flags used to route setup and streaming behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFeatures {
    /// Whether the device requires HAP pairing before streaming.
    pub requires_pairing: bool,
    /// Whether the receiver supports AirPlay 2 semantics.
    pub supports_airplay2: bool,
    /// Whether the receiver advertises ALAC decode support.
    pub supports_alac: bool,
}
