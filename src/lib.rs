//! Core library exports for the `airsink` crate.
//!
//! This crate root defines the foundational module layout and re-exports the
//! cross-module contracts used by the rest of the project.

pub mod app;
pub mod codec;
pub mod config;
pub mod core;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod hap;
pub mod pipewire;
pub mod rtp;
pub mod rtsp;
pub mod timing;
pub mod ui;

pub use app::{App, AppHandle, Command};
pub use config::{Config, FilePairingStore, PairingCredentials, PairingStore, default_store};
pub use core::{
    AppModel, ConnState, Device, DeviceFeatures, DeviceId, EncodedFrame, PcmChunk, PcmFormat,
    SampleFormat,
};
pub use crypto::{AeadContext, NonceStrategy, SessionKeys};
pub use discovery::{DeviceEvent, DiscoveryHandle, start_discovery};
pub use error::{Error, Recoverability, Result};
