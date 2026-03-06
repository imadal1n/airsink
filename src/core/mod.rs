//! Pure domain-model types shared across all major `airsink` modules.

pub mod audio;
pub mod device;
pub mod state;

pub use audio::{EncodedFrame, PcmChunk, PcmFormat, SampleFormat};
pub use device::{Device, DeviceFeatures, DeviceId};
pub use state::{AppModel, ConnState};
