//! Runtime configuration and persistent pairing credential storage.

use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::fs;
use zeroize::Zeroizing;

use crate::core::DeviceId;
use crate::error::{Error, Result};

/// Application configuration shared across startup and supervisor layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Human-readable sender name exposed to remote receivers.
    pub host_name: String,
    /// Optional specific local interface address to bind sockets to.
    pub bind_ip: Option<IpAddr>,
    /// Target end-to-end latency for stream buffering in milliseconds.
    pub target_latency_ms: u32,
    /// Name of the virtual PipeWire sink to create.
    pub virtual_sink_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host_name: "airsink".to_owned(),
            bind_ip: None,
            target_latency_ms: 2_000,
            virtual_sink_name: "airsink".to_owned(),
        }
    }
}

/// Pairing credentials retained for reconnecting to trusted devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCredentials {
    /// Stable local identifier used during HAP exchanges.
    pub pairing_id: String,
    /// Long-term local Ed25519 signing key.
    pub signing_key: SigningKey,
    /// Long-term local Ed25519 verifying key.
    pub verifying_key: VerifyingKey,
    /// Receiver long-term Ed25519 verifying key.
    pub peer_verifying_key: VerifyingKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredPairingCredentials {
    pairing_id: String,
    lt_ed25519_sk: [u8; 32],
    lt_ed25519_pk: [u8; 32],
    peer_lt_ed25519_pk: [u8; 32],
}

impl Serialize for PairingCredentials {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let stored = StoredPairingCredentials {
            pairing_id: self.pairing_id.clone(),
            lt_ed25519_sk: self.signing_key.to_bytes(),
            lt_ed25519_pk: self.verifying_key.to_bytes(),
            peer_lt_ed25519_pk: self.peer_verifying_key.to_bytes(),
        };
        stored.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PairingCredentials {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stored = StoredPairingCredentials::deserialize(deserializer)?;
        let signing_key_bytes = Zeroizing::new(stored.lt_ed25519_sk);
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&stored.lt_ed25519_pk).map_err(serde::de::Error::custom)?;
        let peer_verifying_key = VerifyingKey::from_bytes(&stored.peer_lt_ed25519_pk)
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            pairing_id: stored.pairing_id,
            signing_key,
            verifying_key,
            peer_verifying_key,
        })
    }
}

/// Boxed future used by asynchronous store trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction over persistent pairing credential storage backends.
pub trait PairingStore: Send + Sync {
    /// Loads credentials for a device, returning `None` when not found.
    fn load<'a>(
        &'a self,
        device_id: &'a DeviceId,
    ) -> BoxFuture<'a, Result<Option<PairingCredentials>>>;
    /// Saves credentials for a device, replacing any previous value.
    fn save<'a>(
        &'a self,
        device_id: &'a DeviceId,
        creds: &'a PairingCredentials,
    ) -> BoxFuture<'a, Result<()>>;
    /// Removes credentials for a device if present.
    fn delete<'a>(&'a self, device_id: &'a DeviceId) -> BoxFuture<'a, Result<()>>;
}

/// File-backed pairing store rooted at a configurable device directory.
#[derive(Debug, Clone)]
pub struct FilePairingStore {
    /// Root directory where one JSON file per device is stored.
    pub root: PathBuf,
}

impl FilePairingStore {
    /// Creates a file-based store rooted at the provided path.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Returns the storage path for a specific device identifier.
    pub fn path_for_device(&self, device_id: &DeviceId) -> PathBuf {
        self.root
            .join(format!("{}.json", sanitize_device_id(&device_id.0)))
    }

    /// Ensures the root directory exists before read/write operations.
    pub async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root).await?;
        Ok(())
    }
}

impl PairingStore for FilePairingStore {
    fn load<'a>(
        &'a self,
        device_id: &'a DeviceId,
    ) -> BoxFuture<'a, Result<Option<PairingCredentials>>> {
        Box::pin(async move {
            self.ensure_dir().await?;
            let path = self.path_for_device(device_id);
            if !Path::new(&path).exists() {
                return Ok(None);
            }

            let bytes = fs::read(&path).await?;
            let creds = serde_json::from_slice::<PairingCredentials>(&bytes)?;
            Ok(Some(creds))
        })
    }

    fn save<'a>(
        &'a self,
        device_id: &'a DeviceId,
        creds: &'a PairingCredentials,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.ensure_dir().await?;
            let path = self.path_for_device(device_id);
            let json = serde_json::to_vec_pretty(creds)?;
            fs::write(path, json).await?;
            Ok(())
        })
    }

    fn delete<'a>(&'a self, device_id: &'a DeviceId) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.ensure_dir().await?;
            let path = self.path_for_device(device_id);
            match fs::remove_file(path).await {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(Error::Io(err)),
            }
        })
    }
}

/// Builds the default file store rooted at `~/.config/airsink/devices/`.
pub fn default_store() -> Result<FilePairingStore> {
    let config_root = dirs::config_dir()
        .ok_or_else(|| Error::Config("failed to resolve user config directory".to_owned()))?;
    Ok(FilePairingStore::new(
        config_root.join("airsink").join("devices"),
    ))
}

fn sanitize_device_id(device_id: &str) -> String {
    device_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
