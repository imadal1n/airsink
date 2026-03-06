//! mDNS-based discovery of AirPlay receivers on the local network.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use tokio::{select, sync::broadcast};

use tracing::{debug, info};

use crate::{Device, DeviceFeatures, DeviceId, Error, Result};

const AIRPLAY_SERVICE_TYPE: &str = "_airplay._tcp.local.";
const RAOP_SERVICE_TYPE: &str = "_raop._tcp.local.";

/// Discovery event stream emitted for device lifecycle changes.
#[derive(Debug, Clone)]
pub enum DeviceEvent {
    /// A device was discovered and is now available.
    Up(Device),
    /// A previously discovered device is no longer available.
    Down(DeviceId),
    /// A previously discovered device was updated with new metadata.
    Update(Device),
}

/// Handle returned by [`start_discovery`] for reading events and snapshots.
pub struct DiscoveryHandle {
    /// Receiver for discovery lifecycle events.
    pub events_rx: broadcast::Receiver<DeviceEvent>,
    registry: Arc<RwLock<HashMap<DeviceId, Device>>>,
    _daemon: ServiceDaemon,
    _event_task: tokio::task::JoinHandle<()>,
}

impl DiscoveryHandle {
    /// Returns the current in-memory snapshot of discovered devices.
    pub fn snapshot(&self) -> Vec<Device> {
        let registry = self
            .registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.values().cloned().collect()
    }
}

/// Starts asynchronous mDNS browsing for AirPlay and RAOP service types.
pub async fn start_discovery() -> Result<DiscoveryHandle> {
    let daemon = ServiceDaemon::new().map_err(|e| Error::Discovery(e.to_string()))?;

    let airplay_rx = daemon
        .browse(AIRPLAY_SERVICE_TYPE)
        .map_err(|e| Error::Discovery(e.to_string()))?;
    let raop_rx = daemon
        .browse(RAOP_SERVICE_TYPE)
        .map_err(|e| Error::Discovery(e.to_string()))?;

    let registry = Arc::new(RwLock::new(HashMap::<DeviceId, Device>::new()));
    let registry_for_task = Arc::clone(&registry);

    let (events_tx, events_rx) = broadcast::channel(256);
    let events_tx_for_task = events_tx.clone();

    let daemon_for_task = daemon.clone();
    let event_task = tokio::spawn(async move {
        let _daemon_guard = daemon_for_task;

        let mut service_to_device = HashMap::<String, DeviceId>::new();
        let mut airplay_open = true;
        let mut raop_open = true;

        while airplay_open || raop_open {
            select! {
                result = airplay_rx.recv_async(), if airplay_open => {
                    match result {
                        Ok(event) => {
                            process_service_event(event, &registry_for_task, &events_tx_for_task, &mut service_to_device);
                        }
                        Err(_) => {
                            airplay_open = false;
                        }
                    }
                }
                result = raop_rx.recv_async(), if raop_open => {
                    match result {
                        Ok(event) => {
                            process_service_event(event, &registry_for_task, &events_tx_for_task, &mut service_to_device);
                        }
                        Err(_) => {
                            raop_open = false;
                        }
                    }
                }
            }
        }
    });

    Ok(DiscoveryHandle {
        events_rx,
        registry,
        _daemon: daemon,
        _event_task: event_task,
    })
}

fn process_service_event(
    event: ServiceEvent,
    registry: &Arc<RwLock<HashMap<DeviceId, Device>>>,
    events_tx: &broadcast::Sender<DeviceEvent>,
    service_to_device: &mut HashMap<String, DeviceId>,
) {
    match event {
        ServiceEvent::ServiceResolved(resolved) => {
            if let Some(device) = device_from_resolved(&resolved) {
                let mut registry_guard = registry
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);

                let event_to_emit = match registry_guard.get(&device.id) {
                    None => DeviceEvent::Up(device.clone()),
                    Some(existing) if existing != &device => DeviceEvent::Update(device.clone()),
                    Some(_) => {
                        service_to_device
                            .insert(resolved.get_fullname().to_string(), device.id.clone());
                        return;
                    }
                };

                service_to_device.insert(resolved.get_fullname().to_string(), device.id.clone());
                registry_guard.insert(device.id.clone(), device);
                let _ = events_tx.send(event_to_emit);
            }
        }
        ServiceEvent::ServiceRemoved(_service_type, fullname) => {
            let removed_id = service_to_device
                .remove(&fullname)
                .unwrap_or_else(|| device_id_from_fullname(&fullname));

            if service_to_device.values().any(|id| id == &removed_id) {
                return;
            }

            let mut registry_guard = registry
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if registry_guard.remove(&removed_id).is_some() {
                let _ = events_tx.send(DeviceEvent::Down(removed_id));
            }
        }
        _ => {}
    }
}

fn device_from_resolved(resolved: &ResolvedService) -> Option<Device> {
    let host = select_host(resolved)?;

    let raw_features = resolved
        .get_property_val_str("features")
        .or_else(|| resolved.get_property_val_str("ft"));
    debug!(raw_features = ?raw_features, "mDNS features property");
    let features_mask = raw_features.and_then(parse_features_mask).unwrap_or(0);
    info!(
        features_mask = format_args!("0x{features_mask:016x}"),
        transient = (features_mask & 0x0001_0000_0000_0000) != 0,
        "parsed device features"
    );

    let public_key = resolved
        .get_property_val_str("pk")
        .map(str::trim)
        .filter(|v| !v.is_empty());

    let device_id = if let Some(pk) = public_key {
        DeviceId(pk.to_string())
    } else if let Some(deviceid) = resolved
        .get_property_val_str("deviceid")
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        DeviceId(deviceid.to_ascii_lowercase())
    } else {
        device_id_from_fullname(resolved.get_fullname())
    };

    let instance_name = display_name_from_fullname(resolved.get_fullname());
    let name = if instance_name.is_empty() {
        resolved
            .get_property_val_str("model")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| resolved.get_fullname().to_string())
    } else {
        instance_name
    };

    Some(Device {
        id: device_id,
        name,
        host,
        port_rtsp: resolved.get_port(),
        port_timing: None,
        port_control: None,
        features: DeviceFeatures {
            requires_pairing: (features_mask & 0x800) != 0,
            supports_airplay2: (features_mask & 0x400000) != 0,
            supports_transient_pairing: (features_mask & 0x0001_0000_0000_0000) != 0,
            supports_alac: false,
        },
    })
}

fn parse_features_mask(value: &str) -> Option<u64> {
    let mut parts = value.split(',');
    let first = parts.next()?.trim();
    let lower = parse_hex_u64(first)?;
    let upper = parts
        .next()
        .and_then(|s| parse_hex_u64(s.trim()))
        .unwrap_or(0);
    Some((upper << 32) | lower)
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16).ok()
}

fn select_host(resolved: &ResolvedService) -> Option<IpAddr> {
    let mut first_v6 = None;

    for scoped in resolved.get_addresses() {
        let ip = scoped.to_ip_addr();
        if ip.is_ipv4() {
            return Some(ip);
        }
        if first_v6.is_none() {
            first_v6 = Some(ip);
        }
    }

    first_v6
}

fn display_name_from_fullname(fullname: &str) -> String {
    let instance = fullname.split('.').next().unwrap_or(fullname);
    instance
        .split_once('@')
        .map_or(instance, |(_, name)| name)
        .to_string()
}

fn device_id_from_fullname(fullname: &str) -> DeviceId {
    let instance = fullname.split('.').next().unwrap_or(fullname);
    if let Some((prefix, _)) = instance.split_once('@') {
        return DeviceId(prefix.to_ascii_lowercase());
    }
    DeviceId(instance.to_ascii_lowercase())
}
