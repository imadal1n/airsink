//! Application command and handle contracts shared by UI and supervisor layers.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, Sleep};
use tracing::{error, warn};

use crate::config::{Config, PairingStore};
use crate::core::{AppModel, ConnState, Device, DeviceId, PcmFormat, SampleFormat};
use crate::discovery::{DeviceEvent, start_discovery};
use crate::error::{Error, Recoverability, Result};
use crate::hap::HapClient;
use crate::pipewire::{CaptureHandle, VirtualSinkSpec};
use crate::rtp::{RtpSender, StreamPipeline};
use crate::rtsp::{AudioStreamConfig, RtspClient};
use crate::timing::TimingServer;

/// User- or system-issued intents consumed by the application supervisor.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Selects a receiver device as the active target.
    SelectDevice(
        /// Identifier of the device to select.
        DeviceId,
    ),
    /// Starts session setup and streaming for the selected device.
    StartStreaming,
    /// Stops the currently active stream/session.
    StopStreaming,
    /// Sets normalized output volume in the range `0.0..=1.0`.
    SetVolume(
        /// Normalized UI volume value.
        f32,
    ),
    /// Initiates pairing using a user-provided PIN.
    PairWithPin {
        /// HomeKit-style pairing PIN string.
        pin: String,
    },
    /// Requests graceful application shutdown.
    Quit,
}

/// Frontend-facing handle for command submission and model observation.
#[derive(Debug, Clone)]
pub struct AppHandle {
    /// Sender used by UI/frontends to submit commands.
    pub cmd_tx: mpsc::Sender<Command>,
    /// Watch receiver used by UI/frontends to observe model updates.
    pub model_rx: watch::Receiver<AppModel>,
}

/// Application supervisor entry point.
#[derive(Debug, Default)]
pub struct App;

impl App {
    /// Starts discovery and the supervisor task, then returns an [`AppHandle`].
    pub async fn start(cfg: Config, store: Arc<dyn PairingStore>) -> Result<AppHandle> {
        let discovery = start_discovery().await?;
        let mut initial_model = AppModel {
            devices: discovery.snapshot(),
            ..AppModel::default()
        };
        initial_model.state = ConnState::Discovering;

        let (cmd_tx, cmd_rx) = mpsc::channel(128);
        let (model_tx, model_rx) = watch::channel(initial_model.clone());

        let mut supervisor =
            Supervisor::new(cfg, store, initial_model, cmd_rx, model_tx, discovery);
        tokio::spawn(async move {
            if let Err(err) = supervisor.run().await {
                error!(error = %err, "app supervisor exited with error");
            }
        });

        Ok(AppHandle { cmd_tx, model_rx })
    }
}

#[derive(Debug, Clone, Copy)]
enum SessionTaskKind {
    Timing,
    Pipeline,
    Keepalive,
}

#[derive(Debug)]
struct SessionEvent {
    session_id: u64,
    task: SessionTaskKind,
    result: Result<()>,
}

struct ActiveSession {
    id: u64,
    device: Device,
    rtsp: Arc<tokio::sync::Mutex<RtspClient>>,
    stop_tx: watch::Sender<bool>,
    capture_stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    timing_join: JoinHandle<()>,
    pipeline_join: JoinHandle<()>,
    keepalive_join: JoinHandle<()>,
}

struct ReconnectPlan {
    device: Device,
    attempt: u32,
}

struct Supervisor {
    cfg: Config,
    store: Arc<dyn PairingStore>,
    model: AppModel,
    model_tx: watch::Sender<AppModel>,
    cmd_rx: mpsc::Receiver<Command>,
    discovery_rx: tokio::sync::broadcast::Receiver<DeviceEvent>,
    session_event_tx: mpsc::Sender<SessionEvent>,
    session_event_rx: mpsc::Receiver<SessionEvent>,
    selected_device: Option<Device>,
    active_session: Option<ActiveSession>,
    reconnect: Option<ReconnectPlan>,
    reconnect_sleep: Option<Pin<Box<Sleep>>>,
    next_session_id: u64,
}

impl Supervisor {
    fn new(
        cfg: Config,
        store: Arc<dyn PairingStore>,
        model: AppModel,
        cmd_rx: mpsc::Receiver<Command>,
        model_tx: watch::Sender<AppModel>,
        discovery: crate::discovery::DiscoveryHandle,
    ) -> Self {
        let (session_event_tx, session_event_rx) = mpsc::channel(32);
        Self {
            cfg,
            store,
            model,
            model_tx,
            cmd_rx,
            discovery_rx: discovery.events_rx,
            session_event_tx,
            session_event_rx,
            selected_device: None,
            active_session: None,
            reconnect: None,
            reconnect_sleep: None,
            next_session_id: 1,
        }
    }

    async fn run(&mut self) -> Result<()> {
        self.publish_model();

        loop {
            select! {
                maybe_cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = maybe_cmd else {
                        self.stop_session().await;
                        return Ok(());
                    };

                    if self.handle_command(cmd).await? {
                        return Ok(());
                    }
                }
                device_event = self.discovery_rx.recv() => {
                    match device_event {
                        Ok(event) => self.handle_device_event(event),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "discovery event receiver lagged");
                            self.model.devices.sort_by(|a, b| a.name.cmp(&b.name));
                            self.publish_model();
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            self.set_last_error("discovery event stream closed".to_owned());
                        }
                    }
                }
                session_event = self.session_event_rx.recv() => {
                    if let Some(event) = session_event {
                        self.handle_session_event(event).await;
                    }
                }
                _ = async {
                    if let Some(sleep) = self.reconnect_sleep.as_mut() {
                        sleep.as_mut().await;
                    }
                }, if self.reconnect_sleep.is_some() => {
                    self.reconnect_sleep = None;
                    self.try_reconnect().await;
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: Command) -> Result<bool> {
        match cmd {
            Command::SelectDevice(device_id) => {
                if let Some(device) = self
                    .model
                    .devices
                    .iter()
                    .find(|candidate| candidate.id == device_id)
                    .cloned()
                {
                    self.stop_session().await;
                    self.clear_reconnect();
                    self.selected_device = Some(device.clone());
                    self.transition_state(ConnState::Selected { device });
                } else {
                    self.set_last_error(format!("device '{}' not found", device_id.0));
                }
            }
            Command::StartStreaming => {
                self.clear_reconnect();
                if let Some(device) = self.selected_device.clone() {
                    if let Err(err) = self.ensure_streaming(device).await {
                        self.handle_session_error(err).await;
                    }
                } else {
                    self.set_last_error("select a device before starting streaming".to_owned());
                }
            }
            Command::StopStreaming => {
                self.clear_reconnect();
                self.stop_session().await;
                self.transition_to_selected_or_discovering();
            }
            Command::SetVolume(volume) => {
                self.set_volume(volume).await;
            }
            Command::PairWithPin { pin } => {
                let pairing_device = match &self.model.state {
                    ConnState::Pairing { device } => Some(device.clone()),
                    _ => None,
                };

                if let Some(device) = pairing_device {
                    if let Err(err) = self.pair_and_stream(device, pin).await {
                        self.handle_session_error(err).await;
                    }
                } else {
                    self.set_last_error("pairing is not currently in progress".to_owned());
                }
            }
            Command::Quit => {
                self.clear_reconnect();
                self.stop_session().await;
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn handle_device_event(&mut self, event: DeviceEvent) {
        match event {
            DeviceEvent::Up(device) => {
                if self.model.devices.iter().any(|entry| entry.id == device.id) {
                    return;
                }
                self.model.devices.push(device.clone());
                if self.selected_device.is_none() {
                    self.selected_device = Some(device);
                }
                self.model.devices.sort_by(|a, b| a.name.cmp(&b.name));
                self.publish_model();
            }
            DeviceEvent::Update(device) => {
                if let Some(existing) = self
                    .model
                    .devices
                    .iter_mut()
                    .find(|entry| entry.id == device.id)
                {
                    *existing = device.clone();
                } else {
                    self.model.devices.push(device.clone());
                }

                if self
                    .selected_device
                    .as_ref()
                    .is_some_and(|selected| selected.id == device.id)
                {
                    self.selected_device = Some(device.clone());
                }

                self.model.devices.sort_by(|a, b| a.name.cmp(&b.name));
                self.publish_model();
            }
            DeviceEvent::Down(device_id) => {
                self.model.devices.retain(|entry| entry.id != device_id);
                self.publish_model();
            }
        }
    }

    async fn handle_session_event(&mut self, event: SessionEvent) {
        let Some(active) = self.active_session.as_ref() else {
            return;
        };
        if event.session_id != active.id {
            return;
        }

        if *active.stop_tx.borrow() {
            return;
        }

        match event.result {
            Ok(()) => {
                self.handle_session_error(Error::Network(format!(
                    "{:?} task exited unexpectedly",
                    event.task
                )))
                .await;
            }
            Err(err) => {
                self.handle_session_error(err).await;
            }
        }
    }

    async fn ensure_streaming(&mut self, device: Device) -> Result<()> {
        self.stop_session().await;
        self.selected_device = Some(device.clone());

        let creds = self.store.load(&device.id).await?;
        if creds.is_none() {
            self.transition_state(ConnState::Pairing { device });
            return Ok(());
        }

        let creds = creds.expect("checked is_some");
        let session = self.start_session(device.clone(), creds).await?;
        self.active_session = Some(session);
        self.selected_device = Some(device);
        Ok(())
    }

    async fn pair_and_stream(&mut self, device: Device, pin: String) -> Result<()> {
        let mut hap = HapClient::connect(&device).await?;
        let creds = hap.pair_setup(&pin).await?;
        self.store.save(&device.id, &creds).await?;

        let session = self.start_session(device.clone(), creds).await?;
        self.active_session = Some(session);
        self.selected_device = Some(device);
        Ok(())
    }

    async fn start_session(
        &mut self,
        device: Device,
        creds: crate::config::PairingCredentials,
    ) -> Result<ActiveSession> {
        self.transition_state(ConnState::Verifying {
            device: device.clone(),
        });

        let mut hap = HapClient::connect(&device).await?;
        let session_keys = hap.pair_verify(&creds).await?;

        self.transition_state(ConnState::Connecting {
            device: device.clone(),
        });

        let (timing_server, timing_port) = TimingServer::start(0).await?;

        let mut rtsp = RtspClient::connect(&device).await?;
        rtsp.set_encryption(session_keys.clone());

        let session_uuid = random_session_uuid();
        rtsp.setup_session(&session_uuid, timing_port).await?;

        let stream_config = AudioStreamConfig {
            stream_type: 0x60,
            audio_format: 0x800,
            ct: 1,
            spf: 352,
            sr: 44_100,
            shk: session_keys.audio.key.to_vec(),
            control_port: device.port_control.unwrap_or(0),
            latency_min: self.cfg.target_latency_ms,
            latency_max: self.cfg.target_latency_ms,
            stream_connection_id: rand::random::<u64>(),
        };
        let stream_ports = rtsp.setup_audio_stream(&stream_config).await?;

        let capture_spec = VirtualSinkSpec {
            name: self.cfg.virtual_sink_name.clone(),
            description: format!("{} output", self.cfg.host_name),
            format: PcmFormat {
                rate_hz: 44_100,
                channels: 2,
                sample: SampleFormat::S16LE,
            },
        };
        let CaptureHandle { pcm_rx, stop_tx } = crate::pipewire::start_capture(capture_spec)?;

        let sender = RtpSender::new(device.host, stream_ports.data_port, self.cfg.bind_ip).await?;
        rtsp.record(0, session_keys.base_rtp_timestamp).await?;
        rtsp.set_volume(volume_to_db(self.model.volume)).await?;

        self.transition_state(ConnState::Connected {
            device: device.clone(),
        });
        self.transition_state(ConnState::Streaming {
            device: device.clone(),
        });

        let rtsp = Arc::new(tokio::sync::Mutex::new(rtsp));
        let (stop_signal_tx, stop_signal_rx) = watch::channel(false);
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        let timing_event_tx = self.session_event_tx.clone();
        let timing_stop_rx = stop_signal_rx.clone();
        let timing_join = tokio::spawn(async move {
            let result = timing_server.run(timing_stop_rx).await;
            let _ = timing_event_tx
                .send(SessionEvent {
                    session_id,
                    task: SessionTaskKind::Timing,
                    result,
                })
                .await;
        });

        let pipeline_event_tx = self.session_event_tx.clone();
        let pipeline_stop_rx = stop_signal_rx.clone();
        let audio_ctx = session_keys.audio.clone();
        let pipeline_join = tokio::spawn(async move {
            let result = StreamPipeline::run(pcm_rx, audio_ctx, sender, pipeline_stop_rx).await;
            let _ = pipeline_event_tx
                .send(SessionEvent {
                    session_id,
                    task: SessionTaskKind::Pipeline,
                    result,
                })
                .await;
        });

        let keepalive_event_tx = self.session_event_tx.clone();
        let keepalive_rtsp = Arc::clone(&rtsp);
        let mut keepalive_stop_rx = stop_signal_rx;
        let keepalive_join = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                select! {
                    changed = keepalive_stop_rx.changed() => {
                        match changed {
                            Ok(()) => {
                                if *keepalive_stop_rx.borrow() {
                                    let _ = keepalive_event_tx.send(SessionEvent {
                                        session_id,
                                        task: SessionTaskKind::Keepalive,
                                        result: Ok(()),
                                    }).await;
                                    return;
                                }
                            }
                            Err(_) => {
                                let _ = keepalive_event_tx.send(SessionEvent {
                                    session_id,
                                    task: SessionTaskKind::Keepalive,
                                    result: Ok(()),
                                }).await;
                                return;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        let result = async {
                            let mut client = keepalive_rtsp.lock().await;
                            client.get_info().await.map(|_| ())
                        }.await;

                        if let Err(err) = result {
                            let _ = keepalive_event_tx.send(SessionEvent {
                                session_id,
                                task: SessionTaskKind::Keepalive,
                                result: Err(err),
                            }).await;
                            return;
                        }
                    }
                }
            }
        });

        Ok(ActiveSession {
            id: session_id,
            device,
            rtsp,
            stop_tx: stop_signal_tx,
            capture_stop_tx: stop_tx,
            timing_join,
            pipeline_join,
            keepalive_join,
        })
    }

    async fn set_volume(&mut self, requested_volume: f32) {
        let clamped = requested_volume.clamp(0.0, 1.0);
        self.model.volume = clamped;
        self.publish_model();

        if let Some(session) = self.active_session.as_ref() {
            let db = volume_to_db(clamped);
            let result = async {
                let mut rtsp = session.rtsp.lock().await;
                rtsp.set_volume(db).await
            }
            .await;

            if let Err(err) = result {
                self.handle_session_error(err).await;
            }
        }
    }

    async fn stop_session(&mut self) {
        let Some(mut session) = self.active_session.take() else {
            return;
        };

        let _ = session.stop_tx.send(true);
        if let Some(stop_tx) = session.capture_stop_tx.take() {
            let _ = stop_tx.send(());
        }

        let teardown_result = async {
            let mut rtsp = session.rtsp.lock().await;
            rtsp.teardown().await
        }
        .await;

        if let Err(err) = teardown_result {
            self.set_last_error(format!("teardown failed: {err}"));
        }

        let _ = session.timing_join.await;
        let _ = session.pipeline_join.await;
        let _ = session.keepalive_join.await;
    }

    async fn handle_session_error(&mut self, err: Error) {
        let device = self
            .active_session
            .as_ref()
            .map(|session| session.device.clone())
            .or_else(|| self.selected_device.clone());

        self.stop_session().await;

        match err.recoverability() {
            Recoverability::Recoverable => {
                if let Some(device) = device {
                    let attempt = self.reconnect.as_ref().map_or(1, |state| state.attempt + 1);
                    self.reconnect = Some(ReconnectPlan {
                        device: device.clone(),
                        attempt,
                    });
                    self.transition_state(ConnState::Reconnecting { device, attempt });

                    let backoff_secs = 2_u64.pow(attempt.min(5));
                    self.reconnect_sleep =
                        Some(Box::pin(time::sleep(Duration::from_secs(backoff_secs))));
                    self.set_last_error(format!("recoverable error: {err}"));
                } else {
                    self.transition_state(ConnState::Failed {
                        device: None,
                        message: err.to_string(),
                    });
                }
            }
            Recoverability::Fatal => {
                self.clear_reconnect();
                self.transition_state(ConnState::Failed {
                    device,
                    message: err.to_string(),
                });
            }
        }
    }

    async fn try_reconnect(&mut self) {
        let Some(plan) = self.reconnect.as_ref() else {
            return;
        };

        let device = plan.device.clone();
        let attempt = plan.attempt;
        self.transition_state(ConnState::Reconnecting {
            device: device.clone(),
            attempt,
        });

        let result = self.ensure_streaming(device).await;
        match result {
            Ok(()) => {
                self.clear_reconnect();
            }
            Err(err) => {
                self.handle_session_error(err).await;
            }
        }
    }

    fn clear_reconnect(&mut self) {
        self.reconnect = None;
        self.reconnect_sleep = None;
    }

    fn transition_to_selected_or_discovering(&mut self) {
        if let Some(device) = self.selected_device.clone() {
            self.transition_state(ConnState::Selected { device });
        } else {
            self.transition_state(ConnState::Discovering);
        }
    }

    fn transition_state(&mut self, state: ConnState) {
        self.model.state = state;
        self.publish_model();
    }

    fn set_last_error(&mut self, message: String) {
        self.model.last_error = Some(message);
        self.publish_model();
    }

    fn publish_model(&self) {
        let _ = self.model_tx.send(self.model.clone());
    }
}

fn volume_to_db(volume: f32) -> f64 {
    if volume <= 0.0 {
        -144.0
    } else {
        (20.0 * volume.log10() * 1.5).clamp(-144.0, 0.0) as f64
    }
}

fn random_session_uuid() -> String {
    let random = rand::random::<u128>();
    let bytes = random.to_be_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
