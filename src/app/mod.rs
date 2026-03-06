//! Application command and handle contracts shared by UI and supervisor layers.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, Sleep};
use tracing::{debug, error, info, warn};

use crate::config::{Config, PairingStore};
use crate::core::{AppModel, ConnState, Device, DeviceId, PcmFormat, SampleFormat};
use crate::crypto::SessionKeys;
use crate::discovery::{DeviceEvent, start_discovery};
use crate::error::{Error, Recoverability, Result};
use crate::hap::HapClient;
use crate::pipewire::{CaptureHandle, VirtualSinkSpec};
use crate::rtp::{RtpSender, StreamPipeline, SyncSender};
use crate::rtsp::{AudioStreamConfig, RtspClient};
use crate::timing::TimingServer;
use crate::timing::ptp::{PtpConfig, PtpMaster, PtpSockets};

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
    Event,
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
    ptp_master: Option<Arc<PtpMaster>>,
    ptp_join: Option<JoinHandle<()>>,
    timing_join: JoinHandle<()>,
    pipeline_join: JoinHandle<()>,
    keepalive_join: JoinHandle<()>,
    event_join: Option<JoinHandle<()>>,
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
                    info!(device_name = %device.name, device_id = %device.id.0, "StartStreaming command received");
                    if let Err(err) = self.ensure_streaming(device).await {
                        error!(error = %err, "ensure_streaming failed");
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

        // Try stored credentials first (fast reconnect).
        let creds = self.store.load(&device.id).await?;
        if let Some(creds) = creds {
            info!("found stored credentials, starting verified session");
            let session = self.start_session_with_creds(device.clone(), creds).await?;
            self.active_session = Some(session);
            self.selected_device = Some(device);
            return Ok(());
        }

        // Always attempt transient pairing first (no PIN needed).
        info!(device_name = %device.name, "attempting transient pairing (PIN 3939)");
        self.transition_state(ConnState::Pairing {
            device: device.clone(),
        });
        match self.try_transient_pairing(&device).await {
            Ok((session_keys, stream, leftover)) => {
                info!("transient pairing succeeded");
                let session = self
                    .start_session(device.clone(), session_keys, stream, &leftover)
                    .await?;
                self.active_session = Some(session);
                self.selected_device = Some(device);
                Ok(())
            }
            Err(err) => {
                warn!(error = %err, "transient pairing failed, falling back to PIN-based pairing");
                self.transition_state(ConnState::Pairing { device });
                Ok(())
            }
        }
    }

    async fn try_transient_pairing(
        &self,
        device: &Device,
    ) -> Result<(SessionKeys, TcpStream, Vec<u8>)> {
        let mut hap = HapClient::connect(device).await?;
        let keys = hap.pair_setup_transient().await?;
        let (stream, leftover) = hap.into_parts();
        Ok((keys, stream, leftover))
    }

    async fn pair_and_stream(&mut self, device: Device, pin: String) -> Result<()> {
        info!(device_name = %device.name, host = %device.host, port = device.port_rtsp, "connecting HAP client for pair-setup");
        let mut hap = HapClient::connect(&device).await?;
        info!("HAP connected, starting pair-setup with PIN");
        let creds = hap.pair_setup(&pin).await?;
        info!("pair-setup succeeded, saving credentials");
        self.store.save(&device.id, &creds).await?;

        let session = self.start_session_with_creds(device.clone(), creds).await?;
        self.active_session = Some(session);
        self.selected_device = Some(device);
        Ok(())
    }

    async fn start_session_with_creds(
        &mut self,
        device: Device,
        creds: crate::config::PairingCredentials,
    ) -> Result<ActiveSession> {
        self.transition_state(ConnState::Verifying {
            device: device.clone(),
        });

        let mut hap = HapClient::connect(&device).await?;
        let session_keys = hap.pair_verify(&creds).await?;
        let (stream, leftover) = hap.into_parts();

        self.start_session(device, session_keys, stream, &leftover)
            .await
    }

    async fn start_session(
        &mut self,
        device: Device,
        session_keys: SessionKeys,
        stream: TcpStream,
        leftover: &[u8],
    ) -> Result<ActiveSession> {
        self.transition_state(ConnState::Connecting {
            device: device.clone(),
        });

        debug!("start_session: starting timing server");
        let (timing_server, timing_port) = TimingServer::start(0).await?;
        debug!(timing_port, "start_session: timing server bound");

        debug!("start_session: reusing paired TCP connection for RTSP");
        let mut rtsp = RtspClient::from_parts(stream, leftover, &device);
        debug!("start_session: setting encryption on RTSP");
        rtsp.set_encryption(session_keys.clone());

        debug!("start_session: sending GET /info");
        let info = rtsp.get_info().await?;
        debug!(
            num_keys = info.len(),
            "start_session: /info response received"
        );

        debug!("start_session: binding PTP sockets");
        let ptp_sockets = PtpSockets::bind().await?;
        let our_ptp_port = ptp_sockets.event_port;
        debug!(our_ptp_port, "start_session: PTP sockets bound");

        let session_uuid = random_session_uuid();
        let sender_device_id = random_sender_device_id();
        let sender_mac = random_sender_device_id();
        let group_uuid = random_session_uuid();
        debug!(
            session_uuid,
            sender_device_id, "start_session: sending RTSP setup_session (PTP)"
        );
        let (setup_resp, ptp_clock_id) = rtsp
            .setup_session(
                &session_uuid,
                timing_port,
                &sender_device_id,
                &sender_mac,
                &group_uuid,
                true,
                our_ptp_port,
            )
            .await?;
        debug!("start_session: RTSP session created");

        for (key, val) in &setup_resp {
            let val_summary = match val {
                plist::Value::String(s) => s.clone(),
                plist::Value::Integer(i) => format!("{i:?}"),
                plist::Value::Boolean(b) => format!("{b}"),
                _ => format!("{val:?}"),
            };
            debug!(key, val = %val_summary, "setup_session response field");
        }

        let peer_clock_port = 0_u16;

        let event_port = setup_resp
            .get("eventPort")
            .and_then(|v| v.as_unsigned_integer().map(|p| p as u16)
                .or_else(|| v.as_signed_integer().map(|p| p as u16)))
            .unwrap_or(0);

        let event_channel = if event_port > 0 {
            debug!(event_port, "connecting to event channel");
            let stream = TcpStream::connect((device.host, event_port))
                .await
                .map_err(|e| Error::Network(format!("event channel connect: {e}")))?;
            debug!("event channel connected");
            Some(stream)
        } else {
            warn!("no eventPort in SETUP response");
            None
        };

        let ptp_config = PtpConfig {
            clock_id: ptp_clock_id,
            peer_addr: device.host,
            peer_clock_port,
        };
        debug!(
            clock_id = ptp_clock_id,
            peer_clock_port, "starting PTP follower"
        );
        let ptp_master = PtpMaster::start(ptp_config, ptp_sockets).await?;
        let (ptp_master, ptp_join) = ptp_master;

        let initial_seq: u16 = rand::random();
        let initial_rtptime: u32 = rand::random();

        debug!("start_session: sending RECORD");
        rtsp.record(initial_seq, initial_rtptime).await?;
        debug!("start_session: RECORD accepted");

        debug!("start_session: sending SETPEERS");
        let remote_ip = device.host.to_string();
        rtsp.setpeers(&remote_ip).await?;
        debug!("start_session: SETPEERS accepted");

        let control_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|err| Error::Network(format!("failed to bind control socket: {err}")))?;
        let local_control_port = control_socket
            .local_addr()
            .map_err(|err| Error::Network(format!("failed to read control socket address: {err}")))?
            .port();
        debug!(local_control_port, "start_session: control socket bound");

        // We need a temporary encoder to get the magic cookie for SETUP
        let temp_encoder = crate::codec::new_encoder(
            PcmFormat { rate_hz: 44100, channels: 2, sample: SampleFormat::S16LE },
            352,
            initial_rtptime
        )?;
        let asc = temp_encoder.magic_cookie().map(|b| b.to_vec());

        let stream_config = AudioStreamConfig {
            stream_type: 0x60,
            audio_format: 0x40000,
            ct: 2,
            spf: 352,
            sr: 44_100,
            asc,
            shk: session_keys.audio.key.to_vec(),
            control_port: local_control_port,
            latency_min: 11_025,
            latency_max: 88_200,
            stream_connection_id: rand::random::<u64>(),
        };
        debug!("start_session: sending RTSP setup_audio_stream");
        let stream_ports = rtsp.setup_audio_stream(&stream_config).await?;
        debug!(?stream_ports, "start_session: audio stream ports received");

        let sync_sender = SyncSender::new(
            control_socket,
            SocketAddr::new(device.host, stream_ports.control_port),
            ptp_clock_id as u64,
        );

        let lock_timeout = Duration::from_secs(15);
        let ptp_locked = ptp_master.wait_locked(lock_timeout).await;
        if ptp_locked {
            debug!("start_session: PTP clock locked");
        } else {
            warn!("start_session: PTP clock not locked after {lock_timeout:?}, continuing anyway");
        }

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
        rtsp.set_volume(volume_to_db(self.model.volume)).await?;

        let ptp_master = Arc::new(ptp_master);

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

        let ptp_event_tx = self.session_event_tx.clone();
        let ptp_join_handle = tokio::spawn(async move {
            match ptp_join.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    let _ = ptp_event_tx
                        .send(SessionEvent {
                            session_id,
                            task: SessionTaskKind::Timing,
                            result: Err(err),
                        })
                        .await;
                }
                Err(join_err) => {
                    tracing::error!(error = %join_err, "PTP task panicked");
                }
            }
        });

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
        let audio_key = session_keys.audio.key.clone();
        let ptp_master_clone = Arc::clone(&ptp_master);
        let pipeline_join = tokio::spawn(async move {
            let result = StreamPipeline::run(
                pcm_rx,
                audio_key,
                sender,
                initial_seq,
                initial_rtptime,
                sync_sender,
                ptp_master_clone,
                pipeline_stop_rx,
            )
            .await;
            let _ = pipeline_event_tx
                .send(SessionEvent {
                    session_id,
                    task: SessionTaskKind::Pipeline,
                    result,
                })
                .await;
        });

        let event_stop_rx = stop_signal_rx.clone();

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

        let event_join = event_channel.map(|stream| {
            let ev_tx = self.session_event_tx.clone();
            let mut ev_stop = event_stop_rx;
            tokio::spawn(async move {
                let result = run_event_channel(stream, &mut ev_stop).await;
                let _ = ev_tx
                    .send(SessionEvent {
                        session_id,
                        task: SessionTaskKind::Event,
                        result,
                    })
                    .await;
            })
        });

        Ok(ActiveSession {
            id: session_id,
            device,
            rtsp,
            stop_tx: stop_signal_tx,
            capture_stop_tx: stop_tx,
            ptp_master: Some(Arc::clone(&ptp_master)),
            ptp_join: Some(ptp_join_handle),
            timing_join,
            pipeline_join,
            keepalive_join,
            event_join,
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

        if let Some(ptp) = session.ptp_master.take() {
            ptp.stop();
        }
        if let Some(join) = session.ptp_join.take() {
            let _ = join.await;
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
        if let Some(join) = session.event_join.take() {
            let _ = join.await;
        }
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
        debug!(from = ?std::mem::discriminant(&self.model.state), to = ?std::mem::discriminant(&state), "state transition");
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

async fn run_event_channel(
    mut stream: TcpStream,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        select! {
            changed = stop.changed() => {
                match changed {
                    Ok(()) if *stop.borrow() => return Ok(()),
                    Err(_) => return Ok(()),
                    _ => {}
                }
            }
            result = stream.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        debug!("event channel closed by peer");
                        return Ok(());
                    }
                    Ok(n) => {
                        debug!(bytes = n, "event channel received data");
                    }
                    Err(e) => {
                        debug!(error = %e, "event channel read error");
                        return Ok(());
                    }
                }
            }
        }
    }
}

fn extract_peer_clock_port(setup_resp: &plist::Dictionary) -> u16 {
    let timing_peer_info = setup_resp
        .get("timingPeerInfo")
        .and_then(plist::Value::as_dictionary);
    let clock_ports = timing_peer_info
        .and_then(|info| info.get("ClockPorts"))
        .and_then(plist::Value::as_dictionary);

    if let Some(ports) = clock_ports {
        for (_uuid, port_val) in ports {
            if let Some(port) = port_val.as_unsigned_integer() {
                let port = port as u16;
                debug!(port, "extracted peer clock port from SETUP response");
                return port;
            }
            if let Some(port) = port_val.as_signed_integer() {
                let port = port as u16;
                debug!(port, "extracted peer clock port from SETUP response");
                return port;
            }
        }
    }

    debug!("no ClockPorts in SETUP response, using standard PTP ports");
    0
}

fn volume_to_db(volume: f32) -> f64 {
    if volume <= 0.0 {
        -144.0
    } else {
        (20.0 * volume.log10() * 1.5).clamp(-144.0, 0.0) as f64
    }
}

fn random_sender_device_id() -> String {
    let bytes = rand::random::<[u8; 8]>();
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
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
