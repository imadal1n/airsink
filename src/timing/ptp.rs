use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::error::{Error, Result};

const PTP_TRANSPORT_SPECIFIC: u8 = 0x10;
const PTP_VERSION: u8 = 0x02;
const PTP_DOMAIN: u8 = 0x00;
const PTP_PORT_NUMBER: u16 = 0x8008;
const PTP_EVENT_PORT: u16 = 319;
const PTP_GENERAL_PORT: u16 = 320;

const MSG_SYNC: u8 = 0x00;
const MSG_DELAY_REQ: u8 = 0x01;
const MSG_FOLLOW_UP: u8 = 0x08;
const MSG_DELAY_RESP: u8 = 0x09;
const MSG_ANNOUNCE: u8 = 0x0B;
const MSG_SIGNALING: u8 = 0x0C;

const FLAGS_SYNC: u16 = 0x0608;
const FLAGS_OTHER: u16 = 0x0408;
const FLAGS_ANNOUNCE: u16 = 0x040C;

const CONTROL_SYNC: u8 = 0x00;
const CONTROL_DELAY_REQ: u8 = 0x01;
const CONTROL_FOLLOW_UP: u8 = 0x02;
const CONTROL_DELAY_RESP: u8 = 0x03;
const CONTROL_OTHER: u8 = 0x05;

const LOG_INTERVAL_SYNC: i8 = -3;
const LOG_INTERVAL_ANNOUNCE: i8 = -2;
const LOG_INTERVAL_FOLLOW_UP: i8 = 127;
const LOG_INTERVAL_OTHER: i8 = 127;
const LOG_INTERVAL_SIGNALING: i8 = -128;

const HEADER_LEN: usize = 34;
const TIMESTAMP_LEN: usize = 10;
const PORT_IDENTITY_LEN: usize = 10;
const TLV_ORG_EXTENSION: u16 = 0x0003;
const TLV_PATH_TRACE: u16 = 0x0008;

const ORG_IEEE_802_1: [u8; 3] = [0x00, 0x80, 0xC2];
const ORG_APPLE: [u8; 3] = [0x00, 0x0D, 0x93];

struct HeaderFields {
    msg_type: u8,
    message_len: u16,
    flags: u16,
    sequence_id: u16,
    control_field: u8,
    log_message_interval: i8,
}

#[derive(Debug, Clone, Copy)]
pub struct PtpConfig {
    pub clock_id: i64,
    pub peer_addr: IpAddr,
    pub peer_clock_port: u16,
}

/// Pre-bound PTP sockets ready to be passed into PtpMaster::start_with_sockets.
pub struct PtpSockets {
    pub event_socket: UdpSocket,
    pub general_socket: UdpSocket,
    pub event_port: u16,
}

impl PtpSockets {
    /// Binds PTP event and general sockets. Returns the bound event port so the
    /// caller can advertise it in the RTSP SETUP request before PTP starts.
    pub async fn bind() -> Result<Self> {
        let event_socket = try_bind(PTP_EVENT_PORT)
            .await
            .map_err(|err| Error::Network(format!("failed to bind PTP event socket: {err}")))?;
        let general_socket = try_bind(PTP_GENERAL_PORT)
            .await
            .map_err(|err| Error::Network(format!("failed to bind PTP general socket: {err}")))?;
        let event_port = event_socket
            .local_addr()
            .map_err(|err| {
                Error::Network(format!("failed to read PTP event socket address: {err}"))
            })?
            .port();
        Ok(Self {
            event_socket,
            general_socket,
            event_port,
        })
    }
}

#[derive(Debug)]
pub struct PtpMaster {
    stop_tx: watch::Sender<bool>,
    locked_rx: watch::Receiver<bool>,
    ptp_origin: Instant,
    ptp_offset_rx: watch::Receiver<i128>,
}

impl PtpMaster {
    pub async fn start(
        config: PtpConfig,
        sockets: PtpSockets,
    ) -> Result<(Self, JoinHandle<Result<()>>)> {
        let ptp_origin = Instant::now();
        let (ptp_offset_tx, ptp_offset_rx) = watch::channel(0_i128);
        let event_port = if config.peer_clock_port > 0 {
            config.peer_clock_port
        } else {
            PTP_EVENT_PORT
        };
        let general_port = if config.peer_clock_port > 0 {
            config.peer_clock_port + 1
        } else {
            PTP_GENERAL_PORT
        };
        let event_peer = SocketAddr::new(config.peer_addr, event_port);
        let general_peer = SocketAddr::new(config.peer_addr, general_port);
        let clock_identity = config.clock_id.to_be_bytes();

        let event_local = sockets.event_socket.local_addr().map_err(|err| {
            Error::Network(format!("failed to read PTP event socket address: {err}"))
        })?;
        let general_local = sockets.general_socket.local_addr().map_err(|err| {
            Error::Network(format!("failed to read PTP general socket address: {err}"))
        })?;

        tracing::debug!(
            event_peer = %event_peer,
            general_peer = %general_peer,
            event_local = %event_local,
            general_local = %general_local,
            clock_id = config.clock_id,
            configured_peer_clock_port = config.peer_clock_port,
            "PTP follower started"
        );

        let (stop_tx, stop_rx) = watch::channel(false);
        let (locked_tx, locked_rx) = watch::channel(false);
        let handle = tokio::spawn(run_ptp(
            sockets.event_socket,
            sockets.general_socket,
            event_peer,
            general_peer,
            clock_identity,
            stop_rx,
            locked_tx,
            ptp_origin,
            ptp_offset_tx,
        ));

        Ok((
            Self {
                stop_tx,
                locked_rx,
                ptp_origin,
                ptp_offset_rx,
            },
            handle,
        ))
    }

    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    pub async fn wait_locked(&self, timeout: Duration) -> bool {
        let mut rx = self.locked_rx.clone();
        if *rx.borrow() {
            return true;
        }

        match tokio::time::timeout(timeout, async {
            loop {
                if rx.changed().await.is_err() {
                    return *rx.borrow();
                }
                if *rx.borrow() {
                    return true;
                }
            }
        })
        .await
        {
            Ok(locked) => locked,
            Err(_) => *rx.borrow(),
        }
    }

    /// Returns current PTP master time in nanoseconds since PTP epoch.
    pub fn ptp_time_ns(&self) -> u64 {
        let elapsed = Instant::now().duration_since(self.ptp_origin);
        let local_ns = elapsed.as_nanos() as i128;
        let ptp_ns = local_ns + *self.ptp_offset_rx.borrow();
        ptp_ns.max(0) as u64
    }
}

#[derive(Debug, Clone, Copy)]
struct FollowUpSample {
    sequence_id: u16,
    master_ns: i128,
    local_receive_instant: Instant,
    correction_field: i64,
}

async fn run_ptp(
    event_socket: UdpSocket,
    general_socket: UdpSocket,
    event_peer: SocketAddr,
    general_peer: SocketAddr,
    clock_identity: [u8; 8],
    mut stop_rx: watch::Receiver<bool>,
    locked_tx: watch::Sender<bool>,
    ptp_origin: Instant,
    ptp_offset_tx: watch::Sender<i128>,
) -> Result<()> {
    let mut event_buf = [0_u8; 1500];
    let mut general_buf = [0_u8; 1500];
    let mut follow_up_hex_dump_count: u32 = 0;
    let mut offset_samples: VecDeque<i128> = VecDeque::with_capacity(8);
    let mut locked = false;
    let mut delay_req_interval = time::interval(Duration::from_millis(125));
    delay_req_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let signaling = build_signaling(0, &clock_identity);
    general_socket
        .send_to(&signaling, general_peer)
        .await
        .map_err(|err| Error::Network(format!("failed to send PTP Signaling (general): {err}")))?;
    event_socket
        .send_to(&signaling, event_peer)
        .await
        .map_err(|err| Error::Network(format!("failed to send PTP Signaling (event): {err}")))?;

    let good_announce = build_announce(0, &clock_identity);
    general_socket
        .send_to(&good_announce, general_peer)
        .await
        .map_err(|err| Error::Network(format!("failed to send PTP awakening good (general): {err}")))?;
    event_socket
        .send_to(&good_announce, event_peer)
        .await
        .map_err(|err| Error::Network(format!("failed to send PTP awakening good (event): {err}")))?;

    time::sleep(Duration::from_millis(200)).await;

    let bad_announce = build_announce_bad(1, &clock_identity);
    general_socket
        .send_to(&bad_announce, general_peer)
        .await
        .map_err(|err| Error::Network(format!("failed to send PTP awakening bad (general): {err}")))?;
    event_socket
        .send_to(&bad_announce, event_peer)
        .await
        .map_err(|err| Error::Network(format!("failed to send PTP awakening bad (event): {err}")))?;

    tracing::info!(
        event_peer = %event_peer,
        general_peer = %general_peer,
        "PTP follower: sent awakening sequence, listening for master"
    );

    delay_req_interval.tick().await;

    loop {
        if *stop_rx.borrow() {
            return Ok(());
        }

        select! {
            changed = stop_rx.changed() => {
                match changed {
                    Ok(()) => {
                        if *stop_rx.borrow() {
                            return Ok(());
                        }
                    }
                    Err(_) => return Ok(()),
                }
            }
            _ = delay_req_interval.tick() => {
                // Delay_Req disabled — NQPTP does not send Delay_Req.
                // Lock based on Follow_Up one-way offset instead.
            }
            recv = event_socket.recv_from(&mut event_buf) => {
                let (len, source) = recv
                    .map_err(|err| Error::Network(format!("PTP event recv: {err}")))?;
                if len < HEADER_LEN {
                    tracing::debug!(len, source = %source, "PTP follower: short event packet");
                    continue;
                }

                let msg_type = event_buf[0] & 0x0F;
                if msg_type == MSG_SYNC {
                    tracing::debug!(len, source = %source, "PTP follower: received Sync");
                } else {
                    tracing::debug!(
                        msg_type,
                        name = ptp_msg_name(msg_type),
                        len,
                        source = %source,
                        "PTP follower: ignored event packet"
                    );
                }
            }
            recv = general_socket.recv_from(&mut general_buf) => {
                let (len, source) = recv
                    .map_err(|err| Error::Network(format!("PTP general recv: {err}")))?;

                if len < HEADER_LEN {
                    tracing::debug!(len, source = %source, "PTP follower: short general packet");
                    continue;
                }

                let msg_type = general_buf[0] & 0x0F;

                match msg_type {
                    MSG_FOLLOW_UP => {
                        let packet = &general_buf[..len];
                        let sequence_id = match parse_sequence_id(packet) {
                            Some(sequence_id) => sequence_id,
                            None => {
                                tracing::debug!(len, source = %source, "PTP follower: malformed Follow_Up sequence");
                                continue;
                            }
                        };
                        let correction_field = match parse_correction_field(packet) {
                            Some(correction_field) => correction_field,
                            None => {
                                tracing::debug!(len, source = %source, "PTP follower: malformed Follow_Up correction field");
                                continue;
                            }
                        };
                        let master_ns = match parse_timestamp_ns(packet, HEADER_LEN) {
                            Some(master_ns) => i128::from(master_ns),
                            None => {
                                tracing::debug!(len, source = %source, "PTP follower: malformed Follow_Up timestamp");
                                continue;
                            }
                        };

                        let local_receive_instant = Instant::now();
                        let t2_local_ns = instant_to_local_ns(ptp_origin, local_receive_instant);
                        let offset_ns = master_ns - t2_local_ns;

                        if offset_samples.len() == 8 {
                            offset_samples.pop_front();
                        }
                        offset_samples.push_back(offset_ns);
                        let sample_count = offset_samples.len();
                        let average_offset_ns = if sample_count == 0 {
                            0
                        } else {
                            offset_samples.iter().copied().sum::<i128>() / i128::from(sample_count as i64)
                        };
                        let _ = ptp_offset_tx.send(average_offset_ns);

                        let jitter_ns = if sample_count < 2 {
                            0
                        } else {
                            let min_offset = offset_samples.iter().copied().min().unwrap_or(0);
                            let max_offset = offset_samples.iter().copied().max().unwrap_or(0);
                            max_offset - min_offset
                        };

                        if follow_up_hex_dump_count < 5 {
                            follow_up_hex_dump_count = follow_up_hex_dump_count.saturating_add(1);
                            let hex: Vec<String> = packet.iter().map(|byte| format!("{byte:02x}")).collect();
                            tracing::info!(
                                sequence_id,
                                correction_field,
                                master_ns,
                                offset_ns,
                                jitter_ns,
                                sample_count,
                                hex = %hex.join(" "),
                                "PTP follower: Follow_Up"
                            );
                        } else {
                            tracing::debug!(
                                sequence_id,
                                offset_ns,
                                average_offset_ns,
                                jitter_ns,
                                sample_count,
                                "PTP follower: offset"
                            );
                        }

                        if !locked && sample_count == 8 && jitter_ns < 50_000_000 {
                            locked = true;
                            let _ = locked_tx.send(true);
                            tracing::info!(average_offset_ns, jitter_ns, "PTP clock locked");
                        }
                    }
                    MSG_DELAY_RESP => {
                        tracing::debug!(len, source = %source, "PTP follower: received Delay_Resp (ignored)");
                    }
                    MSG_ANNOUNCE => {
                        tracing::debug!(len, source = %source, "PTP follower: received Announce");
                    }
                    MSG_SIGNALING => {
                        tracing::debug!(len, source = %source, "PTP follower: received Signaling");
                    }
                    _ => {
                        tracing::debug!(
                            msg_type,
                            name = ptp_msg_name(msg_type),
                            len,
                            source = %source,
                            "PTP follower: ignored general packet"
                        );
                    }
                }
            }
        }
    }
}

fn parse_sequence_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 32 {
        return None;
    }

    Some(u16::from_be_bytes([packet[30], packet[31]]))
}

fn parse_correction_field(packet: &[u8]) -> Option<i64> {
    if packet.len() < 16 {
        return None;
    }

    Some(i64::from_be_bytes([
        packet[8],
        packet[9],
        packet[10],
        packet[11],
        packet[12],
        packet[13],
        packet[14],
        packet[15],
    ]))
}

fn parse_timestamp_ns(packet: &[u8], start: usize) -> Option<u64> {
    let end = start.checked_add(TIMESTAMP_LEN)?;
    if packet.len() < end {
        return None;
    }

    let timestamp = &packet[start..end];
    let seconds_high = u16::from_be_bytes([timestamp[0], timestamp[1]]);
    let seconds_low = u32::from_be_bytes([timestamp[2], timestamp[3], timestamp[4], timestamp[5]]);
    let nanoseconds = u32::from_be_bytes([timestamp[6], timestamp[7], timestamp[8], timestamp[9]]);
    let total_seconds = (u64::from(seconds_high) << 32) | u64::from(seconds_low);

    Some(
        total_seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(u64::from(nanoseconds)),
    )
}

fn instant_to_local_ns(origin: Instant, instant: Instant) -> i128 {
    instant.duration_since(origin).as_nanos() as i128
}

fn ptp_msg_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x00 => "Sync",
        0x01 => "Delay_Req",
        0x02 => "Pdelay_Req",
        0x03 => "Pdelay_Resp",
        0x08 => "Follow_Up",
        0x09 => "Delay_Resp",
        0x0A => "Pdelay_Resp_Follow_Up",
        0x0B => "Announce",
        0x0C => "Signaling",
        0x0D => "Management",
        _ => "Unknown",
    }
}

async fn try_bind(port: u16) -> std::io::Result<UdpSocket> {
    let privileged = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    match UdpSocket::bind(privileged).await {
        Ok(socket) => Ok(socket),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::PermissionDenied | ErrorKind::AddrInUse
            ) =>
        {
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await
        }
        Err(err) => Err(err),
    }
}

#[allow(dead_code)]
fn build_sync(sequence_id: u16, clock_identity: &[u8; 8]) -> Vec<u8> {
    let total_len = HEADER_LEN + TIMESTAMP_LEN;
    let mut out = vec![0_u8; total_len];
    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_SYNC,
            message_len: total_len as u16,
            flags: FLAGS_SYNC,
            sequence_id,
            control_field: CONTROL_SYNC,
            log_message_interval: LOG_INTERVAL_SYNC,
        },
    );

    out
}

#[allow(dead_code)]
fn build_follow_up(
    sequence_id: u16,
    clock_identity: &[u8; 8],
    precise_origin: SystemTime,
) -> Vec<u8> {
    let total_len = 96;
    let mut out = vec![0_u8; total_len];

    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_FOLLOW_UP,
            message_len: total_len as u16,
            flags: FLAGS_OTHER,
            sequence_id,
            control_field: CONTROL_FOLLOW_UP,
            log_message_interval: LOG_INTERVAL_FOLLOW_UP,
        },
    );

    write_timestamp(
        &mut out[HEADER_LEN..HEADER_LEN + TIMESTAMP_LEN],
        precise_origin,
    );

    let tlv_1_start = HEADER_LEN + TIMESTAMP_LEN;
    let tlv_1 = &mut out[tlv_1_start..tlv_1_start + 32];
    tlv_1[0..2].copy_from_slice(&TLV_ORG_EXTENSION.to_be_bytes());
    tlv_1[2..4].copy_from_slice(&28_u16.to_be_bytes());
    tlv_1[4..7].copy_from_slice(&ORG_IEEE_802_1);
    tlv_1[7..10].copy_from_slice(&[0x00, 0x00, 0x01]);

    let tlv_2_start = tlv_1_start + 32;
    let tlv_2 = &mut out[tlv_2_start..tlv_2_start + 20];
    tlv_2[0..2].copy_from_slice(&TLV_ORG_EXTENSION.to_be_bytes());
    tlv_2[2..4].copy_from_slice(&16_u16.to_be_bytes());
    tlv_2[4..7].copy_from_slice(&ORG_APPLE);
    tlv_2[7..10].copy_from_slice(&[0x00, 0x00, 0x04]);
    tlv_2[10..18].copy_from_slice(clock_identity);

    out
}

#[allow(dead_code)]
fn build_announce(sequence_id: u16, clock_identity: &[u8; 8]) -> Vec<u8> {
    let total_len = HEADER_LEN + 10 + 20 + 12;
    let mut out = vec![0_u8; total_len];

    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_ANNOUNCE,
            message_len: total_len as u16,
            flags: FLAGS_ANNOUNCE,
            sequence_id,
            control_field: CONTROL_OTHER,
            log_message_interval: LOG_INTERVAL_ANNOUNCE,
        },
    );

    let body = &mut out[HEADER_LEN..];
    // currentUtcOffset = 37 (TAI - UTC leap seconds as of 2017+)
    body[10..12].copy_from_slice(&37_u16.to_be_bytes());
    body[13] = 128;
    body[14..18].copy_from_slice(&0xF8FE_436A_u32.to_be_bytes());
    body[18] = 128;
    body[19..27].copy_from_slice(clock_identity);
    body[29] = 0x20;

    let tlv = &mut out[HEADER_LEN + 30..];
    tlv[0..2].copy_from_slice(&TLV_PATH_TRACE.to_be_bytes());
    tlv[2..4].copy_from_slice(&8_u16.to_be_bytes());
    tlv[4..12].copy_from_slice(clock_identity);

    out
}

fn build_announce_bad(sequence_id: u16, clock_identity: &[u8; 8]) -> Vec<u8> {
    let total_len = HEADER_LEN + 10 + 20 + 12;
    let mut out = vec![0_u8; total_len];

    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_ANNOUNCE,
            message_len: total_len as u16,
            flags: FLAGS_ANNOUNCE,
            sequence_id,
            control_field: CONTROL_OTHER,
            log_message_interval: LOG_INTERVAL_ANNOUNCE,
        },
    );

    let body = &mut out[HEADER_LEN..];
    body[10..12].copy_from_slice(&37_u16.to_be_bytes());
    body[13] = 255;
    body[14] = 255;
    body[15] = 0xFE;
    body[16..18].copy_from_slice(&0xFFFF_u16.to_be_bytes());
    body[18] = 255;
    body[19..27].copy_from_slice(clock_identity);
    body[29] = 0xA0;

    let tlv = &mut out[HEADER_LEN + 30..];
    tlv[0..2].copy_from_slice(&TLV_PATH_TRACE.to_be_bytes());
    tlv[2..4].copy_from_slice(&8_u16.to_be_bytes());
    tlv[4..12].copy_from_slice(clock_identity);

    out
}

fn build_delay_req(sequence_id: u16, clock_identity: &[u8; 8]) -> Vec<u8> {
    let total_len = HEADER_LEN + TIMESTAMP_LEN;
    let mut out = vec![0_u8; total_len];

    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_DELAY_REQ,
            message_len: total_len as u16,
            flags: FLAGS_OTHER,
            sequence_id,
            control_field: CONTROL_DELAY_REQ,
            log_message_interval: LOG_INTERVAL_OTHER,
        },
    );

    out
}

fn build_signaling(sequence_id: u16, clock_identity: &[u8; 8]) -> Vec<u8> {
    let total_len = HEADER_LEN + PORT_IDENTITY_LEN + 26 + 36;
    let mut out = vec![0_u8; total_len];

    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_SIGNALING,
            message_len: total_len as u16,
            flags: FLAGS_OTHER,
            sequence_id,
            control_field: CONTROL_OTHER,
            log_message_interval: LOG_INTERVAL_SIGNALING,
        },
    );

    let body = &mut out[HEADER_LEN..];

    let tlv_1 = &mut body[PORT_IDENTITY_LEN..PORT_IDENTITY_LEN + 26];
    tlv_1[0..2].copy_from_slice(&TLV_ORG_EXTENSION.to_be_bytes());
    tlv_1[2..4].copy_from_slice(&22_u16.to_be_bytes());
    tlv_1[4..7].copy_from_slice(&ORG_APPLE);
    tlv_1[7..10].copy_from_slice(&[0x00, 0x00, 0x01]);
    tlv_1[10..14].copy_from_slice(&[0x00, 0x00, 0x03, 0x01]);

    let tlv_2_start = PORT_IDENTITY_LEN + 26;
    let tlv_2 = &mut body[tlv_2_start..tlv_2_start + 36];
    tlv_2[0..2].copy_from_slice(&TLV_ORG_EXTENSION.to_be_bytes());
    tlv_2[2..4].copy_from_slice(&32_u16.to_be_bytes());
    tlv_2[4..7].copy_from_slice(&ORG_APPLE);
    tlv_2[7..10].copy_from_slice(&[0x00, 0x00, 0x05]);
    tlv_2[10..14].copy_from_slice(&[0x00, 0x00, 0x03, 0x01]);

    out
}

#[allow(dead_code)]
fn build_delay_resp(
    sequence_id: u16,
    clock_identity: &[u8; 8],
    receive_timestamp: SystemTime,
    requesting_port_identity: &[u8; 10],
) -> Vec<u8> {
    let total_len = HEADER_LEN + TIMESTAMP_LEN + PORT_IDENTITY_LEN;
    let mut out = vec![0_u8; total_len];

    write_header(
        &mut out[..HEADER_LEN],
        clock_identity,
        HeaderFields {
            msg_type: MSG_DELAY_RESP,
            message_len: total_len as u16,
            flags: FLAGS_OTHER,
            sequence_id,
            control_field: CONTROL_DELAY_RESP,
            log_message_interval: LOG_INTERVAL_OTHER,
        },
    );
    write_timestamp(
        &mut out[HEADER_LEN..HEADER_LEN + TIMESTAMP_LEN],
        receive_timestamp,
    );
    out[HEADER_LEN + TIMESTAMP_LEN..HEADER_LEN + TIMESTAMP_LEN + PORT_IDENTITY_LEN]
        .copy_from_slice(requesting_port_identity);

    out
}

fn write_header(out: &mut [u8], clock_identity: &[u8; 8], fields: HeaderFields) {
    out[0] = PTP_TRANSPORT_SPECIFIC | (fields.msg_type & 0x0F);
    out[1] = PTP_VERSION;
    out[2..4].copy_from_slice(&fields.message_len.to_be_bytes());
    out[4] = PTP_DOMAIN;
    out[6..8].copy_from_slice(&fields.flags.to_be_bytes());
    out[20..28].copy_from_slice(clock_identity);
    out[28..30].copy_from_slice(&PTP_PORT_NUMBER.to_be_bytes());
    out[30..32].copy_from_slice(&fields.sequence_id.to_be_bytes());
    out[32] = fields.control_field;
    out[33] = fields.log_message_interval as u8;
}

#[allow(dead_code)]
fn write_timestamp(out: &mut [u8], value: SystemTime) {
    let duration = value.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = duration.as_secs();
    let nanos = duration.subsec_nanos();

    let seconds_high = (seconds >> 32) as u16;
    let seconds_low = seconds as u32;

    out[0..2].copy_from_slice(&seconds_high.to_be_bytes());
    out[2..6].copy_from_slice(&seconds_low.to_be_bytes());
    out[6..10].copy_from_slice(&nanos.to_be_bytes());
}

const TAI_UTC_OFFSET: u64 = 37;

#[allow(dead_code)]
fn system_time_now() -> SystemTime {
    SystemTime::now() + Duration::from_secs(TAI_UTC_OFFSET)
}
