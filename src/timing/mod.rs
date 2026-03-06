pub mod ptp;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::watch;
use tracing::debug;

use crate::error::{Error, Result};

/// AirPlay timing request payload type (without marker bit).
const TIMING_REQUEST_PT: u8 = 0x52;
/// AirPlay timing response payload type with RTP marker bit set.
const TIMING_RESPONSE_PT_MARKER: u8 = 0xD3;
/// RTP version 2 protocol byte.
const RTP_PROTO: u8 = 0x80;
const TIMING_PACKET_LEN: usize = 32;
const NTP_UNIX_EPOCH_DELTA_SECS: u64 = 2_208_988_800;

#[derive(Debug)]
/// UDP timing responder for the AirPlay NTP-like synchronization protocol.
pub struct TimingServer {
    socket: UdpSocket,
}

impl TimingServer {
    /// Binds a timing socket and returns the server plus actual bound port.
    pub async fn start(bind_port: u16) -> Result<(Self, u16)> {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind_port);
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|err| Error::Network(format!("failed to bind timing socket: {err}")))?;
        let port = socket
            .local_addr()
            .map_err(|err| Error::Network(format!("failed to read timing socket address: {err}")))?
            .port();

        Ok((Self { socket }, port))
    }

    /// Runs the timing responder loop until a stop signal is received.
    pub async fn run(&self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut buf = [0_u8; 1500];

        loop {
            if *stop.borrow() {
                return Ok(());
            }

            select! {
                changed = stop.changed() => {
                    match changed {
                        Ok(()) => {
                            if *stop.borrow() {
                                return Ok(());
                            }
                        }
                        Err(_) => return Ok(()),
                    }
                }
                recv = self.socket.recv_from(&mut buf) => {
                    let (len, peer) = recv
                        .map_err(|err| Error::Network(format!("timing recv failed: {err}")))?;

                    if len < TIMING_PACKET_LEN {
                        debug!(len, %peer, "timing: short packet, ignoring");
                        continue;
                    }

                    let payload_type = buf[1] & 0x7F;
                    if payload_type != TIMING_REQUEST_PT {
                        debug!(byte0 = buf[0], byte1 = buf[1], %peer, "timing: not a request, ignoring");
                        continue;
                    }

                    let receive_ts = ntp_now();
                    let mut response = [0_u8; TIMING_PACKET_LEN];
                    response[0] = RTP_PROTO;
                    response[1] = TIMING_RESPONSE_PT_MARKER;
                    response[2] = 0;
                    response[3] = 7;
                    response[8..16].copy_from_slice(&buf[24..32]);
                    response[16..24].copy_from_slice(&receive_ts.to_be_bytes());
                    let transmit_ts = ntp_now();
                    response[24..32].copy_from_slice(&transmit_ts.to_be_bytes());

                    debug!(%peer, "timing: responded to request");

                    self.socket
                        .send_to(&response, peer)
                        .await
                        .map_err(|err| Error::Network(format!("timing send failed: {err}")))?;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
/// Smoothed estimate of sender/receiver clock offset and network RTT.
pub struct ClockModel {
    offset_ns: f64,
    round_trip_ns: f64,
    samples: u32,
}

impl ClockModel {
    /// Creates an empty clock model with no timing samples.
    pub fn new() -> Self {
        Self::default()
    }

    /// Incorporates one four-timestamp timing exchange into the model.
    ///
    /// The update uses classic NTP offset/round-trip formulas and applies an
    /// exponential moving average after the first sample.
    pub fn update(
        &mut self,
        client_send_ntp: u64,
        server_receive_ntp: u64,
        server_transmit_ntp: u64,
        client_receive_ntp: u64,
    ) {
        let t0 = ntp_to_unix_ns(client_send_ntp) as i128;
        let t1 = ntp_to_unix_ns(server_receive_ntp) as i128;
        let t2 = ntp_to_unix_ns(server_transmit_ntp) as i128;
        let t3 = ntp_to_unix_ns(client_receive_ntp) as i128;

        let offset = ((t1 - t0) + (t2 - t3)) as f64 / 2.0;
        let round_trip = ((t3 - t0) - (t2 - t1)) as f64;

        if self.samples == 0 {
            self.offset_ns = offset;
            self.round_trip_ns = round_trip;
        } else {
            let weight = 0.125;
            self.offset_ns = self.offset_ns * (1.0 - weight) + offset * weight;
            self.round_trip_ns = self.round_trip_ns * (1.0 - weight) + round_trip * weight;
        }

        self.samples = self.samples.saturating_add(1);
    }

    /// Returns the current clock offset estimate in nanoseconds.
    pub fn offset_ns(&self) -> i64 {
        self.offset_ns.round() as i64
    }

    /// Returns the estimated network round-trip time in nanoseconds.
    pub fn round_trip_ns(&self) -> i64 {
        self.round_trip_ns.max(0.0).round() as i64
    }
}

fn ntp_now() -> u64 {
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let seconds = since_unix
        .as_secs()
        .saturating_add(NTP_UNIX_EPOCH_DELTA_SECS);
    let nanos = u64::from(since_unix.subsec_nanos());
    let fraction = ((u128::from(nanos) << 32) / 1_000_000_000_u128) as u32;

    (seconds << 32) | u64::from(fraction)
}

fn ntp_to_unix_ns(timestamp: u64) -> u64 {
    let seconds = timestamp >> 32;
    let fraction = timestamp as u32;

    let unix_seconds = seconds.saturating_sub(NTP_UNIX_EPOCH_DELTA_SECS);
    let nanos = ((u128::from(fraction) * 1_000_000_000_u128) >> 32) as u64;

    unix_seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanos)
}
