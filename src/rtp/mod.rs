use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::codec;
use crate::core::PcmChunk;
use crate::error::{Error, Result};
use crate::timing::ptp::PtpMaster;

const RTP_HEADER_LEN: usize = 12;
const FRAMES_PER_PACKET: u32 = 352;
const LATENCY_SAMPLES: u32 = 11_025;
#[allow(dead_code)]
const LATENCY_NS: u64 = 250_000_000;

#[derive(Debug, Clone)]
/// RTP packet payload and header fields before UDP transmission.
pub struct RtpPacket {
    /// RTP sequence number incremented per packet.
    pub seq: u16,
    /// RTP media timestamp for packet playout ordering.
    pub timestamp: u32,
    /// Synchronization source identifier for this sender session.
    pub ssrc: u32,
    /// RTP payload bytes, typically encrypted ALAC frame data.
    pub payload: Bytes,
    /// When true, sets the RTP marker bit (M) in the on-wire header.
    /// owntone sets this on the first audio packet to signal stream start.
    pub marker: bool,
}

#[derive(Debug)]
/// UDP sender for serialized RTP packets targeting one receiver endpoint.
pub struct RtpSender {
    socket: UdpSocket,
    target: SocketAddr,
}

fn build_sync_packet(
    sync_type: u8,
    cur_pos: u32,
    ptp_time_ns: u64,
    rtptime: u32,
    clock_id: u64,
) -> [u8; 28] {
    let mut data = [0u8; 28];
    data[0] = sync_type;
    data[1] = 0xd7;
    data[2] = 0x00;
    data[3] = 0x06;
    data[4..8].copy_from_slice(&cur_pos.to_be_bytes());
    data[8..16].copy_from_slice(&ptp_time_ns.to_be_bytes());
    data[16..20].copy_from_slice(&rtptime.to_be_bytes());
    data[20..28].copy_from_slice(&clock_id.to_be_bytes());
    data
}

pub struct SyncSender {
    socket: UdpSocket,
    target: SocketAddr,
    clock_id: u64,
}

impl SyncSender {
    pub fn new(socket: UdpSocket, target: SocketAddr, clock_id: u64) -> Self {
        Self {
            socket,
            target,
            clock_id,
        }
    }

    async fn send_sync(
        &self,
        sync_type: u8,
        cur_pos: u32,
        ptp_time_ns: u64,
        rtptime: u32,
    ) -> Result<()> {
        let packet = build_sync_packet(sync_type, cur_pos, ptp_time_ns, rtptime, self.clock_id);
        if sync_type == 0x90 {
            tracing::warn!(
                cur_pos,
                ptp_time_ns,
                rtptime,
                clock_id = self.clock_id,
                target = %self.target,
                sync_hex = %hex_str(&packet),
                "INITIAL SYNC packet dump"
            );
        }
        self.socket
            .send_to(&packet, self.target)
            .await
            .map_err(|err| Error::Network(format!("failed to send sync packet: {err}")))?;

        let mut buf = [0u8; 512];
        match tokio::time::timeout(
            std::time::Duration::from_millis(5),
            self.socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, from))) => {
                tracing::warn!(
                    n,
                    %from,
                    data_hex = %hex_str(&buf[..n.min(64)]),
                    "control socket received data from HomePod"
                );
            }
            _ => {}
        }
        Ok(())
    }
}

impl RtpSender {
    /// Creates a UDP sender bound to a compatible local address family.
    pub async fn new(
        device_addr: IpAddr,
        device_port: u16,
        bind_ip: Option<IpAddr>,
    ) -> Result<Self> {
        let bind_addr = SocketAddr::new(bind_ip.unwrap_or_else(|| unspecified_for(device_addr)), 0);
        let target = SocketAddr::new(device_addr, device_port);

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|err| Error::Network(format!("failed to bind RTP socket: {err}")))?;

        Ok(Self { socket, target })
    }

    /// Serializes and transmits one RTP packet to the configured target.
    pub async fn send(&self, pkt: &RtpPacket) -> Result<()> {
        let mut header = rtp_header_bytes(pkt.seq, pkt.timestamp, pkt.ssrc);
        if pkt.marker {
            header[1] |= 0x80;
        }
        let mut wire = BytesMut::with_capacity(RTP_HEADER_LEN + pkt.payload.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&pkt.payload);

        if pkt.marker {
            tracing::warn!(
                wire_len = wire.len(),
                target = %self.target,
                wire_header = %hex_str(&wire[..RTP_HEADER_LEN.min(wire.len())]),
                wire_first48 = %hex_str(&wire[..wire.len().min(48)]),
                "ON-WIRE first packet dump"
            );
        }

        let sent = self
            .socket
            .send_to(&wire, self.target)
            .await
            .map_err(|err| Error::Network(format!("failed to send RTP packet: {err}")))?;

        if sent != wire.len() {
            return Err(Error::Network(format!(
                "short RTP send: wrote {sent} bytes, expected {}",
                wire.len()
            )));
        }

        Ok(())
    }
}

/// End-to-end audio pipeline that encodes, seals, and sends RTP packets.
pub struct StreamPipeline;

impl StreamPipeline {
    /// Runs the streaming loop until stop is signaled or input is closed.
    ///
    /// The pipeline lazily initializes the ALAC encoder from the first PCM
    /// chunk, then performs encode -> encrypt -> RTP send for each packet.
    pub async fn run(
        mut pcm_rx: mpsc::Receiver<PcmChunk>,
        audio_key: Zeroizing<[u8; 32]>,
        sender: RtpSender,
        initial_seq: u16,
        initial_rtptime: u32,
        sync_sender: SyncSender,
        ptp_master: Arc<PtpMaster>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut seq = initial_seq;
        let ssrc = rand::random::<u32>();
        let mut encoder: Option<Box<dyn codec::AlacEncoder + Send>> = None;
        let mut sync_sent = false;
        let mut last_sync_seq = initial_seq;

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
                maybe_pcm = pcm_rx.recv() => {
                    let Some(pcm) = maybe_pcm else {
                        return Ok(());
                    };

                    if encoder.is_none() {
                        encoder = Some(codec::new_encoder(pcm.format, FRAMES_PER_PACKET, initial_rtptime)?);
                    }

                    let encoded = encoder
                        .as_mut()
                        .ok_or_else(|| Error::InvalidState("missing ALAC encoder instance".to_owned()))?
                        .encode(&pcm)?;

                    let header = rtp_header_bytes(seq, encoded.rtp_timestamp, ssrc);
                    let sealed = seal_audio_payload(&audio_key, seq, &header, &encoded.payload)?;
                    let sealed_len = sealed.len();
                    let encoded_len = encoded.payload.len();

                    if seq == initial_seq {
                        tracing::info!(
                            seq,
                            ssrc,
                            rtp_timestamp = encoded.rtp_timestamp,
                            alac_len = encoded.payload.len(),
                            sealed_len,
                            rtp_header_hex = %hex_str(&header),
                            key_prefix = %hex_str(&audio_key[..8]),
                            "FIRST PACKET diagnostics"
                        );
                    }

                    if seq % 500 == 0 {
                        let non_zero = pcm.data.iter().filter(|&&b| b != 0).count();
                        tracing::debug!(
                            seq,
                            pcm_bytes = pcm.data.len(),
                            non_zero_bytes = non_zero,
                            encoded_len,
                            sealed_len,
                            "rtp pipeline status"
                        );
                    }

                    let packet = RtpPacket {
                        seq,
                        timestamp: encoded.rtp_timestamp,
                        ssrc,
                        payload: sealed,
                        marker: seq == initial_seq,
                    };

                    let ptp_now = ptp_master.ptp_time_ns();
                    let cur_pos = encoded.rtp_timestamp.wrapping_sub(LATENCY_SAMPLES);
                    if !sync_sent {
                        let _ = sync_sender
                            .send_sync(0x90, cur_pos, ptp_now, encoded.rtp_timestamp)
                            .await;
                        sync_sent = true;
                        last_sync_seq = seq;
                    } else if seq.wrapping_sub(last_sync_seq) >= 125 {
                        let _ = sync_sender
                            .send_sync(0x80, cur_pos, ptp_now, encoded.rtp_timestamp)
                            .await;
                        last_sync_seq = seq;
                    }

                    sender.send(&packet).await?;

                    seq = seq.wrapping_add(1);
                }
            }
        }
    }
}

fn rtp_header_bytes(seq: u16, timestamp: u32, ssrc: u32) -> [u8; RTP_HEADER_LEN] {
    let mut header = [0_u8; RTP_HEADER_LEN];
    header[0] = 0x80;
    header[1] = 0x60;
    header[2..4].copy_from_slice(&seq.to_be_bytes());
    header[4..8].copy_from_slice(&timestamp.to_be_bytes());
    header[8..12].copy_from_slice(&ssrc.to_be_bytes());
    header
}

fn seal_audio_payload(
    key: &[u8; 32],
    seq: u16,
    rtp_header: &[u8; RTP_HEADER_LEN],
    plaintext: &[u8],
) -> Result<Bytes> {
    // owntone uses memcpy(&seqnum, 2) which copies in host byte order (LE on x86).
    // The receiver reconstructs from the appended nonce suffix, so we match owntone.
    let seq_le = seq.to_le_bytes();
    let mut nonce = [0u8; 12];
    nonce[4] = seq_le[0];
    nonce[5] = seq_le[1];

    // HomePod expects AAD to be exactly the 8 bytes of the RTP header from timestamp onwards
    let aad = &rtp_header[4..12];

    if seq % 500 == 0 || seq < 3 {
        tracing::debug!(
            seq,
            nonce_hex = %hex_str(&nonce),
            aad_hex = %hex_str(aad),
            plaintext_len = plaintext.len(),
            plaintext_first8 = %hex_str(&plaintext[..plaintext.len().min(8)]),
            "seal_audio_payload crypto inputs"
        );
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto("audio chacha20poly1305 seal failed".to_owned()))?;

    let mut out = BytesMut::with_capacity(sealed.len() + 8);
    out.extend_from_slice(&sealed);
    out.extend_from_slice(&nonce[4..]);
    Ok(out.freeze())
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

fn unspecified_for(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}
