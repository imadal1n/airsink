use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;

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

/// Sends AirPlay RTP sync packets (payload type `0xD7`) on the control socket.
///
/// Sync packets carry the PTP master clock timestamp alongside the current RTP
/// position so the receiver can maintain playout synchronisation. The first
/// packet uses sync type `0x90` (first-packet flag); subsequent packets use
/// `0x80`. Packets are sent once at stream start and every 125 RTP packets
/// thereafter (~1 second at 125 pkt/sec).
pub struct SyncSender {
    socket: UdpSocket,
    target: SocketAddr,
    clock_id: u64,
    ssrc: u32,
}

impl SyncSender {
    /// Constructs a sync sender that transmits on `socket` to `target`.
    ///
    /// `clock_id` is the 64-bit PTP clock identity advertised in every sync
    /// packet so the receiver can correlate timestamps with the PTP master.
    pub fn new(socket: UdpSocket, target: SocketAddr, clock_id: u64, ssrc: u32) -> Self {
        Self {
            socket,
            target,
            clock_id,
            ssrc,
        }
    }

    async fn send_sync(
        &self,
        sync_type: u8,
        cur_pos: u32,
        ptp_time_ns: u64,
        rtptime: u32,
        packet_count: u32,
        octet_count: u32,
        sender: &RtpSender,
        sent_packets: &VecDeque<RtpPacket>,
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

        let sr = build_rtcp_sr_packet(self.ssrc, rtptime, packet_count, octet_count);
        if let Err(err) = self.socket.send_to(&sr, self.target).await {
            tracing::debug!(error = %err, "failed to send RTCP sender report");
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(
            std::time::Duration::from_millis(5),
            self.socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, from))) => {
                self
                    .handle_control_packet(&buf[..n], from, sender, sent_packets)
                    .await;
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_control_packet(
        &self,
        packet: &[u8],
        from: SocketAddr,
        sender: &RtpSender,
        sent_packets: &VecDeque<RtpPacket>,
    ) {
        if packet.len() < 8 {
            return;
        }
        if packet[0] != 0x80 || packet[1] != 0xD5 {
            tracing::debug!(
                n = packet.len(),
                %from,
                header = %hex_str(&packet[..packet.len().min(8)]),
                "control socket received non-retransmit packet"
            );
            return;
        }

        let seq_start = u16::from_be_bytes([packet[4], packet[5]]);
        let seq_len = u16::from_be_bytes([packet[6], packet[7]]);
        tracing::warn!(seq_start, seq_len, %from, "received retransmit request");

        for i in 0..seq_len {
            let seq = seq_start.wrapping_add(i);
            if let Some(pkt) = sent_packets.iter().find(|pkt| pkt.seq == seq) {
                if let Err(err) = sender.send_cached(pkt).await {
                    tracing::debug!(seq, error = %err, "failed retransmitting packet");
                }
            }
        }
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
        let wire = serialize_rtp_packet(pkt);

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

    pub async fn send_cached(&self, pkt: &RtpPacket) -> Result<()> {
        self.send(pkt).await
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
        ssrc: u32,
        initial_seq: u16,
        initial_rtptime: u32,
        sync_sender: SyncSender,
        ptp_master: Arc<PtpMaster>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut seq = initial_seq;
        let mut encoder: Option<Box<dyn codec::AlacEncoder + Send>> = None;
        let mut sync_sent = false;
        let mut last_sync_seq = initial_seq;
        let mut packet_count: u32 = 0;
        let mut octet_count: u32 = 0;
        let mut sent_packets: VecDeque<RtpPacket> = VecDeque::with_capacity(1024);

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
                    let alac_plaintext = raop_alac_plaintext(&encoded.payload, FRAMES_PER_PACKET as u16);
                    let sealed = seal_audio_payload(&audio_key, seq, &header, &alac_plaintext)?;
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
                        let mut max_abs_sample: i32 = 0;
                        let mut sum_abs_sample: u64 = 0;
                        let mut sample_count: u64 = 0;
                        for frame in pcm.data.chunks_exact(2) {
                            let sample = i16::from_le_bytes([frame[0], frame[1]]) as i32;
                            let abs = sample.abs();
                            if abs > max_abs_sample {
                                max_abs_sample = abs;
                            }
                            sum_abs_sample = sum_abs_sample.saturating_add(abs as u64);
                            sample_count += 1;
                        }
                        let avg_abs_sample = if sample_count > 0 {
                            sum_abs_sample / sample_count
                        } else {
                            0
                        };
                        tracing::debug!(
                            seq,
                            pcm_bytes = pcm.data.len(),
                            non_zero_bytes = non_zero,
                            max_abs_sample,
                            avg_abs_sample,
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
                    packet_count = packet_count.wrapping_add(1);
                    octet_count = octet_count.wrapping_add(sealed_len as u32);

                    sender.send(&packet).await?;
                    sent_packets.push_back(packet.clone());
                    if sent_packets.len() > 1024 {
                        let _ = sent_packets.pop_front();
                    }

                    if !sync_sent {
                        let _ = sync_sender
                            .send_sync(
                                0x90,
                                cur_pos,
                                ptp_now,
                                encoded.rtp_timestamp,
                                packet_count,
                                octet_count,
                                &sender,
                                &sent_packets,
                            )
                            .await;
                        sync_sent = true;
                        last_sync_seq = seq;
                    } else if seq.wrapping_sub(last_sync_seq) >= 125 {
                        let _ = sync_sender
                            .send_sync(
                                0x80,
                                cur_pos,
                                ptp_now,
                                encoded.rtp_timestamp,
                                packet_count,
                                octet_count,
                                &sender,
                                &sent_packets,
                            )
                            .await;
                        last_sync_seq = seq;
                    }

                    seq = seq.wrapping_add(1);
                }
            }
        }
    }
}

fn build_rtcp_sr_packet(ssrc: u32, rtp_timestamp: u32, packet_count: u32, octet_count: u32) -> [u8; 28] {
    let mut data = [0u8; 28];
    data[0] = 0x80;
    data[1] = 200;
    data[2] = 0x00;
    data[3] = 0x06;
    data[4..8].copy_from_slice(&ssrc.to_be_bytes());

    let (ntp_secs, ntp_frac) = ntp_now();
    data[8..12].copy_from_slice(&ntp_secs.to_be_bytes());
    data[12..16].copy_from_slice(&ntp_frac.to_be_bytes());
    data[16..20].copy_from_slice(&rtp_timestamp.to_be_bytes());
    data[20..24].copy_from_slice(&packet_count.to_be_bytes());
    data[24..28].copy_from_slice(&octet_count.to_be_bytes());
    data
}

fn ntp_now() -> (u32, u32) {
    const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs().saturating_add(NTP_UNIX_EPOCH_DELTA);
    let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000u64;
    (secs as u32, frac as u32)
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

fn serialize_rtp_packet(pkt: &RtpPacket) -> BytesMut {
    let mut header = rtp_header_bytes(pkt.seq, pkt.timestamp, pkt.ssrc);
    if pkt.marker {
        header[1] |= 0x80;
    }
    let mut wire = BytesMut::with_capacity(RTP_HEADER_LEN + pkt.payload.len());
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&pkt.payload);
    wire
}

fn raop_alac_plaintext(alac_payload: &[u8], frames_per_packet: u16) -> Bytes {
    let mut plain = BytesMut::with_capacity(4 + alac_payload.len());
    plain.extend_from_slice(&[0x00, 0x00]);
    plain.extend_from_slice(&frames_per_packet.to_be_bytes());
    plain.extend_from_slice(alac_payload);
    plain.freeze()
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
