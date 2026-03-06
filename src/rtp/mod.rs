use std::net::{IpAddr, SocketAddr};

use bytes::{Bytes, BytesMut};
use rand::random;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, watch};

use crate::codec;
use crate::core::PcmChunk;
use crate::crypto::{AeadContext, NonceStrategy};
use crate::error::{Error, Result};

const RTP_HEADER_LEN: usize = 12;
const FRAMES_PER_PACKET: u32 = 352;

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
}

#[derive(Debug)]
/// UDP sender for serialized RTP packets targeting one receiver endpoint.
pub struct RtpSender {
    socket: UdpSocket,
    target: SocketAddr,
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
        let header = rtp_header_bytes(pkt.seq, pkt.timestamp, pkt.ssrc);
        let mut wire = BytesMut::with_capacity(RTP_HEADER_LEN + pkt.payload.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&pkt.payload);

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
        audio_ctx: AeadContext,
        sender: RtpSender,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut seq = random::<u16>();
        let ssrc = random::<u32>();
        let mut packet_counter = 0_u64;
        let mut encoder: Option<Box<dyn codec::AlacEncoder + Send>> = None;

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
                        encoder = Some(codec::new_encoder(pcm.format, FRAMES_PER_PACKET)?);
                    }

                    let encoded = encoder
                        .as_mut()
                        .ok_or_else(|| Error::InvalidState("missing ALAC encoder instance".to_owned()))?
                        .encode(&pcm)?;

                    let aad = rtp_header_bytes(seq, encoded.rtp_timestamp, ssrc);
                    let sealed = seal_audio_payload(&audio_ctx, packet_counter, &aad, &encoded.payload)?;

                    let packet = RtpPacket {
                        seq,
                        timestamp: encoded.rtp_timestamp,
                        ssrc,
                        payload: sealed,
                    };

                    sender.send(&packet).await?;

                    seq = seq.wrapping_add(1);
                    packet_counter = packet_counter.wrapping_add(1);
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
    ctx: &AeadContext,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Bytes> {
    let low = (counter as u32).to_le_bytes();
    let high = (counter >> 32) as u32;
    let fixed = [0_u8, 0_u8, 0_u8, 0_u8, low[0], low[1], low[2], low[3]];
    let packet_ctx = AeadContext::new(*ctx.key, NonceStrategy::Counter32 { fixed });
    packet_ctx.seal(high, aad, plaintext)
}

fn unspecified_for(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}
