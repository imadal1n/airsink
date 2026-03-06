use bytes::Bytes;

use crate::core::{EncodedFrame, PcmChunk, PcmFormat, SampleFormat};
use crate::error::{Error, Result};

const STREAM_RATE_HZ: u32 = 44_100;
const STREAM_CHANNELS: u16 = 2;
const STREAM_FRAMES_PER_PACKET: u32 = 352;

/// Encodes PCM chunks into ALAC frames ready for RTP transport.
pub trait AlacEncoder {
    /// Encodes one PCM chunk and returns the payload plus RTP timestamp.
    fn encode(&mut self, pcm: &PcmChunk) -> Result<EncodedFrame>;
}

/// `alac-encoder` crate-backed ALAC encoder implementation.
///
/// This concrete type is exposed so higher layers can use a stable public API
/// while keeping the default implementation swappable.
pub struct CrateAlacEncoder {
    inner: alac_encoder::AlacEncoder,
    input_format: alac_encoder::FormatDescription,
    scratch: Vec<u8>,
    next_rtp_timestamp: u32,
    frames_per_packet: u32,
}

impl AlacEncoder for CrateAlacEncoder {
    fn encode(&mut self, pcm: &PcmChunk) -> Result<EncodedFrame> {
        validate_stream_format(pcm.format)?;
        if pcm.frames > self.frames_per_packet {
            return Err(Error::Codec(format!(
                "pcm chunk has {} frames, max supported is {}",
                pcm.frames, self.frames_per_packet
            )));
        }

        let expected_bytes = usize::try_from(pcm.frames)
            .map_err(|_| Error::Codec("pcm frame count does not fit usize".to_owned()))?
            .saturating_mul(usize::from(STREAM_CHANNELS))
            .saturating_mul(2);
        if pcm.data.len() != expected_bytes {
            return Err(Error::Codec(format!(
                "pcm byte size mismatch: expected {expected_bytes}, got {}",
                pcm.data.len()
            )));
        }

        let encoded_size = self
            .inner
            .encode(&self.input_format, &pcm.data, &mut self.scratch);
        let payload = Bytes::copy_from_slice(&self.scratch[..encoded_size]);

        let rtp_timestamp = self.next_rtp_timestamp;
        self.next_rtp_timestamp = self
            .next_rtp_timestamp
            .wrapping_add(STREAM_FRAMES_PER_PACKET);

        Ok(EncodedFrame {
            rtp_timestamp,
            payload,
        })
    }
}

/// Builds an ALAC encoder configured for the AirPlay streaming profile.
///
/// The profile is fixed to 44.1 kHz, stereo, S16LE, and 352 frames per packet
/// to match HomePod-compatible AirPlay expectations.
pub fn new_encoder(
    format: PcmFormat,
    frames_per_packet: u32,
) -> Result<Box<dyn AlacEncoder + Send>> {
    validate_stream_format(format)?;

    if frames_per_packet != STREAM_FRAMES_PER_PACKET {
        return Err(Error::Codec(format!(
            "unsupported frames_per_packet {frames_per_packet}; expected {STREAM_FRAMES_PER_PACKET}"
        )));
    }

    let input_format =
        alac_encoder::FormatDescription::pcm::<i16>(STREAM_RATE_HZ as f64, STREAM_CHANNELS as u32);
    let output_format = alac_encoder::FormatDescription::alac(
        STREAM_RATE_HZ as f64,
        STREAM_FRAMES_PER_PACKET,
        STREAM_CHANNELS as u32,
    );
    let scratch = vec![0_u8; output_format.max_packet_size()];

    Ok(Box::new(CrateAlacEncoder {
        inner: alac_encoder::AlacEncoder::new(&output_format),
        input_format,
        scratch,
        next_rtp_timestamp: 0,
        frames_per_packet: STREAM_FRAMES_PER_PACKET,
    }))
}

fn validate_stream_format(format: PcmFormat) -> Result<()> {
    if format.rate_hz != STREAM_RATE_HZ {
        return Err(Error::Codec(format!(
            "unsupported sample rate {}; expected {}",
            format.rate_hz, STREAM_RATE_HZ
        )));
    }
    if format.channels != STREAM_CHANNELS {
        return Err(Error::Codec(format!(
            "unsupported channel count {}; expected {}",
            format.channels, STREAM_CHANNELS
        )));
    }
    if format.sample != SampleFormat::S16LE {
        return Err(Error::Codec(
            "unsupported sample format; expected S16LE".to_owned(),
        ));
    }

    Ok(())
}
