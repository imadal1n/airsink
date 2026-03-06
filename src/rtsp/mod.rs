use std::io::Cursor;

use bytes::{Buf, Bytes, BytesMut};
use plist::{Dictionary, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::core::Device;
use crate::crypto::{AeadContext, NonceStrategy, SessionKeys};
use crate::error::{Error, Result};

const USER_AGENT: &str = "AirPlay/770.8.1";
const APPLE_PROTOCOL_VERSION: &str = "1";
const ENCRYPTED_BLOCK_MAX_LEN: usize = 1024;
const POLY1305_TAG_LEN: usize = 16;

#[derive(Debug, Clone)]
/// Outbound audio stream parameters sent in the RTSP `setup` plist body.
pub struct AudioStreamConfig {
    /// AirPlay stream type bitfield describing media and transport mode.
    pub stream_type: u32,
    /// Receiver-specific audio format code for ALAC negotiation.
    pub audio_format: u32,
    /// Compression type identifier expected by the receiver.
    pub ct: u32,
    /// Number of PCM frames carried per encoded packet.
    pub spf: u32,
    /// Audio sample rate in Hertz.
    pub sr: u32,
    /// Session key bytes used by the receiver for payload decryption.
    pub shk: Vec<u8>,
    /// Local UDP control port advertised to the receiver.
    pub control_port: u16,
    /// Minimum target stream latency in milliseconds.
    pub latency_min: u32,
    /// Maximum target stream latency in milliseconds.
    pub latency_max: u32,
    /// Unique identifier used to bind stream-related RTSP messages.
    pub stream_connection_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Receiver-assigned UDP ports returned after audio setup negotiation.
pub struct AudioStreamPorts {
    /// UDP port used for RTP audio packets.
    pub data_port: u16,
    /// UDP port used for control and retransmission traffic.
    pub control_port: u16,
    /// Optional UDP event port when advertised by the receiver.
    pub event_port: Option<u16>,
}

#[derive(Debug)]
struct RtspResponse {
    code: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Bytes,
}

#[derive(Debug)]
/// Stateful RTSP client for AirPlay session setup and control requests.
pub struct RtspClient {
    stream: TcpStream,
    device: Device,
    cseq: u32,
    session_keys: Option<SessionKeys>,
    write_counter: u64,
    read_counter: u64,
    read_buffer: BytesMut,
    session_header: Option<String>,
}

impl RtspClient {
    /// Connects to a receiver RTSP endpoint and initializes client state.
    pub async fn connect(device: &Device) -> Result<Self> {
        let stream = TcpStream::connect((device.host, device.port_rtsp))
            .await
            .map_err(|err| Error::Network(format!("rtsp connect failed: {err}")))?;

        Ok(Self {
            stream,
            device: device.clone(),
            cseq: 0,
            session_keys: None,
            write_counter: 0,
            read_counter: 0,
            read_buffer: BytesMut::new(),
            session_header: None,
        })
    }

    /// Enables encrypted RTSP framing using verified session keys.
    pub fn set_encryption(&mut self, keys: SessionKeys) {
        self.session_keys = Some(keys);
        self.write_counter = 0;
        self.read_counter = 0;
    }

    /// Requests `/info` and decodes the response body as a plist dictionary.
    pub async fn get_info(&mut self) -> Result<Dictionary> {
        let response = self
            .request("GET", "info", Vec::new(), None, Bytes::new())
            .await?;
        parse_plist_dictionary(&response.body)
    }

    /// Creates an RTSP session and announces timing metadata to the receiver.
    pub async fn setup_session(
        &mut self,
        session_uuid: &str,
        timing_port: u16,
    ) -> Result<Dictionary> {
        let mut body = Dictionary::new();
        body.insert(
            "deviceID".to_owned(),
            Value::String(self.device.id.0.clone()),
        );
        body.insert(
            "sessionUUID".to_owned(),
            Value::String(session_uuid.to_owned()),
        );
        body.insert("timingPort".to_owned(), Value::from(timing_port as u64));
        body.insert("timingProtocol".to_owned(), Value::String("NTP".to_owned()));
        body.insert(
            "macAddress".to_owned(),
            Value::String("00:00:00:00:00:00".to_owned()),
        );
        body.insert("model".to_owned(), Value::String("AirSink1,1".to_owned()));
        body.insert("name".to_owned(), Value::String("airsink".to_owned()));
        body.insert("osName".to_owned(), Value::String("Linux".to_owned()));
        body.insert("osVersion".to_owned(), Value::String("1.0".to_owned()));
        body.insert(
            "sourceVersion".to_owned(),
            Value::String("366.0".to_owned()),
        );

        let response = self
            .request(
                "POST",
                "setup",
                Vec::new(),
                Some("application/x-apple-binary-plist"),
                plist_to_binary(&body)?,
            )
            .await?;

        parse_plist_dictionary(&response.body)
    }

    /// Negotiates one audio stream and returns receiver-assigned transport ports.
    pub async fn setup_audio_stream(
        &mut self,
        stream_config: &AudioStreamConfig,
    ) -> Result<AudioStreamPorts> {
        let mut stream_dict = Dictionary::new();
        stream_dict.insert(
            "type".to_owned(),
            Value::from(stream_config.stream_type as u64),
        );
        stream_dict.insert(
            "audioFormat".to_owned(),
            Value::from(stream_config.audio_format as u64),
        );
        stream_dict.insert("ct".to_owned(), Value::from(stream_config.ct as u64));
        stream_dict.insert("spf".to_owned(), Value::from(stream_config.spf as u64));
        stream_dict.insert("sr".to_owned(), Value::from(stream_config.sr as u64));
        stream_dict.insert("shk".to_owned(), Value::Data(stream_config.shk.clone()));
        stream_dict.insert(
            "controlPort".to_owned(),
            Value::from(stream_config.control_port as u64),
        );
        stream_dict.insert(
            "latencyMin".to_owned(),
            Value::from(stream_config.latency_min as u64),
        );
        stream_dict.insert(
            "latencyMax".to_owned(),
            Value::from(stream_config.latency_max as u64),
        );
        stream_dict.insert(
            "streamConnectionID".to_owned(),
            Value::from(stream_config.stream_connection_id),
        );

        let mut body = Dictionary::new();
        body.insert(
            "streams".to_owned(),
            Value::Array(vec![Value::Dictionary(stream_dict)]),
        );

        let response = self
            .request(
                "POST",
                "setup",
                Vec::new(),
                Some("application/x-apple-binary-plist"),
                plist_to_binary(&body)?,
            )
            .await?;

        let response_dict = parse_plist_dictionary(&response.body)?;
        extract_stream_ports(&response_dict)
    }

    /// Sends `RECORD` to start RTP playout from the provided sequence and time.
    pub async fn record(&mut self, seq: u16, rtptime: u32) -> Result<()> {
        self.request(
            "RECORD",
            "",
            vec![(
                "RTP-Info".to_owned(),
                format!("seq={seq};rtptime={rtptime}"),
            )],
            None,
            Bytes::new(),
        )
        .await?;
        Ok(())
    }

    /// Sends `SET_PARAMETER` with the current playback volume in decibels.
    pub async fn set_volume(&mut self, volume_db: f64) -> Result<()> {
        let body = Bytes::from(format!("volume: {volume_db}\r\n"));
        self.request(
            "SET_PARAMETER",
            "",
            Vec::new(),
            Some("text/parameters"),
            body,
        )
        .await?;
        Ok(())
    }

    /// Sends `FLUSH` to drop queued audio before the provided RTP position.
    pub async fn flush(&mut self, seq: u16, rtptime: u32) -> Result<()> {
        self.request(
            "FLUSH",
            "",
            vec![(
                "RTP-Info".to_owned(),
                format!("seq={seq};rtptime={rtptime}"),
            )],
            None,
            Bytes::new(),
        )
        .await?;
        Ok(())
    }

    /// Sends `TEARDOWN` to close the active receiver session.
    pub async fn teardown(&mut self) -> Result<()> {
        self.request("TEARDOWN", "", Vec::new(), None, Bytes::new())
            .await?;
        Ok(())
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        mut extra_headers: Vec<(String, String)>,
        content_type: Option<&str>,
        body: Bytes,
    ) -> Result<RtspResponse> {
        let cseq = self.next_cseq();
        let normalized_path = if path.is_empty() { "/" } else { path };

        let mut request = String::new();
        request.push_str(method);
        request.push(' ');
        request.push('/');
        request.push_str(normalized_path.trim_start_matches('/'));
        request.push_str(" RTSP/1.0\r\n");
        request.push_str(&format!("CSeq: {cseq}\r\n"));
        request.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
        request.push_str(&format!(
            "X-Apple-ProtocolVersion: {APPLE_PROTOCOL_VERSION}\r\n"
        ));

        if let Some(session_header) = &self.session_header {
            request.push_str(&format!("Session: {session_header}\r\n"));
        }

        if body.is_empty() {
            if let Some(ct) = content_type {
                request.push_str(&format!("Content-Type: {ct}\r\n"));
            }
        } else {
            let ct = content_type.unwrap_or("application/x-apple-binary-plist");
            request.push_str(&format!("Content-Type: {ct}\r\n"));
        }

        for (name, value) in extra_headers.drain(..) {
            request.push_str(&name);
            request.push_str(": ");
            request.push_str(&value);
            request.push_str("\r\n");
        }

        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("\r\n");

        let mut wire = request.into_bytes();
        wire.extend_from_slice(&body);

        self.write_message(&wire).await?;

        let response = self.read_response().await?;
        if let Some(session_header) = find_header_value(&response.headers, "Session") {
            self.session_header = Some(session_header.to_owned());
        }

        if !(200..300).contains(&response.code) {
            let body_summary = match std::str::from_utf8(response.body.as_ref()) {
                Ok(text) if !text.trim().is_empty() => format!(", body={}", text.trim()),
                _ => String::new(),
            };

            return Err(Error::Rtsp(format!(
                "{method} /{} failed: {} {}{}",
                normalized_path.trim_start_matches('/'),
                response.code,
                response.reason,
                body_summary
            )));
        }

        Ok(response)
    }

    fn next_cseq(&mut self) -> u32 {
        self.cseq = self.cseq.wrapping_add(1);
        self.cseq
    }

    async fn write_message(&mut self, message: &[u8]) -> Result<()> {
        if self.session_keys.is_none() {
            self.stream
                .write_all(message)
                .await
                .map_err(|err| Error::Network(format!("rtsp write failed: {err}")))?;
            return Ok(());
        }

        let keys = self
            .session_keys
            .as_ref()
            .ok_or_else(|| Error::Rtsp("missing RTSP encryption keys".to_owned()))?;

        for chunk in message.chunks(ENCRYPTED_BLOCK_MAX_LEN) {
            let len_u16 = u16::try_from(chunk.len())
                .map_err(|_| Error::Rtsp("encrypted RTSP block exceeds u16 length".to_owned()))?;
            let aad = len_u16.to_be_bytes();

            let sealed = seal_rtsp_block(&keys.rtsp, self.write_counter, &aad, chunk)?;
            if sealed.len() < POLY1305_TAG_LEN {
                return Err(Error::Rtsp(
                    "encrypted RTSP block shorter than authentication tag".to_owned(),
                ));
            }

            let split_at = sealed.len() - POLY1305_TAG_LEN;
            let (ciphertext, tag) = sealed.split_at(split_at);

            self.stream
                .write_all(&aad)
                .await
                .map_err(|err| Error::Network(format!("rtsp encrypted write failed: {err}")))?;
            self.stream
                .write_all(ciphertext)
                .await
                .map_err(|err| Error::Network(format!("rtsp encrypted write failed: {err}")))?;
            self.stream
                .write_all(tag)
                .await
                .map_err(|err| Error::Network(format!("rtsp encrypted write failed: {err}")))?;

            self.write_counter = self.write_counter.wrapping_add(1);
        }

        Ok(())
    }

    async fn read_response(&mut self) -> Result<RtspResponse> {
        loop {
            if let Some(response) = try_parse_response(&mut self.read_buffer)? {
                return Ok(response);
            }

            if self.session_keys.is_some() {
                let mut len_buf = [0_u8; 2];
                self.stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|err| Error::Network(format!("rtsp encrypted read failed: {err}")))?;
                let block_len = u16::from_be_bytes(len_buf) as usize;

                let mut block_buf = vec![0_u8; block_len + POLY1305_TAG_LEN];
                self.stream
                    .read_exact(&mut block_buf)
                    .await
                    .map_err(|err| Error::Network(format!("rtsp encrypted read failed: {err}")))?;

                let keys = self
                    .session_keys
                    .as_ref()
                    .ok_or_else(|| Error::Rtsp("missing RTSP encryption keys".to_owned()))?;
                let decrypted =
                    open_rtsp_block(&keys.rtsp, self.read_counter, &len_buf, &block_buf)?;
                self.read_counter = self.read_counter.wrapping_add(1);
                self.read_buffer.extend_from_slice(&decrypted);
            } else {
                let mut chunk = [0_u8; 4096];
                let bytes_read = self
                    .stream
                    .read(&mut chunk)
                    .await
                    .map_err(|err| Error::Network(format!("rtsp read failed: {err}")))?;
                if bytes_read == 0 {
                    return Err(Error::Network("rtsp socket closed by peer".to_owned()));
                }
                self.read_buffer.extend_from_slice(&chunk[..bytes_read]);
            }
        }
    }
}

fn seal_rtsp_block(ctx: &AeadContext, counter: u64, aad: &[u8], plaintext: &[u8]) -> Result<Bytes> {
    let low = (counter as u32).to_le_bytes();
    let high = (counter >> 32) as u32;
    let fixed = [0_u8, 0_u8, 0_u8, 0_u8, low[0], low[1], low[2], low[3]];
    let block_ctx = AeadContext::new(*ctx.key, NonceStrategy::Counter32 { fixed });
    block_ctx.seal(high, aad, plaintext)
}

fn open_rtsp_block(
    ctx: &AeadContext,
    counter: u64,
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Bytes> {
    let low = (counter as u32).to_le_bytes();
    let high = (counter >> 32) as u32;
    let fixed = [0_u8, 0_u8, 0_u8, 0_u8, low[0], low[1], low[2], low[3]];
    let block_ctx = AeadContext::new(*ctx.key, NonceStrategy::Counter32 { fixed });
    block_ctx.open(high, aad, ciphertext_with_tag)
}

fn parse_plist_dictionary(bytes: &[u8]) -> Result<Dictionary> {
    let value = Value::from_reader(Cursor::new(bytes))
        .map_err(|err| Error::Rtsp(format!("failed to parse plist response: {err}")))?;
    match value {
        Value::Dictionary(dict) => Ok(dict),
        _ => Err(Error::Rtsp(
            "plist response body is not a dictionary".to_owned(),
        )),
    }
}

fn plist_to_binary(dict: &Dictionary) -> Result<Bytes> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &Value::Dictionary(dict.clone()))
        .map_err(|err| Error::Rtsp(format!("failed to encode plist body: {err}")))?;
    Ok(Bytes::from(out))
}

fn find_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn extract_stream_ports(dict: &Dictionary) -> Result<AudioStreamPorts> {
    let stream_dict = dict
        .get("streams")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_dictionary)
        .ok_or_else(|| Error::Rtsp("setup response missing streams[0] dictionary".to_owned()))?;

    let data_port = get_required_u16(stream_dict, &["dataPort", "serverPort", "port"])?;
    let control_port = get_required_u16(stream_dict, &["controlPort"])?;
    let event_port = get_optional_u16(stream_dict, &["eventPort"])?;

    Ok(AudioStreamPorts {
        data_port,
        control_port,
        event_port,
    })
}

fn get_required_u16(dict: &Dictionary, keys: &[&str]) -> Result<u16> {
    get_optional_u16(dict, keys)?.ok_or_else(|| {
        Error::Rtsp(format!(
            "setup response missing required numeric key(s): {}",
            keys.join(", ")
        ))
    })
}

fn get_optional_u16(dict: &Dictionary, keys: &[&str]) -> Result<Option<u16>> {
    for key in keys {
        if let Some(value) = dict.get(key) {
            if let Some(unsigned) = value.as_unsigned_integer() {
                let converted = u16::try_from(unsigned).map_err(|_| {
                    Error::Rtsp(format!("plist key '{key}' out of u16 range: {unsigned}"))
                })?;
                return Ok(Some(converted));
            }

            if let Some(signed) = value.as_signed_integer() {
                let converted = u16::try_from(signed).map_err(|_| {
                    Error::Rtsp(format!("plist key '{key}' out of u16 range: {signed}"))
                })?;
                return Ok(Some(converted));
            }

            return Err(Error::Rtsp(format!("plist key '{key}' is not an integer")));
        }
    }

    Ok(None)
}

fn try_parse_response(buffer: &mut BytesMut) -> Result<Option<RtspResponse>> {
    let mut header_end = None;
    for idx in 0..buffer.len().saturating_sub(3) {
        if &buffer[idx..idx + 4] == b"\r\n\r\n" {
            header_end = Some(idx + 4);
            break;
        }
    }

    let Some(header_end) = header_end else {
        return Ok(None);
    };

    let header_text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|err| Error::Rtsp(format!("invalid RTSP header encoding: {err}")))?;

    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Rtsp("missing RTSP status line".to_owned()))?;
    let (code, reason) = parse_status_line(status_line)?;

    let mut headers = Vec::new();
    let mut content_length = 0_usize;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::Rtsp(format!("malformed RTSP header line: '{line}'")))?;
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();

        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.parse::<usize>().map_err(|err| {
                Error::Rtsp(format!("invalid Content-Length header '{value}': {err}"))
            })?;
        }

        headers.push((name, value));
    }

    if buffer.len() < header_end + content_length {
        return Ok(None);
    }

    let body = Bytes::copy_from_slice(&buffer[header_end..header_end + content_length]);
    buffer.advance(header_end + content_length);

    Ok(Some(RtspResponse {
        code,
        reason,
        headers,
        body,
    }))
}

fn parse_status_line(status_line: &str) -> Result<(u16, String)> {
    let mut parts = status_line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| Error::Rtsp("invalid RTSP status line".to_owned()))?;
    if version != "RTSP/1.0" {
        return Err(Error::Rtsp(format!(
            "unsupported RTSP version in status line: {status_line}"
        )));
    }

    let code_str = parts
        .next()
        .ok_or_else(|| Error::Rtsp("RTSP status code missing".to_owned()))?;
    let code = code_str
        .parse::<u16>()
        .map_err(|err| Error::Rtsp(format!("invalid RTSP status code '{code_str}': {err}")))?;
    let reason = parts.next().unwrap_or_default().trim().to_owned();

    Ok((code, reason))
}
