use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha512;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use crate::config::PairingCredentials;
use crate::core::Device;
use crate::crypto::{AeadContext, NonceStrategy, SessionKeys};
use crate::error::{Error, Result};

pub mod srp;
pub mod tlv;

use srp::SrpClient;
use tlv::TlvTag;

/// Stateful HAP transport client used for pairing and session key setup.
///
/// This client owns a persistent TCP connection to the receiver so the full
/// Pair-Setup and Pair-Verify exchanges can be executed as ordered TLV steps.
pub struct HapClient {
    stream: TcpStream,
    host_header: String,
    read_buffer: Vec<u8>,
}

impl HapClient {
    /// Consumes this client and returns the underlying TCP stream and buffered data.
    ///
    /// After pairing completes, the same TCP connection must be reused for
    /// encrypted RTSP communication. Call this to hand the stream off to
    /// [`RtspClient::from_parts`].
    pub fn into_parts(self) -> (TcpStream, Vec<u8>) {
        (self.stream, self.read_buffer)
    }

    /// Opens a TCP connection to the receiver's RTSP/HAP endpoint.
    ///
    /// A single connection is reused across handshake requests to match the
    /// expected flow of Apple pairing exchanges.
    pub async fn connect(device: &Device) -> Result<Self> {
        let stream = TcpStream::connect((device.host, device.port_rtsp))
            .await
            .map_err(|err| Error::Network(format!("hap connect failed: {err}")))?;
        let host_header = if device.host.is_ipv6() {
            format!("[{}]:{}", device.host, device.port_rtsp)
        } else {
            format!("{}:{}", device.host, device.port_rtsp)
        };
        Ok(Self {
            stream,
            host_header,
            read_buffer: Vec::new(),
        })
    }

    /// Executes the HAP Pair-Setup flow and returns persisted credentials.
    ///
    /// This performs SRP authentication, exchanges signed long-term Ed25519
    /// identities, and verifies accessory authenticity before returning keys.
    pub async fn pair_setup(&mut self, pin: &str) -> Result<PairingCredentials> {
        let method = [0_u8];
        let state_1 = [1_u8];
        let m1_body = tlv::encode(&[(TlvTag::Method, &method), (TlvTag::State, &state_1)]);
        let m2 = self.post_tlv("/pair-setup", &m1_body, Some(2)).await?;

        let salt = required_tlv(&m2, TlvTag::Salt)?;
        let server_pubkey_b = required_tlv(&m2, TlvTag::PublicKey)?;

        let mut srp = SrpClient::new(b"Pair-Setup", pin.as_bytes());
        let (public_a, _) = srp.start_auth();
        let (proof_m1, session_key) = srp.process_challenge(salt, server_pubkey_b)?;

        let state_3 = [3_u8];
        let m3_body = tlv::encode(&[
            (TlvTag::State, &state_3),
            (TlvTag::PublicKey, &public_a),
            (TlvTag::Proof, &proof_m1),
        ]);
        let m4 = self.post_tlv("/pair-setup", &m3_body, Some(4)).await?;
        let server_proof = required_tlv(&m4, TlvTag::Proof)?;
        srp.verify_server(server_proof)?;

        let mut rng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let pairing_id = random_pairing_id(&mut rng);

        let setup_encrypt_key = hkdf_expand_32(
            b"Pair-Setup-Encrypt-Salt",
            &session_key,
            b"Pair-Setup-Encrypt-Info",
        )?;
        let controller_x = hkdf_expand_32(
            b"Pair-Setup-Controller-Sign-Salt",
            &session_key,
            b"Pair-Setup-Controller-Sign-Info",
        )?;

        let mut controller_info = Vec::with_capacity(32 + pairing_id.len() + 32);
        controller_info.extend_from_slice(&controller_x);
        controller_info.extend_from_slice(pairing_id.as_bytes());
        controller_info.extend_from_slice(&verifying_key.to_bytes());
        let controller_signature = signing_key.sign(&controller_info).to_bytes();

        let encrypted_m5_payload = tlv::encode(&[
            (TlvTag::Identifier, pairing_id.as_bytes()),
            (TlvTag::PublicKey, &verifying_key.to_bytes()),
            (TlvTag::Signature, &controller_signature),
        ]);

        let encrypted_m5 = encrypt_tlv(&setup_encrypt_key, b"PS-Msg05", &encrypted_m5_payload)?;

        let state_5 = [5_u8];
        let m5_body = tlv::encode(&[
            (TlvTag::State, &state_5),
            (TlvTag::EncryptedData, &encrypted_m5),
        ]);
        let m6 = self.post_tlv("/pair-setup", &m5_body, Some(6)).await?;

        let encrypted_m6 = required_tlv(&m6, TlvTag::EncryptedData)?;
        let decrypted_m6 = decrypt_tlv(&setup_encrypt_key, b"PS-Msg06", encrypted_m6)?;
        let m6_data = tlv::decode(&decrypted_m6)?;

        let accessory_pairing_id = required_tlv(&m6_data, TlvTag::Identifier)?;
        let accessory_public_key = required_tlv(&m6_data, TlvTag::PublicKey)?;
        let accessory_signature = required_tlv(&m6_data, TlvTag::Signature)?;

        let accessory_verifying_key = decode_verifying_key(accessory_public_key)?;
        let accessory_x = hkdf_expand_32(
            b"Pair-Setup-Accessory-Sign-Salt",
            &session_key,
            b"Pair-Setup-Accessory-Sign-Info",
        )?;

        let mut accessory_info = Vec::with_capacity(32 + accessory_pairing_id.len() + 32);
        accessory_info.extend_from_slice(&accessory_x);
        accessory_info.extend_from_slice(accessory_pairing_id);
        accessory_info.extend_from_slice(accessory_public_key);

        verify_signature(
            &accessory_verifying_key,
            &accessory_info,
            accessory_signature,
            "pair-setup accessory signature",
        )?;

        Ok(PairingCredentials {
            pairing_id,
            signing_key,
            verifying_key,
            peer_verifying_key: accessory_verifying_key,
        })
    }

    /// Executes a transient HAP Pair-Setup exchange without persisting credentials.
    ///
    /// Used when no stored pairing exists. Performs a two-round SRP-6a exchange
    /// using the fixed PIN `3939` and `Flags=0x10` with `X-Apple-HKP: 4` to
    /// signal a transient session to the receiver.
    ///
    /// Key derivation differs from full pair-setup:
    /// - RTSP control keys: HKDF-SHA512 over the SRP session key with
    ///   salt `"Control-Salt"` and info `"Control-{Write,Read}-Encryption-Key"`
    /// - Audio key: first 32 bytes of the raw SRP session key (no HKDF)
    ///
    /// The returned [`SessionKeys`] are used immediately for the RTSP session
    /// and are not stored to disk; the next connection will repeat this flow.
    pub async fn pair_setup_transient(&mut self) -> Result<SessionKeys> {
        let method = [0_u8];
        let state_1 = [1_u8];
        let flags: [u8; 1] = [0x10];
        let hkp_header = Some(("X-Apple-HKP", "4"));
        let m1_body = tlv::encode(&[
            (TlvTag::Method, &method),
            (TlvTag::State, &state_1),
            (TlvTag::Flags, &flags),
        ]);
        tracing::debug!("transient pair-setup M1: sending with Flags=0x10 (1 byte)");
        let m2 = self
            .post_tlv_with_header("/pair-setup", &m1_body, Some(2), hkp_header)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "transient M1→M2 failed");
                e
            })?;
        tracing::debug!("transient pair-setup M2: received salt and server public key");

        let salt = required_tlv(&m2, TlvTag::Salt)?;
        let server_pubkey_b = required_tlv(&m2, TlvTag::PublicKey)?;

        let mut srp = SrpClient::new(b"Pair-Setup", b"3939");
        let (public_a, _) = srp.start_auth();
        let (proof_m1, session_key) = srp.process_challenge(salt, server_pubkey_b)?;

        let state_3 = [3_u8];
        let m3_body = tlv::encode(&[
            (TlvTag::State, &state_3),
            (TlvTag::PublicKey, &public_a),
            (TlvTag::Proof, &proof_m1),
        ]);
        tracing::debug!("transient pair-setup M3: sending SRP proof");
        let m4 = self
            .post_tlv_with_header("/pair-setup", &m3_body, Some(4), hkp_header)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "transient M3→M4 failed (SRP proof rejected)");
                e
            })?;
        tracing::debug!("transient pair-setup M4: verifying server proof");
        let server_proof = required_tlv(&m4, TlvTag::Proof)?;
        srp.verify_server(server_proof)?;

        let control_write_key = hkdf_expand_32(
            b"Control-Salt",
            &session_key,
            b"Control-Write-Encryption-Key",
        )?;
        let control_read_key = hkdf_expand_32(
            b"Control-Salt",
            &session_key,
            b"Control-Read-Encryption-Key",
        )?;

        let mut audio_shared_key = [0u8; 32];
        audio_shared_key.copy_from_slice(&session_key[..32]);

        let base_rtp_timestamp = rand::random::<u32>();
        Ok(SessionKeys {
            rtsp: AeadContext::new(
                control_write_key,
                NonceStrategy::Counter32 { fixed: [0_u8; 8] },
            ),
            rtsp_read: AeadContext::new(
                control_read_key,
                NonceStrategy::Counter32 { fixed: [0_u8; 8] },
            ),
            audio: AeadContext::new(
                audio_shared_key,
                NonceStrategy::Counter32 { fixed: [0_u8; 8] },
            ),
            base_rtp_timestamp,
        })
    }

    /// Executes the HAP Pair-Verify flow and derives transport session keys.
    ///
    /// This authenticates both peers using Curve25519 ephemeral keys plus
    /// long-term signatures and returns control/audio AEAD key material.
    pub async fn pair_verify(&mut self, creds: &PairingCredentials) -> Result<SessionKeys> {
        let mut rng = OsRng;
        let mut client_private_key = [0_u8; 32];
        rng.fill_bytes(&mut client_private_key);
        let client_public_key = x25519(client_private_key, X25519_BASEPOINT_BYTES);

        let state_1 = [1_u8];
        let m1_body = tlv::encode(&[
            (TlvTag::State, &state_1),
            (TlvTag::PublicKey, &client_public_key),
        ]);
        let m2 = self.post_tlv("/pair-verify", &m1_body, Some(2)).await?;

        let accessory_curve_public = required_tlv(&m2, TlvTag::PublicKey)?;
        let accessory_curve_public: [u8; 32] = accessory_curve_public.try_into().map_err(|_| {
            Error::Hap("pair-verify accessory curve public key length is invalid".to_owned())
        })?;
        let encrypted_m2 = required_tlv(&m2, TlvTag::EncryptedData)?;

        let shared_secret = x25519(client_private_key, accessory_curve_public);
        let verify_encrypt_key = hkdf_expand_32(
            b"Pair-Verify-Encrypt-Salt",
            &shared_secret,
            b"Pair-Verify-Encrypt-Info",
        )?;
        let decrypted_m2 = decrypt_tlv(&verify_encrypt_key, b"PV-Msg02", encrypted_m2)?;
        let m2_data = tlv::decode(&decrypted_m2)?;

        let accessory_identifier = required_tlv(&m2_data, TlvTag::Identifier)?;
        let accessory_signature = required_tlv(&m2_data, TlvTag::Signature)?;

        let mut accessory_info = Vec::with_capacity(32 + accessory_identifier.len() + 32);
        accessory_info.extend_from_slice(&accessory_curve_public);
        accessory_info.extend_from_slice(accessory_identifier);
        accessory_info.extend_from_slice(&client_public_key);

        verify_signature(
            &creds.peer_verifying_key,
            &accessory_info,
            accessory_signature,
            "pair-verify accessory signature",
        )?;

        let mut controller_info = Vec::with_capacity(32 + creds.pairing_id.len() + 32);
        controller_info.extend_from_slice(&client_public_key);
        controller_info.extend_from_slice(creds.pairing_id.as_bytes());
        controller_info.extend_from_slice(&accessory_curve_public);
        let controller_signature = creds.signing_key.sign(&controller_info).to_bytes();

        let encrypted_m3_payload = tlv::encode(&[
            (TlvTag::Identifier, creds.pairing_id.as_bytes()),
            (TlvTag::Signature, &controller_signature),
        ]);
        let encrypted_m3 = encrypt_tlv(&verify_encrypt_key, b"PV-Msg03", &encrypted_m3_payload)?;

        let state_3 = [3_u8];
        let m3_body = tlv::encode(&[
            (TlvTag::State, &state_3),
            (TlvTag::EncryptedData, &encrypted_m3),
        ]);
        self.post_tlv("/pair-verify", &m3_body, Some(4)).await?;

        let control_write_key = hkdf_expand_32(
            b"Control-Salt",
            &shared_secret,
            b"Control-Write-Encryption-Key",
        )?;
        let control_read_key = hkdf_expand_32(
            b"Control-Salt",
            &shared_secret,
            b"Control-Read-Encryption-Key",
        )?;

        let base_rtp_timestamp = rand::random::<u32>();
        Ok(SessionKeys {
            rtsp: AeadContext::new(
                control_write_key,
                NonceStrategy::Counter32 { fixed: [0_u8; 8] },
            ),
            rtsp_read: AeadContext::new(
                control_read_key,
                NonceStrategy::Counter32 { fixed: [0_u8; 8] },
            ),
            audio: AeadContext::new(
                shared_secret,
                NonceStrategy::Counter32 { fixed: [0_u8; 8] },
            ),
            base_rtp_timestamp,
        })
    }

    async fn post_tlv(
        &mut self,
        path: &str,
        payload: &[u8],
        expected_state: Option<u8>,
    ) -> Result<Vec<(TlvTag, Vec<u8>)>> {
        self.post_tlv_with_header(path, payload, expected_state, None)
            .await
    }

    async fn post_tlv_with_header(
        &mut self,
        path: &str,
        payload: &[u8],
        expected_state: Option<u8>,
        extra_header: Option<(&str, &str)>,
    ) -> Result<Vec<(TlvTag, Vec<u8>)>> {
        let body = self.post_bytes(path, payload, extra_header).await?;
        let decoded = tlv::decode(&body)?;
        check_tlv_error(&decoded)?;
        if let Some(expected_state) = expected_state {
            ensure_state(&decoded, expected_state)?;
        }
        Ok(decoded)
    }

    async fn post_bytes(
        &mut self,
        path: &str,
        payload: &[u8],
        extra_header: Option<(&str, &str)>,
    ) -> Result<Vec<u8>> {
        let extra_header = extra_header
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n{}\r\n",
            self.host_header,
            payload.len(),
            extra_header,
        );

        self.stream
            .write_all(request.as_bytes())
            .await
            .map_err(|err| Error::Network(format!("failed to send hap request headers: {err}")))?;
        self.stream
            .write_all(payload)
            .await
            .map_err(|err| Error::Network(format!("failed to send hap request body: {err}")))?;

        let (status, body) = self.read_http_response().await?;
        if status != 200 {
            return Err(Error::Hap(format!("{path} returned http status {status}")));
        }

        Ok(body)
    }

    async fn read_http_response(&mut self) -> Result<(u16, Vec<u8>)> {
        const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

        let header_end_index = loop {
            if let Some(index) = find_bytes(&self.read_buffer, HEADER_TERMINATOR) {
                break index;
            }

            let mut chunk = [0_u8; 4096];
            let bytes_read = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|err| Error::Network(format!("failed to read hap response: {err}")))?;
            if bytes_read == 0 {
                return Err(Error::Network(
                    "connection closed while reading hap response headers".to_owned(),
                ));
            }
            self.read_buffer.extend_from_slice(&chunk[..bytes_read]);
        };

        let header_bytes = &self.read_buffer[..header_end_index];
        let header_text = std::str::from_utf8(header_bytes)
            .map_err(|_| Error::Network("hap response headers are not valid utf-8".to_owned()))?;
        let status_code = parse_status_code(header_text)?;
        let content_length = parse_content_length(header_text)?;
        let body_start = header_end_index + HEADER_TERMINATOR.len();

        while self.read_buffer.len() < body_start + content_length {
            let mut chunk = [0_u8; 4096];
            let bytes_read = self.stream.read(&mut chunk).await.map_err(|err| {
                Error::Network(format!("failed to read hap response body: {err}"))
            })?;
            if bytes_read == 0 {
                return Err(Error::Network(
                    "connection closed while reading hap response body".to_owned(),
                ));
            }
            self.read_buffer.extend_from_slice(&chunk[..bytes_read]);
        }

        let body_end = body_start + content_length;
        let body = self.read_buffer[body_start..body_end].to_vec();
        self.read_buffer.drain(..body_end);
        Ok((status_code, body))
    }
}

fn check_tlv_error(items: &[(TlvTag, Vec<u8>)]) -> Result<()> {
    if let Some(raw_error) = optional_tlv(items, TlvTag::Error) {
        let code = raw_error.first().copied().unwrap_or_default();
        let message = match code {
            1 => "unknown error",
            2 => "authentication failed",
            other => return Err(Error::Hap(format!("hap error code {other}"))),
        };
        return Err(Error::Hap(message.to_owned()));
    }
    Ok(())
}

fn ensure_state(items: &[(TlvTag, Vec<u8>)], expected_state: u8) -> Result<()> {
    let raw_state = required_tlv(items, TlvTag::State)?;
    if raw_state.len() != 1 {
        return Err(Error::Hap("hap state value has invalid length".to_owned()));
    }

    if raw_state[0] != expected_state {
        return Err(Error::Hap(format!(
            "hap state mismatch: expected {expected_state}, got {}",
            raw_state[0]
        )));
    }

    Ok(())
}

fn required_tlv(items: &[(TlvTag, Vec<u8>)], tag: TlvTag) -> Result<&[u8]> {
    optional_tlv(items, tag)
        .ok_or_else(|| Error::Hap(format!("missing required tlv field: {tag:?}")))
}

fn optional_tlv(items: &[(TlvTag, Vec<u8>)], tag: TlvTag) -> Option<&[u8]> {
    items
        .iter()
        .find(|(candidate, _)| *candidate == tag)
        .map(|(_, value)| value.as_slice())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_status_code(header_text: &str) -> Result<u16> {
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Network("hap response is missing status line".to_owned()))?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts
        .next()
        .ok_or_else(|| Error::Network("hap response status line is malformed".to_owned()))?;
    let status = parts
        .next()
        .ok_or_else(|| Error::Network("hap response status code is missing".to_owned()))?;
    status
        .parse::<u16>()
        .map_err(|err| Error::Network(format!("hap response status code is invalid: {err}")))
}

fn parse_content_length(header_text: &str) -> Result<usize> {
    for line in header_text.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("Content-Length")
        {
            return value.trim().parse::<usize>().map_err(|err| {
                Error::Network(format!("hap response content-length is invalid: {err}"))
            });
        }
    }

    Ok(0)
}

fn hkdf_expand_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut key = [0_u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|_| Error::Crypto("hkdf expand failed".to_owned()))?;
    Ok(key)
}

fn encrypt_tlv(key: &[u8; 32], nonce_label: &[u8; 8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = make_hap_nonce(nonce_label);
    cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto("hap encryption failed".to_owned()))
}

fn decrypt_tlv(key: &[u8; 32], nonce_label: &[u8; 8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = make_hap_nonce(nonce_label);
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| Error::Crypto("hap decryption failed".to_owned()))
}

fn make_hap_nonce(label: &[u8; 8]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(label);
    nonce
}

fn decode_verifying_key(raw_key: &[u8]) -> Result<VerifyingKey> {
    let key_bytes: [u8; 32] = raw_key
        .try_into()
        .map_err(|_| Error::Hap("ed25519 public key has invalid length".to_owned()))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| Error::Hap(format!("ed25519 public key is invalid: {err}")))
}

fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    raw_signature: &[u8],
    context: &str,
) -> Result<()> {
    let signature = Signature::try_from(raw_signature)
        .map_err(|_| Error::Hap(format!("{context} has invalid length")))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::Hap(format!("{context} verification failed")))
}

fn random_pairing_id(rng: &mut OsRng) -> String {
    let mut bytes = [0_u8; 16];
    rng.fill_bytes(&mut bytes);
    hex_encode_upper(&bytes)
}

fn hex_encode_upper(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}
