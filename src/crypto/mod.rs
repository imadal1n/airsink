//! Shared encryption contexts and nonce construction policies.

use bytes::Bytes;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Session-scoped symmetric keys used by control and media paths.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// AEAD context for encrypted RTSP/control channel payloads.
    pub rtsp: AeadContext,
    /// AEAD context for encrypted RTP audio payloads.
    pub audio: AeadContext,
    /// Initial RTP timestamp chosen for this stream session.
    pub base_rtp_timestamp: u32,
}

/// AEAD key and nonce policy for one encrypted stream direction.
#[derive(Debug, Clone)]
pub struct AeadContext {
    /// Secret 32-byte ChaCha20-Poly1305 key material.
    pub key: Zeroizing<[u8; 32]>,
    /// Nonce construction strategy bound to this context.
    pub nonce_strategy: NonceStrategy,
}

/// Nonce derivation strategy for AirPlay control and audio packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceStrategy {
    /// Nonce layout: 8 fixed bytes + 4-byte little-endian counter.
    Counter32 {
        /// Fixed nonce prefix bytes.
        fixed: [u8; 8],
    },
    /// Nonce layout: 10 fixed bytes + 2-byte little-endian sequence.
    SeqU16 {
        /// Fixed nonce prefix bytes.
        fixed: [u8; 10],
    },
}

impl AeadContext {
    /// Constructs an AEAD context from raw key bytes and nonce strategy.
    pub fn new(key: [u8; 32], nonce_strategy: NonceStrategy) -> Self {
        Self {
            key: Zeroizing::new(key),
            nonce_strategy,
        }
    }

    /// Encrypts plaintext with AEAD using derived nonce and provided AAD.
    pub fn seal(&self, counter: u32, aad: &[u8], plaintext: &[u8]) -> Result<Bytes> {
        let cipher = ChaCha20Poly1305::new((&*self.key).into());
        let nonce_bytes = self.nonce_strategy.nonce(counter);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("chacha20poly1305 seal failed".to_owned()))?;
        Ok(Bytes::from(ciphertext))
    }

    /// Decrypts ciphertext with AEAD using derived nonce and provided AAD.
    pub fn open(&self, counter: u32, aad: &[u8], ciphertext: &[u8]) -> Result<Bytes> {
        let cipher = ChaCha20Poly1305::new((&*self.key).into());
        let nonce_bytes = self.nonce_strategy.nonce(counter);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("chacha20poly1305 open failed".to_owned()))?;
        Ok(Bytes::from(plaintext))
    }
}

impl NonceStrategy {
    /// Builds a 12-byte nonce from the strategy and packet counter.
    pub fn nonce(&self, counter: u32) -> [u8; 12] {
        match self {
            Self::Counter32 { fixed } => {
                let mut nonce = [0_u8; 12];
                nonce[..8].copy_from_slice(fixed);
                nonce[8..].copy_from_slice(&counter.to_le_bytes());
                nonce
            }
            Self::SeqU16 { fixed } => {
                let mut nonce = [0_u8; 12];
                nonce[..10].copy_from_slice(fixed);
                let seq = (counter as u16).to_le_bytes();
                nonce[10..].copy_from_slice(&seq);
                nonce
            }
        }
    }
}
