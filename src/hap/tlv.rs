use crate::error::{Error, Result};

/// TLV8 tags used by HomeKit Pair-Setup and Pair-Verify messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlvTag {
    /// Pairing method selector.
    Method = 0x00,
    /// Long-term pairing identifier.
    Identifier = 0x01,
    /// SRP salt value.
    Salt = 0x02,
    /// Public key material for SRP or Curve25519.
    PublicKey = 0x03,
    /// SRP proof value.
    Proof = 0x04,
    /// AEAD-wrapped nested TLV payload.
    EncryptedData = 0x05,
    /// Pairing state machine step.
    State = 0x06,
    /// Protocol error code.
    Error = 0x07,
    /// Ed25519 signature bytes.
    Signature = 0x0A,
    /// Pairing flags (e.g. transient mode).
    Flags = 0x13,
}

impl TryFrom<u8> for TlvTag {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Method),
            0x01 => Ok(Self::Identifier),
            0x02 => Ok(Self::Salt),
            0x03 => Ok(Self::PublicKey),
            0x04 => Ok(Self::Proof),
            0x05 => Ok(Self::EncryptedData),
            0x06 => Ok(Self::State),
            0x07 => Ok(Self::Error),
            0x0A => Ok(Self::Signature),
            0x13 => Ok(Self::Flags),
            tag => Err(Error::Hap(format!("unknown tlv tag: 0x{tag:02x}"))),
        }
    }
}

/// Encodes a sequence of TLV items into TLV8 wire bytes.
///
/// Values larger than 255 bytes are fragmented into multiple entries with the
/// same tag to satisfy TLV8 field length limits.
pub fn encode(items: &[(TlvTag, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in items {
        if value.is_empty() {
            out.push(*tag as u8);
            out.push(0);
            continue;
        }

        let mut cursor = 0;
        while cursor < value.len() {
            let chunk_len = std::cmp::min(255, value.len() - cursor);
            out.push(*tag as u8);
            out.push(chunk_len as u8);
            out.extend_from_slice(&value[cursor..cursor + chunk_len]);
            cursor += chunk_len;
        }
    }
    out
}

/// Decodes TLV8 wire bytes into ordered `(tag, value)` entries.
///
/// Adjacent fragments with the same tag are merged back into a single value.
pub fn decode(data: &[u8]) -> Result<Vec<(TlvTag, Vec<u8>)>> {
    let mut out: Vec<(TlvTag, Vec<u8>)> = Vec::new();
    let mut idx = 0;

    while idx < data.len() {
        if idx + 2 > data.len() {
            return Err(Error::Hap("truncated tlv header".to_owned()));
        }

        let raw_tag = data[idx];
        let len = data[idx + 1] as usize;
        idx += 2;

        if idx + len > data.len() {
            return Err(Error::Hap("truncated tlv value".to_owned()));
        }

        let value = &data[idx..idx + len];
        idx += len;

        let tag = match TlvTag::try_from(raw_tag) {
            Ok(tag) => tag,
            Err(_) => continue,
        };

        if let Some((last_tag, last_value)) = out.last_mut()
            && *last_tag == tag
        {
            last_value.extend_from_slice(value);
            continue;
        }

        out.push((tag, value.to_vec()));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{TlvTag, decode, encode};

    #[test]
    fn encode_small_items_matches_expected_bytes() {
        let method = [0x00_u8];
        let state = [0x01_u8];
        let encoded = encode(&[(TlvTag::Method, &method), (TlvTag::State, &state)]);
        assert_eq!(encoded, vec![0x00, 0x01, 0x00, 0x06, 0x01, 0x01]);
    }

    #[test]
    fn encode_splits_large_values_into_fragments() {
        let value = vec![0xAB_u8; 300];
        let encoded = encode(&[(TlvTag::PublicKey, &value)]);

        assert_eq!(encoded[0], TlvTag::PublicKey as u8);
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded[2..257], vec![0xAB_u8; 255]);

        assert_eq!(encoded[257], TlvTag::PublicKey as u8);
        assert_eq!(encoded[258], 45);
        assert_eq!(encoded[259..], vec![0xAB_u8; 45]);
    }

    #[test]
    fn decode_merges_fragmented_values() {
        let mut data = Vec::new();
        data.extend_from_slice(&[TlvTag::PublicKey as u8, 255]);
        data.extend_from_slice(&vec![0xCD_u8; 255]);
        data.extend_from_slice(&[TlvTag::PublicKey as u8, 16]);
        data.extend_from_slice(&[0xCD_u8; 16]);
        data.extend_from_slice(&[TlvTag::State as u8, 1, 0x02]);

        let decoded = decode(&data).expect("decode should succeed");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, TlvTag::PublicKey);
        assert_eq!(decoded[0].1, vec![0xCD_u8; 271]);
        assert_eq!(decoded[1], (TlvTag::State, vec![0x02]));
    }

    #[test]
    fn decode_rejects_truncated_value() {
        let data = [TlvTag::State as u8, 2, 0x01];
        let err = decode(&data).expect_err("decode should fail");
        assert_eq!(err.to_string(), "hap: truncated tlv value");
    }
}
