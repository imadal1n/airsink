use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::error::{Error, Result};

const APPLE_SRP_N_HEX: &str = "
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
";

/// SRP-6a client for HomeKit Pair-Setup authentication.
///
/// The implementation uses Apple's 3072-bit parameters and SHA-512 so the
/// controller can prove PIN knowledge without exposing the PIN itself.
pub struct SrpClient {
    username: Vec<u8>,
    password: Vec<u8>,
    n: BigUint,
    n_bytes: Vec<u8>,
    g: BigUint,
    private_a: Option<BigUint>,
    public_a: Option<BigUint>,
    session_key: Option<Vec<u8>>,
    expected_server_proof: Option<Vec<u8>>,
}

impl SrpClient {
    /// Creates a new SRP client bound to the provided username and PIN bytes.
    pub fn new(username: &[u8], password: &[u8]) -> Self {
        let n_bytes = decode_hex_constant(APPLE_SRP_N_HEX);
        let n = BigUint::from_bytes_be(&n_bytes);
        Self {
            username: username.to_vec(),
            password: password.to_vec(),
            n,
            n_bytes,
            g: BigUint::from(5_u8),
            private_a: None,
            public_a: None,
            session_key: None,
            expected_server_proof: None,
        }
    }

    /// Starts SRP authentication and returns `(A, a)`.
    ///
    /// The returned public key `A` is sent to the accessory while `a` is kept
    /// for diagnostics/tests and is also retained internally for challenge use.
    pub fn start_auth(&mut self) -> (Vec<u8>, BigUint) {
        let mut rng = rand::thread_rng();
        let (public_a, private_a) = loop {
            let mut private_bytes = [0_u8; 64];
            rng.fill_bytes(&mut private_bytes);
            let mut a = BigUint::from_bytes_be(&private_bytes);
            if a.is_zero() {
                a = BigUint::one();
            }

            let public = self.g.modpow(&a, &self.n);
            if !public.is_zero() {
                break (public, a);
            }
        };

        let public_a_bytes = public_a.to_bytes_be();
        self.public_a = Some(public_a);
        self.private_a = Some(private_a.clone());
        self.session_key = None;
        self.expected_server_proof = None;
        (public_a_bytes, private_a)
    }

    /// Processes salt and server public key `B`, returning `(M1, K)`.
    ///
    /// This validates the challenge, derives the shared secret and session key,
    /// and computes the client proof to send in Pair-Setup M3.
    pub fn process_challenge(
        &mut self,
        salt: &[u8],
        server_pubkey_b: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let private_a = self.private_a.as_ref().ok_or_else(|| {
            Error::Hap("srp start_auth must be called before process_challenge".to_owned())
        })?;
        let public_a = self.public_a.as_ref().ok_or_else(|| {
            Error::Hap("srp start_auth must be called before process_challenge".to_owned())
        })?;

        let public_b = BigUint::from_bytes_be(server_pubkey_b);
        if (&public_b % &self.n).is_zero() {
            return Err(Error::Hap("srp server public key is invalid".to_owned()));
        }

        // k and u use PAD(x) per RFC 5054 / Apple SRP variant
        let k = self.compute_multiplier_k();
        let public_a_padded = self.pad_to_n(public_a);
        let public_b_padded = self.pad_to_n(&public_b);
        let u = hash_biguint(&[&public_a_padded, &public_b_padded]);
        if u.is_zero() {
            return Err(Error::Hap("srp scrambling parameter is zero".to_owned()));
        }

        let x = self.compute_x(salt);
        let g_pow_x = self.g.modpow(&x, &self.n);
        let kgx = (&k * g_pow_x) % &self.n;
        let base = if public_b >= kgx {
            &public_b - &kgx
        } else {
            &public_b + &self.n - &kgx
        };
        let exponent = private_a + (&u * &x);
        let shared_secret = base.modpow(&exponent, &self.n);

        // K, M1, M2 use raw (unpadded) byte representations per csrp/owntone
        let public_a_raw = public_a.to_bytes_be();
        let public_b_raw = public_b.to_bytes_be();
        let shared_secret_raw = shared_secret.to_bytes_be();
        let session_key = hash_bytes(&[&shared_secret_raw]);

        let hash_n = hash_bytes(&[&self.n_bytes]);
        let g_raw = self.g.to_bytes_be();
        let hash_g = hash_bytes(&[&g_raw]);
        let hash_i = hash_bytes(&[&self.username]);

        let hash_ng_xor: Vec<u8> = hash_n
            .iter()
            .zip(hash_g.iter())
            .map(|(left, right)| left ^ right)
            .collect();

        let client_proof = hash_bytes(&[
            &hash_ng_xor,
            &hash_i,
            salt,
            &public_a_raw,
            &public_b_raw,
            &session_key,
        ]);
        let expected_server_proof = hash_bytes(&[&public_a_raw, &client_proof, &session_key]);

        self.session_key = Some(session_key.clone());
        self.expected_server_proof = Some(expected_server_proof);

        Ok((client_proof, session_key))
    }

    /// Verifies the server proof `M2` produced by the accessory.
    ///
    /// Successful verification confirms both peers derived the same SRP session
    /// key, completing the SRP authentication phase.
    pub fn verify_server(&self, server_proof_m2: &[u8]) -> Result<()> {
        let expected = self.expected_server_proof.as_ref().ok_or_else(|| {
            Error::Hap("srp process_challenge must be called before verify_server".to_owned())
        })?;

        if expected.as_slice() != server_proof_m2 {
            return Err(Error::Hap(
                "srp server proof verification failed".to_owned(),
            ));
        }

        Ok(())
    }

    fn compute_multiplier_k(&self) -> BigUint {
        let padded_g = self.pad_to_n(&self.g);
        hash_biguint(&[&self.n_bytes, &padded_g])
    }

    fn compute_x(&self, salt: &[u8]) -> BigUint {
        let identity_password_hash = hash_bytes(&[&self.username, b":", &self.password]);
        hash_biguint(&[salt, &identity_password_hash])
    }

    fn pad_to_n(&self, value: &BigUint) -> Vec<u8> {
        let mut bytes = value.to_bytes_be();
        if bytes.len() >= self.n_bytes.len() {
            return bytes;
        }

        let mut padded = vec![0_u8; self.n_bytes.len() - bytes.len()];
        padded.append(&mut bytes);
        padded
    }
}

fn hash_biguint(parts: &[&[u8]]) -> BigUint {
    BigUint::from_bytes_be(&hash_bytes(parts))
}

fn hash_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn decode_hex_constant(input: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let mut pending_nibble: Option<u8> = None;

    for byte in input.bytes() {
        let nibble = match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };

        if let Some(nibble) = nibble {
            if let Some(high) = pending_nibble.take() {
                output.push((high << 4) | nibble);
            } else {
                pending_nibble = Some(nibble);
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::SrpClient;

    #[test]
    fn srp_start_auth_returns_non_empty_public_key() {
        let mut client = SrpClient::new(b"Pair-Setup", b"123-45-678");
        let (public_a, private_a) = client.start_auth();
        assert!(!public_a.is_empty());
        assert!(private_a.bits() > 0);
    }
}
