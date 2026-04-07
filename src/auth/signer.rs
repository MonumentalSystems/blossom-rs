//! BIP-340 Schnorr signing trait and default implementation.

use secp256k1::rand::rngs::OsRng;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

/// Trait for BIP-340 Schnorr signing used in Blossom auth events.
///
/// Implement this for your own identity/key management type.
pub trait BlossomSigner: Send + Sync {
    /// Return the 64-char hex-encoded x-only public key.
    fn public_key_hex(&self) -> String;

    /// Sign a 32-byte message digest using BIP-340 Schnorr.
    /// Returns the 128-char hex-encoded signature.
    fn sign_schnorr(&self, message: &[u8; 32]) -> String;
}

/// Default BIP-340 signer backed by a secp256k1 keypair.
///
/// For testing or standalone use. In production, implement [`BlossomSigner`]
/// for your own identity type (e.g., one backed by a hardware key or Nostr identity).
#[derive(Debug, Clone)]
pub struct Signer {
    secret_key: SecretKey,
    public_key: XOnlyPublicKey,
}

impl Signer {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut OsRng);
        let (xonly, _parity) = keypair.x_only_public_key();
        Signer {
            secret_key: keypair.secret_key(),
            public_key: xonly,
        }
    }

    /// Reconstruct from a hex-encoded secret key.
    pub fn from_secret_hex(nsec: &str) -> Result<Self, String> {
        let bytes = hex::decode(nsec).map_err(|e| format!("invalid hex: {e}"))?;
        let sk = SecretKey::from_slice(&bytes).map_err(|e| format!("invalid secret key: {e}"))?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        Ok(Signer {
            secret_key: sk,
            public_key: xonly,
        })
    }

    /// 64-char hex-encoded secret key.
    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.secret_key.secret_bytes())
    }

    /// Verify a BIP-340 Schnorr signature.
    ///
    /// This is a static method — no signer instance needed, just the public key.
    pub fn verify(pubkey_hex: &str, message: &[u8; 32], sig_hex: &str) -> bool {
        let secp = Secp256k1::verification_only();

        let pub_bytes = match hex::decode(pubkey_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let xonly = match XOnlyPublicKey::from_slice(&pub_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let msg = match Message::from_digest_slice(message) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let sig = match secp256k1::schnorr::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        secp.verify_schnorr(&sig, &msg, &xonly).is_ok()
    }
}

impl BlossomSigner for Signer {
    fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.serialize())
    }

    fn sign_schnorr(&self, message: &[u8; 32]) -> String {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &self.secret_key);
        let msg =
            Message::from_digest_slice(message).expect("32-byte message always valid for Message");
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        hex::encode(sig.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sign_verify() {
        let signer = Signer::generate();
        let message = [42u8; 32];
        let sig = signer.sign_schnorr(&message);
        assert!(Signer::verify(&signer.public_key_hex(), &message, &sig));
    }

    #[test]
    fn test_wrong_message_rejected() {
        let signer = Signer::generate();
        let sig = signer.sign_schnorr(&[42u8; 32]);
        assert!(!Signer::verify(&signer.public_key_hex(), &[99u8; 32], &sig));
    }

    #[test]
    fn test_from_secret_hex_roundtrip() {
        let s1 = Signer::generate();
        let s2 = Signer::from_secret_hex(&s1.secret_key_hex()).unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
    }
}
