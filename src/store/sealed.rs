//! Bytes sealed with a key derived from a secret, so they can lie on disk:
//! XChaCha20-Poly1305 (an AEAD) under HKDF-SHA256 of the secret. Whoever
//! lacks the secret reads nothing, and a changed byte fails to open.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// What a sealed file starts with; bumped if the format ever changes.
const MAGIC: &[u8] = b"sesame-sealed-1\n";
const NONCE: usize = 24;

pub struct Sealer {
    cipher: XChaCha20Poly1305,
    /// Bound to every sealing: bytes sealed for another context do not open.
    context: Vec<u8>,
}

impl Sealer {
    /// The key is HKDF-SHA256 of `secret`, for `context` (what the bytes are,
    /// and for whom): the same secret seals each context under its own key.
    pub fn new(secret: &str, context: &str) -> Sealer {
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(MAGIC), secret.as_bytes())
            .expand(context.as_bytes(), &mut key)
            .unwrap_or_else(|_| unreachable!("32 bytes is a valid HKDF-SHA256 length"));
        Sealer {
            cipher: XChaCha20Poly1305::new(&Key::from(key)),
            context: context.as_bytes().to_vec(),
        }
    }

    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let nonce: [u8; NONCE] = rand::random();
        let sealed = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plain,
                    aad: &self.context,
                },
            )
            .unwrap_or_else(|_| unreachable!("encrypting in memory does not fail"));
        [MAGIC, &nonce, &sealed].concat()
    }

    /// The bytes `seal` sealed under the same secret and context; `None` for
    /// anything else (another secret, another context, a changed byte).
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        let rest = sealed.strip_prefix(MAGIC)?;
        let (nonce, body) = rest.split_at_checked(NONCE)?;
        let nonce: [u8; NONCE] = nonce.try_into().ok()?;
        self.cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: body,
                    aad: &self.context,
                },
            )
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_only_under_the_same_secret_and_context() {
        let a = Sealer::new("token-a", "vault v");
        let sealed = a.seal(b"the secret rows");
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(a.open(&sealed).unwrap(), b"the secret rows");
        assert!(Sealer::new("token-b", "vault v").open(&sealed).is_none());
        assert!(Sealer::new("token-a", "vault w").open(&sealed).is_none());
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(a.open(&changed).is_none());
        assert!(a.open(b"").is_none());
        assert!(a.open(MAGIC).is_none());
        assert!(a.open(&sealed[..MAGIC.len() + NONCE]).is_none());
        // A fresh nonce each time.
        assert_ne!(a.seal(b"x"), a.seal(b"x"));
    }
}
