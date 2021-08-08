use ring::{aead, agreement, error, pbkdf2};

pub fn derive_symmetric_key(
    sk: agreement::EphemeralPrivateKey,
    pk: &[u8],
) -> Result<aead::LessSafeKey, error::Unspecified> {
    let pk = agreement::UnparsedPublicKey::new(&agreement::X25519, pk);
    agreement::agree_ephemeral(sk, &pk, error::Unspecified, |material| {
        let mut key_bytes: [u8; 32] = [0; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100000).unwrap(),
            &[],
            &material,
            &mut key_bytes,
        );
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)?;
        Ok(aead::LessSafeKey::new(key))
    })
}

#[derive(Debug, Default)]
pub struct CounterNonce(u64);

impl aead::NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0 = self.0.checked_add(1).ok_or(error::Unspecified)?;
        let b = self.0.to_ne_bytes();
        Ok(aead::Nonce::assume_unique_for_key([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0,
        ]))
    }
}
