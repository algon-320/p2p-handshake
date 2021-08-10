use crate::error::{Error, Result};
use ring::{aead, agreement, error::Unspecified, pbkdf2};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Sealed<T> {
    nonce: [u8; 12],
    data: Vec<u8>,
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug)]
pub struct SymmetricKey {
    key: aead::LessSafeKey,
    counter: CounterNonce,
}

impl SymmetricKey {
    /// For entities which share the same symmetric key,
    /// each entity has to use unique `nonce_id`,
    /// because the use of same `nonce_id` causes nonce duplication
    /// which could invalidate the encryption.
    ///
    /// For example, on encryption between two entities (A and B),
    /// they have to use different `nonce_id`s.
    ///     If A uses `nonce_id` = 0 then
    ///     B can use `nonce_id` = 1 (other than 0 since 0 is used by A)
    pub fn new(key_material: &[u8], nonce_id: u32) -> Result<Self> {
        let mut key_bytes: [u8; 32] = [0; 32];
        let pbkdf2 = pbkdf2::PBKDF2_HMAC_SHA256;
        let iteration = std::num::NonZeroU32::new(100000).unwrap();
        pbkdf2::derive(pbkdf2, iteration, &[], key_material, &mut key_bytes);

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)?;
        let key = aead::LessSafeKey::new(unbound_key);

        Ok(Self {
            key,
            counter: CounterNonce::new(nonce_id),
        })
    }

    pub fn encrypt<T>(&mut self, plaintext: T) -> Result<Sealed<T>>
    where
        T: serde::Serialize,
    {
        use aead::NonceSequence;
        let mut buf = serde_cbor::to_vec(&plaintext)?;
        let nonce = self.counter.advance()?;
        let nonce_bytes = *nonce.as_ref();
        let aad = aead::Aad::from(&nonce_bytes);
        self.key.seal_in_place_append_tag(nonce, aad, &mut buf)?;
        Ok(Sealed {
            nonce: nonce_bytes,
            data: buf,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn decrypt<T>(&self, sealed: Sealed<T>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut buf = sealed.data;
        let aad = aead::Aad::from(sealed.nonce);
        let nonce = aead::Nonce::assume_unique_for_key(sealed.nonce);
        let slice = self.key.open_in_place(nonce, aad, &mut buf)?;
        Ok(serde_cbor::from_slice(slice)?)
    }
}

pub fn derive_symmetric_key(
    sk: agreement::EphemeralPrivateKey,
    pk: &[u8],
    id: u32,
) -> Result<SymmetricKey> {
    let pk = agreement::UnparsedPublicKey::new(&agreement::X25519, pk);
    agreement::agree_ephemeral(sk, &pk, Error::Crypto, |material| {
        SymmetricKey::new(material, id)
    })
}

#[derive(Debug)]
pub struct CounterNonce(u64, u32);

impl CounterNonce {
    /// Different `id`s yield difference nonce sequences.
    pub fn new(id: u32) -> Self {
        Self(0, id)
    }
}

impl aead::NonceSequence for CounterNonce {
    fn advance(&mut self) -> std::result::Result<aead::Nonce, Unspecified> {
        self.0 = self.0.checked_add(1).ok_or(Unspecified)?;
        let b = self.0.to_be_bytes();
        let c = self.1.to_be_bytes();
        Ok(aead::Nonce::assume_unique_for_key([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], c[0], c[1], c[2], c[3],
        ]))
    }
}
