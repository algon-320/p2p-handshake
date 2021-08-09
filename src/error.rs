use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Serialization/Deserialization error")]
    Serde(#[from] serde_cbor::Error),

    #[error("Crypto error")]
    Crypto,

    #[error("Unexpected message")]
    UnexpectedMessage,
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Crypto
    }
}

pub type Result<T> = std::result::Result<T, Error>;
