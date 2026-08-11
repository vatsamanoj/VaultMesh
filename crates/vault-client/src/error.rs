use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Transport(e.to_string())
    }
}
