pub use crate::config::Error as ConfigParseError;
pub use crate::connect::{AuthError, Error as ConnectError};

use russh::client::Handler;
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};

pub use russh::Error as RusshError;

impl Display for ConfigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserNotFound(e) => write!(
                f,
                "Could not get your user name so we do not know which user to login: {e}"
            ),
        }
    }
}

impl StdError for ConfigParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::UserNotFound(e) => Some(e),
        }
    }
}

impl Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadPrivkey(e) => write!(f, "Could not load IdentityFile: {e}"),
            Self::LoadCert(e) => write!(f, "Could not load CertificateFile: {e}"),
            Self::ConnectAgent(e) => {
                write!(f, "Failed connect to the SSH agent: {e}")
            }
            Self::RequestAgent(e) => write!(
                f,
                "Unexpected error when authenticating wih the SSH agent: {e}"
            ),
            Self::Connection(e) => write!(f, "Connection failed during the authentication: {e}"),
            Self::PubkeyUnsupported => write!(f, "Server does not support pubkey authentication"),
            Self::MultiStep => write!(
                f,
                "Server requires the multi-step authentication, but we do not support it"
            ),
        }
    }
}

impl StdError for AuthError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::LoadPrivkey(e) => Some(e),
            Self::LoadCert(e) => Some(e),
            Self::ConnectAgent(e) => Some(e),
            Self::RequestAgent(e) => Some(e),
            Self::Connection(e) => Some(e),
            Self::PubkeyUnsupported | Self::MultiStep => None,
        }
    }
}

impl<H: Handler> Debug for ConnectError<H> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectError::AuthError(e) => f.debug_tuple("AuthError").field(e).finish(),
            ConnectError::Establish(e) => f.debug_tuple("Establish").field(e).finish(),
            ConnectError::ProxyJump(e) => f.debug_tuple("ProxyJump").field(e).finish(),
        }
    }
}

impl<H: Handler> Display for ConnectError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthError(e) => write!(f, "Authentication failed: {e}"),
            Self::Establish(e) => write!(
                f,
                "Could not establish the connection (either TCP or TLS layer): {e:?}"
            ),
            Self::ProxyJump(e) => write!(f, "Could not open a channel for proxy jump: {e}"),
        }
    }
}

impl<H> StdError for ConnectError<H>
where
    H: Handler,
    H::Error: StdError + 'static,
{
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::AuthError(e) => Some(e),
            Self::Establish(e) => Some(e),
            Self::ProxyJump(e) => Some(e),
        }
    }
}
