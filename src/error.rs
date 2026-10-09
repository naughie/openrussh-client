pub use crate::auth::Error as AuthError;
pub use crate::config::Error as ConfigParseError;
pub use crate::connect::Error as ConnectError;

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
            Self::NoPrivateKey => write!(f, "Private key is not configured"),
            Self::NoIdentityFilter => write!(
                f,
                "`IdentitiesOnly` is `yes`, but no valid `IdentityFile` are found"
            ),
            Self::LoadPrivkey(e) => write!(f, "Could not load IdentityFile: {e}"),
            Self::LoadCert(e) => write!(f, "Could not load CertificateFile: {e}"),
            Self::PubkeyMismatch => write!(
                f,
                "Public keys from `IdentityFile` and `CertificateFile` are mismatched"
            ),
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
            Self::PubkeyMismatch => None,
            Self::NoPrivateKey | Self::NoIdentityFilter => None,
        }
    }
}

impl<H: Handler, M: Debug> Debug for ConnectError<H, M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectError::AuthError(e) => f.debug_tuple("AuthError").field(e).finish(),
            ConnectError::AuthFailure => f.debug_tuple("AuthFailure").finish(),
            ConnectError::Establish(e) => f.debug_tuple("Establish").field(e).finish(),
            ConnectError::ProxyJump(e) => f.debug_tuple("ProxyJump").field(e).finish(),
            ConnectError::MakeHandler(e) => f.debug_tuple("MakeHandler").field(e).finish(),
        }
    }
}

impl<H: Handler, M: Display> Display for ConnectError<H, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthError(e) => write!(f, "Error happened while authenticating: {e}"),
            Self::AuthFailure => write!(f, "Authentication failed"),
            Self::Establish(e) => write!(
                f,
                "Could not establish the connection (either TCP or TLS layer): {e:?}"
            ),
            Self::ProxyJump(e) => write!(f, "Could not open a channel for proxy jump: {e}"),
            Self::MakeHandler(e) => write!(f, "Failed to make a handler: {e}"),
        }
    }
}

impl<H, M> StdError for ConnectError<H, M>
where
    H: Handler,
    H::Error: StdError + 'static,
    M: StdError + 'static,
{
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::AuthError(e) => Some(e),
            Self::Establish(e) => Some(e),
            Self::ProxyJump(e) => Some(e),
            Self::MakeHandler(e) => Some(e),
            Self::AuthFailure => None,
        }
    }
}
