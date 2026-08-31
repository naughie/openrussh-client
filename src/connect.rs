use crate::config::{AuthMethod, Chain, Host};

use russh::client::Config;
use russh::client::{Handle, Handler};
use russh::keys::{Algorithm, HashAlg};

pub use russh::Disconnect;

use std::path::Path;
use std::sync::Arc;

#[non_exhaustive]
#[derive(Debug)]
pub enum AuthError {
    LoadPrivkey(russh::keys::Error),
    LoadCert(russh::keys::ssh_key::Error),

    ConnectAgent(russh::keys::Error),
    RequestAgent(russh::AgentAuthError),

    Connection(russh::Error),

    PubkeyUnsupported,
    MultiStep,
}

pub enum Error<H: Handler> {
    AuthError(AuthError),
    Establish(H::Error),
    ProxyJump(russh::Error),
}

pub struct Connection<H: Handler> {
    handle: Handle<H>,
}

impl<H: Handler> Connection<H> {
    pub fn handle(&self) -> &Handle<H> {
        &self.handle
    }

    pub fn handle_mut(&mut self) -> &mut Handle<H> {
        &mut self.handle
    }

    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: &str,
        lang_tag: &str,
    ) -> Result<(), russh::Error> {
        self.handle.disconnect(reason, description, lang_tag).await
    }
}

impl<H: Handler + Send + 'static> Connection<H> {
    pub async fn connect<F, U>(
        target: &Chain,
        make_handler: F,
        update_conf: U,
    ) -> Result<Self, Error<H>>
    where
        F: FnMut(&Host) -> H,
        U: FnMut(&H, &mut Config),
    {
        Self::connect_impl(target, make_handler, update_conf).await
    }

    async fn connect_impl<F, U>(
        target: &Chain,
        mut make_handler: F,
        mut update_conf: U,
    ) -> Result<Self, Error<H>>
    where
        F: FnMut(&Host) -> H,
        U: FnMut(&H, &mut Config),
    {
        use tokio::io::{AsyncRead, AsyncWrite};

        async fn connect<H: Handler + Send + 'static>(
            conf: Arc<Config>,
            host: &Host,
            handler: H,
        ) -> Result<Handle<H>, Error<H>> {
            let mut handle =
                russh::client::connect(conf, (&*host.dest.name, host.dest.port), handler)
                    .await
                    .map_err(Error::Establish)?;
            auth(host, &mut handle).await.map_err(Error::AuthError)?;

            Ok(handle)
        }
        async fn connect_stream<S, H>(
            conf: Arc<Config>,
            host: &Host,
            stream: S,
            handler: H,
        ) -> Result<Handle<H>, Error<H>>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
            H: Handler + Send + 'static,
        {
            let mut handle = russh::client::connect_stream(conf, stream, handler)
                .await
                .map_err(Error::Establish)?;
            auth(host, &mut handle).await.map_err(Error::AuthError)?;

            Ok(handle)
        }

        let mut setup_handler = |host: &Host| {
            let handler = make_handler(host);
            let mut conf = Config::default();
            update_conf(&handler, &mut conf);
            (handler, conf)
        };

        let (first, bastions) = target.iter();

        let handle = if let Some(bastions) = bastions {
            let mut handle = {
                let (handler, conf) = setup_handler(first);
                connect(Arc::new(conf), first, handler).await?
            };

            for bastion in bastions {
                let channel = handle
                    .channel_open_direct_tcpip(
                        &bastion.to.dest.name,
                        bastion.to.dest.port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(Error::ProxyJump)?;
                handle = {
                    let (handler, conf) = setup_handler(bastion.to);
                    connect_stream(Arc::new(conf), bastion.to, channel.into_stream(), handler)
                        .await?
                };
            }

            handle
        } else {
            let (handler, conf) = setup_handler(first);
            connect(Arc::new(conf), first, handler).await?
        };

        Ok(Self { handle })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthResult {
    Success,
    Failure,
}

impl AuthResult {
    fn try_from(res: russh::client::AuthResult) -> Result<Self, AuthError> {
        use russh::client::AuthResult as RusshAuthResult;
        match res {
            RusshAuthResult::Success => Ok(Self::Success),
            RusshAuthResult::Failure {
                partial_success: true,
                ..
            } => Err(AuthError::MultiStep),
            RusshAuthResult::Failure {
                partial_success: false,
                ..
            } => Ok(Self::Failure),
        }
    }
}

async fn find_hash_alg<H: Handler>(
    key_alg: Algorithm,
    handle: &mut Handle<H>,
) -> Result<Option<HashAlg>, AuthError> {
    if matches!(key_alg, Algorithm::Rsa { .. }) {
        let res = handle
            .best_supported_rsa_hash()
            .await
            .map_err(AuthError::Connection)?
            .flatten();
        Ok(res)
    } else {
        Ok(None)
    }
}

async fn auth_pubkey<H: Handler>(
    priv_key: &Path,
    user: &str,
    handle: &mut Handle<H>,
) -> Result<AuthResult, AuthError> {
    use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

    let key = load_secret_key(priv_key, None).map_err(AuthError::LoadPrivkey)?;

    let hash_alg = find_hash_alg(key.algorithm(), handle).await?;

    let res = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg))
        .await
        .map_err(AuthError::Connection)?;

    AuthResult::try_from(res)
}

async fn auth_cert<H: Handler>(
    priv_key: &Path,
    cert: &Path,
    user: &str,
    handle: &mut Handle<H>,
) -> Result<AuthResult, AuthError> {
    use russh::keys::{load_openssh_certificate, load_secret_key};

    let key = load_secret_key(priv_key, None).map_err(AuthError::LoadPrivkey)?;
    let cert = load_openssh_certificate(cert).map_err(AuthError::LoadCert)?;

    let res = handle
        .authenticate_openssh_cert(user, Arc::new(key), cert)
        .await
        .map_err(AuthError::Connection)?;

    AuthResult::try_from(res)
}

async fn auth_agent<H: Handler>(
    agent: &Path,
    user: &str,
    handle: &mut Handle<H>,
) -> Result<AuthResult, AuthError> {
    use russh::client::AuthResult as RusshResult;
    use russh::keys::agent::{AgentIdentity, client::AgentClient};
    use russh::{AgentAuthError, keys::Error as KeyError};

    let mut agent = AgentClient::connect_uds(agent)
        .await
        .map_err(AuthError::ConnectAgent)?;

    let identities = agent
        .request_identities()
        .await
        .map_err(AuthError::ConnectAgent)?;

    for id in identities {
        let res = match id {
            AgentIdentity::PublicKey { key, .. } => {
                let alg = find_hash_alg(key.algorithm(), handle).await?;
                handle
                    .authenticate_publickey_with(user, key, alg, &mut agent)
                    .await
            }
            AgentIdentity::Certificate { certificate, .. } => {
                let alg = find_hash_alg(certificate.algorithm(), handle).await?;
                handle
                    .authenticate_certificate_with(user, certificate, alg, &mut agent)
                    .await
            }
        };

        match res {
            Ok(RusshResult::Success) => return Ok(AuthResult::Success),
            Ok(RusshResult::Failure {
                partial_success: false,
                ..
            })
            | Err(AgentAuthError::Key(KeyError::AgentFailure)) => {}
            Ok(RusshResult::Failure {
                partial_success: true,
                ..
            }) => return Err(AuthError::MultiStep),
            Err(e) => return Err(AuthError::RequestAgent(e)),
        }
    }

    Ok(AuthResult::Failure)
}

async fn auth<H: Handler>(host: &Host, handle: &mut Handle<H>) -> Result<AuthResult, AuthError> {
    use russh::MethodKind;
    use russh::client::AuthResult as RusshAuthResult;

    let none_result = handle
        .authenticate_none(&host.dest.user)
        .await
        .map_err(AuthError::Connection)?;
    match none_result {
        RusshAuthResult::Success => return Ok(AuthResult::Success),
        RusshAuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            if !remaining_methods.contains(&MethodKind::PublicKey) {
                return Err(AuthError::PubkeyUnsupported);
            }
            if partial_success {
                return Err(AuthError::MultiStep);
            }
        }
    }

    let Some(auth_methods) = &host.auth.auth_methods else {
        return Ok(AuthResult::Failure);
    };

    for method in auth_methods.iter() {
        let res = match method {
            AuthMethod::LocalKey(key) => {
                if let Some(cert) = &host.auth.cert {
                    auth_cert(key, cert, &host.dest.user, handle).await
                } else {
                    auth_pubkey(key, &host.dest.user, handle).await
                }
            }
            AuthMethod::Agent(agent) => auth_agent(agent, &host.dest.user, handle).await,
        }?;

        if res == AuthResult::Success {
            return Ok(AuthResult::Success);
        }
    }

    Ok(AuthResult::Failure)
}
