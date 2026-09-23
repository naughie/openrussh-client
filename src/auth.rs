//! Provides various authentication methods loaded from an OpenSSH config.
//!
//! The supported authentication methods are listed as the [`AuthMethod`] type.

use crate::config::Auth as AuthConfig;

use russh::client::{Handle, Handler};
use russh::keys::PublicKey;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};

use tokio::net::UnixStream;

use std::path::Path;

/// The authentication error. It is likely to mean unexpected, unrecoverable errors, rather than the
/// authentication failure.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Private key is not configured.
    NoPrivateKey,
    /// `IdentitiesOnly` is `yes`, but no valid `IdentityFile` are found.
    NoIdentityFilter,

    /// Could not load the private key from file.
    LoadPrivkey(russh::keys::Error),
    /// Could not load the certificate from file.
    LoadCert(russh::keys::ssh_key::Error),

    /// Public keys, one given by `IdentityFile` and one extracted from `CertificateFile`, are
    /// not equal.
    PubkeyMismatch,

    /// Failed to connect to the SSH agent.
    ConnectAgent(russh::keys::Error),
    /// The agent could not sign.
    RequestAgent(russh::AgentAuthError),

    /// Unexpected errors by a [`Handle`].
    Connection(russh::Error),

    /// `pubkey` authentication is not support on the server.
    PubkeyUnsupported,
    /// The server requires the multi-step authentication, but we do not support it.
    MultiStep,
}

/// The authentication succeeded or failed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure,
}

impl AuthResult {
    fn try_from(res: russh::client::AuthResult) -> Result<Self, Error> {
        use russh::MethodKind;
        use russh::client::AuthResult as RusshAuthResult;

        match res {
            RusshAuthResult::Success => Ok(Self::Success),
            RusshAuthResult::Failure {
                remaining_methods,
                partial_success,
            } => {
                if !remaining_methods.contains(&MethodKind::PublicKey) {
                    Err(Error::PubkeyUnsupported)
                } else if partial_success {
                    Err(Error::MultiStep)
                } else {
                    Ok(AuthResult::Failure)
                }
            }
        }
    }

    pub fn is_success(self) -> bool {
        self == Self::Success
    }

    pub fn is_failure(self) -> bool {
        self == Self::Failure
    }
}

use helper::*;
mod helper {
    use super::AuthResult;
    use super::Error;

    use russh::client::{Handle, Handler};
    use russh::keys::agent::AgentIdentity;
    use russh::keys::agent::client::{AgentClient, AgentStream};
    use russh::keys::{Algorithm, HashAlg};
    use russh::keys::{Certificate, PrivateKey, PublicKey};

    use russh::AgentAuthError as RusshAgentError;
    use russh::client::AuthResult as RusshResult;

    use tokio::net::UnixStream;

    use std::path::Path;
    use std::sync::Arc;

    #[cfg(not(feature = "rsa"))]
    pub(super) async fn find_hash_alg<H: Handler>(
        _key_alg: Algorithm,
        _handle: &mut Handle<H>,
    ) -> Result<Option<HashAlg>, Error> {
        Ok(None)
    }

    #[cfg(feature = "rsa")]
    pub(super) async fn find_hash_alg<H: Handler>(
        key_alg: Algorithm,
        handle: &mut Handle<H>,
    ) -> Result<Option<HashAlg>, Error> {
        if matches!(key_alg, Algorithm::Rsa { .. }) {
            let res = handle
                .best_supported_rsa_hash()
                .await
                .map_err(Error::Connection)?
                .flatten();
            Ok(res)
        } else {
            Ok(None)
        }
    }

    pub(super) fn load_pub_local(pub_key: &Path) -> Result<PublicKey, Error> {
        russh::keys::load_public_key(pub_key).map_err(Error::LoadPrivkey)
    }

    pub(super) fn load_priv_local(priv_key: &Path) -> Result<PrivateKey, Error> {
        russh::keys::load_secret_key(priv_key, None).map_err(Error::LoadPrivkey)
    }

    pub(super) fn load_cert_local(cert: &Path) -> Result<Certificate, Error> {
        russh::keys::load_openssh_certificate(cert).map_err(Error::LoadCert)
    }

    pub(super) async fn auth_by_priv_local<H: Handler>(
        priv_key: PrivateKey,
        user: &str,
        handle: &mut Handle<H>,
    ) -> Result<AuthResult, Error> {
        use russh::keys::PrivateKeyWithHashAlg;

        let hash_alg = find_hash_alg(priv_key.algorithm(), handle).await?;

        let res = handle
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(Arc::new(priv_key), hash_alg),
            )
            .await
            .map_err(Error::Connection)?;

        AuthResult::try_from(res)
    }

    pub(super) fn check_pub_equality_against_priv(
        priv_key: &PrivateKey,
        cert: &Certificate,
    ) -> Result<(), Error> {
        let pub_of_key = PublicKey::from(priv_key);
        check_pub_equality_against_pub(&pub_of_key, cert)
    }

    pub(super) fn check_pub_equality_against_pub(
        pub_key: &PublicKey,
        cert: &Certificate,
    ) -> Result<(), Error> {
        let pub_of_cert = cert.public_key();

        if pub_key.key_data() == pub_of_cert {
            Ok(())
        } else {
            Err(Error::PubkeyMismatch)
        }
    }

    pub(super) async fn auth_by_cert_local<H: Handler>(
        cert: Certificate,
        priv_key: PrivateKey,
        user: &str,
        handle: &mut Handle<H>,
    ) -> Result<AuthResult, Error> {
        let res = handle
            .authenticate_openssh_cert(user, Arc::new(priv_key), cert)
            .await
            .map_err(Error::Connection)?;

        AuthResult::try_from(res)
    }

    pub(super) async fn load_agent(agent: &Path) -> Result<AgentClient<UnixStream>, Error> {
        AgentClient::connect_uds(agent)
            .await
            .map_err(Error::ConnectAgent)
    }

    fn signer_result(res: Result<RusshResult, RusshAgentError>) -> Result<AuthResult, Error> {
        use russh::keys::Error as KeyError;

        match res {
            Ok(RusshResult::Success) => Ok(AuthResult::Success),
            Ok(RusshResult::Failure {
                partial_success: false,
                ..
            })
            | Err(RusshAgentError::Key(KeyError::AgentFailure)) => Ok(AuthResult::Failure),
            Ok(RusshResult::Failure {
                partial_success: true,
                ..
            }) => Err(Error::MultiStep),
            Err(e) => Err(Error::RequestAgent(e)),
        }
    }

    pub(super) async fn auth_by_pub_agent<H, A>(
        pub_key: PublicKey,
        agent: &mut AgentClient<A>,
        user: &str,
        handle: &mut Handle<H>,
    ) -> Result<AuthResult, Error>
    where
        H: Handler,
        A: AgentStream + Unpin + Send,
    {
        let alg = find_hash_alg(pub_key.algorithm(), handle).await?;
        let res = handle
            .authenticate_publickey_with(user, pub_key, alg, agent)
            .await;

        signer_result(res)
    }

    pub(super) async fn auth_by_cert_agent<H, A>(
        cert: Certificate,
        agent: &mut AgentClient<A>,
        user: &str,
        handle: &mut Handle<H>,
    ) -> Result<AuthResult, Error>
    where
        H: Handler,
        A: AgentStream + Unpin + Send,
    {
        let alg = find_hash_alg(cert.algorithm(), handle).await?;
        let res = handle
            .authenticate_certificate_with(user, cert, alg, agent)
            .await;

        signer_result(res)
    }

    pub(super) async fn all_identities<A>(
        agent: &mut AgentClient<A>,
    ) -> Result<Vec<AgentIdentity>, Error>
    where
        A: AgentStream + Unpin,
    {
        agent
            .request_identities()
            .await
            .map_err(Error::ConnectAgent)
    }
}

/// Performs the SSH authentication.
///
/// The type parameter `A` means either 1) the unit type `()`, indicating that you use no SSH agents
/// for the next authentication request, or 2) an [`AgentClient`] you initialized elsewhere or
/// during the [`perform()`](Authenticator::perform()) method.
pub struct Authenticator<'a, H: Handler, A = ()> {
    handle: &'a mut Handle<H>,
    user: &'a str,
    agent: A,
}

impl<'a, H: Handler> Authenticator<'a, H, ()> {
    /// Creates an [`Authenticator`] with empty [`AgentClient`]; that is, does not use any SSH
    /// agents in the next authentication.
    pub fn new(handle: &'a mut Handle<H>, user: &'a str) -> Self {
        Self {
            handle,
            user,
            agent: (),
        }
    }

    /// Performs authentication. It automatically calls [`Authenticator::load_agent()`] with the
    /// `agent` (if any) given by the `method`.
    ///
    /// It then invokes an individual authentication method on [`Authenticator`].
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn perform(&mut self, method: AuthMethod<'_>) -> Result<AuthResult, Error> {
        self::auth(self.handle, self.user, method).await
    }
}

impl<'a, H: Handler, A> Authenticator<'a, H, A> {
    /// Drops the current SSH agent (type parameter `A`) and sets the new agent.
    pub fn set_agent<NewA>(self, agent: NewA) -> Authenticator<'a, H, NewA> {
        Authenticator {
            handle: self.handle,
            user: self.user,
            agent,
        }
    }

    /// Drops the current SSH agent (type parameter `A`) and sets the new agent loaded from the
    /// socket at `agent`.
    pub async fn load_agent(
        self,
        agent: &Path,
    ) -> Result<Authenticator<'a, H, AgentClient<UnixStream>>, Error> {
        let agent = load_agent(agent).await?;
        Ok(self.set_agent(agent))
    }
}

impl<'a, H: Handler> Authenticator<'a, H, ()> {
    /// Performs the authentication method `none`.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn none(&mut self) -> Result<AuthResult, Error> {
        let res = self
            .handle
            .authenticate_none(self.user)
            .await
            .map_err(Error::Connection)?;
        AuthResult::try_from(res)
    }

    /// Performs the authentication method `pubkey` with the public key contained in `priv_key`,
    /// signed by `priv_key`.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn local_priv_key(&mut self, priv_key: &Path) -> Result<AuthResult, Error> {
        let priv_key = helper::load_priv_local(priv_key)?;
        helper::auth_by_priv_local(priv_key, self.user, self.handle).await
    }

    /// Performs the authentication method `pubkey` with the certificate `cert`, signed by
    /// `priv_key`. It returns [`Err(Error::PubkeyMismatch)`](Error::PubkeyMismatch) if the two
    /// public keys, one from `cert` and the other from `priv_key`, do not coincide.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn local_cert(&mut self, cert: &Path, priv_key: &Path) -> Result<AuthResult, Error> {
        let cert = helper::load_cert_local(cert)?;
        let priv_key = helper::load_priv_local(priv_key)?;

        helper::check_pub_equality_against_priv(&priv_key, &cert)?;

        helper::auth_by_cert_local(cert, priv_key, self.user, self.handle).await
    }
}

impl<'a, H: Handler, S: AgentStream + Unpin + Send> Authenticator<'a, H, AgentClient<S>> {
    /// Performs the authentication method `pubkey` with the given SSH agent.
    ///
    /// It tries [all identities](AgentClient::request_identities()) obtained from the agent,
    /// serving one by one, signed by the agent.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn all_in_agent(&mut self) -> Result<AuthResult, Error> {
        let identities = helper::all_identities(&mut self.agent).await?;

        for id in identities {
            let res = match id {
                AgentIdentity::PublicKey { key, .. } => {
                    helper::auth_by_pub_agent(key, &mut self.agent, self.user, self.handle).await
                }
                AgentIdentity::Certificate { certificate, .. } => {
                    helper::auth_by_cert_agent(certificate, &mut self.agent, self.user, self.handle)
                        .await
                }
            }?;

            if res.is_success() {
                return Ok(AuthResult::Success);
            }
        }

        Ok(AuthResult::Failure)
    }

    /// Performs the authentication method `pubkey` with the given SSH agent.
    ///
    /// It loads the `priv_key`, extracts the public key from the private key, and serves this
    /// public key signed by the agent. It does not use the private key for signing.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn local_priv_key(&mut self, priv_key: &Path) -> Result<AuthResult, Error> {
        let priv_key = helper::load_priv_local(priv_key)?;
        let pub_key = PublicKey::from(&priv_key);
        helper::auth_by_pub_agent(pub_key, &mut self.agent, self.user, self.handle).await
    }

    /// Performs the authentication method `pubkey` with the given SSH agent.
    ///
    /// It loads the `pub_key` and have it signed by the agent.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn local_pub_key(&mut self, pub_key: &Path) -> Result<AuthResult, Error> {
        let pub_key = helper::load_pub_local(pub_key)?;
        helper::auth_by_pub_agent(pub_key, &mut self.agent, self.user, self.handle).await
    }

    /// Performs the authentication method `pubkey` with the given SSH agent.
    ///
    /// It loads both the certificate `cert` and the private key `priv_key`,
    /// then serves the certificate signed by the agent.
    ///
    /// It returns [`Err(Error::PubkeyMismatch)`](Error::PubkeyMismatch) if the two
    /// public keys, one from `cert` and the other from `priv_key`, do not coincide.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn local_cert_priv_key(
        &mut self,
        cert: &Path,
        priv_key: &Path,
    ) -> Result<AuthResult, Error> {
        let cert = helper::load_cert_local(cert)?;
        let priv_key = helper::load_priv_local(priv_key)?;

        helper::check_pub_equality_against_priv(&priv_key, &cert)?;

        helper::auth_by_cert_agent(cert, &mut self.agent, self.user, self.handle).await
    }

    /// Performs the authentication method `pubkey` with the given SSH agent.
    ///
    /// It loads both the certificate `cert` and the public key `pub_key`,
    /// then serves the certificate signed by the agent.
    ///
    /// It returns [`Err(Error::PubkeyMismatch)`](Error::PubkeyMismatch) if the two
    /// public keys, one from `cert` and the other from `pub_key`, do not coincide.
    ///
    /// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
    /// while `Err` suggests that you stop the authentication immediately.
    pub async fn local_cert_pub_key(
        &mut self,
        cert: &Path,
        pub_key: &Path,
    ) -> Result<AuthResult, Error> {
        let cert = helper::load_cert_local(cert)?;
        let pub_key = helper::load_pub_local(pub_key)?;

        helper::check_pub_equality_against_pub(&pub_key, &cert)?;

        helper::auth_by_cert_agent(cert, &mut self.agent, self.user, self.handle).await
    }
}

/// Represents the authentication methods that needs to be signed by the local private key.
#[derive(Debug, Clone, Copy)]
pub enum AuthLocalKind<'a> {
    /// Authentication by the public-private key pair extracted from the given path.
    LocalPriv { priv_key: &'a Path },
    /// Shows the server the certificate, signed by the given private key. The public keys of the
    /// certificate and that of the private key must identical.
    LocalCert { cert: &'a Path, priv_key: &'a Path },
}

/// Connects to an SSH agent to sign the payload.
#[derive(Debug, Clone, Copy)]
pub enum AuthAgentKind<'a> {
    /// Tries all the identities returned by [`AgentClient::request_identities()`] first, then
    /// fallback to [`AuthLocalKind`].
    Full { fallback: Option<AuthLocalKind<'a>> },
    /// Uses the public key, extracted from the given private key, signed by the SSH agent. Fallback
    /// to [`AuthLocalKind::LocalPriv`].
    LocalPriv { priv_key: &'a Path },
    /// Uses the public key, signed by the SSH agent.
    LocalPub { pub_key: &'a Path },
    /// Uses the certificate, signed by the SSH agent. The private key is used only for checking the
    /// public key matching (i.e., checking if the public key in the certificate and that from the
    /// private key are equal). Fallback to [`AuthLocalKind::LocalCert`].
    LocalCertPriv { cert: &'a Path, priv_key: &'a Path },
    /// Uses the certificate, signed by the SSH agent. The public key is used only for checking if
    /// the public key in the certificate coincides the given public key.
    LocalCertPub { cert: &'a Path, pub_key: &'a Path },
}

/// Authentication methods.
#[derive(Debug, Clone, Copy)]
pub enum AuthMethod<'a> {
    /// Uses local keys only (no SSH agent).
    Local { kind: AuthLocalKind<'a> },
    /// Uses an SSH agent with or without local files as fallback.
    Agent {
        agent: &'a Path,
        kind: AuthAgentKind<'a>,
    },
}

impl<'a> AuthMethod<'a> {
    /// Converts the OpenSSH configurations to an [`AuthMethod`].
    pub fn from_config(auth: &'a AuthConfig) -> Result<Self, Error> {
        if let Some(agent) = &auth.agent {
            if auth.identities_only {
                if let Some(path) = auth.identities.as_ref().and_then(|v| v.first()) {
                    match (check_pub_or_priv(path), &auth.cert) {
                        (KeyType::Error, _) => Err(Error::NoIdentityFilter),
                        (KeyType::MaybePrivate, Some(cert)) => Ok(AuthMethod::Agent {
                            agent,
                            kind: AuthAgentKind::LocalCertPriv {
                                cert,
                                priv_key: path,
                            },
                        }),
                        (KeyType::MaybePrivate, None) => Ok(AuthMethod::Agent {
                            agent,
                            kind: AuthAgentKind::LocalPriv { priv_key: path },
                        }),
                        (KeyType::MaybePublic, Some(cert)) => Ok(AuthMethod::Agent {
                            agent,
                            kind: AuthAgentKind::LocalCertPub {
                                cert,
                                pub_key: path,
                            },
                        }),
                        (KeyType::MaybePublic, None) => Ok(AuthMethod::Agent {
                            agent,
                            kind: AuthAgentKind::LocalPub { pub_key: path },
                        }),
                    }
                } else {
                    Err(Error::NoIdentityFilter)
                }
            } else {
                let fallback = if let Some(path) = auth.identities.as_ref().and_then(|v| v.first())
                {
                    match (check_pub_or_priv(path), &auth.cert) {
                        (KeyType::Error | KeyType::MaybePublic, _) => None,
                        (KeyType::MaybePrivate, Some(cert)) => Some(AuthLocalKind::LocalCert {
                            cert,
                            priv_key: path,
                        }),
                        (KeyType::MaybePrivate, None) => {
                            Some(AuthLocalKind::LocalPriv { priv_key: path })
                        }
                    }
                } else {
                    None
                };

                Ok(AuthMethod::Agent {
                    agent,
                    kind: AuthAgentKind::Full { fallback },
                })
            }
        } else {
            if let Some(path) = auth.identities.as_ref().and_then(|v| v.first())
                && check_pub_or_priv(path) == KeyType::MaybePrivate
            {
                if let Some(cert) = &auth.cert {
                    Ok(Self::Local {
                        kind: AuthLocalKind::LocalCert {
                            cert,
                            priv_key: path,
                        },
                    })
                } else {
                    Ok(Self::Local {
                        kind: AuthLocalKind::LocalPriv { priv_key: path },
                    })
                }
            } else {
                Err(Error::NoPrivateKey)
            }
        }
    }
}

/// Whether a local key file looks like a public key or like a private key.
///
/// It does not guarantee that the file *is* a public key or a private key, nor does it guarantee
/// that the file does not contain the malformed data.
/// It is just a hint for
/// extracting [`AuthMethod`] from the path settings in the OpenSSH config.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    MaybePublic,
    MaybePrivate,
    Error,
}

/// It is intended to be sync (no [`tokio::fs`](tokio)).
pub fn check_pub_or_priv(path: &Path) -> KeyType {
    fn check_impl(path: &Path) -> std::io::Result<KeyType> {
        use std::fs::File;
        use std::io::{BufRead as _, BufReader};

        let mut f = BufReader::new(File::open(path)?);

        let mut buf = String::new();
        f.read_line(&mut buf)?;

        let line = buf.trim_ascii_start();
        if line.is_empty() {
            return Ok(KeyType::Error);
        }

        if line.starts_with("-----BEGIN ") || line.starts_with("---- BEGIN ") {
            if line.contains("PRIVATE") {
                Ok(KeyType::MaybePrivate)
            } else if line.contains("PUBLIC") {
                Ok(KeyType::MaybePublic)
            } else {
                Ok(KeyType::Error)
            }
        } else if line.contains(' ') {
            Ok(KeyType::MaybePublic)
        } else {
            Ok(KeyType::Error)
        }
    }

    if let Some(ext) = path.extension()
        && ext == "pub"
    {
        return KeyType::MaybePublic;
    }

    check_impl(path).unwrap_or(KeyType::Error)
}

/// Performs authentication. It automatically calls [`Authenticator::load_agent()`] with the
/// `agent` (if any) given by the `method`.
///
/// It then invokes an individual authentication method on [`Authenticator`].
///
/// `Ok(AuthResult::Failure)` means "failed, but you can try the next pubkey authentication,"
/// while `Err` suggests that you stop the authentication immediately.
pub async fn auth<H: Handler>(
    handle: &mut Handle<H>,
    user: &str,
    method: AuthMethod<'_>,
) -> Result<AuthResult, Error> {
    match method {
        AuthMethod::Local {
            kind: AuthLocalKind::LocalPriv { priv_key },
        } => {
            let mut auth = Authenticator::new(handle, user);
            auth.local_priv_key(priv_key).await
        }
        AuthMethod::Local {
            kind: AuthLocalKind::LocalCert { cert, priv_key },
        } => {
            let mut auth = Authenticator::new(handle, user);
            auth.local_cert(cert, priv_key).await
        }
        AuthMethod::Agent { agent, kind } => {
            let mut auth = Authenticator::new(handle, user).load_agent(agent).await?;

            match kind {
                AuthAgentKind::Full { fallback } => {
                    if auth.all_in_agent().await?.is_success() {
                        Ok(AuthResult::Success)
                    } else if let Some(fallback) = fallback {
                        match fallback {
                            AuthLocalKind::LocalPriv { priv_key } => {
                                let mut auth = Authenticator::new(handle, user);
                                auth.local_priv_key(priv_key).await
                            }
                            AuthLocalKind::LocalCert { cert, priv_key } => {
                                let mut auth = Authenticator::new(handle, user);
                                auth.local_cert(cert, priv_key).await
                            }
                        }
                    } else {
                        Ok(AuthResult::Failure)
                    }
                }
                AuthAgentKind::LocalPriv { priv_key } => {
                    if auth.local_priv_key(priv_key).await?.is_success() {
                        Ok(AuthResult::Success)
                    } else {
                        let mut auth = Authenticator::new(handle, user);
                        auth.local_priv_key(priv_key).await
                    }
                }
                AuthAgentKind::LocalPub { pub_key } => auth.local_pub_key(pub_key).await,
                AuthAgentKind::LocalCertPriv { cert, priv_key } => {
                    if auth.local_cert_priv_key(cert, priv_key).await?.is_success() {
                        Ok(AuthResult::Success)
                    } else {
                        let mut auth = Authenticator::new(handle, user);
                        auth.local_cert(cert, priv_key).await
                    }
                }
                AuthAgentKind::LocalCertPub { cert, pub_key } => {
                    auth.local_cert_pub_key(cert, pub_key).await
                }
            }
        }
    }
}
