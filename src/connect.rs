use crate::auth::Error as AuthError;
use crate::auth::{AuthMethods, AuthResult, Authenticator};
use crate::config::{Chain, Dest, Host};

use russh::client::Config;
use russh::client::{Handle, Handler};

use tokio::io::{AsyncRead, AsyncWrite};

pub use russh::Disconnect;

use std::sync::Arc;

pub async fn connect<H: Handler + Send + 'static>(
    dest: &Dest,
    auth_methods: AuthMethods<'_>,
    ctx: Context<H>,
) -> Result<Handle<H>, Error<H>> {
    let mut handle = russh::client::connect(ctx.conf, (&*dest.name, dest.port), ctx.handler)
        .await
        .map_err(Error::Establish)?;
    let res = auth(dest, auth_methods, &mut handle)
        .await
        .map_err(Error::AuthError)?;
    if res.is_success() {
        Ok(handle)
    } else {
        Err(Error::AuthFailure)
    }
}

pub async fn connect_stream<S, H>(
    dest: &Dest,
    auth_methods: AuthMethods<'_>,
    stream: S,
    ctx: Context<H>,
) -> Result<Handle<H>, Error<H>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
{
    let mut handle = russh::client::connect_stream(ctx.conf, stream, ctx.handler)
        .await
        .map_err(Error::Establish)?;
    let res = auth(dest, auth_methods, &mut handle)
        .await
        .map_err(Error::AuthError)?;
    if res.is_success() {
        Ok(handle)
    } else {
        Err(Error::AuthFailure)
    }
}

#[derive(Debug, Clone)]
pub struct Context<H> {
    handler: H,
    conf: Arc<Config>,
}

impl<H> Context<H> {
    pub fn new(handler: H, conf: Arc<Config>) -> Self {
        Self { handler, conf }
    }

    pub fn with_default_conf(handler: H) -> Self {
        Self {
            handler,
            conf: Default::default(),
        }
    }

    pub fn into_inner(self) -> (H, Arc<Config>) {
        (self.handler, self.conf)
    }
}

pub trait MakeHandler {
    type Handler: Handler + Send + 'static;
    type Error;

    fn make_handler(&self, host: &Host) -> Result<Context<Self::Handler>, Self::Error>;
}
impl<M: MakeHandler> MakeHandler for &M {
    type Handler = M::Handler;
    type Error = M::Error;

    fn make_handler(&self, host: &Host) -> Result<Context<Self::Handler>, Self::Error> {
        M::make_handler(self, host)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MakeHandlerFn<F>(pub F);

impl<Func, H, E> MakeHandler for MakeHandlerFn<Func>
where
    Func: Fn(&Host) -> Result<Context<H>, E>,
    H: Handler + Send + 'static,
{
    type Handler = H;
    type Error = E;

    fn make_handler(&self, host: &Host) -> Result<Context<Self::Handler>, Self::Error> {
        self.0(host)
    }
}

pub enum Error<H: Handler, M = std::convert::Infallible> {
    AuthError(AuthError),
    AuthFailure,
    Establish(H::Error),
    ProxyJump(russh::Error),
    MakeHandler(M),
}

impl<H: Handler, M> Error<H, M> {
    pub fn failed(&self) -> bool {
        matches!(self, Self::AuthFailure)
    }
}

impl<H: Handler> Error<H> {
    pub fn cast<M>(self) -> Error<H, M> {
        match self {
            Self::AuthError(e) => Error::AuthError(e),
            Self::AuthFailure => Error::AuthFailure,
            Self::Establish(e) => Error::Establish(e),
            Self::ProxyJump(e) => Error::ProxyJump(e),
        }
    }
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
    pub async fn connect<M: MakeHandler<Handler = H>>(
        target: &Chain,
        make_handler: M,
    ) -> Result<Self, Error<H, M::Error>> {
        Self::connect_impl(target, make_handler).await
    }

    async fn connect_impl<M: MakeHandler<Handler = H>>(
        target: &Chain,
        make_handler: M,
    ) -> Result<Self, Error<H, M::Error>> {
        let (first, bastions) = target.iter();

        let handle = if let Some(bastions) = bastions {
            let mut handle = {
                let ctx = make_handler
                    .make_handler(first)
                    .map_err(Error::MakeHandler)?;
                let auth_methods = AuthMethods::from_config(&first.auth);
                connect(&first.dest, auth_methods, ctx)
                    .await
                    .map_err(Error::cast::<M::Error>)?
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
                    let ctx = make_handler
                        .make_handler(bastion.to)
                        .map_err(Error::MakeHandler)?;
                    let auth_methods = AuthMethods::from_config(&bastion.to.auth);
                    connect_stream(&bastion.to.dest, auth_methods, channel.into_stream(), ctx)
                        .await
                        .map_err(Error::cast::<M::Error>)?
                };
            }

            handle
        } else {
            let ctx = make_handler
                .make_handler(first)
                .map_err(Error::MakeHandler)?;
            let auth_methods = AuthMethods::from_config(&first.auth);
            connect(&first.dest, auth_methods, ctx)
                .await
                .map_err(Error::cast::<M::Error>)?
        };

        Ok(Self { handle })
    }
}

async fn auth<H: Handler>(
    dest: &Dest,
    auth_methods: AuthMethods<'_>,
    handle: &mut Handle<H>,
) -> Result<AuthResult, AuthError> {
    let mut auth = Authenticator::new(handle, &dest.user);

    for method in auth_methods.iter() {
        if auth.perform(method).await?.is_success() {
            return Ok(AuthResult::Success);
        }
    }

    Ok(AuthResult::Failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_PRIVATE_KEY1: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBWy0Wd0xWHLlXe81ET/P+ersfuV2xkYc4GrgkwulCc4wAAAJj2GJu/9hib
vwAAAAtzc2gtZWQyNTUxOQAAACBWy0Wd0xWHLlXe81ET/P+ersfuV2xkYc4GrgkwulCc4w
AAAEClrwPfUxUjysdnKG6Pd6sQL+zUwTZvXNa7p0lRr3ITi1bLRZ3TFYcuVd7zURP8/56u
x+5XbGRhzgauCTC6UJzjAAAAEG1hc2F0b25AaG9tZWhvc3QBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    const SERVER_PUBLIC_KEY1: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFbLRZ3TFYcuVd7zURP8/56ux+5XbGRhzgauCTC6UJzj";
    const SERVER_PRIVATE_KEY2: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDQYMPJ3VMDtaVoU71/CVijKJI9N9t0YzhJdvDAinUrzgAAAJia9AUkmvQF
JAAAAAtzc2gtZWQyNTUxOQAAACDQYMPJ3VMDtaVoU71/CVijKJI9N9t0YzhJdvDAinUrzg
AAAEBYYdPCowQZDvual5VN/1Q1+i8f5rPzWfAlyfOdQoF9z9Bgw8ndUwO1pWhTvX8JWKMo
kj0323RjOEl28MCKdSvOAAAAEG1hc2F0b25AaG9tZWhvc3QBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    const SERVER_PUBLIC_KEY2: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINBgw8ndUwO1pWhTvX8JWKMokj0323RjOEl28MCKdSvO";
    const SERVER_PRIVATE_KEY3: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCjmtltMU/u0iQm6clM5e1mgX0KkSO+RwfgG9hKwNKo6AAAAJh5taRqebWk
agAAAAtzc2gtZWQyNTUxOQAAACCjmtltMU/u0iQm6clM5e1mgX0KkSO+RwfgG9hKwNKo6A
AAAEABebqwUftyhWhCcYSOs6MIfsseQTxptNYGJe5ZzbJkS6Oa2W0xT+7SJCbpyUzl7WaB
fQqRI75HB+Ab2ErA0qjoAAAAEG1hc2F0b25AaG9tZWhvc3QBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    const SERVER_PUBLIC_KEY3: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKOa2W0xT+7SJCbpyUzl7WaBfQqRI75HB+Ab2ErA0qjo";

    const CLIENT_PRIVATE_KEY1: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD43aH+Jx73lJqi523JAQ7Ddrzw0nKbivVY7/yYExUh1wAAAJjqyFxY6shc
WAAAAAtzc2gtZWQyNTUxOQAAACD43aH+Jx73lJqi523JAQ7Ddrzw0nKbivVY7/yYExUh1w
AAAEDSP63l5d1prM3F+CpXSNRpJ3c3yIAv6Dx3GoVXzeWjqPjdof4nHveUmqLnbckBDsN2
vPDScpuK9Vjv/JgTFSHXAAAAEG1hc2F0b25AaG9tZWhvc3QBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    const CLIENT_PUBLIC_KEY1: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPjdof4nHveUmqLnbckBDsN2vPDScpuK9Vjv/JgTFSHX";
    const CLIENT_PRIVATE_KEY2: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCNSswS92ve7rX5IcudnSfKzlleSYDpIogXLFyG44XUNwAAAJho9OnaaPTp
2gAAAAtzc2gtZWQyNTUxOQAAACCNSswS92ve7rX5IcudnSfKzlleSYDpIogXLFyG44XUNw
AAAEAvCkLY3n44Q5qbcRwxF7lAm+g4J7jjW7o5SYum8ajZ+Y1KzBL3a97utfkhy52dJ8rO
WV5JgOkiiBcsXIbjhdQ3AAAAEG1hc2F0b25AaG9tZWhvc3QBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    const CLIENT_PUBLIC_KEY2: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII1KzBL3a97utfkhy52dJ8rOWV5JgOkiiBcsXIbjhdQ3";
    const CLIENT_PRIVATE_KEY3: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDpBA9Nmdg1/Ei8u2bx985CDhuF7/CFyhwazrTsDaxX0QAAAJgRPbcpET23
KQAAAAtzc2gtZWQyNTUxOQAAACDpBA9Nmdg1/Ei8u2bx985CDhuF7/CFyhwazrTsDaxX0Q
AAAEDWBKg6L09Xmtg+Nq6ke31w8VCcrQUr1D8RIjTV7/Gv2+kED02Z2DX8SLy7ZvH3zkIO
G4Xv8IXKHBrOtOwNrFfRAAAAEG1hc2F0b25AaG9tZWhvc3QBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    const CLIENT_PUBLIC_KEY3: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOkED02Z2DX8SLy7ZvH3zkIOG4Xv8IXKHBrOtOwNrFfR";

    use crate::auth::{AuthLocalKind, AuthMethod, AuthMethods};

    use russh::{
        client,
        keys::{PublicKey, PublicKeyOrCertificate, decode_secret_key},
        server::{self, Auth},
    };
    use tokio::net::{TcpListener, UnixStream};
    use tokio::task::JoinHandle;

    use tempfile::NamedTempFile;

    use std::fmt;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Arc;

    fn server_config(priv_key: &str) -> Arc<server::Config> {
        let server_private_key = decode_secret_key(priv_key.trim(), None).unwrap();

        Arc::new(server::Config {
            keys: vec![server_private_key],
            ..Default::default()
        })
    }

    async fn start_ssh_server_sock<H>(handler: H, priv_key: &str) -> (JoinHandle<()>, UnixStream)
    where
        H: russh::server::Handler + fmt::Debug + Send + 'static,
        H::Error: fmt::Debug,
    {
        let config = server_config(priv_key);

        let (server_socket, client_socket) = UnixStream::pair().unwrap();

        let task = tokio::spawn(async move {
            let session = server::run_stream(config, server_socket, handler)
                .await
                .unwrap();

            session.await.unwrap();
        });

        (task, client_socket)
    }

    async fn start_ssh_server_tcp<H>(handler: H, priv_key: &str) -> (JoinHandle<()>, SocketAddr)
    where
        H: server::Handler + fmt::Debug + Send + 'static,
        H::Error: fmt::Debug,
    {
        let config = server_config(priv_key);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let (server_socket, _) = listener.accept().await.unwrap();
            drop(listener);

            let session = server::run_stream(config, server_socket, handler)
                .await
                .unwrap();

            session.await.unwrap();
        });

        (task, addr)
    }

    #[derive(Debug)]
    struct ServerHandler {
        client_public_key: &'static str,
        _task: Option<JoinHandle<()>>,
    }
    impl ServerHandler {
        fn new(client_public_key: &'static str) -> Self {
            Self {
                client_public_key,
                _task: None,
            }
        }
    }

    impl server::Handler for ServerHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            user: &str,
            public_key: &PublicKey,
        ) -> Result<Auth, Self::Error> {
            let client_public_key = PublicKey::from_openssh(self.client_public_key.trim()).unwrap();
            Ok(
                if user == "alice" && public_key.key_data() == client_public_key.key_data() {
                    Auth::Accept
                } else {
                    Auth::reject()
                },
            )
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<server::Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            use tokio::{io::copy_bidirectional, net::TcpStream};

            if host_to_connect != "127.0.0.1" {
                drop(reply);
                return Ok(());
            }

            let Ok(port) = u16::try_from(port_to_connect) else {
                drop(reply);
                return Ok(());
            };

            let Ok(mut socket) = TcpStream::connect((host_to_connect, port)).await else {
                drop(reply);
                return Ok(());
            };

            reply.accept().await;

            let task = tokio::spawn(async move {
                let mut stream = channel.into_stream();
                copy_bidirectional(&mut stream, &mut socket).await.ok();
            });
            self._task = Some(task);

            Ok(())
        }
    }

    impl Drop for ServerHandler {
        fn drop(&mut self) {
            if let Some(t) = &self._task {
                t.abort();
            }
        }
    }

    struct ClientHandler {
        server_public_key: &'static str,
    }
    impl ClientHandler {
        fn new(server_public_key: &'static str) -> Self {
            Self { server_public_key }
        }
    }

    impl client::Handler for ClientHandler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            let expected = PublicKey::from_openssh(self.server_public_key.trim()).unwrap();

            Ok(match server_public_key {
                PublicKeyOrCertificate::PublicKey { key, .. } => {
                    key.key_data() == expected.key_data()
                }
                PublicKeyOrCertificate::Certificate(_) => false,
            })
        }
    }

    struct LocalKey {
        key: NamedTempFile,
    }
    impl LocalKey {
        fn priv_key(key: &str) -> Self {
            Self::from_bytes(key.as_bytes())
        }
        fn from_bytes(bytes: &[u8]) -> Self {
            use std::io::Write as _;

            let mut key = NamedTempFile::new().unwrap();
            key.write_all(bytes).unwrap();
            key.flush().unwrap();
            Self { key }
        }
        fn path(&self) -> &Path {
            self.key.path()
        }
    }

    fn test_dest(port: u16) -> Dest {
        Dest {
            name: "127.0.0.1".to_owned(),
            port,
            user: "alice".to_owned(),
        }
    }

    #[tokio::test]
    async fn single_sock() {
        let dest = test_dest(22);

        let (server, sock) =
            start_ssh_server_sock(ServerHandler::new(CLIENT_PUBLIC_KEY1), SERVER_PRIVATE_KEY1)
                .await;
        let key = LocalKey::priv_key(CLIENT_PRIVATE_KEY1);
        let auth = AuthMethod::Local {
            kind: AuthLocalKind::LocalPriv {
                priv_key: key.path(),
            },
        };
        let conn = connect_stream(
            &dest,
            AuthMethods::singleton(auth),
            sock,
            Context::new(ClientHandler::new(SERVER_PUBLIC_KEY1), Default::default()),
        )
        .await;
        assert!(conn.is_ok());
        conn.unwrap()
            .disconnect(Disconnect::ByApplication, "test finished", "")
            .await
            .unwrap();
        server.await.ok();

        let (server, sock) =
            start_ssh_server_sock(ServerHandler::new(CLIENT_PUBLIC_KEY1), SERVER_PRIVATE_KEY1)
                .await;
        let key = LocalKey::priv_key(CLIENT_PRIVATE_KEY2);
        let auth = AuthMethod::Local {
            kind: AuthLocalKind::LocalPriv {
                priv_key: key.path(),
            },
        };
        assert!(
            connect_stream(
                &dest,
                AuthMethods::singleton(auth),
                sock,
                Context::new(ClientHandler::new(SERVER_PUBLIC_KEY1), Default::default())
            )
            .await
            .is_err_and(|e| e.failed())
        );
        server.await.ok();
    }

    #[tokio::test]
    async fn single_tcp() {
        let (server, addr) =
            start_ssh_server_tcp(ServerHandler::new(CLIENT_PUBLIC_KEY1), SERVER_PRIVATE_KEY1).await;
        let dest = test_dest(addr.port());
        let key = LocalKey::priv_key(CLIENT_PRIVATE_KEY1);
        let auth = AuthMethod::Local {
            kind: AuthLocalKind::LocalPriv {
                priv_key: key.path(),
            },
        };
        let conn = connect(
            &dest,
            AuthMethods::singleton(auth),
            Context::new(ClientHandler::new(SERVER_PUBLIC_KEY1), Default::default()),
        )
        .await;
        assert!(conn.is_ok());
        conn.unwrap()
            .disconnect(Disconnect::ByApplication, "test finished", "")
            .await
            .unwrap();
        server.await.ok();

        let (server, addr) =
            start_ssh_server_tcp(ServerHandler::new(CLIENT_PUBLIC_KEY1), SERVER_PRIVATE_KEY1).await;
        let dest = test_dest(addr.port());
        let key = LocalKey::priv_key(CLIENT_PRIVATE_KEY2);
        let auth = AuthMethod::Local {
            kind: AuthLocalKind::LocalPriv {
                priv_key: key.path(),
            },
        };
        assert!(
            connect(
                &dest,
                AuthMethods::singleton(auth),
                Context::new(ClientHandler::new(SERVER_PUBLIC_KEY1), Default::default())
            )
            .await
            .is_err_and(|e| e.failed())
        );
        server.await.ok();
    }

    #[tokio::test]
    async fn bastions() {
        use std::convert::Infallible;
        fn client_handlers(ports: [u16; 3]) -> impl MakeHandler<Error = Infallible> {
            fn make_handler(
                host: &Host,
                ports: [u16; 3],
            ) -> Result<Context<ClientHandler>, Infallible> {
                let port = host.dest.port;

                let key = if ports[0] == port {
                    SERVER_PUBLIC_KEY1
                } else if ports[1] == port {
                    SERVER_PUBLIC_KEY2
                } else if ports[2] == port {
                    SERVER_PUBLIC_KEY3
                } else {
                    unreachable!()
                };

                let handler = ClientHandler::new(key);
                Ok(Context::new(handler, Default::default()))
            }

            MakeHandlerFn(move |host: &Host| make_handler(host, ports))
        }

        use crate::config::Auth;

        let (server1, addr1) =
            start_ssh_server_tcp(ServerHandler::new(CLIENT_PUBLIC_KEY1), SERVER_PRIVATE_KEY1).await;
        let (server2, addr2) =
            start_ssh_server_tcp(ServerHandler::new(CLIENT_PUBLIC_KEY2), SERVER_PRIVATE_KEY2).await;
        let (server3, addr3) =
            start_ssh_server_tcp(ServerHandler::new(CLIENT_PUBLIC_KEY3), SERVER_PRIVATE_KEY3).await;

        let ports = [addr1.port(), addr2.port(), addr3.port()];
        let make_handler = client_handlers(ports);

        let key1 = LocalKey::priv_key(CLIENT_PRIVATE_KEY1);
        let key2 = LocalKey::priv_key(CLIENT_PRIVATE_KEY2);
        let key3 = LocalKey::priv_key(CLIENT_PRIVATE_KEY3);

        let chain = Chain {
            target: Host {
                dest: Dest {
                    name: "127.0.0.1".to_owned(),
                    port: addr3.port(),
                    user: "alice".to_owned(),
                },
                auth: Auth {
                    identities: Some(vec![key3.path().to_owned()]),
                    identities_only: true,
                    includes_none: false,
                    ..Default::default()
                },
            },
            bastions: Some(
                vec![
                    Host {
                        dest: Dest {
                            name: "127.0.0.1".to_owned(),
                            port: addr2.port(),
                            user: "alice".to_owned(),
                        },
                        auth: Auth {
                            identities: Some(vec![key2.path().to_owned()]),
                            identities_only: true,
                            includes_none: false,
                            ..Default::default()
                        },
                    },
                    Host {
                        dest: Dest {
                            name: "127.0.0.1".to_owned(),
                            port: addr1.port(),
                            user: "alice".to_owned(),
                        },
                        auth: Auth {
                            identities: Some(vec![key1.path().to_owned()]),
                            identities_only: true,
                            includes_none: false,
                            ..Default::default()
                        },
                    },
                ]
                .into_boxed_slice(),
            ),
        };

        let conn = Connection::connect(&chain, make_handler).await;
        assert!(conn.is_ok());
        conn.unwrap()
            .disconnect(Disconnect::ByApplication, "test finished", "")
            .await
            .unwrap();

        server3.await.ok();
        server2.await.ok();
        server1.await.ok();
    }
}
