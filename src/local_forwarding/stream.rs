use super::{Error, LocalForward};

use russh::client::{Handle, Handler};

use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::UnixStream;

use std::io::Error as IoError;

pub async fn forward_stream<'a, H, S>(
    handle: &Handle<H>,
    remote_socket: String,
    mut local_stream: S,
) -> Result<LocalForward<impl Future<Output = Result<(), IoError>> + 'a>, Error>
where
    H: Handler,
    S: AsyncRead + AsyncWrite + Unpin + 'a,
{
    let mut channel = handle
        .channel_open_direct_streamlocal(remote_socket)
        .await
        .map_err(Error::OpenChannel)?
        .into_stream();

    let fut = async move {
        tokio::io::copy_bidirectional(&mut local_stream, &mut channel)
            .await
            .map(|_| ())
    };

    Ok(LocalForward::new(fut))
}

#[cfg(unix)]
pub async fn forward_uds<H>(
    handle: &Handle<H>,
    remote_socket: String,
    local_socket: UnixStream,
) -> Result<LocalForward<impl Future<Output = Result<(), IoError>> + 'static>, Error>
where
    H: Handler,
{
    forward_stream(handle, remote_socket, local_socket).await
}

impl<H: Handler> crate::connect::Connection<H> {
    pub async fn forward_local_stream<'a, S>(
        &self,
        remote_socket: String,
        local_stream: S,
    ) -> Result<LocalForward<impl Future<Output = Result<(), IoError>> + 'a>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        forward_stream(self.handle(), remote_socket, local_stream).await
    }

    #[cfg(unix)]
    pub async fn forward_local_uds(
        &self,
        remote_socket: String,
        local_socket: UnixStream,
    ) -> Result<LocalForward<impl Future<Output = Result<(), IoError>> + 'static>, Error> {
        forward_uds(self.handle(), remote_socket, local_socket).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Auth, Chain, Dest, Host};
    use crate::connect::{Connection, Context, MakeHandlerFn};
    use crate::test_helpers::stop_server;

    use russh::{
        client,
        keys::{PrivateKey, PublicKey, PublicKeyOrCertificate},
        server,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, UnixListener};
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};

    use tempfile::NamedTempFile;

    use std::convert::Infallible;
    use std::fmt;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Arc;

    fn server_config(server_private_key: PrivateKey) -> Arc<server::Config> {
        Arc::new(server::Config {
            keys: vec![server_private_key],
            ..Default::default()
        })
    }

    async fn start_ssh_server_tcp<H>(
        handler: H,
        server_private_key: PrivateKey,
    ) -> (JoinHandle<()>, SocketAddr)
    where
        H: server::Handler<Error = russh::Error> + fmt::Debug + Send + 'static,
    {
        let config = server_config(server_private_key);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let (server_socket, _) = listener.accept().await.unwrap();
            drop(listener);

            let session = server::run_stream(config, server_socket, handler)
                .await
                .unwrap();

            match session.await {
                Ok(()) => {}
                Err(russh::Error::IO(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(error) => panic!("Test SSH server session failed: {error:?}"),
            }
        });

        (task, addr)
    }

    #[derive(Debug)]
    struct ServerHandler {
        client_public_key: PublicKey,
        _task: Option<JoinHandle<()>>,
    }
    impl ServerHandler {
        fn new(client_public_key: PublicKey) -> Self {
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
        ) -> Result<server::Auth, Self::Error> {
            Ok(
                if user == "alice" && public_key.key_data() == self.client_public_key.key_data() {
                    server::Auth::Accept
                } else {
                    server::Auth::reject()
                },
            )
        }

        async fn channel_open_direct_streamlocal(
            &mut self,
            channel: russh::Channel<server::Msg>,
            socket_path: &str,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            use tokio::io::copy_bidirectional;

            let Ok(mut socket) = UnixStream::connect(socket_path).await else {
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
        server_public_key: PublicKey,
    }
    impl ClientHandler {
        fn new(server_public_key: PublicKey) -> Self {
            Self { server_public_key }
        }
    }

    impl client::Handler for ClientHandler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(match server_public_key {
                PublicKeyOrCertificate::PublicKey { key, .. } => {
                    key.key_data() == self.server_public_key.key_data()
                }
                PublicKeyOrCertificate::Certificate(_) => false,
            })
        }
    }

    struct LocalKey {
        key: NamedTempFile,
    }
    impl LocalKey {
        fn priv_key(key: PrivateKey) -> Self {
            use russh::keys::ssh_key::LineEnding;
            let key = key.to_openssh(LineEnding::LF).unwrap();
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

    struct KeyPairs {
        client_public_key: PublicKey,
        client_private_key: PrivateKey,
        server_public_key: PublicKey,
        server_private_key: PrivateKey,
    }
    impl KeyPairs {
        fn rand() -> Self {
            use russh::keys::Algorithm;

            let mut rng = rand::rng();

            let client_private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
            let client_public_key = client_private_key.public_key().clone();

            let server_private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
            let server_public_key = server_private_key.public_key().clone();

            Self {
                client_public_key,
                client_private_key,
                server_public_key,
                server_private_key,
            }
        }
    }

    #[tokio::test]
    async fn forward_local_uds() {
        let key_pair = KeyPairs::rand();
        let (server, addr) = start_ssh_server_tcp(
            ServerHandler::new(key_pair.client_public_key),
            key_pair.server_private_key,
        )
        .await;
        let key = LocalKey::priv_key(key_pair.client_private_key);

        let chain = Chain {
            target: Host {
                dest: test_dest(addr.port()),
                auth: Auth {
                    identities: Some(vec![key.path().to_owned()]),
                    identities_only: true,
                    includes_none: false,
                    ..Default::default()
                },
                tty: Default::default(),
            },
            bastions: None,
        };
        let make_handler = MakeHandlerFn(move |_: &Host| {
            Ok::<_, Infallible>(Context::new(
                ClientHandler::new(key_pair.server_public_key.clone()),
                Default::default(),
            ))
        });
        let conn = Connection::connect(&chain, make_handler).await;
        assert!(conn.is_ok());
        let conn = conn.unwrap();

        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let socket_path = dir.path().join("forward.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let (socket, mut local_socket) = UnixStream::pair().unwrap();
            let forward = conn
                .forward_local_uds(socket_path.to_str().unwrap().to_owned(), socket)
                .await
                .unwrap();
            let greetings = async move {
                let (mut remote_socket, _) = listener.accept().await.unwrap();
                drop(listener);

                let greeting = b"Hello, server!";
                local_socket.write_all(greeting).await.unwrap();
                let mut received = [0; 14];
                remote_socket.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, greeting);

                let greeting = b"Hello, client!";
                remote_socket.write_all(greeting).await.unwrap();
                local_socket.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, greeting);

                local_socket.shutdown().await.unwrap();
                remote_socket.shutdown().await.unwrap();
            };
            let (forward_result, ()) = tokio::join!(forward.wait(), greetings);
            forward_result.unwrap();

            conn.disconnect(russh::Disconnect::ByApplication, "test finished", "")
                .await
                .unwrap();
            stop_server(server).await;
        })
        .await
        .expect("Local UDS forwarding test timed out");
    }

    #[tokio::test]
    async fn forward_local_bytes() {
        let key_pair = KeyPairs::rand();
        let (server, addr) = start_ssh_server_tcp(
            ServerHandler::new(key_pair.client_public_key),
            key_pair.server_private_key,
        )
        .await;
        let key = LocalKey::priv_key(key_pair.client_private_key);

        let chain = Chain {
            target: Host {
                dest: test_dest(addr.port()),
                auth: Auth {
                    identities: Some(vec![key.path().to_owned()]),
                    identities_only: true,
                    includes_none: false,
                    ..Default::default()
                },
                tty: Default::default(),
            },
            bastions: None,
        };
        let make_handler = MakeHandlerFn(move |_: &Host| {
            Ok::<_, Infallible>(Context::new(
                ClientHandler::new(key_pair.server_public_key.clone()),
                Default::default(),
            ))
        });
        let conn = Connection::connect(&chain, make_handler).await;
        assert!(conn.is_ok());
        let conn = conn.unwrap();

        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let socket_path = dir.path().join("forward.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let (local_stream, mut local_socket) = tokio::io::duplex(8);
            let forward = conn
                .forward_local_stream(socket_path.to_str().unwrap().to_owned(), local_stream)
                .await
                .unwrap();
            let greetings = async move {
                let (mut remote_socket, _) = listener.accept().await.unwrap();
                drop(listener);

                let greeting = b"Hello, server!";
                let mut received = [0; 14];
                let (written, read) = tokio::join!(
                    local_socket.write_all(greeting),
                    remote_socket.read_exact(&mut received),
                );
                written.unwrap();
                read.unwrap();
                assert_eq!(&received, greeting);

                let greeting = b"Hello, client!";
                remote_socket.write_all(greeting).await.unwrap();
                local_socket.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, greeting);

                local_socket.shutdown().await.unwrap();
                remote_socket.shutdown().await.unwrap();
            };
            let (forward_result, ()) = tokio::join!(forward.wait(), greetings);
            forward_result.unwrap();

            conn.disconnect(russh::Disconnect::ByApplication, "test finished", "")
                .await
                .unwrap();
            stop_server(server).await;
        })
        .await
        .expect("Local byte stream forwarding test timed out");
    }
}
