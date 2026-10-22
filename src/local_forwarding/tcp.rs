use super::{Error, LocalForward};

use russh::client::{Handle, Handler};

use tokio::net::TcpStream;

use std::io::Error as IoError;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub struct Address {
    pub host: String,
    pub port: u16,
}

impl From<SocketAddrV4> for Address {
    fn from(value: SocketAddrV4) -> Self {
        Self {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}
impl From<SocketAddrV6> for Address {
    fn from(value: SocketAddrV6) -> Self {
        Self {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}
impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}
impl From<(String, u16)> for Address {
    fn from(value: (String, u16)) -> Self {
        let (host, port) = value;
        Self { host, port }
    }
}
impl From<(&str, u16)> for Address {
    fn from(value: (&str, u16)) -> Self {
        let (host, port) = value;
        Self {
            host: host.to_owned(),
            port,
        }
    }
}

pub async fn forward_tcp<H>(
    handle: &Handle<H>,
    connect_to: Address,
    originator: Option<Address>,
    mut socket: TcpStream,
) -> Result<LocalForward<impl Future<Output = Result<(), IoError>> + 'static>, Error>
where
    H: Handler,
{
    let (originator_host, originator_port) = originator
        .map(|addr| (addr.host, addr.port))
        .unwrap_or_else(|| ("127.0.0.1".to_owned(), 0));

    let mut channel = handle
        .channel_open_direct_tcpip(
            connect_to.host,
            connect_to.port as u32,
            originator_host,
            originator_port as u32,
        )
        .await
        .map_err(Error::OpenChannel)?
        .into_stream();

    let fut = async move {
        tokio::io::copy_bidirectional(&mut socket, &mut channel)
            .await
            .map(|_| ())
    };

    Ok(LocalForward::new(fut))
}

impl<H: Handler> crate::connect::Connection<H> {
    pub async fn forward_local_tcp(
        &self,
        connect_to: Address,
        originator: Option<Address>,
        socket: TcpStream,
    ) -> Result<LocalForward<impl Future<Output = Result<(), IoError>> + 'static>, Error> {
        forward_tcp(self.handle(), connect_to, originator, socket).await
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
    use tokio::net::TcpListener;
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
    async fn forward_local_tcp() {
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
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = listener.local_addr().unwrap();

            let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut local_socket = TcpStream::connect(local_listener.local_addr().unwrap())
                .await
                .unwrap();
            let (socket, _) = local_listener.accept().await.unwrap();
            drop(local_listener);

            let forward = conn
                .forward_local_tcp(target_addr.into(), None, socket)
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
        .expect("Local TCP forwarding test timed out");
    }
}
