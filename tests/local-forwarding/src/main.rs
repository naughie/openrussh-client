use t::openrussh_client;

use openrussh_client::config::Chain;

fn setup_conf<'a>(
    append: impl IntoIterator<Item = &'a str>,
) -> Result<impl std::io::Read, t::Error> {
    use std::io::Cursor;

    let home = t::home_dir()?;
    let default_path = home.join(".ssh/config");
    let default_conf = std::fs::read_to_string(default_path)?;
    let mut conf = String::new();

    {
        let mut it = append.into_iter();
        if let Some(item) = it.next() {
            conf.push_str("Host bob-test\n    ");
            conf.push_str(item.trim());
            conf.push('\n');
        }
        for item in it {
            conf.push_str("    ");
            conf.push_str(item.trim());
            conf.push('\n');
        }
    }

    conf.push_str(&default_conf);
    Ok(Cursor::new(conf.into_bytes()))
}

fn parse_target<'a>(
    host: &str,
    append: impl IntoIterator<Item = &'a str>,
) -> Result<Chain, t::Error> {
    use openrussh_client::config::Target;
    use openrussh_client::ssh2_config::{ParseRule, SshConfig};
    use std::io::BufReader;

    let conf = {
        let mut rdr = BufReader::new(setup_conf(append)?);
        SshConfig::default().parse(&mut rdr, ParseRule::ALLOW_UNSUPPORTED_FIELDS)?
    };

    let target = Target::parse(host);
    let hosts = target.query(&conf)?;
    Ok(hosts)
}

struct TaskGuard<T>(t::tokio::task::JoinHandle<T>);

impl<T> Drop for TaskGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn main() {
    use http_body_util::{BodyExt as _, Empty};
    use hyper::body::Bytes;
    use hyper::client::conn::{http1, http2};
    use hyper::{Request, StatusCode, Version, header};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use openrussh_client::connect::Connection;
    use openrussh_client::error::{LocalForwardError, RusshError};
    use openrussh_client::known_hosts::KnownHosts;
    use openrussh_client::russh::ChannelOpenFailure;

    use t::tokio;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
    use tokio::time::{Duration, timeout};
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
    use tokio_rustls::{TlsConnector, rustls};

    use std::sync::Arc;

    let mut rt = t::runtime();

    rt.register("TCP forwarding with HTTP/1.1", async || {
        timeout(Duration::from_secs(30), async {
            let host = parse_target(
                "bob-test",
                ["IdentityFile ~/.ssh/id_ed25519", "IdentitiesOnly yes"],
            )?;
            let known_hosts = KnownHosts::parse_default_path()?;
            let conn = Connection::connect(&host, known_hosts).await?;

            let remote_host = std::env::var("MY_TCP_SERVER")?;
            let remote_port = std::env::var("MY_TCP_SERVER_PORT_1")?.parse::<u16>()?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local_addr = listener.local_addr()?;

            let forward = async {
                let (socket, originator) = listener.accept().await?;
                let forward = conn
                    .forward_local_tcp(
                        (remote_host.clone(), remote_port).into(),
                        Some(originator.into()),
                        socket,
                    )
                    .await?;
                let mut task = TaskGuard(forward.spawn_wait());
                (&mut task.0).await??;
                Ok::<(), t::Error>(())
            };

            let request = async {
                let socket = TcpStream::connect(local_addr).await?;
                let (mut sender, connection) = http1::handshake(TokioIo::new(socket)).await?;
                let mut http_task = TaskGuard(tokio::spawn(connection));
                let req = Request::builder()
                    .uri("/test")
                    .version(Version::HTTP_11)
                    .header(header::HOST, &remote_host)
                    .header(header::CONNECTION, "close")
                    .body(Empty::<Bytes>::new())?;
                let resp = sender.send_request(req).await?;

                t::assert_eq(resp.status(), StatusCode::OK, "HTTP status")?;
                t::assert_eq(resp.version(), Version::HTTP_11, "HTTP version")?;
                t::assert_eq(
                    resp.into_body().collect().await?.to_bytes(),
                    &b"Hello, HTTP/1.1"[..],
                    "forwarded HTTP body",
                )?;
                drop(sender);
                (&mut http_task.0).await??;
                Ok::<(), t::Error>(())
            };

            tokio::try_join!(forward, request)?;
            t::finish(&conn).await?;

            Ok(())
        })
        .await?
    });

    rt.register("TCP forwarding with HTTP/2", async || {
        timeout(Duration::from_secs(30), async {
            let host = parse_target(
                "bob-test",
                ["IdentityFile ~/.ssh/id_ed25519", "IdentitiesOnly yes"],
            )?;
            let known_hosts = KnownHosts::parse_default_path()?;
            let conn = Connection::connect(&host, known_hosts).await?;

            let remote_host = std::env::var("MY_TCP_SERVER")?;
            let remote_port = std::env::var("MY_TCP_SERVER_PORT_2")?.parse::<u16>()?;
            let ca_cert_path = std::env::var("MY_TCP_SERVER_CA_CERT")?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from_pem_file(ca_cert_path)?)?;
            let mut tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            tls_config.alpn_protocols = vec![b"h2".to_vec()];
            let tls = TlsConnector::from(Arc::new(tls_config));
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local_addr = listener.local_addr()?;

            let forward = async {
                let (socket, originator) = listener.accept().await?;
                drop(listener);
                let forward = conn
                    .forward_local_tcp(
                        (remote_host.clone(), remote_port).into(),
                        Some(originator.into()),
                        socket,
                    )
                    .await?;
                let mut task = TaskGuard(forward.spawn_wait());
                (&mut task.0).await??;
                Ok::<(), t::Error>(())
            };

            let request = async {
                let socket = TcpStream::connect(local_addr).await?;
                let socket = tls
                    .connect(ServerName::try_from(remote_host.clone())?, socket)
                    .await?;
                t::assert(
                    socket.get_ref().1.alpn_protocol() == Some(b"h2"),
                    "TLS negotiated HTTP/2",
                )?;
                let (mut sender, connection) = http2::Builder::new(TokioExecutor::new())
                    .adaptive_window(false)
                    .initial_stream_window_size(65_535)
                    .initial_connection_window_size(1024 * 1024)
                    .handshake(TokioIo::new(socket))
                    .await?;
                let mut http_task = TaskGuard(tokio::spawn(connection));
                let base_url = format!("https://{remote_host}:{remote_port}");
                let req1 = Request::builder()
                    .uri(format!("{base_url}/download"))
                    .version(Version::HTTP_2)
                    .body(Empty::<Bytes>::new())?;

                let req2 = Request::builder()
                    .uri(format!("{base_url}/test"))
                    .version(Version::HTTP_2)
                    .body(Empty::<Bytes>::new())?;

                let resp1 = sender.send_request(req1).await?;
                t::assert_eq(resp1.status(), StatusCode::OK, "download status")?;
                t::assert_eq(resp1.version(), Version::HTTP_2, "download version")?;
                let mut download = resp1.into_body();

                let mut downloaded = 0;
                while let Some(frame) = download.frame().await {
                    if let Ok(chunk) = frame?.into_data() {
                        downloaded += chunk.len();
                        if downloaded > 0 {
                            break;
                        }
                    }
                }
                t::assert(downloaded > 0, "download started")?;

                let resp2 = sender.send_request(req2).await?;
                t::assert_eq(resp2.status(), StatusCode::OK, "HTTP status")?;
                t::assert_eq(resp2.version(), Version::HTTP_2, "HTTP version")?;
                t::assert_eq(
                    resp2.into_body().collect().await?.to_bytes(),
                    &b"Hello, HTTP/2"[..],
                    "multiplexed HTTP body",
                )?;

                while let Some(frame) = download.frame().await {
                    if let Ok(chunk) = frame?.into_data() {
                        downloaded += chunk.len();
                    }
                }
                t::assert_eq(downloaded, 256 * 1024, "forwarded download length")?;
                drop(download);
                drop(sender);
                (&mut http_task.0).await??;
                Ok::<(), t::Error>(())
            };

            tokio::try_join!(forward, request)?;
            t::finish(&conn).await?;

            Ok(())
        })
        .await?
    });

    rt.register("TCP forwarding connection refused", async || {
        timeout(Duration::from_secs(30), async {
            let host = parse_target(
                "bob-test",
                ["IdentityFile ~/.ssh/id_ed25519", "IdentitiesOnly yes"],
            )?;
            let known_hosts = KnownHosts::parse_default_path()?;
            let conn = Connection::connect(&host, known_hosts).await?;

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local_addr = listener.local_addr()?;

            let forward = async {
                let (socket, originator) = listener.accept().await?;
                let error = conn
                    .forward_local_tcp(("127.0.0.1", 8880).into(), Some(originator.into()), socket)
                    .await
                    .err();

                t::assert(
                    matches!(
                        &error,
                        Some(LocalForwardError::OpenChannel(
                            RusshError::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed)
                        ))
                    ),
                    format!("expected connection refused as SSH ConnectFailed, got {error:?}"),
                )?;
                Ok::<(), t::Error>(())
            };

            let request = async {
                let response = async {
                    let socket = TcpStream::connect(local_addr).await?;
                    let (mut sender, connection) = http1::handshake(TokioIo::new(socket)).await?;
                    let _http_task = TaskGuard(tokio::spawn(connection));
                    let request = Request::builder()
                        .uri("/test")
                        .header(header::HOST, local_addr.to_string())
                        .header(header::CONNECTION, "close")
                        .body(Empty::<Bytes>::new())?;
                    Ok::<_, t::Error>(sender.send_request(request).await?)
                }
                .await;

                t::assert(response.is_err(), "connection refused")?;
                Ok::<(), t::Error>(())
            };

            tokio::try_join!(forward, request)?;
            t::finish(&conn).await?;

            Ok(())
        })
        .await?
    });

    rt.register("UDS forwarding", async || {
        let socket_path = std::env::temp_dir().join(format!(
            "openrussh-local-forwarding-{}.sock",
            std::process::id(),
        ));
        let listener = UnixListener::bind(&socket_path)?;

        let result = timeout(Duration::from_secs(30), async {
            let host = parse_target(
                "bob-test",
                ["IdentityFile ~/.ssh/id_ed25519", "IdentitiesOnly yes"],
            )?;
            let known_hosts = KnownHosts::parse_default_path()?;
            let conn = Connection::connect(&host, known_hosts).await?;
            let remote_socket = std::env::var("MY_SOCKET")?;

            let forward = async {
                let (socket, _) = listener.accept().await?;
                let forward = conn.forward_local_uds(remote_socket, socket).await?;
                let mut task = TaskGuard(forward.spawn_wait());
                (&mut task.0).await??;
                Ok::<(), t::Error>(())
            };

            let messages = async {
                let socket = UnixStream::connect(&socket_path).await?;
                let mut socket = BufReader::new(socket);

                socket.get_mut().write_all(b"Hello, Bob!\n").await?;
                let mut response = String::new();
                socket.read_line(&mut response).await?;
                t::assert_eq(response, "received: Hello, Bob!\n", "first UDS reply")?;

                socket.get_mut().write_all(b"Hello again\n").await?;
                let mut response = String::new();
                socket.read_line(&mut response).await?;
                t::assert_eq(response, "received: Hello again\n", "second UDS reply")?;

                socket.get_mut().write_all(b"\n").await?;
                let mut response = String::new();
                socket.read_line(&mut response).await?;
                t::assert_eq(response, "received: \n", "third UDS reply")?;

                socket
                    .get_mut()
                    .write_all(b"  spaces and \\ backslashes  \n")
                    .await?;
                let mut response = String::new();
                socket.read_line(&mut response).await?;
                t::assert_eq(
                    response,
                    "received:   spaces and \\ backslashes  \n",
                    "fourth UDS reply",
                )?;

                socket.get_mut().shutdown().await?;
                let mut response = String::new();
                t::assert_eq(socket.read_line(&mut response).await?, 0, "UDS EOF")?;
                Ok::<(), t::Error>(())
            };

            tokio::try_join!(forward, messages)?;
            t::finish(&conn).await?;

            Ok::<(), t::Error>(())
        })
        .await;

        drop(listener);
        let cleanup = std::fs::remove_file(socket_path);
        result??;
        cleanup?;

        Ok(())
    });

    rt.run();
}
