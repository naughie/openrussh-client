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

// Stop forwarding if a request fails or the test times out.
struct ForwardTask<T>(t::tokio::task::JoinHandle<T>);

impl<T> Drop for ForwardTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn main() {
    use openrussh_client::connect::Connection;
    use openrussh_client::error::{LocalForwardError, RusshError};
    use openrussh_client::known_hosts::KnownHosts;
    use openrussh_client::russh::ChannelOpenFailure;

    use t::tokio;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::{TcpListener, UnixListener, UnixStream};
    use tokio::time::{Duration, timeout};

    let mut rt = t::runtime();

    rt.register("TCP forwarding", async || {
        timeout(Duration::from_secs(30), async {
            let host = parse_target(
                "bob-test",
                ["IdentityFile ~/.ssh/id_ed25519", "IdentitiesOnly yes"],
            )?;
            let known_hosts = KnownHosts::parse_default_path()?;
            let conn = Connection::connect(&host, known_hosts).await?;

            let remote_host = std::env::var("MY_TCP_SERVER")?;
            let remote_port = std::env::var("MY_TCP_SERVER_PORT")?.parse::<u16>()?;
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
                let mut task = ForwardTask(forward.spawn_wait());
                (&mut task.0).await??;
                Ok::<(), t::Error>(())
            };

            let request = async {
                let client = reqwest::Client::builder().no_proxy().build()?;
                let response = client
                    .get(format!("http://{local_addr}/test"))
                    .header(reqwest::header::HOST, &remote_host)
                    .header(reqwest::header::CONNECTION, "close")
                    .send()
                    .await?;

                t::assert_eq(response.status(), reqwest::StatusCode::OK, "HTTP status")?;
                t::assert_eq(response.text().await?, "Hello, TCP", "forwarded HTTP body")?;
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
                    .forward_local_tcp(("127.0.0.1", 8889).into(), Some(originator.into()), socket)
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
                let client = reqwest::Client::builder().no_proxy().build()?;
                let response = client
                    .get(format!("http://{local_addr}/test"))
                    .header(reqwest::header::CONNECTION, "close")
                    .send()
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
                let mut task = ForwardTask(forward.spawn_wait());
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
