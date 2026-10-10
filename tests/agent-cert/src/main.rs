use t::Error;
use t::openrussh_client;

use openrussh_client::config::Chain;

fn setup_conf<'a>(append: impl IntoIterator<Item = &'a str>) -> Result<impl std::io::Read, Error> {
    use std::io::Cursor;

    let home = std::env::home_dir().unwrap();
    let default_path = home.join(".ssh/config");
    let default_conf = std::fs::read_to_string(default_path)?;
    let mut conf = String::new();

    {
        let mut it = append.into_iter();
        if let Some(item) = it.next() {
            conf.push_str("Host alice-test\n    ");
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

fn parse_target<'a>(host: &str, append: impl IntoIterator<Item = &'a str>) -> Result<Chain, Error> {
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

fn main() {
    use openrussh_client::connect::Connection;
    use openrussh_client::error::{AuthError, ConnectError};
    use openrussh_client::known_hosts::KnownHosts;

    let mut rt = t::runtime();

    rt.register("agent certificate", async || {
        let host = parse_target("alice-test", ["IdentityAgent $MY_AGENT_SOCK"])?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        let host = parse_target(
            "alice-test",
            [
                "IdentityAgent $MY_AGENT_SOCK",
                "IdentitiesOnly yes",
                "IdentityFile ~/.ssh/id_ed25519.pub",
                "CertificateFile ~/.ssh/id_ed25519-cert.pub",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("expired certificate", async || {
        let host = parse_target(
            "alice-test",
            [
                "IdentityAgent $EXPIRED_AGENT_SOCK",
                "IdentitiesOnly yes",
                "IdentityFile ~/.ssh/id_ed25519.pub",
                "CertificateFile ~/.ssh/dummy/expired-cert.pub",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        match Connection::connect(&host, known_hosts).await {
            Ok(conn) => {
                t::finish(&conn).await?;

                t::error("expected the authentication failed, but succeeded")?;
            }
            Err(ConnectError::AuthFailure) => {}
            Err(e) => {
                t::error(e)?;
            }
        }

        Ok(())
    });

    rt.register("certificate signed by untrusted CA", async || {
        let host = parse_target(
            "alice-test",
            [
                "IdentityAgent $UNTRUSTED_AGENT_SOCK",
                "IdentitiesOnly yes",
                "IdentityFile ~/.ssh/id_ed25519.pub",
                "CertificateFile ~/.ssh/dummy/untrusted-cert.pub",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        match Connection::connect(&host, known_hosts).await {
            Ok(conn) => {
                t::finish(&conn).await?;

                t::error("expected the authentication failed, but succeeded")?;
            }
            Err(ConnectError::AuthFailure) => {}
            Err(e) => {
                t::error(e)?;
            }
        }

        Ok(())
    });

    rt.register("certificate for another key", async || {
        let host = parse_target(
            "alice-test",
            [
                "IdentityAgent $MY_AGENT_SOCK",
                "IdentitiesOnly yes",
                "IdentityFile ~/.ssh/id_ed25519.pub",
                "CertificateFile ~/.ssh/dummy/mismatched-cert.pub",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        match Connection::connect(&host, known_hosts).await {
            Ok(conn) => {
                t::finish(&conn).await?;

                t::error("expected the authentication failed, but succeeded")?;
            }
            Err(ConnectError::AuthError(AuthError::PubkeyMismatch)) => {}
            Err(e) => {
                t::error(e)?;
            }
        }

        Ok(())
    });

    rt.run();
}
