use t::Error;
use t::openrussh_client;

use openrussh_client::config::Chain;

fn setup_conf<'a>(append: impl IntoIterator<Item = &'a str>) -> Result<impl std::io::Read, Error> {
    use std::io::Cursor;

    let home = std::env::home_dir().unwrap();
    let default_path = home.join(".ssh/config");
    let mut conf = std::fs::read_to_string(default_path)?;

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

    unsafe {
        std::env::remove_var("SSH_AUTH_SOCK");
    }

    let mut rt = t::runtime();

    rt.register("local private key", async || {
        let host = parse_target("bob-test", ["IdentityFile ~/.ssh/id_ed25519"])?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("invalid local private key", async || {
        let host = parse_target("bob-test", ["IdentityFile ~/.ssh/unknown_id"])?;
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

    rt.register("agent by env, try all", async || {
        let host = parse_target("bob-test", ["IdentityAgent $MY_AGENT_SOCK"])?;
        let known_hosts = KnownHosts::parse_default_path()?;

        match Connection::connect(&host, known_hosts).await {
            Ok(conn) => {
                t::finish(&conn).await?;

                t::error("expected the authentication failed, but succeeded")?;
            }
            Err(ConnectError::AuthError(AuthError::RequestAgent(_))) => {}
            Err(e) => {
                t::error(e)?;
            }
        }

        Ok(())
    });

    rt.register("agent by env, IdentitiesOnly yes", async || {
        let host = parse_target(
            "bob-test",
            [
                "IdentityAgent $MY_AGENT_SOCK",
                "IdentitiesOnly yes",
                "IdentityFile  ~/.ssh/id_ed25519.pub",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        let host = parse_target(
            "bob-test",
            [
                "IdentityAgent $MY_AGENT_SOCK",
                "IdentitiesOnly yes",
                "IdentityFile  ~/.ssh/id_ed25519",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        Ok(())
    });

    rt.register(
        "agent with IdentitiesOnly yes, but with invalid key",
        async || {
            let host = parse_target(
                "bob-test",
                [
                    "IdentityAgent $MY_AGENT_SOCK",
                    "IdentitiesOnly yes",
                    "IdentityFile  ~/.ssh/unknown_id.pub",
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
        },
    );

    rt.register("agent by path, try all", async || {
        let host = parse_target("bob-test", ["IdentityAgent ~/.ssh/agent.sock"])?;
        let known_hosts = KnownHosts::parse_default_path()?;

        match Connection::connect(&host, known_hosts).await {
            Ok(conn) => {
                t::finish(&conn).await?;

                t::error("expected the authentication failed, but succeeded")?;
            }
            Err(ConnectError::AuthError(AuthError::RequestAgent(_))) => {}
            Err(e) => {
                t::error(e)?;
            }
        }

        Ok(())
    });

    rt.register("agent by path, IdentitiesOnly yes", async || {
        let host = parse_target(
            "bob-test",
            [
                "IdentityAgent ~/.ssh/agent.sock",
                "IdentitiesOnly yes",
                "IdentityFile  ~/.ssh/id_ed25519.pub",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        let host = parse_target(
            "bob-test",
            [
                "IdentityAgent ~/.ssh/agent.sock",
                "IdentitiesOnly yes",
                "IdentityFile  ~/.ssh/id_ed25519",
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;
        t::finish(&conn).await?;

        Ok(())
    });

    rt.run();
}
