use t::openrussh_client;

use openrussh_client::config::Chain;

fn setup_conf<'a>(
    append: impl IntoIterator<Item = (&'a str, &'a [&'a str])>,
) -> Result<impl std::io::Read, t::Error> {
    use std::io::Cursor;

    let home = t::home_dir()?;
    let default_path = home.join(".ssh/config");
    let default_conf = std::fs::read_to_string(default_path)?;
    let mut conf = String::new();

    for (host, settings) in append {
        conf.push_str("Host ");
        conf.push_str(host);
        conf.push('\n');
        for item in settings {
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
    append: impl IntoIterator<Item = (&'a str, &'a [&'a str])>,
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

fn main() {
    use openrussh_client::connect::Connection;
    use openrussh_client::error::{ConnectError, RusshError};
    use openrussh_client::known_hosts::KnownHosts;
    use openrussh_client::process::Command;
    use openrussh_client::russh::ChannelOpenFailure;

    use std::io::ErrorKind;

    let mut rt = t::runtime();

    rt.register("direct connection", async || {
        let host = parse_target(
            "bob1-test",
            [(
                "bob1-test",
                &["IdentityFile ~/.ssh/id_ed25519_bob1", "IdentitiesOnly yes"][..],
            )],
        )?;

        let known_hosts = KnownHosts::parse_default_path()?;
        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("id").arg("-un").complete(false);
        let child = conn.exec(cmd).await?;
        let output = child.wait_with_output().await;

        t::assert_cmd_output(output, "bob1\n", "", Some(0), "id -un")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("one jump", async || {
        let host = parse_target(
            "bob1-test",
            [
                (
                    "bob1-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob1",
                        "ProxyJump bob2-test",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob2-test",
                    &["IdentityFile ~/.ssh/id_ed25519_bob2", "IdentitiesOnly yes"][..],
                ),
            ],
        )?;

        let known_hosts = KnownHosts::parse_default_path()?;
        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("id").arg("-un").complete(false);
        let child = conn.exec(cmd).await?;
        let output = child.wait_with_output().await;

        t::assert_cmd_output(output, "bob1\n", "", Some(0), "id -un")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("two jumps", async || {
        let host = parse_target(
            "bob1-test",
            [
                (
                    "bob1-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob1",
                        "ProxyJump bob3-test,bob2-test",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob2-test",
                    &["IdentityFile ~/.ssh/id_ed25519_bob2", "IdentitiesOnly yes"][..],
                ),
                (
                    "bob3-test",
                    &["IdentityFile ~/.ssh/id_ed25519_bob3", "IdentitiesOnly yes"][..],
                ),
            ],
        )?;

        let known_hosts = KnownHosts::parse_default_path()?;
        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("id").arg("-un").complete(false);
        let child = conn.exec(cmd).await?;
        let output = child.wait_with_output().await;

        t::assert_cmd_output(output, "bob1\n", "", Some(0), "id -un")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("recursive jumps", async || {
        let host = parse_target(
            "bob1-test",
            [
                (
                    "bob1-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob1",
                        "ProxyJump bob2-test",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob2-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob2",
                        "ProxyJump bob3-test",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob3-test",
                    &["IdentityFile ~/.ssh/id_ed25519_bob3", "IdentitiesOnly yes"][..],
                ),
            ],
        )?;

        let known_hosts = KnownHosts::parse_default_path()?;
        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("id").arg("-un").complete(false);
        let child = conn.exec(cmd).await?;
        let output = child.wait_with_output().await;

        t::assert_cmd_output(output, "bob1\n", "", Some(0), "id -un")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("two jumps with multiple identity files", async || {
        let host = parse_target(
            "bob1-test",
            [
                ("bob1-test", &["ProxyJump bob3-test,bob2-test"][..]),
                (
                    "bob*",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob1",
                        "IdentityFile ~/.ssh/id_ed25519_bob2",
                        "IdentityFile ~/.ssh/id_ed25519_bob3",
                        "IdentitiesOnly yes",
                    ][..],
                ),
            ],
        )?;

        let known_hosts = KnownHosts::parse_default_path()?;
        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("id").arg("-un").complete(false);
        let child = conn.exec(cmd).await?;
        let output = child.wait_with_output().await;

        t::assert_cmd_output(output, "bob1\n", "", Some(0), "id -un")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("forwarding disabled on bob1", async || {
        let host = parse_target(
            "bob1-test",
            [
                ("bob1-test", &["ProxyJump bob1"][..]),
                (
                    "bob1*",
                    &["IdentityFile ~/.ssh/id_ed25519_bob1", "IdentitiesOnly yes"][..],
                ),
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        t::assert_connect_failed(
            Connection::connect(&host, known_hosts),
            |e| {
                matches!(
                    e,
                    ConnectError::ProxyJump(RusshError::ChannelOpenFailure(
                        ChannelOpenFailure::AdministrativelyProhibited
                    ))
                )
            },
            "expected administratively prohibited forwarding",
        )
        .await?;

        Ok(())
    });

    rt.register("wrong identity for final target", async || {
        let host = parse_target(
            "bob1-test",
            [
                (
                    "bob1-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob2",
                        "ProxyJump bob2-test",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob2-test",
                    &["IdentityFile ~/.ssh/id_ed25519_bob2", "IdentitiesOnly yes"][..],
                ),
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        t::assert_connect_failed(
            Connection::connect(&host, known_hosts),
            |e| matches!(e, ConnectError::AuthFailure),
            "expected AuthFailure",
        )
        .await?;

        Ok(())
    });

    rt.register("wrong identity for bastion", async || {
        let host = parse_target(
            "bob1-test",
            [
                (
                    "bob1-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob1",
                        "ProxyJump bob2-test",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob2-test",
                    &["IdentityFile ~/.ssh/id_ed25519_bob1", "IdentitiesOnly yes"][..],
                ),
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        t::assert_connect_failed(
            Connection::connect(&host, known_hosts),
            |e| matches!(e, ConnectError::AuthFailure),
            "expected AuthFailure",
        )
        .await?;

        Ok(())
    });

    rt.register("connection refused at bastion", async || {
        let host = parse_target(
            "bob1-test",
            [
                (
                    "bob1-test",
                    &[
                        "IdentityFile ~/.ssh/id_ed25519_bob1",
                        "ProxyJump bob4",
                        "IdentitiesOnly yes",
                    ][..],
                ),
                (
                    "bob4",
                    &[
                        "Port 2224",
                        "User bob2",
                        "IdentityFile ~/.ssh/id_ed25519_bob2",
                        "IdentitiesOnly yes",
                    ][..],
                ),
            ],
        )?;
        let known_hosts = KnownHosts::parse_default_path()?;

        t::assert_connect_failed(
            Connection::connect(&host, known_hosts),
            |e| {
                matches!(
                    e,
                    ConnectError::Establish(RusshError::IO(e))
                        if e.kind() == ErrorKind::ConnectionRefused
                )
            },
            "expected connection refused",
        )
        .await?;

        Ok(())
    });

    rt.run();
}
