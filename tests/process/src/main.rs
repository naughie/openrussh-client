use t::openrussh_client;

use openrussh_client::config::Chain;

fn setup_conf(append: &str) -> Result<impl std::io::Read, t::Error> {
    use std::io::Cursor;

    let home = t::home_dir()?;
    let default_path = home.join(".ssh/config");
    let mut conf = std::fs::read_to_string(default_path)?;
    if !append.is_empty() {
        conf.push_str("Host bob-test\n");
        conf.push_str(append);
    }
    Ok(Cursor::new(conf.into_bytes()))
}

fn parse_target(host: &str, append: &str) -> Result<Chain, t::Error> {
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
    use openrussh_client::error::RusshError;
    use openrussh_client::known_hosts::KnownHosts;
    use openrussh_client::process::{
        Chunk, Command,
        cmd::{Redirect, RedirectDup},
        escape::ExpandCommand,
        shell::Exit,
    };

    use t::tokio;

    let mut rt = t::runtime();

    rt.register("simple command", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new()
            .prog("echo")
            .args(["Hello", "World"])
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(
            String::from_utf8_lossy_owned(output.stdout),
            "Hello World\n",
            "stdout",
        )?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(0), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("redirect", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new()
            .prog("echo")
            .arg("arg1")
            .and()
            .prog("echo")
            .arg("arg2")
            .redirect(Redirect::Stdout {
                to: RedirectDup(2),
                append: false,
            })
            .and()
            .prog("echo")
            .arg("arg3")
            .and()
            .prog("echo")
            .arg("arg4")
            .redirect(Redirect::Stdout {
                to: RedirectDup(2),
                append: false,
            })
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(
            String::from_utf8_lossy_owned(output.stdout),
            "arg1\narg3\n",
            "stdout",
        )?;
        t::assert_eq(
            String::from_utf8_lossy_owned(output.stderr),
            "arg2\narg4\n",
            "stderr",
        )?;
        t::assert_eq(output.status.code(), Some(0), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("failed command", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("false").complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(String::from_utf8_lossy_owned(output.stdout), "", "stdout")?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(1), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("control flows", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new()
            .prog("true")
            .and()
            .prog("echo")
            .arg("ok")
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(
            String::from_utf8_lossy_owned(output.stdout),
            "ok\n",
            "stdout",
        )?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(0), "exit")?;

        let cmd = Command::new()
            .prog("true")
            .or()
            .prog("echo")
            .arg("ok")
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(String::from_utf8_lossy_owned(output.stdout), "", "stdout")?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(0), "exit")?;

        let cmd = Command::new()
            .prog("false")
            .and()
            .prog("echo")
            .arg("ok")
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(String::from_utf8_lossy_owned(output.stdout), "", "stdout")?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(1), "exit")?;

        let cmd = Command::new()
            .prog("false")
            .or()
            .prog("echo")
            .arg("ok")
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(
            String::from_utf8_lossy_owned(output.stdout),
            "ok\n",
            "stdout",
        )?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(0), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("cat stdin", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new().prog("cat").complete(false);
        let mut child = conn.exec(cmd).await?;
        let (writer, mut reader) = child.channel();

        let w_fut = async move {
            writer.write_stdin(&b"Hello World\n"[..]).await?;
            writer.eof().await?;
            Result::<(), RusshError>::Ok(())
        };

        let r_fut = async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            while let Some(chunk) = reader.read_next().await {
                match chunk {
                    Chunk::Stdout(b) => stdout.extend_from_slice(&b),
                    Chunk::Stderr(b) => stderr.extend_from_slice(&b),
                }
            }

            (stdout, stderr)
        };

        let (w_res, (stdout, stderr)) = tokio::join!(w_fut, r_fut);
        t::assert_is_ok(w_res, "failed to write stdin")?;

        let status = child.wait().await;

        t::assert_eq(
            String::from_utf8_lossy_owned(stdout),
            "Hello World\n",
            "stdout",
        )?;
        t::assert_eq(String::from_utf8_lossy_owned(stderr), "", "stderr")?;
        t::assert_eq(status.code(), Some(0), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("expand command", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let cmd = Command::new()
            .prog("echo")
            .arg((
                "my uid is ",
                ExpandCommand::new().prog("id").arg("-u").complete(),
            ))
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;
        t::assert_eq(
            String::from_utf8_lossy_owned(output.stdout),
            "my uid is 1001\n",
            "stdout",
        )?;
        t::assert_eq(String::from_utf8_lossy_owned(output.stderr), "", "stderr")?;
        t::assert_eq(output.status.code(), Some(0), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.register("shell request", async || {
        let host = parse_target("bob-test", "    IdentityFile ~/.ssh/id_ed25519")?;
        let known_hosts = KnownHosts::parse_default_path()?;

        let conn = Connection::connect(&host, known_hosts).await?;

        let mut child = conn.shell().await?;
        let (writer, mut reader) = child.channel();

        let w_fut = async move {
            writer
                .write_stdin(Command::new().prog("echo").arg("Hello").complete(false))
                .await?;
            writer
                .write_stdin(
                    Command::new()
                        .prog("echo")
                        .args(["Hello", "again"])
                        .redirect(Redirect::Stdout {
                            to: RedirectDup(2),
                            append: false,
                        })
                        .complete(false),
                )
                .await?;
            writer
                .write_stdin(
                    Command::new()
                        .prog("echo")
                        .arg("See you")
                        .and()
                        .prog("echo")
                        .arg("Good bye")
                        .redirect(Redirect::Stdout {
                            to: RedirectDup(2),
                            append: false,
                        })
                        .complete(false),
                )
                .await?;
            writer.write_stdin(Exit).await?;
            Result::<(), RusshError>::Ok(())
        };

        let r_fut = async move {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            while let Some(chunk) = reader.read_next().await {
                match chunk {
                    Chunk::Stdout(b) => stdout.extend_from_slice(&b),
                    Chunk::Stderr(b) => stderr.extend_from_slice(&b),
                }
            }

            (stdout, stderr)
        };

        let (w_res, (stdout, stderr)) = tokio::join!(w_fut, r_fut);
        t::assert_is_ok(w_res, "failed to write stdin")?;

        let status = child.wait().await;

        t::assert_eq(
            String::from_utf8_lossy_owned(stdout),
            "Hello\nSee you\n",
            "stdout",
        )?;
        t::assert_eq(
            String::from_utf8_lossy_owned(stderr),
            "Hello again\nGood bye\n",
            "stderr",
        )?;
        t::assert_eq(status.code(), Some(0), "exit")?;

        t::finish(&conn).await?;

        Ok(())
    });

    rt.run();
}
