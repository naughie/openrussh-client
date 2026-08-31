# OpenRussh Client

OpenRussh client is an implementation of a SSH client using the [Russh](https://crates.io/crates/russh) crate.

It reads OpenSSH's `~/.ssh/config` and `~/.ssh/known_hosts`, hence "OpenRussh".


# OpenSSH Config

Supported directives:

- `Host`
- `Port`
- `User`
- `IdentityFile`
- `IdentityAgent` (or `${SSH_AUTH_SOCK}`)
- `CertificateFile`


## SSH Features

We do not support X11 forwarding and agent forwarding for the security reason.

Plan to support:

- Local port forwarding (OpenSSH's `-L` option)
- Local socket forwarding (OpenSSH's `-L` option)
- Remote port forwarding (OpenSSH's `-R` option)
- Remote socket forwarding (OpenSSH's `-R` option)
- PTY
- Limited support for FIDO2
- More flexible configuration of combination of `IdentityFile` / `CertificateFile` and `IdentityAgent`


# Digital Signature Algorithms

We deliberately support only the following host key / certificate algorithms when reading `known_hosts`:

- ssh-ed25519
- ecdsa-sha2-nistp521
- ecdsa-sha2-nistp384
- ecdsa-sha2-nistp256
- rsa-sha2-512
- rsa-sha2-256


# Usage

`Cargo.toml`:

```toml
[dependencies]
tokio = { version = "1.53.1", features = ["full"] }
openrussh-client = { path = "../openrussh-client" }
```

`src/main.rs`:

```rust
use openrussh_client::config::Target;
use openrussh_client::connect::Connection;
use openrussh_client::known_hosts::KnownHosts;
use openrussh_client::process::Chunk;
use openrussh_client::process::Command;
use openrussh_client::process::escape::{Env, ExpandCommand};
use openrussh_client::process::shell::Exit;
use openrussh_client::ssh2_config::{ParseRule, SshConfig};

use openrussh_client::connect::Disconnect;
use openrussh_client::error::RusshError;

use tokio::io::AsyncWriteExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conf = SshConfig::parse_default_file(ParseRule::ALLOW_UNSUPPORTED_FIELDS)?;

    // Format: [user@]host[:port]
    let target = Target::parse("your-host");
    let hosts = target.query(&conf)?;

    let known_hosts = KnownHosts::parse_default_path()?;

    let conn = Connection::connect(
        &hosts,
        // `KnownHosts` generates `KnownHostsHandler` that is tied with the target host
        |host| known_hosts.handler(&host.dest.name, host.dest.port),
        // Updates host key / certificate algorithms during the handshake
        |handler, conf| handler.update_preferred_config(&mut conf.preferred),
    )
    .await?;

    println!("SSH established");

    // Example 1: echo Hello World
    {
        let cmd = Command::new()
            .prog("echo")
            .args(["Hello", "World"])
            // true: background (`&`) / false: foreground (`;`)
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;

        println!("{}", String::from_utf8_lossy(&output.stdout));
        println!("{}", String::from_utf8_lossy(&output.stderr));
        println!("status = {}", output.status);
    }

    // Example 2: Streaming stdio
    {
        let cmd = Command::new().prog("cat").complete(false);
        let mut child = conn.exec(cmd).await?;
        let (writer, mut reader) = child.channel();

        let w_fut = async move {
            writer.write_stdin(&b"Hello World\n"[..]).await?;
            writer.eof().await?;
            Result::<(), RusshError>::Ok(())
        };

        let r_fut = async move {
            let mut stdout = tokio::io::stdout();
            while let Some(chunk) = reader.read_next().await {
                match chunk {
                    Chunk::Stdout(b) => {
                        stdout.write_all(&b).await.ok();
                        stdout.flush().await.ok();
                    }
                    Chunk::Stderr(b) => {
                        stdout.write_all(&b).await.ok();
                        stdout.flush().await.ok();
                    }
                }
            }
            // `reader` sends the `close` message to the server
            // automatically after `read_next()` returns `None`
        };

        let (w_res, _) = tokio::join!(w_fut, r_fut);
        w_res.ok();

        let status = child.wait().await;
        println!("status = {status}");
    }

    // Example 3: Complex command
    {
        // 'cd' 'src' && \
        // 'echo' "found path = $(
        //     LS_COLORS="$(dircolors -p)" 'ls' '-1' "${PWD}" \
        //         | 'grep' '.rs' \
        //         | 'head' '-1'
        //     )" ;
        let cmd = Command::new()
            .prog("cd")
            .arg("src")
            .and()
            .prog("echo")
            .arg((
                "found path = ",
                ExpandCommand::new()
                    .env(
                        "LS_COLORS",
                        ExpandCommand::new().prog("dircolors").arg("-p").complete(),
                    )
                    .prog("ls")
                    .arg("-1")
                    .arg(Env("PWD"))
                    .pipe()
                    .prog("grep")
                    .arg(".rs")
                    .pipe()
                    .prog("head")
                    .arg("-1")
                    .complete(),
            ))
            .complete(false);
        let child = conn.exec(cmd).await?;

        let output = child.wait_with_output().await;

        println!("{}", String::from_utf8_lossy(&output.stdout));
        println!("{}", String::from_utf8_lossy(&output.stderr));
        println!("status = {}", output.status);
    }

    // Example 4: Shell request
    {
        let mut child = conn.shell().await?;
        let (writer, mut reader) = child.channel();

        let w_fut = async move {
            writer
                .write_stdin(
                    Command::new()
                        .prog("echo")
                        .args(["Hello,", "interactive Shell"])
                        .complete(false),
                )
                .await?;
            writer.write_stdin(Exit).await?;
            Result::<(), RusshError>::Ok(())
        };

        let r_fut = async move {
            let mut stdout = tokio::io::stdout();
            while let Some(chunk) = reader.read_next().await {
                match chunk {
                    Chunk::Stdout(b) => {
                        stdout.write_all(&b).await.ok();
                        stdout.flush().await.ok();
                    }
                    Chunk::Stderr(b) => {
                        stdout.write_all(&b).await.ok();
                        stdout.flush().await.ok();
                    }
                }
            }
        };

        let (w_res, _) = tokio::join!(w_fut, r_fut);
        w_res.ok();

        let status = child.wait().await;

        println!("status = {status}");
    }

    conn.disconnect(Disconnect::ByApplication, "Done successfully", "en")
        .await?;

    Ok(())
}
```
