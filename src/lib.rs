//! # OpenRussh Client
//!
//! OpenRussh client is an implementation of a SSH client using the [Russh](russh) crate.
//!
//! It reads OpenSSH's `~/.ssh/config` and `~/.ssh/known_hosts`, hence "OpenRussh".
//!
//! **Important Notes**: "OpenSSH" support means the ability to recognize OpenSSH-related files.
//! We do not guarantee that it works in exactly the same way as the OpenSSH client.
//! For example, while OpenSSH fallbacks to the default key paths (`~/.ssh/id_XXX` etc.), we stop attempting such keys for the security reason.
//! We do *recognize* OpenSSH but do not *behave* as OpenSSH. That does not mean you cannot use the OpenRussh client as the OpenSSH duplication.
//!
//!
//! ## Disclaimer
//!
//! **Disclaimer**: This software is provided "as is," without warranty of any kind, express or implied. It may include insecure implementations, and it is not guaranteed to follow timely security updates. Use this library at your own risk, and do not use it in production environments or systems requiring strict security guarantees.
//!
//!
//! # OpenSSH Config
//!
//! You can configure our SSH client by `~/.ssh/config`.
//! It leverages the [`ssh2-config`](ssh2_config) crate for parsing and querying the config file,
//! but we need some [`ignored_fields`](ssh2_config::HostParams::ignored_fields) for controling the
//! behavior of authentication methods.
//! One of the most important implication is that the `ssh2_config` crate itself may add the new
//! fields for those directives, removing them from the `ignored_fields` mapping, hence breaking our
//! code at runtime with the minor version updates.
//!
//! Supported directives:
//!
//! - `Host`
//! - `Port`
//! - `User`
//! - `IdentityFile` (limitation: use the first `IdentityFile` only even if you specify multiple items)
//! - `IdentityAgent` (or `${SSH_AUTH_SOCK}`)
//! - `CertificateFile`
//! - `IdentitiesOnly`
//!
//!
//! # Known Hosts
//!
//! When we receive the server host keys (or certificates) during the handshake process,
//! [`KnownHostsHandler`](known_hosts::KnownHostsHandler) checks the matched key in your
//! `~/.ssh/known_hosts` file. It will result in error if no matched key is found: we do not add it
//! automatically (like `StrictHostKeyChecking accept-new`), nor do we prompt you.
//! If you need more flexibility you should use
//! [`KnownHostsHandler::check_server_key()`](known_hosts::KnownHostsHandler::check_server_key())
//! directly and implement your own [`Handler`](russh::client::Handler).
//!
//! # Usage
//!
//! `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! openrussh-client = "0.1"
//! ```
//!
//! `main.rs`:
//!
//! ```
//! # async fn dummy() {
//! use openrussh_client::config::Target;
//! use openrussh_client::connect::Connection;
//! use openrussh_client::known_hosts::KnownHosts;
//! use openrussh_client::process::Command;
//! use openrussh_client::ssh2_config::{ParseRule, SshConfig};
//!
//! use openrussh_client::connect::Disconnect;
//!
//! let conf = SshConfig::parse_default_file(ParseRule::ALLOW_UNSUPPORTED_FIELDS).unwrap();
//!
//! // Format: [user@]host[:port]
//! let target = Target::parse("your-host");
//! let hosts = target.query(&conf).unwrap();
//!
//! let known_hosts = KnownHosts::parse_default_path().unwrap();
//!
//! let conn = Connection::connect(
//!     &hosts,
//!     // `KnownHosts` generates `KnownHostsHandler` that is tied with the target host
//!     |host| known_hosts.handler(&host.dest.name, host.dest.port),
//!     // Updates host key / certificate algorithms during the handshake
//!     |handler, conf| handler.update_preferred_config(&mut conf.preferred),
//! )
//!     .await
//!     .unwrap();
//!
//! println!("SSH established");
//!
//! let cmd = Command::new()
//!     .prog("echo")
//!     .args(["Hello", "World"])
//!     // true: background (`&`) / false: foreground (`;`)
//!     .complete(false);
//! let child = conn.exec(cmd).await.unwrap();
//!
//! let output = child.wait_with_output().await;
//!
//! println!("{}", String::from_utf8_lossy(&output.stdout));
//! eprintln!("{}", String::from_utf8_lossy(&output.stderr));
//! println!("status = {}", output.status);
//!
//! conn.disconnect(Disconnect::ByApplication, "Done successfully", "en")
//!     .await
//!     .unwrap();
//! # }
//! ```
//!
//! You can use the child process IO via [`tokio::io::{AsyncRead, AsynWrite}`](tokio::io):
//!
//! ```
//! # use openrussh_client::connect::Connection;
//! # use openrussh_client::known_hosts::KnownHostsHandler;
//! # use openrussh_client::process::Command;
//! # async fn dummy(conn: Connection<KnownHostsHandler>) {
//! use openrussh_client::process::Chunk;
//! use openrussh_client::error::RusshError;
//!
//! let cmd = Command::new().prog("cat").complete(false);
//! let mut child = conn.exec(cmd).await.unwrap();
//! let (writer, mut reader) = child.channel();
//!
//! // write to child's stdin
//! let w_fut = async move {
//!     writer.write_stdin(&b"Hello World\n"[..]).await?;
//!     writer.eof().await?;
//!     Result::<(), RusshError>::Ok(())
//! };
//!
//! // read from child's stdout/stderr
//! let r_fut = async move {
//!     let mut stdout: Vec<u8> = Vec::new();
//!     let mut stderr: Vec<u8> = Vec::new();
//!
//!     while let Some(chunk) = reader.read_next().await {
//!         match chunk {
//!             Chunk::Stdout(b) => stdout.extend_from_slice(&b),
//!             Chunk::Stderr(b) => stderr.extend_from_slice(&b),
//!         }
//!     }
//!
//!     println!("{}", String::from_utf8_lossy(&stdout));
//!     eprintln!("{}", String::from_utf8_lossy(&stderr));
//!
//!     // `reader` sends the `close` message to the server
//!     // automatically after `read_next()` returns `None`
//!     Ok(())
//! };
//!
//! let res = tokio::try_join!(w_fut, r_fut);
//! res.ok();
//!
//! let status = child.wait().await;
//! println!("status = {status}");
//! # }
//! ```
//!
//! Command arguments are automatically escaped by single quotes or double quotes, depending on the
//! [content](process::Arg::need_double()).
//! You can use raw strings (`&str`, `String`), primitive integers, boolean (`"true"` or `"false"`),
//! [`Display`](process::escape::Display) (the wrapper of std [`Display`](std::fmt::Display)),
//! [`Concat`](process::escape::Concat) (string concatenation of [`Iterator`]),
//! [`Env`](process::escape::Env) (shell variables `${FOO}`, either exported or not, uppercase or not), [`ExpandCommand`](process::escape::ExpandCommand) (expanding a command, `$( inner-command )`), and tuples of any of these types.
//! We forbid to pass an [`&OsStr`](std::ffi::OsStr) or a [`&Path`](std::path::Path) because
//! they depend on the OS at the *compile time*, not on the server environment.
//!
//! Example of complicated commands:
//!
//! ```
//! # use openrussh_client::connect::Connection;
//! # use openrussh_client::known_hosts::KnownHostsHandler;
//! # use openrussh_client::process::Command;
//! # async fn dummy(conn: Connection<KnownHostsHandler>) {
//! use openrussh_client::process::escape::{Env, ExpandCommand};
//! // 'cd' 'src' && \
//! // 'echo' "found path = $(
//! //     LS_COLORS="$(dircolors -p)" 'ls' '-1' "${PWD}" \
//! //         | 'grep' '.rs' \
//! //         | 'head' '-1'
//! //     )" ;
//! let cmd = Command::new()
//!     .prog("cd")
//!     .arg("src")
//!     .and()
//!     .prog("echo")
//!     .arg((
//!         "found path = ",
//!         ExpandCommand::new()
//!             .env(
//!                 "LS_COLORS",
//!                 ExpandCommand::new().prog("dircolors").arg("-p").complete(),
//!             )
//!             .prog("ls")
//!             .arg("-1")
//!             .arg(Env("PWD"))
//!             .pipe()
//!             .prog("grep")
//!             .arg(".rs")
//!             .pipe()
//!             .prog("head")
//!             .arg("-1")
//!             .complete(),
//!     ))
//!     .complete(false);
//! let child = conn.exec(cmd).await.unwrap();
//!
//! let output = child.wait_with_output().await;
//!
//! println!("{}", String::from_utf8_lossy(&output.stdout));
//! eprintln!("{}", String::from_utf8_lossy(&output.stderr));
//! println!("status = {}", output.status);
//! # }
//! ```
//!
//! You can also send the shell request (though we do not support PTY yet):
//!
//! ```
//! # use openrussh_client::connect::Connection;
//! # use openrussh_client::known_hosts::KnownHostsHandler;
//! # use openrussh_client::process::Command;
//! # async fn dummy(conn: Connection<KnownHostsHandler>) {
//! use openrussh_client::process::Chunk;
//! use openrussh_client::process::shell::Exit;
//! use openrussh_client::error::RusshError;
//!
//! let mut child = conn.shell().await.unwrap();
//! let (writer, mut reader) = child.channel();
//!
//! // write to shell's stdin
//! let w_fut = async move {
//!     writer
//!         .write_stdin(
//!             Command::new()
//!                 .prog("echo")
//!                 .args(["Hello,", "interactive Shell"])
//!                 .complete(false),
//!         )
//!         .await?;
//!
//!     // equivalent to writing b"exit\n"
//!     writer.write_stdin(Exit).await?;
//!     Result::<(), RusshError>::Ok(())
//! };
//!
//! // read from shell's stdout/stderr
//! let r_fut = async move {
//!     let mut stdout: Vec<u8> = Vec::new();
//!     let mut stderr: Vec<u8> = Vec::new();
//!
//!     while let Some(chunk) = reader.read_next().await {
//!         match chunk {
//!             Chunk::Stdout(b) => stdout.extend_from_slice(&b),
//!             Chunk::Stderr(b) => stderr.extend_from_slice(&b),
//!         }
//!     }
//!
//!     println!("{}", String::from_utf8_lossy(&stdout));
//!     eprintln!("{}", String::from_utf8_lossy(&stderr));
//!     // `reader` sends the `close` message to the server
//!     // automatically after `read_next()` returns `None`
//!
//!     Ok(())
//! };
//!
//! let res = tokio::try_join!(w_fut, r_fut);
//! res.ok();
//!
//! let status = child.wait().await;
//!
//! println!("status = {status}");
//! # }
//! ```
//!
//! # Feature Flags
//!
//! This crate has the following feature flags:
//!
//! - **aws-lc-rs** (default: enabled): Uses [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) as the crypto backend. It affects only [`russh`].
//! - **ring** (default: disabled): Uses [`ring`](https://crates.io/crates/ring) as the crypto backend. It affects only [`russh`].
//! - **rsa** (default: enabled): Enables `rsa` feature of [`russh`].
//! - **flate2** (default: enabled): Enables `flate2` feature of [`russh`].
//! - **serde** (default: disabled): Enables `serde` feature of [`russh`].
//! - **russh-default** (default: enabled): Enables the default feature flags of [`russh`]: `aws-lc-rs`, `rsa`, `flate2`.
//! - **known-hosts** (default: enabled): Exposes the reader for `~/.ssh/known_hosts` and the associated [`Handler`](russh::client::Handler) implementation.
//! - **cmd** (default: enabled): Defines the rich interface to send `exec`/`shell` requests.

pub mod error;

pub mod config;

pub mod auth;

pub mod connect;

#[cfg(feature = "known-hosts")]
pub mod known_hosts;

#[cfg(feature = "cmd")]
pub mod process;

pub use ssh2_config;
