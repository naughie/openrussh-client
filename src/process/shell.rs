//! Requests a remote shell and writes commands to its stdin.
//!
//! You can pass a [`Command<Completed>`](Command) to [`Child::write_stdin()`]. It is converted to
//! [`Bytes`], appending exactly one newline to the command buffer.

use super::Child;
use super::{Command, Completed};

use crate::config::RequestTty;

use russh::Error as RusshError;
use russh::client::{Handle, Handler};

use bytes::Bytes;

/// Requests a shell on a new [session channel](Handle::channel_open_session()).
///
/// It requests PTY with [`russh::Channel::request_pty()`], if configured by `tty`, then requests
/// the shell with [`russh::Channel::request_shell()`], both with `want_reply = true`.
/// It returns the [`Child`] without reading the replies; `Ok` does not mean that the server
/// accepted the requests. A call to [`ChildOut::read_next()`](super::ChildOut::read_next()) discards
/// success replies and returns `None` on a failure reply.
///
/// See [`RequestTty`] and the [`process`](super) module for the PTY parameters.
///
/// # Usage
///
/// ```
/// # use russh::client::{Handle, Handler};
/// # async fn dummy<H: Handler>(handle: &Handle<H>) {
/// use openrussh_client::config::RequestTty;
/// use openrussh_client::process::Command;
/// use openrussh_client::process::shell::{shell, Exit};
///
/// let child = shell(handle, RequestTty::Never).await.unwrap();
/// child
///     .write_stdin(Command::new().prog("echo").args(["Hello", "World"]).complete(false))
///     .await
///     .unwrap();
/// child.write_stdin(Exit).await.unwrap();
///
/// let output = child.wait_with_output().await;
/// println!("{}", String::from_utf8_lossy(&output.stdout));
/// eprintln!("{}", String::from_utf8_lossy(&output.stderr));
/// println!("status = {}", output.status);
/// # }
/// ```
pub async fn shell<H>(handle: &Handle<H>, tty: RequestTty) -> Result<Child, RusshError>
where
    H: Handler,
{
    use super::helpers::tty_conf;

    let channel = handle.channel_open_session().await?;
    if let Some(tty) = tty_conf(tty, true) {
        channel
            .request_pty(
                true,
                &tty.term,
                tty.col_width,
                tty.row_height,
                tty.pix_width,
                tty.pix_height,
                &tty.terminal_modes,
            )
            .await?;
    }
    channel.request_shell(true).await?;

    Ok(Child::new(channel))
}

impl From<Command<Completed>> for Bytes {
    fn from(value: Command<Completed>) -> Self {
        let mut buf = value.into_inner();
        buf.push('\n');
        Self::from(buf)
    }
}

/// The `exit` command followed by a newline.
///
/// You can write it to stdin with [`ChildIn::write_stdin()`](super::ChildIn::write_stdin()).
pub struct Exit;

impl From<Exit> for Bytes {
    fn from(_value: Exit) -> Self {
        Bytes::from_static(b"exit\n")
    }
}
