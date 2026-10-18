use super::Child;
use super::{Command, Completed};

use crate::config::RequestTty;

use russh::Error as RusshError;
use russh::client::{Handle, Handler};

use bytes::Bytes;

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

pub struct Exit;

impl From<Exit> for Bytes {
    fn from(_value: Exit) -> Self {
        Bytes::from_static(b"exit\n")
    }
}
