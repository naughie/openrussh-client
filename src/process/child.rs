//! IO and exit status of a remote command or shell.
//!
//! You can write stdin and read stdout/stderr concurrently with [`Child::channel()`].

use russh::Error as RusshError;
pub use russh::Sig as Signal;
use russh::{Channel, ChannelMsg, client::Msg};
use russh::{ChannelReadHalf, ChannelWriteHalf};

use bytes::Bytes;

use tokio::io::{AsyncRead, AsyncWrite};

use std::process::ExitStatus;
use std::process::Output;

/// Represents a remote command or shell.
///
/// It is returned by [`exec()`](super::cmd::exec()) or [`shell()`](super::shell::shell()). You can
/// read stdout/stderr one chunk at a time with [`Child::read_next()`], or collect all the output
/// with [`Child::wait_with_output()`].
pub struct Child {
    writer: ChannelWriteHalf<Msg>,
    reader: ChannelReadHalf,
    status: u32,
}

/// A chunk of stdout or stderr, returned by [`ChildOut::read_next()`].
pub enum Chunk {
    /// A stdout, i.e., [data message](ChannelMsg::Data).
    Stdout(Bytes),
    /// A stderr, i.e., [extended-data message](ChannelMsg::ExtendedData) with `ext == 1`.
    Stderr(Bytes),
}

/// The stdin writer of a [`Child`], returned by [`Child::writer()`] or [`Child::channel()`].
#[derive(Clone, Copy)]
pub struct ChildIn<'a> {
    writer: &'a ChannelWriteHalf<Msg>,
}

/// The stdout/stderr reader of a [`Child`], returned by [`Child::reader()`] or [`Child::channel()`].
pub struct ChildOut<'a> {
    writer: &'a ChannelWriteHalf<Msg>,
    reader: &'a mut ChannelReadHalf,
    status: &'a mut u32,
}

impl<'a> ChildIn<'a> {
    fn new(child: &'a Child) -> Self {
        Self {
            writer: &child.writer,
        }
    }

    /// Returns the [`ChannelWriteHalf`] of the SSH channel.
    pub fn channel(self) -> &'a ChannelWriteHalf<Msg> {
        self.writer
    }
}

impl<'a> ChildOut<'a> {
    fn new(child: &'a mut Child) -> Self {
        Self {
            writer: &child.writer,
            reader: &mut child.reader,
            status: &mut child.status,
        }
    }
}

impl ChildIn<'_> {
    /// Creates an [`AsyncWrite`] for the child's stdin. Alias to
    /// [`ChannelWriteHalf::make_writer()`].
    pub fn async_writer(self) -> impl AsyncWrite + 'static {
        self.writer.make_writer()
    }

    /// Writes `data` to stdin with [`ChannelWriteHalf::data_bytes()`].
    ///
    /// ```
    /// # use openrussh_client::process::ChildIn;
    /// # async fn dummy(writer: ChildIn<'_>) {
    /// writer.write_stdin(&b"Hello World\n"[..]).await.unwrap();
    /// # }
    /// ```
    pub async fn write_stdin<B>(self, data: B) -> Result<(), RusshError>
    where
        B: Into<Bytes>,
    {
        self.writer.data_bytes(data).await
    }

    /// Copies `data` from the [`AsyncRead`] to stdin until it returns EOF.
    /// It does not send EOF to the channel.
    ///
    /// ```
    /// # use openrussh_client::process::ChildIn;
    /// # async fn dummy(writer: ChildIn<'_>) {
    /// writer.write_stdin_io(&b"Hello World\n"[..]).await.unwrap();
    /// # }
    /// ```
    pub async fn write_stdin_io<R>(self, data: R) -> Result<(), RusshError>
    where
        R: AsyncRead + Unpin,
    {
        self.writer.data(data).await
    }

    /// Sends EOF with [`ChannelWriteHalf::eof()`].
    pub async fn eof(self) -> Result<(), RusshError> {
        self.writer.eof().await
    }

    /// Sends a signal with [`ChannelWriteHalf::signal()`].
    pub async fn signal(self, sig: Signal) -> Result<(), RusshError> {
        self.writer.signal(sig).await
    }
}

impl ChildOut<'_> {
    pub fn channel(&mut self) -> &mut ChannelReadHalf {
        self.reader
    }

    /// Creates an [`AsyncRead`] for the child's stdout. Alias to
    /// [`ChannelReadHalf::make_reader()`].
    pub fn async_reader(&mut self) -> impl AsyncRead + '_ {
        self.reader.make_reader()
    }

    /// Reads the next [`Chunk`] of stdout or stderr.
    ///
    /// Each chunk corresponds to one received [`ChannelMsg`]. `Data` yields `Chunk::Stdout`, and
    /// `ExtendedData` with `ext == 1` yields `Chunk::Stderr`.
    ///
    /// It records `ExitStatus` messages for [`Child::status()`] and continues reading. Other
    /// messages, including `Eof`, `Close`, `ExitSignal`, and `ExtendedData` with `ext != 1`, are
    /// discarded.
    ///
    /// It returns `None` when [`ChannelReadHalf::wait()`] returns `None` or when it receives
    /// `Failure`. Before returning `None`, it sends `close` to the server, ignoring errors from
    /// that request.
    pub async fn read_next(&mut self) -> Option<Chunk> {
        loop {
            let Some(msg) = self.reader.wait().await else {
                break;
            };

            match msg {
                ChannelMsg::Data { data } => {
                    return Some(Chunk::Stdout(data));
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    return Some(Chunk::Stderr(data));
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    *self.status = exit_status;
                }
                ChannelMsg::Failure => break,
                _ => {}
            }
        }

        self.writer.close().await.ok();

        None
    }

    /// Discards stdout/stderr until [`ChildOut::read_next()`] returns `None`.
    ///
    /// It returns the [`ExitStatus`] recorded in [`Child::status()`] and does not send EOF to stdin.
    pub async fn wait(mut self) -> ExitStatus {
        while self.read_next().await.is_some() {}
        cast_status(*self.status)
    }

    /// Collects the remaining stdout/stderr until [`ChildOut::read_next()`] returns `None`.
    ///
    /// It buffers all the output in memory without a size limit. The returned
    /// [`Output::status`] is obtained in the same way as [`Child::status()`]. It does not send EOF
    /// to stdin.
    pub async fn wait_with_output(mut self) -> Output {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(chunk) = self.read_next().await {
            match chunk {
                Chunk::Stdout(bytes) => stdout.extend_from_slice(&bytes),
                Chunk::Stderr(bytes) => stderr.extend_from_slice(&bytes),
            }
        }

        Output {
            status: cast_status(*self.status),
            stdout,
            stderr,
        }
    }
}

impl Child {
    pub fn new(channel: Channel<Msg>) -> Self {
        let (reader, writer) = channel.split();
        Self {
            writer,
            reader,
            status: 0,
        }
    }

    pub fn reader(&mut self) -> ChildOut<'_> {
        ChildOut::new(self)
    }

    pub fn writer(&self) -> ChildIn<'_> {
        ChildIn::new(self)
    }

    /// Splits the child's IO into a [`ChildIn`] for stdin and a [`ChildOut`] for stdout/stderr.
    ///
    /// You can write stdin and read stdout/stderr concurrently:
    ///
    /// ```
    /// # use openrussh_client::process::Child;
    /// # async fn dummy(mut child: Child) {
    /// let (writer, reader) = child.channel();
    ///
    /// let w_fut = async move {
    ///     writer.write_stdin(&b"Hello World\n"[..]).await.unwrap();
    ///     writer.eof().await.unwrap();
    /// };
    /// let r_fut = reader.wait_with_output();
    ///
    /// let (_, output) = tokio::join!(w_fut, r_fut);
    ///
    /// println!("{}", String::from_utf8_lossy(&output.stdout));
    /// eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    /// println!("status = {}", output.status);
    /// # }
    /// ```
    pub fn channel(&mut self) -> (ChildIn<'_>, ChildOut<'_>) {
        (
            ChildIn {
                writer: &self.writer,
            },
            ChildOut {
                writer: &self.writer,
                reader: &mut self.reader,
                status: &mut self.status,
            },
        )
    }

    /// Writes `data` to stdin. Alias to [`ChildIn::write_stdin()`].
    pub async fn write_stdin<B>(&self, data: B) -> Result<(), RusshError>
    where
        B: Into<Bytes>,
    {
        ChildIn::new(self).write_stdin(data).await
    }

    /// Copies `data` to stdin. Alias to [`ChildIn::write_stdin_io()`].
    pub async fn write_stdin_io<R>(&self, data: R) -> Result<(), RusshError>
    where
        R: AsyncRead + Unpin,
    {
        ChildIn::new(self).write_stdin_io(data).await
    }

    /// Reads the next chunk of stdout or stderr. Alias to [`ChildOut::read_next()`].
    pub async fn read_next(&mut self) -> Option<Chunk> {
        ChildOut::new(self).read_next().await
    }

    /// Discards stdout/stderr until reading ends. Alias to [`ChildOut::wait()`].
    pub async fn wait(mut self) -> ExitStatus {
        ChildOut::new(&mut self).wait().await
    }

    /// Collects the remaining stdout/stderr. Alias to [`ChildOut::wait_with_output()`].
    pub async fn wait_with_output(mut self) -> Output {
        ChildOut::new(&mut self).wait_with_output().await
    }

    /// Sends EOF. Alias to [`ChildIn::eof()`].
    pub async fn eof(&self) -> Result<(), RusshError> {
        self.writer.eof().await
    }

    /// Closes the channel. Alias to [`ChannelWriteHalf::close()`].
    pub async fn close(&self) -> Result<(), RusshError> {
        self.writer.close().await
    }

    /// Sends a signal. Alias to [`ChildIn::signal()`].
    pub async fn signal(&self, sig: Signal) -> Result<(), RusshError> {
        self.writer.signal(sig).await
    }

    /// Returns the last [`ExitStatus`] received by [`ChildOut::read_next()`].
    ///
    /// It defaults to zero if no [exit-status message](ChannelMsg::ExitStatus) has been read. It
    /// encodes the lowest eight bits as a normal Unix exit code using
    /// [`ExitStatusExt::from_raw()`](std::os::unix::process::ExitStatusExt::from_raw()); exit signals
    /// are not reflected in the status.
    pub fn status(&self) -> ExitStatus {
        cast_status(self.status)
    }
}

fn cast_status(status: u32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    ExitStatus::from_raw(((status & 0xff) as i32) << 8)
}
