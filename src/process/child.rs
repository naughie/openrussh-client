use russh::Error as RusshError;
pub use russh::Sig as Signal;
use russh::{Channel, ChannelMsg, client::Msg};
use russh::{ChannelReadHalf, ChannelWriteHalf};

use bytes::Bytes;

use tokio::io::{AsyncRead, AsyncWrite};

use std::process::ExitStatus;
use std::process::Output;

pub struct Child {
    writer: ChannelWriteHalf<Msg>,
    reader: ChannelReadHalf,
    status: u32,
}

pub enum Chunk {
    Stdout(Bytes),
    Stderr(Bytes),
}

#[derive(Clone, Copy)]
pub struct ChildIn<'a> {
    writer: &'a ChannelWriteHalf<Msg>,
}

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
    pub fn async_writer(self) -> impl AsyncWrite + 'static {
        self.writer.make_writer()
    }

    pub async fn write_stdin<B>(self, data: B) -> Result<(), RusshError>
    where
        B: Into<Bytes>,
    {
        self.writer.data_bytes(data).await
    }

    pub async fn write_stdin_io<R>(self, data: R) -> Result<(), RusshError>
    where
        R: AsyncRead + Unpin,
    {
        self.writer.data(data).await
    }

    pub async fn eof(self) -> Result<(), RusshError> {
        self.writer.eof().await
    }

    pub async fn signal(self, sig: Signal) -> Result<(), RusshError> {
        self.writer.signal(sig).await
    }
}

impl ChildOut<'_> {
    pub fn channel(&mut self) -> &mut ChannelReadHalf {
        self.reader
    }

    pub fn async_reader(&mut self) -> impl AsyncRead + '_ {
        self.reader.make_reader()
    }

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

    pub async fn wait(mut self) -> ExitStatus {
        while self.read_next().await.is_some() {}
        cast_status(*self.status)
    }

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

    pub async fn write_stdin<B>(&self, data: B) -> Result<(), RusshError>
    where
        B: Into<Bytes>,
    {
        ChildIn::new(self).write_stdin(data).await
    }

    pub async fn write_stdin_io<R>(&self, data: R) -> Result<(), RusshError>
    where
        R: AsyncRead + Unpin,
    {
        ChildIn::new(self).write_stdin_io(data).await
    }

    pub async fn read_next(&mut self) -> Option<Chunk> {
        ChildOut::new(self).read_next().await
    }

    pub async fn wait(mut self) -> ExitStatus {
        ChildOut::new(&mut self).wait().await
    }

    pub async fn wait_with_output(mut self) -> Output {
        ChildOut::new(&mut self).wait_with_output().await
    }

    pub async fn eof(&self) -> Result<(), RusshError> {
        self.writer.eof().await
    }

    pub async fn close(&self) -> Result<(), RusshError> {
        self.writer.close().await
    }

    pub async fn signal(&self, sig: Signal) -> Result<(), RusshError> {
        self.writer.signal(sig).await
    }

    pub fn status(&self) -> ExitStatus {
        cast_status(self.status)
    }
}

fn cast_status(status: u32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    ExitStatus::from_raw(((status & 0xff) as i32) << 8)
}
