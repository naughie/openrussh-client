#[cfg(feature = "local-tcp-forwarding")]
pub mod tcp;

#[cfg(feature = "local-stream-forwarding")]
pub mod stream;

use russh::Error as RusshError;

use tokio::task::JoinHandle;

use std::io::Error as IoError;

#[derive(Debug)]
pub enum Error {
    OpenChannel(RusshError),
    CopyBytes(IoError),
}

pub struct LocalForward<F> {
    fut: F,
}

impl<F> LocalForward<F> {
    fn new(fut: F) -> Self {
        Self { fut }
    }
}

impl<F> LocalForward<F>
where
    F: Future<Output = Result<(), IoError>>,
{
    pub async fn wait(self) -> Result<(), Error> {
        self.fut.await.map_err(Error::CopyBytes)
    }

    pub fn into_inner(self) -> F {
        self.fut
    }
}

impl<F> LocalForward<F>
where
    F: Future<Output = Result<(), IoError>> + Send + 'static,
{
    pub fn spawn_wait(self) -> JoinHandle<Result<(), Error>> {
        tokio::spawn(self.wait())
    }
}
