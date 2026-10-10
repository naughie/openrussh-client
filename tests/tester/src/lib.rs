pub type Error = Box<dyn std::error::Error>;

mod runtime;
pub use runtime::Runtime;

pub fn runtime() -> Runtime {
    Runtime::new()
}

mod assert;
pub use assert::*;

pub use openrussh_client;

pub use tokio;

use std::convert::Infallible;
use std::fmt;

use openrussh_client::connect::{Connection, Handler};

pub fn error(msg: impl fmt::Display + 'static) -> Result<Infallible, Error> {
    struct Error<T>(T);

    impl<T: fmt::Display> fmt::Debug for Error<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            T::fmt(&self.0, f)
        }
    }
    impl<T: fmt::Display> fmt::Display for Error<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            T::fmt(&self.0, f)
        }
    }
    impl<T: fmt::Display> std::error::Error for Error<T> {}

    Err(Box::new(Error(msg)))
}

pub async fn finish<H: Handler>(conn: &Connection<H>) -> Result<(), Error> {
    use openrussh_client::connect::Disconnect;

    conn.disconnect(Disconnect::ByApplication, "test is done", "en")
        .await?;
    Ok(())
}
