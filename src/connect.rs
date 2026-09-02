use crate::auth::Error as AuthError;
use crate::auth::{AuthMethod, AuthResult, Authenticator};
use crate::config::{Chain, Host};

use russh::client::Config;
use russh::client::{Handle, Handler};

pub use russh::Disconnect;

use std::sync::Arc;

pub enum Error<H: Handler> {
    AuthError(AuthError),
    Establish(H::Error),
    ProxyJump(russh::Error),
}

pub struct Connection<H: Handler> {
    handle: Handle<H>,
}

impl<H: Handler> Connection<H> {
    pub fn handle(&self) -> &Handle<H> {
        &self.handle
    }

    pub fn handle_mut(&mut self) -> &mut Handle<H> {
        &mut self.handle
    }

    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: &str,
        lang_tag: &str,
    ) -> Result<(), russh::Error> {
        self.handle.disconnect(reason, description, lang_tag).await
    }
}

impl<H: Handler + Send + 'static> Connection<H> {
    pub async fn connect<F, U>(
        target: &Chain,
        make_handler: F,
        update_conf: U,
    ) -> Result<Self, Error<H>>
    where
        F: FnMut(&Host) -> H,
        U: FnMut(&H, &mut Config),
    {
        Self::connect_impl(target, make_handler, update_conf).await
    }

    async fn connect_impl<F, U>(
        target: &Chain,
        mut make_handler: F,
        mut update_conf: U,
    ) -> Result<Self, Error<H>>
    where
        F: FnMut(&Host) -> H,
        U: FnMut(&H, &mut Config),
    {
        use tokio::io::{AsyncRead, AsyncWrite};

        async fn connect<H: Handler + Send + 'static>(
            conf: Arc<Config>,
            host: &Host,
            handler: H,
        ) -> Result<Handle<H>, Error<H>> {
            let mut handle =
                russh::client::connect(conf, (&*host.dest.name, host.dest.port), handler)
                    .await
                    .map_err(Error::Establish)?;
            auth(host, &mut handle).await.map_err(Error::AuthError)?;

            Ok(handle)
        }
        async fn connect_stream<S, H>(
            conf: Arc<Config>,
            host: &Host,
            stream: S,
            handler: H,
        ) -> Result<Handle<H>, Error<H>>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
            H: Handler + Send + 'static,
        {
            let mut handle = russh::client::connect_stream(conf, stream, handler)
                .await
                .map_err(Error::Establish)?;
            auth(host, &mut handle).await.map_err(Error::AuthError)?;

            Ok(handle)
        }

        let mut setup_handler = |host: &Host| {
            let handler = make_handler(host);
            let mut conf = Config::default();
            update_conf(&handler, &mut conf);
            (handler, conf)
        };

        let (first, bastions) = target.iter();

        let handle = if let Some(bastions) = bastions {
            let mut handle = {
                let (handler, conf) = setup_handler(first);
                connect(Arc::new(conf), first, handler).await?
            };

            for bastion in bastions {
                let channel = handle
                    .channel_open_direct_tcpip(
                        &bastion.to.dest.name,
                        bastion.to.dest.port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(Error::ProxyJump)?;
                handle = {
                    let (handler, conf) = setup_handler(bastion.to);
                    connect_stream(Arc::new(conf), bastion.to, channel.into_stream(), handler)
                        .await?
                };
            }

            handle
        } else {
            let (handler, conf) = setup_handler(first);
            connect(Arc::new(conf), first, handler).await?
        };

        Ok(Self { handle })
    }
}

async fn auth<H: Handler>(host: &Host, handle: &mut Handle<H>) -> Result<AuthResult, AuthError> {
    let mut auth = Authenticator::new(handle, &host.dest.user);
    if auth.none().await?.is_success() {
        return Ok(AuthResult::Success);
    }

    let method = AuthMethod::from_config(&host.auth)?;
    auth.perform(method).await
}
