use crate::auth::Error as AuthError;
use crate::auth::{AuthMethods, AuthResult, Authenticator};
use crate::config::{Chain, Dest, Host};

use russh::client::Config;
use russh::client::{Handle, Handler};

use tokio::io::{AsyncRead, AsyncWrite};

pub use russh::Disconnect;

use std::sync::Arc;

pub async fn connect<H: Handler + Send + 'static>(
    dest: &Dest,
    auth_methods: AuthMethods<'_>,
    ctx: Context<H>,
) -> Result<Handle<H>, Error<H>> {
    let mut handle = russh::client::connect(ctx.conf, (&*dest.name, dest.port), ctx.handler)
        .await
        .map_err(Error::Establish)?;
    let res = auth(dest, auth_methods, &mut handle)
        .await
        .map_err(Error::AuthError)?;
    if res.is_success() {
        Ok(handle)
    } else {
        Err(Error::AuthFailure)
    }
}

pub async fn connect_stream<S, H>(
    dest: &Dest,
    auth_methods: AuthMethods<'_>,
    stream: S,
    ctx: Context<H>,
) -> Result<Handle<H>, Error<H>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
{
    let mut handle = russh::client::connect_stream(ctx.conf, stream, ctx.handler)
        .await
        .map_err(Error::Establish)?;
    let res = auth(dest, auth_methods, &mut handle)
        .await
        .map_err(Error::AuthError)?;
    if res.is_success() {
        Ok(handle)
    } else {
        Err(Error::AuthFailure)
    }
}

#[derive(Debug, Clone)]
pub struct Context<H> {
    handler: H,
    conf: Arc<Config>,
}

impl<H> Context<H> {
    pub fn new(handler: H, conf: Arc<Config>) -> Self {
        Self { handler, conf }
    }

    pub fn with_default_conf(handler: H) -> Self {
        Self {
            handler,
            conf: Default::default(),
        }
    }

    pub fn into_inner(self) -> (H, Arc<Config>) {
        (self.handler, self.conf)
    }
}

pub trait MakeHandler {
    type Handler: Handler + Send + 'static;
    type Error;

    fn make_handler(&self, host: &Host) -> Result<Context<Self::Handler>, Self::Error>;
}
impl<M: MakeHandler> MakeHandler for &M {
    type Handler = M::Handler;
    type Error = M::Error;

    fn make_handler(&self, host: &Host) -> Result<Context<Self::Handler>, Self::Error> {
        M::make_handler(self, host)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MakeHandlerFn<F>(pub F);

impl<Func, H, E> MakeHandler for MakeHandlerFn<Func>
where
    Func: Fn(&Host) -> Result<Context<H>, E>,
    H: Handler + Send + 'static,
{
    type Handler = H;
    type Error = E;

    fn make_handler(&self, host: &Host) -> Result<Context<Self::Handler>, Self::Error> {
        self.0(host)
    }
}

pub enum Error<H: Handler, M = std::convert::Infallible> {
    AuthError(AuthError),
    AuthFailure,
    Establish(H::Error),
    ProxyJump(russh::Error),
    MakeHandler(M),
}

impl<H: Handler> Error<H> {
    pub fn cast<M>(self) -> Error<H, M> {
        match self {
            Self::AuthError(e) => Error::AuthError(e),
            Self::AuthFailure => Error::AuthFailure,
            Self::Establish(e) => Error::Establish(e),
            Self::ProxyJump(e) => Error::ProxyJump(e),
        }
    }
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
    pub async fn connect<M: MakeHandler<Handler = H>>(
        target: &Chain,
        make_handler: M,
    ) -> Result<Self, Error<H, M::Error>> {
        Self::connect_impl(target, make_handler).await
    }

    async fn connect_impl<M: MakeHandler<Handler = H>>(
        target: &Chain,
        make_handler: M,
    ) -> Result<Self, Error<H, M::Error>> {
        let (first, bastions) = target.iter();

        let handle = if let Some(bastions) = bastions {
            let mut handle = {
                let ctx = make_handler
                    .make_handler(first)
                    .map_err(Error::MakeHandler)?;
                let auth_methods = AuthMethods::from_config(&first.auth);
                connect(&first.dest, auth_methods, ctx)
                    .await
                    .map_err(Error::cast::<M::Error>)?
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
                    let ctx = make_handler
                        .make_handler(bastion.to)
                        .map_err(Error::MakeHandler)?;
                    let auth_methods = AuthMethods::from_config(&bastion.to.auth);
                    connect_stream(&bastion.to.dest, auth_methods, channel.into_stream(), ctx)
                        .await
                        .map_err(Error::cast::<M::Error>)?
                };
            }

            handle
        } else {
            let ctx = make_handler
                .make_handler(first)
                .map_err(Error::MakeHandler)?;
            let auth_methods = AuthMethods::from_config(&first.auth);
            connect(&first.dest, auth_methods, ctx)
                .await
                .map_err(Error::cast::<M::Error>)?
        };

        Ok(Self { handle })
    }
}

async fn auth<H: Handler>(
    dest: &Dest,
    auth_methods: AuthMethods<'_>,
    handle: &mut Handle<H>,
) -> Result<AuthResult, AuthError> {
    let mut auth = Authenticator::new(handle, &dest.user);

    for method in auth_methods.iter() {
        if auth.perform(method).await?.is_success() {
            return Ok(AuthResult::Success);
        }
    }

    Ok(AuthResult::Failure)
}
