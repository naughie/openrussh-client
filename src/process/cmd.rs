use super::Arg;
use super::Child;
use super::helpers;

use russh::Error as RusshError;
use russh::client::{Handle, Handler};

use std::marker::PhantomData;

const DEFAULT_CAP: usize = 256;

pub struct Command<T = NeedProg> {
    buf: String,
    _state: PhantomData<T>,
}

#[derive(Debug, Clone, Copy)]
pub struct RedirectPath<A>(pub A);
#[derive(Debug, Clone, Copy)]
pub struct RedirectDup(pub u32);

pub(crate) mod seal {
    use super::super::escape::{Arg, Escaper, SurroundBy};
    use core::fmt::NumBuffer;

    pub trait RedirectToSeal {
        fn push_to(self, buf: &mut String);
    }

    impl<A: Arg> RedirectToSeal for super::RedirectPath<A> {
        fn push_to(self, buf: &mut String) {
            if A::need_double() {
                buf.push('"');
                Escaper::new(buf, SurroundBy::Double).escape(self.0);
                buf.push('"');
            } else {
                buf.push('\'');
                Escaper::new(buf, SurroundBy::Single).escape(self.0);
                buf.push('\'');
            }
        }
    }

    impl RedirectToSeal for super::RedirectDup {
        fn push_to(self, buf: &mut String) {
            buf.push('&');
            let mut num_buf = NumBuffer::new();
            let fd = self.0.format_into(&mut num_buf);
            buf.push_str(fd);
        }
    }
}

pub trait RedirectTo: seal::RedirectToSeal {}
impl<T: seal::RedirectToSeal> RedirectTo for T {}

#[derive(Debug, Clone, Copy)]
pub enum RedirectMode {
    Read,
    Write,
    Append,
    ReadWrite,
}

#[derive(Debug, Clone, Copy)]
pub enum Redirect<T: RedirectTo> {
    Stdin { to: T },
    Stdout { to: T, append: bool },
    Stderr { to: T, append: bool },
    Custom { fd: u32, to: T, mode: RedirectMode },
}

pub struct NeedProg;

impl Command<NeedProg> {
    pub fn env<V: Arg>(mut self, key: &str, value: V) -> Self {
        helpers::env(&mut self.buf, key, value);
        self
    }

    pub fn envs<'a, I, V>(mut self, envs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, V)>,
        V: Arg,
    {
        for (key, value) in envs {
            helpers::env(&mut self.buf, key, value);
        }
        self
    }

    pub fn redirect<T: RedirectTo>(mut self, redir: Redirect<T>) -> Self {
        helpers::redir(&mut self.buf, redir);
        self
    }

    pub fn prog<S: Arg>(mut self, prog: S) -> Command<NeedTerm> {
        helpers::arg(&mut self.buf, prog);
        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    pub fn new() -> Self {
        Self {
            buf: String::with_capacity(DEFAULT_CAP),
            _state: PhantomData,
        }
    }
}

impl Default for Command<NeedProg> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NeedTerm;

impl Command<NeedTerm> {
    pub fn arg<S: Arg>(mut self, arg: S) -> Self {
        helpers::arg(&mut self.buf, arg);
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Arg,
    {
        for arg in args {
            helpers::arg(&mut self.buf, arg);
        }
        self
    }

    pub fn redirect<T: RedirectTo>(mut self, redir: Redirect<T>) -> Self {
        helpers::redir(&mut self.buf, redir);
        self
    }

    pub fn and(mut self) -> Command<NeedProg> {
        self.buf.push_str("&& ");

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    pub fn or(mut self) -> Command<NeedProg> {
        self.buf.push_str("|| ");

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    pub fn pipe(mut self) -> Command<NeedProg> {
        self.buf.push_str("| ");

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    pub fn complete(mut self, bg: bool) -> Command<Completed> {
        if bg {
            self.buf.push_str("& ");
        } else {
            self.buf.push_str("; ");
        }

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }
}

pub struct Completed;

impl Command<Completed> {
    pub fn chain(self) -> Command<NeedProg> {
        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.buf
    }

    pub fn into_inner(self) -> String {
        self.buf
    }

    pub fn take_inner(&mut self) -> String {
        std::mem::take(&mut self.buf)
    }

    /// # Safety
    ///
    /// This function does not check the syntax and does not escape any characters.
    /// It just passes the argument to the `exec` request as-is.
    pub unsafe fn new_unchecked(cmd: String) -> Command<Completed> {
        Command {
            buf: cmd,
            _state: PhantomData,
        }
    }

    pub async fn spawn<H: Handler>(self, handle: &Handle<H>) -> Result<Child, RusshError> {
        exec(handle, self.buf.into_bytes()).await
    }
}

pub async fn exec<H, C>(handle: &Handle<H>, cmd: C) -> Result<Child, RusshError>
where
    H: Handler,
    C: Into<Vec<u8>>,
{
    let channel = handle.channel_open_session().await?;
    channel.exec(true, cmd).await?;

    Ok(Child::new(channel))
}

#[cfg(test)]
mod tests {
    use super::super::escape::Env;
    use super::*;

    #[test]
    fn cmd() {
        let cmd = Command::new()
            .prog("echo")
            .arg("Hello")
            .arg("World")
            .complete(false);
        assert_eq!(cmd.as_str(), "'echo' 'Hello' 'World' ; ");

        let cmd = Command::new()
            .prog("echo")
            .redirect(Redirect::Stdin {
                to: RedirectPath("abc"),
            })
            .redirect(Redirect::Stdin { to: RedirectDup(0) })
            .redirect(Redirect::Stdout {
                to: RedirectPath("abc"),
                append: true,
            })
            .redirect(Redirect::Stdout {
                to: RedirectDup(2),
                append: false,
            })
            .redirect(Redirect::Stderr {
                to: RedirectPath("abc"),
                append: true,
            })
            .redirect(Redirect::Stderr {
                to: RedirectDup(1),
                append: false,
            })
            .redirect(Redirect::Custom {
                fd: 4,
                to: RedirectDup(3),
                mode: RedirectMode::ReadWrite,
            })
            .complete(true);
        assert_eq!(
            cmd.as_str(),
            "'echo' <'abc' <&0 >>'abc' >&2 2>>'abc' 2>&1 4<>&3 & "
        );

        let cmd = Command::new()
            .prog("echo")
            .arg(("I'm ", Env("my_name")))
            .redirect(Redirect::Stdout {
                to: RedirectPath(("./", Env("my_name"), ".txt")),
                append: false,
            })
            .complete(false);
        assert_eq!(
            cmd.as_str(),
            r#"'echo' "I'm ${my_name}" >"./${my_name}.txt" ; "#
        );
    }
}
