pub mod escape;
pub use escape::{Arg, Escaper};

pub mod cmd;
use cmd::Completed;
pub use cmd::{Command, Redirect, RedirectMode, RedirectPath};

pub mod shell;

pub mod child;
pub use child::{Child, ChildIn, ChildOut, Chunk};

use russh::client::Handler;

impl<H: Handler> crate::connect::Connection<H> {
    pub async fn exec(&self, cmd: Command<Completed>) -> Result<Child, russh::Error> {
        cmd::exec(self.handle(), cmd.into_inner().into_bytes()).await
    }

    pub async fn shell(&self) -> Result<Child, russh::Error> {
        shell::shell(self.handle()).await
    }
}

mod helpers {
    use super::cmd::seal::RedirectToSeal;
    use super::cmd::{Redirect, RedirectMode, RedirectTo};
    use super::escape::{Arg, Escaper, SurroundBy};
    use core::fmt::NumBuffer;

    pub(super) fn env<A: Arg>(buf: &mut String, key: &str, value: A) {
        buf.push_str(key);
        if A::need_double() {
            buf.push_str("=\"");
            Escaper::new(buf, SurroundBy::Double).escape(value);
            buf.push_str("\" ");
        } else {
            buf.push_str("='");
            Escaper::new(buf, SurroundBy::Single).escape(value);
            buf.push_str("' ");
        }
    }

    pub(super) fn arg<A: Arg>(buf: &mut String, arg: A) {
        if A::need_double() {
            buf.push('"');
            Escaper::new(buf, SurroundBy::Double).escape(arg);
            buf.push_str("\" ");
        } else {
            buf.push('\'');
            Escaper::new(buf, SurroundBy::Single).escape(arg);
            buf.push_str("' ");
        }
    }

    pub(super) fn redir<T: RedirectTo>(buf: &mut String, redir: Redirect<T>) {
        match redir {
            Redirect::Stdin { to } => {
                buf.push('<');
                <T as RedirectToSeal>::push_to(to, buf);
            }
            Redirect::Stdout { to, append: true } => {
                buf.push_str(">>");
                <T as RedirectToSeal>::push_to(to, buf);
            }
            Redirect::Stdout { to, append: false } => {
                buf.push('>');
                <T as RedirectToSeal>::push_to(to, buf);
            }
            Redirect::Stderr { to, append: true } => {
                buf.push_str("2>>");
                <T as RedirectToSeal>::push_to(to, buf);
            }
            Redirect::Stderr { to, append: false } => {
                buf.push_str("2>");
                <T as RedirectToSeal>::push_to(to, buf);
            }
            Redirect::Custom { fd, to, mode } => {
                let mut num_buf = NumBuffer::new();
                let fd = fd.format_into(&mut num_buf);
                buf.push_str(fd);

                match mode {
                    RedirectMode::Read => buf.push('<'),
                    RedirectMode::Write => buf.push('>'),
                    RedirectMode::Append => buf.push_str(">>"),
                    RedirectMode::ReadWrite => buf.push_str("<>"),
                }

                <T as RedirectToSeal>::push_to(to, buf);
            }
        }

        buf.push(' ');
    }
}
