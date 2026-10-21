//! Sends [`exec`](russh::Channel::exec())/[`shell`](russh::Channel::request_shell()) requests
//! and provides the child process IO.
//!
//! You can build shell commands with [`Command`], escaping their arguments automatically, and
//! execute the completed command with [`Connection::exec()`](crate::connect::Connection::exec()),
//! or request a shell with [`Connection::shell()`](crate::connect::Connection::shell()) and write
//! commands to its stdin. Both return a [`Child`] that exposes stdout/stderr and the
//! [exit status](std::process::ExitStatus).
//!
//! Whether to [request PTY](russh::Channel::request_pty()) follows the
//! [`RequestTty`](crate::config::RequestTty) configuration, taken from the connection.
//! The request parameters are:
//!
//! - The terminal name is read from the environment variable `${TERM}`, or
//!   `xterm` if that fails.
//! - The character dimensions are obtained from local stdin with
//!   [`terminal_size_of(stdin)`](terminal_size::terminal_size_of()) if it
//!   [`IsTerminal`](std::io::IsTerminal), or `80x24` otherwise. If obtaining the
//!   dimensions fails, then they are also `80x24`. Both pixel dimensions are zero.
//! - On Unix, if local stdin is a terminal and
//!   [`tcgetattr(stdin)`](libc::tcgetattr()) succeeds, then
//!   the modes are `VINTR`, `VQUIT`, `VERASE`, `VKILL`, `VEOF`, `ECHO`, `ICANON`, `ISIG`, `ICRNL`,
//!   `IXON`, and `OPOST`, taken from stdin. Otherwise the modes are empty, including on non-Unix
//!   targets.
//!
//! These functions request PTY initially only; they do not change the local terminal modes or
//! send subsequent [`window-change`](russh::Channel::window_change()) requests.
//!
//! # Usage
//!
//! ```
//! # use openrussh_client::connect::Connection;
//! # use russh::client::Handler;
//! # async fn dummy<H: Handler>(conn: Connection<H>) {
//! use openrussh_client::process::Command;
//!
//! let cmd = Command::new()
//!     .prog("echo")
//!     .args(["Hello", "World"])
//!     .complete(false);
//! let child = conn.exec(cmd).await.unwrap();
//!
//! let output = child.wait_with_output().await;
//!
//! println!("{}", String::from_utf8_lossy(&output.stdout));
//! eprintln!("{}", String::from_utf8_lossy(&output.stderr));
//! println!("status = {}", output.status);
//! # }
//! ```
//!
//! You can also read stdout/stderr one chunk at a time with [`ChildOut::read_next()`], and
//! write to stdin with [`ChildIn::write_stdin()`]. See [`Child::channel()`] for the usage.

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
    /// Sends the [`exec`](russh::Channel::exec()) request with this connection's
    /// [`RequestTty`](crate::config::RequestTty) configuration. Alias to [`cmd::exec()`].
    pub async fn exec(&self, cmd: Command<Completed>) -> Result<Child, russh::Error> {
        cmd::exec(
            self.handle(),
            cmd.into_inner().into_bytes(),
            self.request_tty(),
        )
        .await
    }

    /// Sends the [`shell`](russh::Channel::request_shell()) request with this connection's
    /// [`RequestTty`](crate::config::RequestTty) configuration. Alias to [`shell::shell()`].
    pub async fn shell(&self) -> Result<Child, russh::Error> {
        shell::shell(self.handle(), self.request_tty()).await
    }
}

mod helpers {
    use super::cmd::seal::RedirectToSeal;
    use super::cmd::{Redirect, RedirectMode, RedirectTo};
    use super::escape::{Arg, Escaper, SurroundBy};
    use crate::config::RequestTty;
    use core::fmt::NumBuffer;
    use std::borrow::Cow;

    pub(super) fn env<A: Arg>(buf: &mut String, key: &str, value: A) {
        {
            let key_bytes = key.as_bytes();
            let Some((&first, rest)) = key_bytes.split_first() else {
                return;
            };
            if !(first == b'_' || ((first | 0x20).wrapping_sub(b'a') < 26)) {
                return;
            }
            let idx = rest
                .iter()
                .position(|&b| {
                    !(b == b'_'
                        || ((b | 0x20).wrapping_sub(b'a') < 26)
                        || b.wrapping_sub(b'0') < 10)
                })
                .unwrap_or(rest.len());
            let idx = key.floor_char_boundary(idx + 1);

            buf.push_str(&key[..idx]);
        }
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

    pub(super) struct TtyConf {
        pub(super) term: Cow<'static, str>,
        pub(super) col_width: u32,
        pub(super) row_height: u32,
        pub(super) pix_width: u32,
        pub(super) pix_height: u32,
        pub(super) terminal_modes: Cow<'static, [(russh::Pty, u32)]>,
    }

    pub(super) fn tty_conf(tty: RequestTty, shell: bool) -> Option<TtyConf> {
        use russh::Pty;
        use std::io::{self, IsTerminal as _};

        fn get_term() -> Cow<'static, str> {
            if let Ok(term) = std::env::var("TERM") {
                Cow::Owned(term)
            } else {
                Cow::Borrowed("xterm")
            }
        }

        fn default_conf(term: Cow<'static, str>) -> TtyConf {
            let size = Size::default();
            TtyConf {
                term,
                col_width: size.col_width,
                row_height: size.row_height,
                pix_width: 0,
                pix_height: 0,
                terminal_modes: Cow::Borrowed(&[]),
            }
        }

        struct Size {
            col_width: u32,
            row_height: u32,
        }
        impl Size {
            fn default() -> Self {
                Self {
                    col_width: 80,
                    row_height: 24,
                }
            }
        }

        fn get_size(stdin: &io::Stdin) -> Size {
            use terminal_size::{Height, Width, terminal_size_of};
            terminal_size_of(stdin)
                .map(|(Width(w), Height(h))| Size {
                    col_width: w as u32,
                    row_height: h as u32,
                })
                .unwrap_or(Size::default())
        }

        #[cfg(not(unix))]
        fn get_modes(_stdin: &io::Stdin) -> Cow<'static, [(Pty, u32)]> {
            Cow::Borrowed(&[])
        }

        #[cfg(unix)]
        fn get_modes(stdin: &io::Stdin) -> Cow<'static, [(Pty, u32)]> {
            use std::{mem::MaybeUninit, os::fd::AsRawFd as _};

            let mut termios = MaybeUninit::<libc::termios>::uninit();

            if unsafe { libc::tcgetattr(stdin.as_raw_fd(), termios.as_mut_ptr()) } != 0 {
                return Cow::Borrowed(&[]);
            }

            let t = unsafe { termios.assume_init() };

            Cow::Owned(vec![
                (Pty::VINTR, t.c_cc[libc::VINTR] as u32),
                (Pty::VQUIT, t.c_cc[libc::VQUIT] as u32),
                (Pty::VERASE, t.c_cc[libc::VERASE] as u32),
                (Pty::VKILL, t.c_cc[libc::VKILL] as u32),
                (Pty::VEOF, t.c_cc[libc::VEOF] as u32),
                (Pty::ECHO, u32::from(t.c_lflag & libc::ECHO != 0)),
                (Pty::ICANON, u32::from(t.c_lflag & libc::ICANON != 0)),
                (Pty::ISIG, u32::from(t.c_lflag & libc::ISIG != 0)),
                (Pty::ICRNL, u32::from(t.c_iflag & libc::ICRNL != 0)),
                (Pty::IXON, u32::from(t.c_iflag & libc::IXON != 0)),
                (Pty::OPOST, u32::from(t.c_oflag & libc::OPOST != 0)),
            ])
        }

        match tty {
            RequestTty::Never => None,
            RequestTty::ForShell => {
                if !shell {
                    return None;
                }

                let term = get_term();
                let stdin = io::stdin();

                if stdin.is_terminal() {
                    let size = get_size(&stdin);
                    let terminal_modes = get_modes(&stdin);

                    Some(TtyConf {
                        term,
                        col_width: size.col_width,
                        row_height: size.row_height,
                        pix_width: 0,
                        pix_height: 0,
                        terminal_modes,
                    })
                } else {
                    Some(default_conf(term))
                }
            }
            RequestTty::IfTty => {
                let stdin = io::stdin();
                if !stdin.is_terminal() {
                    return None;
                }

                let term = get_term();
                let size = get_size(&stdin);
                let terminal_modes = get_modes(&stdin);

                Some(TtyConf {
                    term,
                    col_width: size.col_width,
                    row_height: size.row_height,
                    pix_width: 0,
                    pix_height: 0,
                    terminal_modes,
                })
            }
            RequestTty::Always => {
                let term = get_term();
                let stdin = io::stdin();

                if stdin.is_terminal() {
                    let size = get_size(&stdin);
                    let terminal_modes = get_modes(&stdin);

                    Some(TtyConf {
                        term,
                        col_width: size.col_width,
                        row_height: size.row_height,
                        pix_width: 0,
                        pix_height: 0,
                        terminal_modes,
                    })
                } else {
                    Some(default_conf(term))
                }
            }
        }
    }
}
