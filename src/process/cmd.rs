//! Builds shell commands for the SSH [`exec`](russh::Channel::exec()) request.
//!
//! [`Command`] escapes the program name, arguments, environment values,
//! and redirect paths.
//! You can combine commands with `&&`, `||`, and `|`, then
//! execute the completed command on a connection with
//! [`Connection::exec()`](crate::connect::Connection::exec()), or through an existing handle
//! with [`Command::spawn()`].

use super::Arg;
use super::Child;
use super::helpers;

use crate::config::RequestTty;

use russh::Error as RusshError;
use russh::client::{Handle, Handler};

use std::marker::PhantomData;

const DEFAULT_CAP: usize = 256;

/// Represents a shell command to execute on the server.
///
/// The type parameter `T` indicates what you can append next. A command created with
/// [`Command::new()`] accepts environment assignments and redirects before the program name.
/// After setting the program name with [`Command::prog()`], you can append arguments, redirects,
/// or another command. You can then call [`Command::complete()`] to execute it.
///
/// Arguments are escaped inside double quotes if [`Arg::need_double()`] is true, or single quotes
/// otherwise. See [`escape`](super::escape) for the escaping rules.
/// The builder writes to an internal [`String`] as each method is called.
/// Each program name, argument, assignment, redirect, and operator is followed by one space,
/// including the final `;` or `&`.
///
/// # Usage
///
/// ```
/// use openrussh_client::process::Command;
/// use openrussh_client::process::escape::Env;
///
/// let cmd = Command::new()
///     .prog("cd")
///     .arg("src")
///     .and()
///     .prog("echo")
///     .arg(("cwd = ", Env("PWD")))
///     .complete(false);
/// assert_eq!(cmd.as_str(), "'cd' 'src' && 'echo' \"cwd = ${PWD}\" ; ");
/// ```
pub struct Command<T = NeedProg> {
    buf: String,
    _state: PhantomData<T>,
}

/// Redirects to a path.
#[derive(Debug, Clone, Copy)]
pub struct RedirectPath<A>(pub A);
/// Redirects to another file descriptor, e.g., `RedirectDup(1)` for `&1`.
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

/// Target of a [`Redirect`], either a [`RedirectPath`] or a [`RedirectDup`].
pub trait RedirectTo: seal::RedirectToSeal {}
impl<T: seal::RedirectToSeal> RedirectTo for T {}

/// The operator used by [`Redirect::Custom`].
#[derive(Debug, Clone, Copy)]
pub enum RedirectMode {
    /// Reads from the target (`<`).
    Read,
    /// Writes to the target (`>`).
    Write,
    /// Appends to the target (`>>`).
    Append,
    /// Reads from and writes to the target (`<>`).
    ReadWrite,
}

/// Represents a shell redirect.
///
/// `to` can be either a [`RedirectPath`] or a [`RedirectDup`]. The redirects
/// are written in the order of the [`Command::redirect()`] calls.
/// The operator is selected independently of the target: `append: true` writes `>>` or `2>>`
/// even with a `RedirectDup` target. We do not check whether the resulting
/// redirect is valid for the server's shell.
///
/// ```
/// use openrussh_client::process::{Command, Redirect, RedirectPath};
/// use openrussh_client::process::cmd::RedirectDup;
///
/// let cmd = Command::new()
///     .prog("echo")
///     .args(["Hello", "World"])
///     .redirect(Redirect::Stdout {
///         to: RedirectPath("output.txt"),
///         append: false,
///     })
///     .redirect(Redirect::Stderr {
///         to: RedirectDup(1),
///         append: false,
///     })
///     .complete(false);
/// assert_eq!(cmd.as_str(), "'echo' 'Hello' 'World' >'output.txt' 2>&1 ; ");
/// ```
#[derive(Debug, Clone, Copy)]
pub enum Redirect<T: RedirectTo> {
    /// Redirects stdin (`<TO`).
    Stdin { to: T },
    /// Redirects stdout (`>TO`) or appends (`>>TO`).
    Stdout { to: T, append: bool },
    /// Redirects stderr (`2>TO`) or appends (`2>>TO`).
    Stderr { to: T, append: bool },
    /// Redirects the file descriptor `fd` with the given [`RedirectMode`].
    Custom { fd: u32, to: T, mode: RedirectMode },
}

pub struct NeedProg;

impl Command<NeedProg> {
    /// Appends an environment assignment before the program name.
    ///
    /// It writes `key=value` in the command string, not an SSH
    /// [`env`](russh::Channel::set_env()) request. Assignments are appended in the order of the
    /// calls, including duplicate keys.
    /// The value is escaped in the same way as command arguments. The key is truncated at the
    /// first character outside `[a-zA-Z0-9_]`. If it is empty or does not start with `[a-zA-Z_]`,
    /// then the assignment is ignored.
    /// Unlike [`escape::Env`](super::escape::Env), which writes parameter expansions without validating
    /// their contents to allow shell expressions, this method validates and truncates assignment
    /// names.
    ///
    /// ```
    /// use openrussh_client::process::Command;
    /// use openrussh_client::process::escape::Env;
    ///
    /// let cmd = Command::new()
    ///     .env("PATH", ("/bin:", Env("PATH")))
    ///     .env(".ignored key", "hello")
    ///     .prog("echo")
    ///     .arg("Hello")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "PATH=\"/bin:${PATH}\" 'echo' 'Hello' ; ");
    /// ```
    pub fn env<V: Arg>(mut self, key: &str, value: V) -> Self {
        helpers::env(&mut self.buf, key, value);
        self
    }

    /// Appends an environment assignment for each pair, as in [`Command::env()`].
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

    /// Appends a [`Redirect`] before the program name.
    ///
    /// You can call `redirect()` multiple times; redirects are written in the order of the calls.
    ///
    /// ```
    /// use openrussh_client::process::{Command, Redirect};
    /// use openrussh_client::process::cmd::RedirectDup;
    ///
    /// let cmd = Command::new()
    ///     .redirect(Redirect::Stderr {
    ///         to: RedirectDup(1),
    ///         append: false,
    ///     })
    ///     .prog("true")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "2>&1 'true' ; ");
    /// ```
    pub fn redirect<T: RedirectTo>(mut self, redir: Redirect<T>) -> Self {
        helpers::redir(&mut self.buf, redir);
        self
    }

    /// Appends the program name, escaped in the same way as command arguments.
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new().prog("true").complete(false);
    /// assert_eq!(cmd.as_str(), "'true' ; ");
    /// ```
    pub fn prog<S: Arg>(mut self, prog: S) -> Command<NeedTerm> {
        helpers::arg(&mut self.buf, prog);
        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    /// Creates an empty command.
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
    /// Appends an escaped argument, using double quotes if
    /// [`Arg::need_double()`] is true, or single quotes otherwise.
    pub fn arg<S: Arg>(mut self, arg: S) -> Self {
        helpers::arg(&mut self.buf, arg);
        self
    }

    /// Appends an argument for each item, as in [`Command::arg()`].
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

    /// Appends a [`Redirect`] after the program name or arguments.
    ///
    /// You can call `redirect()` multiple times; redirects are written in the order of the calls.
    ///
    /// ```
    /// use openrussh_client::process::{Command, Redirect};
    /// use openrussh_client::process::cmd::RedirectDup;
    ///
    /// let cmd = Command::new()
    ///     .prog("true")
    ///     .redirect(Redirect::Stderr {
    ///         to: RedirectDup(1),
    ///         append: false,
    ///     })
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "'true' 2>&1 ; ");
    /// ```
    pub fn redirect<T: RedirectTo>(mut self, redir: Redirect<T>) -> Self {
        helpers::redir(&mut self.buf, redir);
        self
    }

    /// Appends `&&` and starts the next command.
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new()
    ///     .prog("true")
    ///     .and()
    ///     .prog("false")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "'true' && 'false' ; ");
    /// ```
    pub fn and(mut self) -> Command<NeedProg> {
        self.buf.push_str("&& ");

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    /// Appends `||` and starts the next command.
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new()
    ///     .prog("false")
    ///     .or()
    ///     .prog("true")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "'false' || 'true' ; ");
    /// ```
    pub fn or(mut self) -> Command<NeedProg> {
        self.buf.push_str("|| ");

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    /// Appends `|` and starts the next command.
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new()
    ///     .prog("echo")
    ///     .arg("Hello")
    ///     .pipe()
    ///     .prog("tee")
    ///     .arg("your-path")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "'echo' 'Hello' | 'tee' 'your-path' ; ");
    /// ```
    pub fn pipe(mut self) -> Command<NeedProg> {
        self.buf.push_str("| ");

        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    /// Completes the command build with `&` if `bg` is `true`, or `;` if `false`.
    ///
    /// You can execute the returned command with [`Command::spawn()`], or
    /// continue building it with [`Command::chain()`].
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new().prog("true").complete(false);
    /// assert_eq!(cmd.as_str(), "'true' ; ");
    ///
    /// let cmd = Command::new().prog("true").complete(true);
    /// assert_eq!(cmd.as_str(), "'true' & ");
    /// ```
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
    /// Continues building after a completed command.
    ///
    /// It keeps the `&` or `;` written by [`Command::complete()`].
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new()
    ///     .prog("false")
    ///     .complete(false)
    ///     .chain()
    ///     .prog("true")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "'false' ; 'true' ; ");
    /// ```
    pub fn chain(self) -> Command<NeedProg> {
        Command {
            buf: self.buf,
            _state: PhantomData,
        }
    }

    /// Returns the full command string.
    ///
    /// ```
    /// use openrussh_client::process::Command;
    ///
    /// let cmd = Command::new()
    ///     .prog("false")
    ///     .complete(false)
    ///     .chain()
    ///     .prog("true")
    ///     .complete(false);
    /// assert_eq!(cmd.as_str(), "'false' ; 'true' ; ");
    /// ```
    pub fn as_str(&self) -> &str {
        &self.buf
    }

    pub fn into_inner(self) -> String {
        self.buf
    }

    /// Takes the command string, leaving an empty completed command.
    pub fn take_inner(&mut self) -> String {
        std::mem::take(&mut self.buf)
    }

    /// Creates a completed command from a raw string.
    ///
    /// # Safety
    ///
    /// This function does not check the syntax and does not escape any characters.
    /// It just passes the argument to the [`exec`](russh::Channel::exec()) request as-is.
    pub unsafe fn new_unchecked(cmd: String) -> Command<Completed> {
        Command {
            buf: cmd,
            _state: PhantomData,
        }
    }

    /// Alias to [`exec()`].
    pub async fn spawn<H: Handler>(
        self,
        handle: &Handle<H>,
        tty: RequestTty,
    ) -> Result<Child, RusshError> {
        exec(handle, self.buf.into_bytes(), tty).await
    }
}

/// Opens a [session channel](Handle::channel_open_session()) and
/// sends the [`exec`](russh::Channel::exec()) request.
///
/// It passes `cmd` as-is, without checking the syntax or escaping any characters.
/// You can build an escaped [`Command`] first. It does not append a newline.
/// Whether to [request PTY](russh::Channel::request_pty()) follows [`RequestTty`];
/// the `ForShell` mode does not request PTY here.
/// See the [process module](super) for the PTY parameters.
///
/// It requests PTY, if configured, then executes the command, both with `want_reply = true`.
/// It returns a [`Child`] without reading the replies, so `Ok` does not mean the
/// server accepted the requests. The replies are handled by
/// [`ChildOut::read_next()`](super::ChildOut::read_next()).
pub async fn exec<H, C>(handle: &Handle<H>, cmd: C, tty: RequestTty) -> Result<Child, RusshError>
where
    H: Handler,
    C: Into<Vec<u8>>,
{
    use super::helpers::tty_conf;

    let channel = handle.channel_open_session().await?;
    if let Some(tty) = tty_conf(tty, false) {
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
    channel.exec(true, cmd).await?;

    Ok(Child::new(channel))
}

#[cfg(test)]
mod tests {
    use super::super::escape::Env;
    use super::*;

    #[test]
    fn simple_cmd() {
        let cmd = Command::new()
            .prog("echo")
            .arg("Hello")
            .arg("World")
            .complete(false);
        assert_eq!(cmd.as_str(), "'echo' 'Hello' 'World' ; ");
    }

    #[test]
    fn env_init() {
        let cmd = Command::new()
            .env("ENV1", "value1")
            .env("ENV2", "value'2")
            .env("ENV3", Env("ENV"))
            .prog("echo")
            .complete(false);
        assert_eq!(
            cmd.as_str(),
            "ENV1='value1' ENV2='value'\\''2' ENV3=\"${ENV}\" 'echo' ; "
        );

        let cmd = Command::new()
            .envs([("ENV1", "value1"), ("ENV2", "value'2")])
            .env("ENV3", Env("ENV"))
            .prog("echo")
            .complete(false);
        assert_eq!(
            cmd.as_str(),
            "ENV1='value1' ENV2='value'\\''2' ENV3=\"${ENV}\" 'echo' ; "
        );
    }

    #[test]
    fn redir() {
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
    }

    #[test]
    fn complex_env_expansion() {
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

    #[test]
    fn illegal_env() {
        let cmd = Command::new()
            .env("ILLEGAL ENV", "foo")
            .env("?ENV", "bar")
            .env("", "empty")
            .prog("echo")
            .complete(false);
        assert_eq!(cmd.as_str(), "ILLEGAL='foo' 'echo' ; ");

        fn test_impl_ok1(b: u8) {
            let buf = [b];
            let key = std::str::from_utf8(&buf).unwrap();

            let cmd = Command::new().env(key, "foo").prog("echo").complete(false);
            let expected = format!("{key}='foo' 'echo' ; ");
            assert_eq!(cmd.as_str(), &expected);
        }
        fn test_impl_ok2(b: u8) {
            let buf = [b'a', b];
            let key = std::str::from_utf8(&buf).unwrap();

            let cmd = Command::new().env(key, "foo").prog("echo").complete(false);
            let expected = format!("{key}='foo' 'echo' ; ");
            assert_eq!(cmd.as_str(), &expected);
        }
        fn test_impl_fail1(b: u8) {
            let buf = [b];
            let key = std::str::from_utf8(&buf).unwrap();

            let cmd = Command::new().env(key, "foo").prog("echo").complete(false);
            assert_eq!(cmd.as_str(), "'echo' ; ");
        }
        fn test_impl_fail2(b: u8) {
            let buf = [b'a', b];
            let key = std::str::from_utf8(&buf).unwrap();

            let cmd = Command::new().env(key, "foo").prog("echo").complete(false);
            assert_eq!(cmd.as_str(), "a='foo' 'echo' ; ");
        }

        for b in 0u8..=0x7fu8 {
            let (ok1, ok2) = match b {
                0..0x30 => (false, false),
                0x30..0x3a => (false, true),
                0x3a..0x41 => (false, false),
                0x41..0x5b => (true, true),
                0x5b..0x5f => (false, false),
                0x5f => (true, true),
                0x60 => (false, false),
                0x61..0x7b => (true, true),
                0x7b.. => (false, false),
            };

            if ok1 {
                test_impl_ok1(b);
            } else {
                test_impl_fail1(b);
            }
            if ok2 {
                test_impl_ok2(b);
            } else {
                test_impl_fail2(b);
            }
        }
    }
}
