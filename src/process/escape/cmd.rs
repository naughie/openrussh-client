use super::super::cmd::{Completed, NeedProg, NeedTerm, Redirect, RedirectTo};
use super::super::helpers;
use super::{Arg, Escaper};

use std::marker::PhantomData;

/// Expands a command on the server, `$( inner-command )`.
///
/// The builder itself is allocation-free and has no internal buffer, unlike
/// [`Command`](super::super::Command), which owns its command buffer. It stores the command
/// parts and writes them directly to the outer buffer in [`Arg::write()`].
/// The resulting `$(...)` is written without escaping its contents again.
///
/// Call [`ExpandCommand::complete()`] before passing it as an [`Arg`].
/// This argument requires double quotes.
///
/// Environment assignments can only be added before the program name. Arguments and redirects
/// can be added after it. After [`ExpandCommand::and()`], [`ExpandCommand::or()`], or
/// [`ExpandCommand::pipe()`], you must supply another program name. `complete()` always terminates
/// by `;`, with no background flag or equivalent to [`Command::chain()`](super::super::Command::chain()).
///
/// # Usage
///
/// ```
/// use openrussh_client::process::Command;
/// use openrussh_client::process::escape::{Env, ExpandCommand};
///
/// let cmd = Command::new()
///     .prog("echo")
///     .arg((
///         "found path = ",
///         ExpandCommand::new()
///             .prog("ls")
///             .arg(Env("PWD"))
///             .pipe()
///             .prog("head")
///             .arg("-1")
///             .complete(),
///     ))
///     .complete(false);
///
/// assert_eq!(cmd.as_str(), "'echo' \"found path = $('ls' \"${PWD}\" | 'head' '-1' ; )\" ; ");
/// ```
pub struct ExpandCommand<St = NeedProg, Arg = ()>(PhantomData<St>, Arg);

use self::ExpandCommand as Ec;

impl ExpandCommand {
    /// Creates a new command expansion.
    pub fn new() -> Self {
        Self(PhantomData, ())
    }
}

impl Default for ExpandCommand {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Then<S, T>(S, T);

pub struct Env<'a, V>(&'a str, V);
pub struct Envs<I>(I);
pub struct Args<I>(I);
pub struct And;
pub struct Or;
pub struct Pipe;
pub struct Term;

/// Represents a part of an [`ExpandCommand`].
pub trait Part {
    fn write(self, buf: &mut String);
}

pub use self::Part as ExpandCommandArg;

impl<V: Arg> Part for Env<'_, V> {
    fn write(self, buf: &mut String) {
        helpers::env(buf, self.0, self.1);
    }
}
impl<'a, I, V> Part for Envs<I>
where
    I: IntoIterator<Item = (&'a str, V)>,
    V: Arg,
{
    fn write(self, buf: &mut String) {
        for (key, value) in self.0 {
            helpers::env(buf, key, value);
        }
    }
}
impl<I, A> Part for Args<I>
where
    I: IntoIterator<Item = A>,
    A: Arg,
{
    fn write(self, buf: &mut String) {
        for arg in self.0 {
            helpers::arg(buf, arg);
        }
    }
}
impl<S: Part, T: Part> Part for Then<S, T> {
    fn write(self, buf: &mut String) {
        <S as Part>::write(self.0, buf);
        <T as Part>::write(self.1, buf);
    }
}
impl Part for And {
    fn write(self, buf: &mut String) {
        buf.push_str("&& ");
    }
}
impl Part for Or {
    fn write(self, buf: &mut String) {
        buf.push_str("|| ");
    }
}
impl Part for Pipe {
    fn write(self, buf: &mut String) {
        buf.push_str("| ");
    }
}
impl Part for Term {
    fn write(self, buf: &mut String) {
        buf.push_str("; ");
    }
}
impl<T: RedirectTo> Part for Redirect<T> {
    fn write(self, buf: &mut String) {
        helpers::redir(buf, self);
    }
}
impl<A: Arg> Part for A {
    fn write(self, buf: &mut String) {
        helpers::arg(buf, self);
    }
}

impl<St> ExpandCommand<St, ()> {
    /// Adds a redirection to the command.
    pub fn redirect<T: RedirectTo>(self, redir: Redirect<T>) -> ExpandCommand<St, Redirect<T>> {
        Ec(PhantomData, redir)
    }
}

impl ExpandCommand<NeedProg, ()> {
    /// Appends an environment assignment before the program name.
    ///
    /// Names and values are handled in the same way as
    /// [`Command::env()`](super::super::Command::env()).
    pub fn env<V: Arg>(self, key: &str, value: V) -> ExpandCommand<NeedProg, Env<'_, V>> {
        Ec(PhantomData, Env(key, value))
    }

    /// Appends environment assignments before the program name.
    ///
    /// Names are handled in the same way as [`ExpandCommand::env()`].
    pub fn envs<'a, I, V>(self, envs: I) -> ExpandCommand<NeedProg, Envs<I>>
    where
        I: IntoIterator<Item = (&'a str, V)>,
        V: Arg,
    {
        Ec(PhantomData, Envs(envs))
    }

    /// Appends the program name, escaped in the same way as command arguments.
    pub fn prog<S: Arg>(self, prog: S) -> ExpandCommand<NeedTerm, S> {
        Ec(PhantomData, prog)
    }
}

impl<A: Part> ExpandCommand<NeedProg, A> {
    /// Appends an environment assignment before the program name.
    ///
    /// Names and values are handled in the same way as
    /// [`Command::env()`](super::super::Command::env()).
    pub fn env<V: Arg>(self, key: &str, value: V) -> ExpandCommand<NeedProg, Then<A, Env<'_, V>>> {
        Ec(PhantomData, Then(self.1, Env(key, value)))
    }

    /// Appends environment assignments before the program name.
    ///
    /// Names are handled in the same way as [`ExpandCommand::env()`].
    pub fn envs<'a, I, V>(self, envs: I) -> ExpandCommand<NeedProg, Then<A, Envs<I>>>
    where
        I: IntoIterator<Item = (&'a str, V)>,
        V: Arg,
    {
        Ec(PhantomData, Then(self.1, Envs(envs)))
    }

    /// Adds a redirection to the command.
    pub fn redirect<T: RedirectTo>(
        self,
        redir: Redirect<T>,
    ) -> ExpandCommand<NeedProg, Then<A, Redirect<T>>> {
        Ec(PhantomData, Then(self.1, redir))
    }

    /// Appends the program name, escaped in the same way as command arguments.
    pub fn prog<S: Arg>(self, prog: S) -> ExpandCommand<NeedTerm, Then<A, S>> {
        Ec(PhantomData, Then(self.1, prog))
    }
}

impl<A: Part> ExpandCommand<NeedTerm, A> {
    /// Adds an argument to the command.
    pub fn arg<S: Arg>(self, arg: S) -> ExpandCommand<NeedTerm, Then<A, S>> {
        Ec(PhantomData, Then(self.1, arg))
    }

    /// Adds arguments to the command.
    pub fn args<I, S>(self, args: I) -> ExpandCommand<NeedTerm, Then<A, Args<I>>>
    where
        I: IntoIterator<Item = S>,
        S: Arg,
    {
        Ec(PhantomData, Then(self.1, Args(args)))
    }

    /// Adds a redirection to the command.
    pub fn redirect<T: RedirectTo>(
        self,
        redir: Redirect<T>,
    ) -> ExpandCommand<NeedTerm, Then<A, Redirect<T>>> {
        Ec(PhantomData, Then(self.1, redir))
    }

    /// Appends `&&` and starts the next command.
    pub fn and(self) -> ExpandCommand<NeedProg, Then<A, And>> {
        Ec(PhantomData, Then(self.1, And))
    }

    /// Appends `||` and starts the next command.
    pub fn or(self) -> ExpandCommand<NeedProg, Then<A, Or>> {
        Ec(PhantomData, Then(self.1, Or))
    }

    /// Appends `|` and starts the next command.
    pub fn pipe(self) -> ExpandCommand<NeedProg, Then<A, Pipe>> {
        Ec(PhantomData, Then(self.1, Pipe))
    }

    /// Completes the inner command by `;` so that it can be passed as an [`Arg`].
    pub fn complete(self) -> ExpandCommand<Completed, Then<A, Term>> {
        Ec(PhantomData, Then(self.1, Term))
    }
}

impl<A: ExpandCommandArg> Arg for ExpandCommand<Completed, A> {
    fn need_double() -> bool {
        true
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.write_raw("$(");
        <A as Part>::write(self.1, escaper.as_raw());
        escaper.write_raw_char(')');
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::cmd::RedirectPath;
    use super::super::Env;
    use super::super::SurroundBy;
    use super::*;

    #[test]
    fn escape_env() {
        fn test_helper(cmd: impl Arg, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Double);
            esc.escape(cmd);
            assert_eq!(
                buf, expected,
                "escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(
            ExpandCommand::new().prog("echo").complete(),
            r#"$('echo' ; )"#,
        );
        test_helper(
            ExpandCommand::new()
                .prog("echo")
                .arg("Hello")
                .arg("World")
                .complete(),
            r#"$('echo' 'Hello' 'World' ; )"#,
        );
        test_helper(
            ExpandCommand::new()
                .prog("echo")
                .args(["Hello", "World"])
                .complete(),
            r#"$('echo' 'Hello' 'World' ; )"#,
        );

        test_helper(
            ExpandCommand::new()
                .env("PATH", ("/bin:", Env("PATH")))
                .prog("echo")
                .complete(),
            r#"$(PATH="/bin:${PATH}" 'echo' ; )"#,
        );

        test_helper(
            ExpandCommand::new()
                .envs([("FOO", "foo"), ("BAR", "bar"), ("BAZ", "baz")])
                .prog("echo")
                .complete(),
            r#"$(FOO='foo' BAR='bar' BAZ='baz' 'echo' ; )"#,
        );

        test_helper(
            ExpandCommand::new()
                .prog("echo")
                .pipe()
                .prog("grep")
                .arg("exp")
                .pipe()
                .prog("cat")
                .complete(),
            r#"$('echo' | 'grep' 'exp' | 'cat' ; )"#,
        );

        test_helper(
            ExpandCommand::new()
                .prog("cat")
                .redirect(Redirect::Stdin {
                    to: RedirectPath("path"),
                })
                .redirect(Redirect::Stderr {
                    to: RedirectPath("/dev/null"),
                    append: false,
                })
                .complete(),
            r#"$('cat' <'path' 2>'/dev/null' ; )"#,
        );

        test_helper(
            (
                "/run/user/",
                ExpandCommand::new().prog("id").arg("-u").complete(),
                "/myapp.sock",
            ),
            r#"/run/user/$('id' '-u' ; )/myapp.sock"#,
        );
    }
}
