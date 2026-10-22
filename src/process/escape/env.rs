use super::{Arg, Escaper};

/// Expands a shell variable on the server, `${FOO}`.
///
/// The contents are written as-is between `${` and `}`, without validation or escaping.
/// Unlike [`Command::env()`](super::super::Command::env()), this accepts parameter
/// expansions such as `${FOO:-default}`, so the contents are not validated as a variable name.
/// This argument requires double quotes.
///
/// ```
/// use openrussh_client::process::Command;
/// use openrussh_client::process::escape::Env;
///
/// let cmd = Command::new()
///     .prog("echo")
///     .arg(Env("HOME"))
///     .arg(Env("FOO:-default"))
///     .complete(false);
///
/// assert_eq!(cmd.as_str(), "'echo' \"${HOME}\" \"${FOO:-default}\" ; ");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Env<'a>(pub &'a str);

impl Arg for Env<'_> {
    fn need_double() -> bool {
        true
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.write_raw("${");
        escaper.write_raw(self.0);
        escaper.write_raw_char('}');
    }
}

impl Arg for &Env<'_> {
    fn need_double() -> bool {
        true
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        <Env<'_> as Arg>::write(*self, escaper)
    }
}

#[cfg(test)]
mod tests {
    use super::super::SurroundBy;
    use super::*;

    #[test]
    fn escape_env() {
        fn test_helper(env: &str, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Double);
            esc.escape(Env(env));
            assert_eq!(
                buf, expected,
                "env ({env}), escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper("abc0_ABC", "${abc0_ABC}");
        test_helper("ENV:-default", "${ENV:-default}");
    }
}
