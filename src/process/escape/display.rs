use super::{Arg, Escaper};

use std::fmt;

/// Wraps a value implementing [`fmt::Display`] as a command argument.
///
/// The formatted value is escaped in the same way as [`Escaper::escape_str()`].
///
/// ```
/// use openrussh_client::process::Command;
/// use openrussh_client::process::escape::Display;
///
/// let cmd = Command::new()
///     .prog("echo")
///     .arg(Display(format_args!("{}-{}", 1, 2)))
///     .complete(false);
///
/// assert_eq!(cmd.as_str(), "'echo' '1-2' ; ");
/// ```
#[derive(Debug, Clone)]
pub struct Display<T>(pub T);

impl<T> Arg for Display<T>
where
    T: fmt::Display,
{
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_fmt(&self.0);
    }
}

impl<T> Arg for &Display<T>
where
    T: fmt::Display,
{
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_fmt(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::SurroundBy;
    use super::*;

    #[test]
    fn escape_fmt_single() {
        fn test_helper(arg: impl fmt::Display, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Single);
            esc.escape_fmt(&arg);
            assert_eq!(
                buf, expected,
                "arg ({arg}), escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper('a', r#"a"#);
        test_helper('\'', r#"'\''"#);

        test_helper(r#""#, r#""#);
        test_helper(r#"ab'cd"#, r#"ab'\''cd"#);

        test_helper(0i32, "0");
        test_helper(1i32, "1");
        test_helper(65535i32, "65535");

        test_helper(format_args!("{}-{}-{}", 1, 2, 3), r#"1-2-3"#);
        test_helper(format_args!("{}'-{}'-{}'", 1, 2, 3), r#"1'\''-2'\''-3'\''"#);
    }
}
