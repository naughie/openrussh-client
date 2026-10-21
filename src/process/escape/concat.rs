use super::{Arg, Escaper};

/// Concatenates the items of an [`IntoIterator`] into a single argument.
///
/// Items are escaped and written without separators. The surrounding quotes are selected by the
/// item type's [`Arg::need_double()`], including for an empty iterator.
///
/// ```
/// use openrussh_client::process::Command;
/// use openrussh_client::process::escape::Concat;
///
/// let cmd = Command::new()
///     .prog("echo")
///     .arg(Concat(["I", " don't", " know"]))
///     .complete(false);
///
/// assert_eq!(cmd.as_str(), "'echo' 'I don'\\''t know' ; ");
/// ```
#[derive(Debug, Clone)]
pub struct Concat<I>(pub I);

impl<I, A> Arg for Concat<I>
where
    I: IntoIterator<Item = A>,
    A: Arg,
{
    fn need_double() -> bool {
        A::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self.0 {
            <A as Arg>::write(item, escaper);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::SurroundBy;
    use super::*;

    #[test]
    fn escape_concat() {
        fn test_helper<A: Arg, I: IntoIterator<Item = A>>(arg: I, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Single);
            esc.escape(Concat(arg));
            assert_eq!(
                buf, expected,
                "escaped ({buf:?}) and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(["I"], "I");
        test_helper(["I", "don't", "know"], "Idon'\\''tknow");
    }
}
