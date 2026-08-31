use super::{Arg, Escaper};

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
