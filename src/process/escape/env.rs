use super::{Arg, Escaper};

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
