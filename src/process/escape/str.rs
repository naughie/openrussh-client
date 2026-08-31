use super::{Arg, Escaper};

impl Arg for &str {
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_str(self);
    }
}

impl Arg for String {
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_str(&self);
    }
}

impl Arg for char {
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_char(self);
    }
}

#[cfg(test)]
mod tests {
    use super::super::SurroundBy;
    use super::*;

    #[test]
    fn escape_str_single() {
        fn test_helper(arg: &str, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Single);
            esc.escape_str(arg);
            assert_eq!(
                buf, expected,
                "arg ({arg:?}), escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(r#""#, r#""#);
        test_helper(r#"'"#, r#"'\''"#);
        test_helper(r#"''"#, r#"'\'''\''"#);

        test_helper(r#"abcd"#, r#"abcd"#);
        test_helper(r#"'abcd"#, r#"'\''abcd"#);
        test_helper(r#"a'bcd"#, r#"a'\''bcd"#);
        test_helper(r#"ab'cd"#, r#"ab'\''cd"#);
        test_helper(r#"abc'd"#, r#"abc'\''d"#);
        test_helper(r#"abcd'"#, r#"abcd'\''"#);

        test_helper(r#"''abcd"#, r#"'\'''\''abcd"#);
        test_helper(r#"'a'bcd"#, r#"'\''a'\''bcd"#);
        test_helper(r#"'ab'cd"#, r#"'\''ab'\''cd"#);
        test_helper(r#"'abc'd"#, r#"'\''abc'\''d"#);
        test_helper(r#"'abcd'"#, r#"'\''abcd'\''"#);

        test_helper(r#"a''bcd"#, r#"a'\'''\''bcd"#);
        test_helper(r#"a'b'cd"#, r#"a'\''b'\''cd"#);
        test_helper(r#"a'bc'd"#, r#"a'\''bc'\''d"#);
        test_helper(r#"a'bcd'"#, r#"a'\''bcd'\''"#);

        test_helper(r#"ab''cd"#, r#"ab'\'''\''cd"#);
        test_helper(r#"ab'c'd"#, r#"ab'\''c'\''d"#);
        test_helper(r#"ab'cd'"#, r#"ab'\''cd'\''"#);

        test_helper(r#"abc''d"#, r#"abc'\'''\''d"#);
        test_helper(r#"abc'd'"#, r#"abc'\''d'\''"#);

        test_helper(r#"abcd''"#, r#"abcd'\'''\''"#);
    }

    #[test]
    fn escape_str_double() {
        fn test_helper(arg: &str, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Double);
            esc.escape_str(arg);
            assert_eq!(
                buf, expected,
                "arg ({arg:?}), escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(r#""#, r#""#);
        test_helper(r#"""#, r#"\""#);
        test_helper(r#""""#, r#"\"\""#);
        test_helper(r#"$"#, r#"\$"#);
        test_helper(r#"$$"#, r#"\$\$"#);
        test_helper(r#"\"#, r#"\\"#);
        test_helper(r#"\\"#, r#"\\\\"#);
        test_helper(r#"`"#, r#"\`"#);
        test_helper(r#"``"#, r#"\`\`"#);
        test_helper(r#""$\`"#, r#"\"\$\\\`"#);

        test_helper(r#"abcd"#, r#"abcd"#);
        test_helper(r#""abcd"#, r#"\"abcd"#);
        test_helper(r#"a"bcd"#, r#"a\"bcd"#);
        test_helper(r#"ab"cd"#, r#"ab\"cd"#);
        test_helper(r#"abc"d"#, r#"abc\"d"#);
        test_helper(r#"abcd""#, r#"abcd\""#);

        test_helper(r#"""abcd"#, r#"\"\"abcd"#);
        test_helper(r#""a"bcd"#, r#"\"a\"bcd"#);
        test_helper(r#""ab"cd"#, r#"\"ab\"cd"#);
        test_helper(r#""abc"d"#, r#"\"abc\"d"#);
        test_helper(r#""abcd""#, r#"\"abcd\""#);

        test_helper(r#"a""bcd"#, r#"a\"\"bcd"#);
        test_helper(r#"a"b"cd"#, r#"a\"b\"cd"#);
        test_helper(r#"a"bc"d"#, r#"a\"bc\"d"#);
        test_helper(r#"a"bcd""#, r#"a\"bcd\""#);

        test_helper(r#"ab""cd"#, r#"ab\"\"cd"#);
        test_helper(r#"ab"c"d"#, r#"ab\"c\"d"#);
        test_helper(r#"ab"cd""#, r#"ab\"cd\""#);

        test_helper(r#"abc""d"#, r#"abc\"\"d"#);
        test_helper(r#"abc"d""#, r#"abc\"d\""#);

        test_helper(r#"abcd"""#, r#"abcd\"\""#);
    }
}
