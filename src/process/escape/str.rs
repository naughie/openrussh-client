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
impl Arg for &String {
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_str(self);
    }
}

impl Arg for char {
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_char(self);
    }
}
impl Arg for &char {
    fn write(self, escaper: &mut Escaper<'_>) {
        escaper.escape_char(*self);
    }
}

/// Represents a byte string that is not necessarily valid UTF-8.
///
/// All bytes but `\0` that are not printable ASCII are encoded as `\x<hex>`, like
/// `"\u{3042}" ("あ")` becomes `$'\xe3\x81\x82'`.
/// The null byte `\0` is completely ignored.
///
/// ```
/// use openrussh_client::process::Command;
/// use openrussh_client::process::escape::RawBytes;
///
/// let cmd = Command::new()
///     .prog("echo")
///     // "\xe3\x81\x82" == "あ"
///     .arg(RawBytes(b"\xe3\x81\x82"))
///     .arg(RawBytes(b"hello\xff"))
///     .complete(false);
///
/// assert_eq!(cmd.as_str(), "'echo' ''$'\\xe3\\x81\\x82''' 'hello'$'\\xff''' ; ");
/// ```
pub struct RawBytes<T>(pub T);

impl<T: AsRef<[u8]>> Arg for RawBytes<T> {
    fn write(self, escaper: &mut Escaper<'_>) {
        <_ as Arg>::write(&self, escaper)
    }
}
impl<T: AsRef<[u8]>> Arg for &RawBytes<T> {
    fn write(self, escaper: &mut Escaper<'_>) {
        use super::SurroundBy;

        let quote = match escaper.surr {
            SurroundBy::Single => '\'',
            SurroundBy::Double => '"',
        };
        let mut encoding = false;
        for &byte in self.0.as_ref() {
            if (0x20..0x7f).contains(&byte) {
                if encoding {
                    escaper.write_raw_char('\'');
                    escaper.write_raw_char(quote);
                    encoding = false;
                }
                escaper.escape_char(char::from(byte));
            } else if byte != 0 {
                if !encoding {
                    escaper.write_raw_char(quote);
                    escaper.write_raw("$'");
                    encoding = true;
                }

                let hi = byte >> 4;
                let lo = byte & 0x0f;

                let hi = if hi < 0x0a {
                    hi + b'0'
                } else {
                    hi + (b'a' - 0x0a)
                };
                let lo = if lo < 0x0a {
                    lo + b'0'
                } else {
                    lo + (b'a' - 0x0a)
                };

                let escaped = [b'\\', b'x', hi, lo];
                escaper.write_raw(unsafe { std::str::from_utf8_unchecked(&escaped) });
            }
        }
        if encoding {
            escaper.write_raw_char('\'');
            escaper.write_raw_char(quote);
        }
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

    #[test]
    fn escape_raw_bytes() {
        fn test_helper(arg: &[u8], expected: &str) {
            let mut buf = String::new();
            Escaper::new(&mut buf, SurroundBy::Single).escape(RawBytes(arg));
            assert_eq!(
                buf, expected,
                "arg ({arg:?}), escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(b"", "");
        test_helper(b"hello world", "hello world");
        test_helper(b"'\"$\\`", "'\\''\"$\\`");
        test_helper(b"\\xff", "\\xff");

        test_helper("\u{3042}".as_bytes(), r"'$'\xe3\x81\x82''");
        test_helper("é".as_bytes(), r"'$'\xc3\xa9''");
        test_helper(b"\t\n\r", r"'$'\x09\x0a\x0d''");
        test_helper(b"\x1f ~\x7f", r"'$'\x1f'' ~'$'\x7f''");
        test_helper(b"\xff", r"'$'\xff''");
        test_helper(b"\xe3\x81", r"'$'\xe3\x81''");
        test_helper(b"a\xff'f\n", r"a'$'\xff'''\''f'$'\x0a''");
        test_helper(b"\x80af", r"'$'\x80''af");

        test_helper(b"\0hel\0lo\0 world\0", "hello world");
        test_helper(
            "\u{3042}\0\u{3042}".as_bytes(),
            r"'$'\xe3\x81\x82\xe3\x81\x82''",
        );
        test_helper("abc\0\u{3042}".as_bytes(), r"abc'$'\xe3\x81\x82''");
        test_helper("\u{3042}\0abc".as_bytes(), r"'$'\xe3\x81\x82''abc");
    }
}
