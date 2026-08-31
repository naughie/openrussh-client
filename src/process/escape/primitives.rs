use super::{Arg, Escaper};

impl Arg for bool {
    fn write(self, escaper: &mut Escaper<'_>) {
        let s = if self { "true" } else { "false" };
        escaper.write_raw(s);
    }
}

impl Arg for u8 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for u16 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for u32 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for u64 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for usize {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}

impl Arg for i8 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for i16 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for i32 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for i64 {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}
impl Arg for isize {
    fn write(self, escaper: &mut Escaper<'_>) {
        let mut buf = core::fmt::NumBuffer::new();
        escaper.write_raw(self.format_into(&mut buf));
    }
}

#[cfg(test)]
mod tests {
    use super::super::SurroundBy;
    use super::*;

    #[test]
    fn escape_bool() {
        fn test_helper(arg: bool, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Single);
            esc.escape(arg);
            assert_eq!(
                buf, expected,
                "escaped ({buf:?}) and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(true, "true");
        test_helper(false, "false");
    }

    #[test]
    fn escape_int() {
        fn test_helper(arg: i32, expected: &str) {
            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, SurroundBy::Single);
            esc.escape(arg);
            assert_eq!(
                buf, expected,
                "escaped ({buf:?}) and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(0, "0");
        test_helper(1000, "1000");
        test_helper(-1000, "-1000");
    }
}
