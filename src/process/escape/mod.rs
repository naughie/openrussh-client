mod cmd;
mod concat;
mod display;
mod env;
mod primitives;
mod str;
mod tuple;

pub use cmd::ExpandCommand;
pub use cmd::ExpandCommandArg;
pub use concat::Concat;
pub use display::Display;
pub use env::Env;

use std::fmt;

pub struct Escaper<'a> {
    buf: &'a mut String,
    surr: SurroundBy,
}

impl<'a> Escaper<'a> {
    pub fn new(buf: &'a mut String, surr: SurroundBy) -> Self {
        Self { buf, surr }
    }
}

impl Escaper<'_> {
    fn write_raw(&mut self, s: &str) {
        self.buf.push_str(s);
    }

    fn write_raw_char(&mut self, c: char) {
        self.buf.push(c);
    }

    fn as_raw(&mut self) -> &mut String {
        self.buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurroundBy {
    Double,
    Single,
}

impl Escaper<'_> {
    fn escape_str_single(&mut self, s: &str) {
        let mut it = s.split('\'');

        if let Some(segment) = it.next() {
            self.write_raw(segment);
        }

        for segment in it {
            self.write_raw("'\\''");
            self.write_raw(segment);
        }
    }

    fn escape_str_double(&mut self, s: &str) {
        const TARGET: [char; 4] = ['\\', '$', '"', '`'];
        let it = s.split_inclusive(TARGET);

        for segment in it {
            if let Some(s) = segment.strip_suffix(TARGET) {
                self.write_raw(s);
                self.write_raw_char('\\');
                self.write_raw_char(segment.as_bytes()[s.len()] as char);
            } else {
                self.write_raw(segment);
            }
        }
    }

    pub fn escape_str(&mut self, s: &str) {
        match self.surr {
            SurroundBy::Double => self.escape_str_double(s),
            SurroundBy::Single => self.escape_str_single(s),
        }
    }

    fn escape_char_single(&mut self, c: char) {
        if c == '\'' {
            self.write_raw("'\\''");
        } else {
            self.write_raw_char(c);
        }
    }

    fn escape_char_double(&mut self, c: char) {
        const TARGET: [char; 4] = ['\\', '$', '"', '`'];
        if TARGET.contains(&c) {
            self.write_raw_char('\\');
            self.write_raw_char(c);
        } else {
            self.write_raw_char(c);
        }
    }

    pub fn escape_char(&mut self, c: char) {
        match self.surr {
            SurroundBy::Double => self.escape_char_double(c),
            SurroundBy::Single => self.escape_char_single(c),
        }
    }

    pub fn escape_fmt<T: fmt::Display>(&mut self, v: &T) {
        use fmt::Write as _;
        write!(self, "{v}").ok();
    }

    pub fn escape<T: Arg>(&mut self, v: T) {
        T::write(v, self);
    }
}

impl fmt::Write for Escaper<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.escape_str(s);
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        self.escape_char(c);
        Ok(())
    }
}

pub trait Arg {
    fn need_double() -> bool {
        false
    }

    fn write(self, escaper: &mut Escaper<'_>);
}
