//! Provides the escaping of command arguments.
//!
//! [`Command`](super::Command) surrounds each [`Arg`] by single quotes or double quotes, depending
//! on [`Arg::need_double()`]. The quote choice depends only on the argument type. [`Env`] provides
//! parameter expansions, and [`ExpandCommand`] provides command substitutions.
//! Tuples and [`Concat`] concatenate their components inside a single pair of quotes.
//!
//! # Usage
//!
//! ```
//! use openrussh_client::process::Command;
//! use openrussh_client::process::escape::Env;
//!
//! let cmd = Command::new()
//!     .prog("echo")
//!     .arg(("your home = ", Env("HOME")))
//!     .complete(false);
//!
//! assert_eq!(cmd.as_str(), "'echo' \"your home = ${HOME}\" ; ");
//! ```

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

/// Appends escaped command arguments to a buffer.
///
/// It writes the contents inside quotes; the surrounding quotes themselves are written by
/// [`Command`](super::Command). You can use this type when implementing [`Arg`].
///
/// ```
/// use openrussh_client::process::escape::{Escaper, SurroundBy};
///
/// let mut buf = String::new();
/// let mut escaper = Escaper::new(&mut buf, SurroundBy::Single);
/// escaper.escape_str("don't");
///
/// assert_eq!(buf, "don'\\''t");
/// ```
pub struct Escaper<'a> {
    buf: &'a mut String,
    surr: SurroundBy,
}

impl<'a> Escaper<'a> {
    /// Creates an escaper for the contents surrounded by `surr`.
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

/// The surrounding quotes used for escaping an argument.
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

    /// Escapes a string according to the surrounding quotes.
    ///
    /// With single quotes, it replaces `'` with `'\''`. With double quotes, it prefixes
    /// `\`, `$`, `"`, and `` ` `` with `\`.
    /// Other characters are written as-is.
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

    /// Escapes a character in the same way as [`Escaper::escape_str()`].
    pub fn escape_char(&mut self, c: char) {
        match self.surr {
            SurroundBy::Double => self.escape_char_double(c),
            SurroundBy::Single => self.escape_char_single(c),
        }
    }

    /// Escapes a value formatted by [`fmt::Display`].
    pub fn escape_fmt<T: fmt::Display>(&mut self, v: &T) {
        use fmt::Write as _;
        write!(self, "{v}").ok();
    }

    /// Writes an argument by [`Arg::write()`].
    ///
    /// It uses the escaping mode given to [`Escaper::new()`], without checking
    /// [`Arg::need_double()`].
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

/// Represents a command argument.
///
/// We forbid to pass an [`&OsStr`](std::ffi::OsStr) or a [`&Path`](std::path::Path) because
/// they depend on the OS at the *compile time*, not on the server environment.
pub trait Arg {
    /// Indicates whether the argument requires double quotes.
    ///
    /// `true` requires double quotes, while `false` permits either single quotes or double quotes.
    /// It defaults to `false`.
    fn need_double() -> bool {
        false
    }

    /// Writes the argument to the [`Escaper`], without the surrounding quotes.
    fn write(self, escaper: &mut Escaper<'_>);
}
