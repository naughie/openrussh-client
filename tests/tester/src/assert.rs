use crate::Error;

use std::fmt;

struct Msg<M>(M);

impl<M: fmt::Display> fmt::Debug for Msg<&M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        M::fmt(self.0, f)
    }
}

pub fn assert_eq<T, U>(lhs: T, rhs: U, msg: impl fmt::Display + 'static) -> Result<(), Error>
where
    T: PartialEq<U> + fmt::Debug + 'static,
    U: fmt::Debug + 'static,
{
    struct Error<T, U, M>(T, U, M);

    impl<T: fmt::Debug, U: fmt::Debug, M: fmt::Display> fmt::Debug for Error<T, U, M> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("AssertEq")
                .field("lhs", &self.0)
                .field("rhs", &self.1)
                .field("msg", &Msg(&self.2))
                .finish()
        }
    }
    impl<T: fmt::Debug, U: fmt::Debug, M: fmt::Display> fmt::Display for Error<T, U, M> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "assertion failed: {} (lhs: {:?}, rhs: {:?})",
                self.2, self.0, self.1
            )
        }
    }
    impl<T: fmt::Debug, U: fmt::Debug, M: fmt::Display> std::error::Error for Error<T, U, M> {}

    if lhs == rhs {
        Ok(())
    } else {
        Err(Box::new(Error(lhs, rhs, msg)))
    }
}

pub fn assert(v: bool, msg: impl fmt::Display + 'static) -> Result<(), Error> {
    struct Error<M>(M);

    impl<M: fmt::Display> fmt::Debug for Error<M> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Assert").field(&Msg(&self.0)).finish()
        }
    }
    impl<M: fmt::Display> fmt::Display for Error<M> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "assertion failed: {} (expected: true)", self.0)
        }
    }
    impl<M: fmt::Display> std::error::Error for Error<M> {}

    if v { Ok(()) } else { Err(Box::new(Error(msg))) }
}

pub fn assert_is_ok<T, E>(
    result: Result<T, E>,
    msg: impl fmt::Display + 'static,
) -> Result<(), Error>
where
    E: fmt::Display + 'static,
{
    struct Error<E, M>(E, M);

    impl<E: fmt::Display, M: fmt::Display> fmt::Debug for Error<E, M> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("AssertIsOk")
                .field("result", &Msg(&self.0))
                .field("msg", &Msg(&self.1))
                .finish()
        }
    }
    impl<E: fmt::Display, M: fmt::Display> fmt::Display for Error<E, M> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "assertion failed: {} (expected Ok(_) but Err({}) was found)",
                self.1, self.0
            )
        }
    }
    impl<E: fmt::Display, M: fmt::Display> std::error::Error for Error<E, M> {}

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(Error(e, msg))),
    }
}
