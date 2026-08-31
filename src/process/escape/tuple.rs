use super::{Arg, Escaper};

macro_rules! _impl_arg_for_tuple {
    ($T0:ident, $( $T:ident, )* ) => {
        impl<$T0, $( $T, )* > Arg for ($T0, $( $T, )* )
        where
            $T0: Arg,
            $( $T: Arg, )*
        {
            fn need_double() -> bool {
                <$T0 as Arg>::need_double()
                $( || <$T as Arg>::need_double() )*
            }
            #[allow(non_snake_case)]
            fn write(self, escaper: &mut Escaper<'_>) {
                let (
                    $T0,
                    $( $T, )*
                ) = self;
                <$T0 as Arg>::write($T0, escaper);
                $( <$T as Arg>::write($T, escaper); )*
            }
        }
    };
}

_impl_arg_for_tuple! { T0, }
_impl_arg_for_tuple! { T0, T1, }
_impl_arg_for_tuple! { T0, T1, T2, }
_impl_arg_for_tuple! { T0, T1, T2, T3, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, }
_impl_arg_for_tuple! { T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, }

#[cfg(test)]
mod tests {
    use super::super::{Env, SurroundBy};
    use super::*;

    use std::fmt::Debug;

    #[test]
    fn escape_tuple() {
        fn test_helper<A: Arg + Debug + Copy>(arg: A, double: bool, expected: &str) {
            assert_eq!(
                <A as Arg>::need_double(),
                double,
                "A::need_double() ({arg:?}): expected {double} but found {}",
                <A as Arg>::need_double()
            );

            let surr = if double {
                SurroundBy::Double
            } else {
                SurroundBy::Single
            };

            let mut buf = String::new();
            let mut esc = Escaper::new(&mut buf, surr);
            esc.escape(arg);
            assert_eq!(
                buf, expected,
                "arg ({arg:?}), escaped ({buf:?}), and expected ({expected:?}) are mismatched"
            );
        }

        test_helper(("abc",), false, r#"abc"#);
        test_helper(("abc", 30, "'def"), false, r#"abc30'\''def"#);

        test_helper((Env("abc"),), true, r#"${abc}"#);
        test_helper((Env("abc"), "ab'c", "de$f"), true, r#"${abc}ab'cde\$f"#);
        test_helper(("ab'c", Env("abc"), "de$f"), true, r#"ab'c${abc}de\$f"#);
        test_helper(("ab'c", "de$f", Env("abc")), true, r#"ab'cde\$f${abc}"#);
    }
}
