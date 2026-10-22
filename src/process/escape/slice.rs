use super::{Arg, Escaper};

impl<'a, A> Arg for &'a [A]
where
    &'a A: Arg,
{
    fn need_double() -> bool {
        <&A as Arg>::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <&A as Arg>::write(item, escaper);
        }
    }
}

impl<A: Arg> Arg for Box<[A]> {
    fn need_double() -> bool {
        A::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <A as Arg>::write(item, escaper);
        }
    }
}
impl<'a, A> Arg for &'a Box<[A]>
where
    &'a A: Arg,
{
    fn need_double() -> bool {
        <&A as Arg>::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <&A as Arg>::write(item, escaper);
        }
    }
}

impl<A: Arg> Arg for Vec<A> {
    fn need_double() -> bool {
        A::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <A as Arg>::write(item, escaper);
        }
    }
}
impl<'a, A> Arg for &'a Vec<A>
where
    &'a A: Arg,
{
    fn need_double() -> bool {
        <&A as Arg>::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <&A as Arg>::write(item, escaper);
        }
    }
}

impl<A: Arg, const N: usize> Arg for [A; N] {
    fn need_double() -> bool {
        A::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <A as Arg>::write(item, escaper);
        }
    }
}
impl<'a, A, const N: usize> Arg for &'a [A; N]
where
    &'a A: Arg,
{
    fn need_double() -> bool {
        <&A as Arg>::need_double()
    }

    fn write(self, escaper: &mut Escaper<'_>) {
        for item in self {
            <&A as Arg>::write(item, escaper);
        }
    }
}
