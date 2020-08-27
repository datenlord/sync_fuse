macro_rules! impl_from {
    ($target: ty) => {
        impl Uint<$target> for $target {
            #[inline]
            fn overflow_add(self, other: $target) -> Self {
                let (res, overflow) = self.overflowing_add(other);
                debug_assert!(
                    !overflow,
                    "number = {} add number = {} overflowing",
                    self, other
                );
                res
            }

            #[inline]
            fn overflow_sub(self, other: $target) -> Self {
                let (res, overflow) = self.overflowing_sub(other);
                debug_assert!(
                    !overflow,
                    "number = {} substract number = {} overflowing",
                    self, other
                );
                res
            }

            #[inline]
            fn overflow_mul(self, other: $target) -> Self {
                let (res, overflow) = self.overflowing_mul(other);
                debug_assert!(
                    !overflow,
                    "number = {} multiply number = {} overflowing",
                    self, other
                );
                res
            }

            #[inline]
            fn overflow_div(self, other: $target) -> Self {
                let (res, overflow) = self.overflowing_div(other);
                debug_assert!(
                    !overflow,
                    "number = {} divide number = {} overflowing",
                    self, other
                );
                res
            }
        }
    };
}
impl_from!(u8);
impl_from!(u16);
impl_from!(u32);
impl_from!(u64);
impl_from!(u128);
impl_from!(i8);
impl_from!(i16);
impl_from!(i32);
impl_from!(i64);
impl_from!(i128);
impl_from!(usize);
impl_from!(isize);

/// A type cast trait used to do the integer arithmetic.
pub trait Uint<T> {
    /// Overflow add.
    fn overflow_add(self, other: Self) -> Self;

    /// Overflow sub.
    fn overflow_sub(self, other: Self) -> Self;

    /// Overflow mul.
    fn overflow_mul(self, other: Self) -> Self;

    /// Overflow div.
    fn overflow_div(self, other: Self) -> Self;
}
