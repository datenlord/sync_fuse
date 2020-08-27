macro_rules! impl_overflow_arithmetic {
    ($target: ty) => {
        impl OverflowArithmetic<$target> for $target {
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
impl_overflow_arithmetic!(u8);
impl_overflow_arithmetic!(u16);
impl_overflow_arithmetic!(u32);
impl_overflow_arithmetic!(u64);
impl_overflow_arithmetic!(u128);
impl_overflow_arithmetic!(i8);
impl_overflow_arithmetic!(i16);
impl_overflow_arithmetic!(i32);
impl_overflow_arithmetic!(i64);
impl_overflow_arithmetic!(i128);
impl_overflow_arithmetic!(usize);
impl_overflow_arithmetic!(isize);

/// A type cast trait used to do the integer arithmetic.
pub trait OverflowArithmetic<T> {
    /// Overflow add.
    fn overflow_add(self, other: Self) -> Self;

    /// Overflow sub.
    fn overflow_sub(self, other: Self) -> Self;

    /// Overflow mul.
    fn overflow_mul(self, other: Self) -> Self;

    /// Overflow div.
    fn overflow_div(self, other: Self) -> Self;
}
