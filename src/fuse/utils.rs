/// A type cast trait used to do the integer arithmetic.
pub trait Uint {
    /// Overflow add.
    fn overflow_add(self, other: Self) -> Self
    where
        Self: std::fmt::Display + num_traits::ops::checked::CheckedAdd,
    {
        let result = Self::checked_add(&self, &other);
        if let Some(value) = result {
            value
        } else {
            debug_assert!(
                false,
                "number = {} add number = {} overflowing",
                self, other
            );
            self
        }
    }

    /// Overflow sub.
    fn overflow_sub(self, other: Self) -> Self
    where
        Self: std::fmt::Display + num_traits::ops::checked::CheckedSub,
    {
        let result = Self::checked_sub(&self, &other);
        if let Some(value) = result {
            value
        } else {
            debug_assert!(
                false,
                "number = {} substract number = {} overflowing",
                self, other
            );
            self
        }
    }

    /// Overflow mul.
    fn overflow_mul(self, other: Self) -> Self
    where
        Self: std::fmt::Display + num_traits::ops::checked::CheckedMul,
    {
        let result = Self::checked_mul(&self, &other);
        if let Some(value) = result {
            value
        } else {
            debug_assert!(
                false,
                "number = {} multiply number = {} overflowing",
                self, other
            );
            self
        }
    }

    /// Overflow div.
    fn overflow_div(self, other: Self) -> Self
    where
        Self: std::fmt::Display + num_traits::ops::checked::CheckedDiv,
    {
        let result = Self::checked_div(&self, &other);
        if let Some(value) = result {
            value
        } else {
            debug_assert!(
                false,
                "number = {} divide number = {} overflowing",
                self, other
            );
            self
        }
    }
}

impl<T> Uint for T {}
