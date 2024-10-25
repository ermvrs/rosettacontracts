use core::integer::{u512};
use core::num::traits::{Zero, One, BitSize, OverflowingAdd, OverflowingMul, Bounded};
use core::panic_with_felt252;
use core::traits::{BitAnd};

// === Exponentiation ===

pub trait Exponentiation<T> {
    /// Raise a number to a power.
    ///
    /// # Arguments
    ///
    /// * `self` - The base number
    /// * `exponent` - The exponent to raise the base to
    ///
    /// # Returns
    ///
    /// The result of raising `self` to the power of `exponent`
    ///
    /// # Panics
    ///
    /// Panics if the result overflows the type T.
    fn pow(self: T, exponent: T) -> T;
}

impl ExponentiationImpl<
    T,
    +Zero<T>,
    +One<T>,
    +Add<T>,
    +Sub<T>,
    +Mul<T>,
    +Div<T>,
    +BitAnd<T>,
    +PartialEq<T>,
    +Copy<T>,
    +Drop<T>
> of Exponentiation<T> {
    fn pow(self: T, mut exponent: T) -> T {
        let zero = Zero::zero();
        if self.is_zero() {
            return zero;
        }
        let one = One::one();
        let mut result = one;
        let mut base = self;
        let two = one + one;

        loop {
            if exponent & one == one {
                result = result * base;
            }

            exponent = exponent / two;
            if exponent == zero {
                break result;
            }

            base = base * base;
        }
    }
}

pub trait WrappingExponentiation<T> {
    /// Raise a number to a power modulo MAX<T> (max value of type T).
    /// Instead of explicitly providing a modulo, we use overflowing functions
    /// from the core library, which wrap around when overflowing.
    ///
    /// # Arguments
    ///
    /// * `self` - The base number
    /// * `exponent` - The exponent to raise the base to
    ///
    /// # Returns
    ///
    /// The result of base raised to the power of exp modulo MAX<T>.
    fn wrapping_pow(self: T, exponent: T) -> T;

    /// Performs exponentiation by repeatedly multiplying the base number with itself.
    ///
    /// This function uses a simple loop to perform exponentiation. It continues to multiply
    /// the base number (`self`) with itself, for the number of times specified by `exponent`.
    /// The method uses a wrapping strategy to handle overflow, which means if the result
    /// overflows the type `T`, then higher bits are discarded and the result is wrapped.
    ///
    /// # Arguments
    ///
    /// * `self` - The base number of type `T`.
    /// * `exponent` - The exponent to which the base number is raised, also of type `T`.
    ///
    /// # Returns
    ///
    /// The result of raising `self` to the power of `exponent`, of type `T`.
    /// The result is wrapped in case of overflow.
    fn wrapping_spow(self: T, exponent: T) -> T;

    /// Performs exponentiation using the binary exponentiation method.
    ///
    /// This function calculates the power of a number using binary exponentiation, which is
    /// an optimized method for exponentiation that reduces the number of multiplications.
    /// It works by repeatedly squaring the base and reducing the exponent by half, using
    /// a wrapping strategy to handle overflow. This means if intermediate or final results
    /// overflow the type `T`, then the higher bits are discarded and the result is wrapped.
    ///
    /// # Arguments
    ///
    /// * `self` - The base number of type `T`.
    /// * `exponent` - The exponent to which the base number is raised, also of type `T`.
    ///
    /// # Returns
    ///
    /// The result of raising `self` to the power of `exponent`, of type `T`.
    /// The result is wrapped in case of overflow.
    fn wrapping_fpow(self: T, exponent: T) -> T;
}


pub impl WrappingExponentiationImpl<
    T,
    +OverflowingMul<T>,
    +Zero<T>,
    +One<T>,
    +Add<T>,
    +Mul<T>,
    +Div<T>,
    +Rem<T>,
    +Copy<T>,
    +Drop<T>,
    +PartialEq<T>,
    +PartialOrd<T>,
    +core::ops::SubAssign<T, T>
> of WrappingExponentiation<T> {
    fn wrapping_pow(self: T, exponent: T) -> T {
        if exponent == Zero::zero() {
            return One::one();
        }

        if self == Zero::zero() {
            return Zero::zero();
        }

        let one = One::<T>::one();
        let ten = one + one + one + one + one + one + one + one + one + one;

        if exponent > ten {
            self.wrapping_fpow(exponent)
        } else {
            self.wrapping_spow(exponent)
        }
    }

    fn wrapping_spow(self: T, exponent: T) -> T {
        let mut exponent = exponent;
        let mut base = self;
        let mut result = One::one();

        while exponent != Zero::zero() {
            let (new_result, _) = result.overflowing_mul(base);
            result = new_result;
            exponent -= One::one();
        };
        result
    }

    fn wrapping_fpow(self: T, exponent: T) -> T {
        let mut result = One::one();
        let mut base = self;
        let mut exponent = exponent;
        let two = One::<T>::one() + One::<T>::one();

        loop {
            if exponent % two != Zero::zero() {
                let (new_result, _) = result.overflowing_mul(base);
                result = new_result;
            }

            exponent = exponent / two;
            if exponent == Zero::zero() {
                break result;
            }

            let (new_base, _) = base.overflowing_mul(base);
            base = new_base;
        }
    }
}

// === BitShift ===

pub trait Bitshift<T> {
    /// Shift a number left by a given number of bits.
    ///
    /// # Arguments
    ///
    /// * `self` - The number to shift
    /// * `shift` - The number of bits to shift by
    ///
    /// # Returns
    ///
    /// The result of shifting `self` left by `shift` bits
    ///
    /// # Panics
    ///
    /// Panics if the shift is greater than 255.
    /// Panics if the result overflows the type T.
    fn shl(self: T, shift: usize) -> T;

    /// Shift a number right by a given number of bits.
    ///
    /// # Arguments
    ///
    /// * `self` - The number to shift
    /// * `shift` - The number of bits to shift by
    ///
    /// # Returns
    ///
    /// The result of shifting `self` right by `shift` bits
    ///
    /// # Panics
    ///
    /// Panics if the shift is greater than 255.
    fn shr(self: T, shift: usize) -> T;
}

impl BitshiftImpl<
    T,
    +Zero<T>,
    +One<T>,
    +Add<T>,
    +Sub<T>,
    +Div<T>,
    +Mul<T>,
    +Exponentiation<T>,
    +Copy<T>,
    +Drop<T>,
    +PartialOrd<T>,
    +BitSize<T>,
    +TryInto<usize, T>,
    +TryInto<T, usize>,
    +TryInto<u256, T>,
> of Bitshift<T> {
    fn shl(self: T, shift: usize) -> T {
        // if we shift by more than nb_bits of T, the result is 0
        // we early return to save gas and prevent unexpected behavior
        if shift > BitSize::<T>::bits() - One::one() {
            panic_with_felt252('mul Overflow');
        }
        let two = One::one() + One::one();
        self * two.pow(shift.try_into().expect('mul Overflow'))
    }

    fn shr(self: T, shift: usize) -> T {
        // early return to save gas if shift > nb_bits of T
        if shift > BitSize::<T>::bits() - One::one() {
            panic_with_felt252('mul Overflow');
        }
        let two = One::one() + One::one();
        self / two.pow(shift.try_into().expect('mul Overflow'))
    }
}

pub trait WrappingBitshift<T> {
    /// Shift a number left by a given number of bits.
    /// If the shift is greater than 255, the result is 0.
    /// The bits moved after the 256th one are discarded, the new bits are set to 0.
    ///
    /// # Arguments
    ///
    /// * `self` - The number to shift
    /// * `shift` - The number of bits to shift by
    ///
    /// # Returns
    ///
    /// The result of shifting `self` left by `shift` bits, wrapped if necessary
    fn wrapping_shl(self: T, shift: usize) -> T;

    /// Shift a number right by a given number of bits.
    /// If the shift is greater than 255, the result is 0.
    ///
    /// # Arguments
    ///
    /// * `self` - The number to shift
    /// * `shift` - The number of bits to shift by
    ///
    /// # Returns
    ///
    /// The result of shifting `self` right by `shift` bits, or 0 if shift > 255
    fn wrapping_shr(self: T, shift: usize) -> T;
}

pub impl WrappingBitshiftImpl<
    T,
    +Zero<T>,
    +One<T>,
    +Add<T>,
    +Sub<T>,
    +Div<T>,
    +Exponentiation<T>,
    +PartialOrd<T>,
    +Drop<T>,
    +Copy<T>,
    +OverflowingMul<T>,
    +WrappingExponentiation<T>,
    +BitSize<T>,
    +Bounded<T>,
    +TryInto<usize, T>,
    +TryInto<T, usize>,
    +TryInto<u256, T>,
    +Into<T, u256>
> of WrappingBitshift<T> {
    fn wrapping_shl(self: T, shift: usize) -> T {
        let two = One::<T>::one() + One::<T>::one();
        let (result, _) = self.overflowing_mul(two.wrapping_pow(shift.try_into().unwrap()));
        result
    }

    fn wrapping_shr(self: T, shift: usize) -> T {
        let two = One::<T>::one() + One::<T>::one();

        if shift > BitSize::<T>::bits() - One::one() {
            return Zero::zero();
        }
        self / two.pow(shift.try_into().unwrap())
    }
}

// === Standalone functions ===

/// Adds two 256-bit unsigned integers, returning a 512-bit unsigned integer result.
///
/// limb3 will always be 0, because the maximum sum of two 256-bit numbers is at most
/// 2**257 - 2 which fits in 257 bits.
///
/// # Arguments
///
/// * `a` - First 256-bit unsigned integer
/// * `b` - Second 256-bit unsigned integer
///
/// # Returns
///
/// A 512-bit unsigned integer representing the sum of `a` and `b`
pub fn u256_wide_add(a: u256, b: u256) -> u512 {
    let (sum, overflow) = a.overflowing_add(b);

    let limb0 = sum.low;
    let limb1 = sum.high;

    let limb2 = if overflow {
        1
    } else {
        0
    };

    let limb3 = 0;

    u512 { limb0, limb1, limb2, limb3 }
}
