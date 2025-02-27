use core::ops::DivAssign;
use core::num::traits::{OverflowingMul, WideMul };

pub fn get_bit_at<
    T,
    +Add<T>,
    +Sub<T>,
    +Mul<T>,
    +Div<T>,
    +DivAssign<T, T>,
    +Rem<T>,
    +BitAnd<T>,
    +BitOr<T>,
    +BitNot<T>,
    +PartialEq<T>,
    +PartialOrd<T>,
    +Into<u8, T>,
    +Into<T, u256>,
    +TryInto<u256, T>,
    +Drop<T>,
    +Copy<T>,
>(
    x: T, i: u8
) -> bool {
    let mask: T = fast_power(2_u8.into(), i.into());
    x & mask == mask
}

pub fn most_significant_bit<
    T,
    +Add<T>,
    +Sub<T>,
    +Mul<T>,
    +Div<T>,
    +DivAssign<T, T>,
    +Rem<T>,
    +BitAnd<T>,
    +BitOr<T>,
    +BitNot<T>,
    +PartialEq<T>,
    +PartialOrd<T>,
    +Into<u8, T>,
    +Into<T, u256>,
    +TryInto<u256, T>,
    +Drop<T>,
    +Copy<T>,
>(
    x: T
) -> Option<u8> {
    let mut x: u256 = x.into();
    if x == 0_u8.into() {
        return Option::None;
    }
    let mut r: u8 = 0;

    if x >= 0x100000000000000000000000000000000 {
        x /= 0x100000000000000000000000000000000;
        r += 128;
    }
    if x >= 0x10000000000000000 {
        x /= 0x10000000000000000;
        r += 64;
    }
    if x >= 0x100000000 {
        x /= 0x100000000;
        r += 32;
    }
    if x >= 0x10000 {
        x /= 0x10000;
        r += 16;
    }
    if x >= 0x100 {
        x /= 0x100;
        r += 8;
    }
    if x >= 0x10 {
        x /= 0x10;
        r += 4;
    }
    if x >= 0x4 {
        x /= 0x4;
        r += 2;
    }
    if x >= 0x2 {
        r += 1;
    }
    Option::Some(r)
}

pub fn fast_power<
    T,
    +Div<T>,
    +DivAssign<T, T>,
    +Rem<T>,
    +Into<u8, T>,
    +Into<T, u256>,
    +TryInto<u256, T>,
    +PartialEq<T>,
    +Copy<T>,
    +Drop<T>,
>(
    base: T, mut power: T,
) -> T {
    assert!(base != 0_u8.into(), "fast_power: invalid input");

    let mut base: u256 = base.into();
    let mut result: u256 = 1;

    loop {
        if power % 2_u8.into() != 0_u8.into() {
            result *= base;
        }
        power /= 2_u8.into();
        if (power == 0_u8.into()) {
            break;
        }
        base *= base;
    };

    result.try_into().expect('too large to fit output type')
}

pub fn pow<T, +Sub<T>, +Mul<T>, +Div<T>, +Rem<T>, +PartialEq<T>, +Into<u8, T>, +Drop<T>, +Copy<T>>(
    base: T, exp: T,
) -> T {
    if exp == 0_u8.into() {
        1_u8.into()
    } else if exp == 1_u8.into() {
        base
    } else if exp % 2_u8.into() == 0_u8.into() {
        pow(base * base, exp / 2_u8.into())
    } else {
        base * pow(base * base, exp / 2_u8.into())
    }
}


pub trait BitShift<
    T, +Sub<T>, +Mul<T>, +Div<T>, +Rem<T>, +PartialEq<T>, +Into<u8, T>, +Drop<T>, +Copy<T>,
> {
    // Cannot make SHL generic as u256 doesn't support everything required
    fn shl(x: T, n: T) -> T;
    fn shr(x: T, n: T) -> T {
        x / pow(2_u8.into(), n)
    }
}

pub impl U128BitShift of BitShift<u128> {
    fn shl(x: u128, n: u128) -> u128 {
        WideMul::wide_mul(x, pow(2, n)).low
    }
}

pub impl U256BitShift of BitShift<u256> {
    fn shl(x: u256, n: u256) -> u256 {
        let (r, _) = x.overflowing_mul(pow(2, n));
        r
    }
}
