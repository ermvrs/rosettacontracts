use core::ops::DivAssign;



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
>(x: T, i: u8) -> bool {
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
>(x: T) -> Option<u8> {
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