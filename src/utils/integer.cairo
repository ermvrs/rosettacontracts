use core::integer::{u128_byte_reverse};
use core::num::traits::{Zero, One, Bounded, BitSize};
use crate::utils::helpers::{u128_split};
use crate::utils::math::{Bitshift};

#[generate_trait]
pub impl U64Impl of U64Trait {
    /// Returns the number of trailing zeroes in the bit representation of `self`.
    /// # Arguments
    /// * `self` a `u64` value.
    /// # Returns
    /// * The number of trailing zeroes in the bit representation of `self`.
    fn count_trailing_zeroes(self: u64) -> u8 {
        let mut count = 0;

        if self == 0 {
            return 64; // If n is 0, all 64 bits are zeros
        };

        let mut mask = 1;

        while (self & mask) == 0 {
            count += 1;
            mask *= 2;
        };

        count
    }
}


#[generate_trait]
pub impl U128Impl of U128Trait {
    /// Returns the Least significant 64 bits of a u128
    fn as_u64(self: u128) -> u64 {
        let (_, bottom_word) = u128_split(self);
        bottom_word
    }
}

#[generate_trait]
pub impl U256Impl of U256Trait {
    /// Splits an u256 into 4 little endian u64.
    /// Returns ((high_high, high_low),(low_high, low_low))
    fn split_into_u64_le(self: u256) -> ((u64, u64), (u64, u64)) {
        let low_le = u128_byte_reverse(self.low);
        let high_le = u128_byte_reverse(self.high);
        (u128_split(high_le), u128_split(low_le))
    }

    /// Reverse the endianness of an u256
    fn reverse_endianness(self: u256) -> u256 {
        let new_low = u128_byte_reverse(self.high);
        let new_high = u128_byte_reverse(self.low);
        u256 { low: new_low, high: new_high }
    }
}

pub trait BytesUsedTrait<T> {
    /// Returns the number of bytes used to represent a `T` value.
    /// # Arguments
    /// * `self` - The value to check.
    /// # Returns
    /// The number of bytes used to represent the value.
    fn bytes_used(self: T) -> u8;
}

pub impl U8BytesUsedTraitImpl of BytesUsedTrait<u8> {
    fn bytes_used(self: u8) -> u8 {
        if self == 0 {
            return 0;
        }

        return 1;
    }
}

pub impl USizeBytesUsedTraitImpl of BytesUsedTrait<usize> {
    fn bytes_used(self: usize) -> u8 {
        if self < 0x10000 { // 256^2
            if self < 0x100 { // 256^1
                if self == 0 {
                    return 0;
                } else {
                    return 1;
                };
            }
            return 2;
        } else {
            if self < 0x1000000 { // 256^3
                return 3;
            }
            return 4;
        }
    }
}

pub impl U64BytesUsedTraitImpl of BytesUsedTrait<u64> {
    fn bytes_used(self: u64) -> u8 {
        if self <= Bounded::<u32>::MAX.into() { // 256^4
            return BytesUsedTrait::<u32>::bytes_used(self.try_into().unwrap());
        } else {
            if self < 0x1000000000000 { // 256^6
                if self < 0x10000000000 {
                    if self < 0x100000000 {
                        return 4;
                    }
                    return 5;
                }
                return 6;
            } else {
                if self < 0x100000000000000 { // 256^7
                    return 7;
                } else {
                    return 8;
                }
            }
        }
    }
}

pub impl U128BytesTraitUsedImpl of BytesUsedTrait<u128> {
    fn bytes_used(self: u128) -> u8 {
        let (u64high, u64low) = u128_split(self);
        if u64high == 0 {
            return BytesUsedTrait::<u64>::bytes_used(u64low.try_into().unwrap());
        } else {
            return BytesUsedTrait::<u64>::bytes_used(u64high.try_into().unwrap()) + 8;
        }
    }
}

pub impl U256BytesUsedTraitImpl of BytesUsedTrait<u256> {
    fn bytes_used(self: u256) -> u8 {
        if self.high == 0 {
            return BytesUsedTrait::<u128>::bytes_used(self.low.try_into().unwrap());
        } else {
            return BytesUsedTrait::<u128>::bytes_used(self.high.try_into().unwrap()) + 16;
        }
    }
}

pub trait ByteSize<T> {
    fn byte_size() -> usize;
}

pub impl ByteSizeImpl<T, +BitSize<T>> of ByteSize<T> {
    fn byte_size() -> usize {
        BitSize::<T>::bits() / 8
    }
}

pub trait BitsUsed<T> {
    /// Returns the number of bits required to represent `self`, ignoring leading zeros.
    /// # Arguments
    /// `self` - The value to check.
    /// # Returns
    /// The number of bits used to represent the value, ignoring leading zeros.
    fn bits_used(self: T) -> u32;

    /// Returns the number of leading zeroes in the bit representation of `self`.
    /// # Arguments
    /// `self` - The value to check.
    /// # Returns
    /// The number of leading zeroes in the bit representation of `self`.
    fn count_leading_zeroes(self: T) -> u32;
}

pub impl BitsUsedImpl<
    T,
    +Zero<T>,
    +One<T>,
    +Add<T>,
    +Sub<T>,
    +Mul<T>,
    +Bitshift<T>,
    +BitSize<T>,
    +BytesUsedTrait<T>,
    +Into<u8, T>,
    +TryInto<T, u8>,
    +Copy<T>,
    +Drop<T>,
    +PartialEq<T>
> of BitsUsed<T> {
    fn bits_used(self: T) -> u32 {
        if self == Zero::zero() {
            return 0;
        }

        let bytes_used = self.bytes_used();
        let last_byte = self.shr(8_u32 * (bytes_used.into() - One::one()));

        // safe unwrap since we know at most 8 bits are used
        let bits_used: u8 = bits_used_internal::bits_used_in_byte(last_byte.try_into().unwrap());

        bits_used.into() + 8 * (bytes_used - 1).into()
    }

    fn count_leading_zeroes(self: T) -> u32 {
        BitSize::<T>::bits() - self.bits_used()
    }
}

pub(crate) mod bits_used_internal {
    /// Returns the number of bits used to represent the value in binary representation
    /// # Arguments
    /// * `self` - The value to compute the number of bits used
    /// # Returns
    /// * The number of bits used to represent the value in binary representation
    pub(crate) fn bits_used_in_byte(self: u8) -> u8 {
        if self < 0b100000 {
            if self < 0b1000 {
                if self < 0b100 {
                    if self < 0b10 {
                        if self == 0 {
                            return 0;
                        } else {
                            return 1;
                        };
                    }
                    return 2;
                }

                return 3;
            }

            if self < 0b10000 {
                return 4;
            }

            return 5;
        } else {
            if self < 0b10000000 {
                if self < 0b1000000 {
                    return 6;
                }
                return 7;
            }
            return 8;
        }
    }
}
