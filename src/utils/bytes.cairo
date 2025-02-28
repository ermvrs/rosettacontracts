use crate::constants::pow2;
pub const BYTES_PER_ELEMENT: usize = 16;

#[derive(Drop, Clone, PartialEq, Serde)]
pub struct Bytes {
    size: usize,
    data: Array<u128>,
}

pub trait BytesTrait {
    fn new(size: usize, data: Array<u128>) -> Bytes;
    fn blank() -> Bytes;
    fn zero(size: usize) -> Bytes;
    fn locate(offset: usize) -> (usize, usize);
    fn size(self: @Bytes) -> usize;
    fn data(self: Bytes) -> Array<u128>;
    fn read_u32(self: @Bytes, offset: usize) -> (usize, u32);
    fn read_u128(self: @Bytes, offset: usize) -> (usize, u128);
    fn read_u256(self: @Bytes, offset: usize) -> (usize, u256);
    fn read_u128_packed(self: @Bytes, offset: usize, size: usize) -> (usize, u128);
    fn read_bytes(self: @Bytes, offset: usize, size: usize) -> (usize, Bytes);
    fn append_u32(ref self: Bytes, value: u32);
    fn append_u128(ref self: Bytes, value: u128);
    fn append_u256(ref self: Bytes, value: u256);
    fn append_u128_packed(ref self: Bytes, value: u128, size: usize);
}

impl BytesImpl of BytesTrait {
    #[inline(always)]
    fn new(size: usize, data: Array::<u128>) -> Bytes {
        Bytes { size, data }
    }

    #[inline(always)]
    fn blank() -> Bytes {
        Bytes { size: 0_usize, data: array![] }
    }

    fn zero(size: usize) -> Bytes {
        let mut data = array![];
        let (data_index, mut data_len) = DivRem::div_rem(
            size, BYTES_PER_ELEMENT.try_into().expect('Division by 0'),
        );

        if data_index != 0 {
            data_len += 1;
        }

        while data_len != 0 {
            data.append(0_u128);
            data_len -= 1;
        };

        Bytes { size, data }
    }

    #[inline(always)]
    fn locate(offset: usize) -> (usize, usize) {
        DivRem::div_rem(offset, BYTES_PER_ELEMENT.try_into().expect('Division by 0'))
    }

    #[inline(always)]
    fn size(self: @Bytes) -> usize {
        *self.size
    }

    fn data(self: Bytes) -> Array<u128> {
        self.data
    }

    #[inline(always)]
    fn read_u32(self: @Bytes, offset: usize) -> (usize, u32) {
        let (new_offset, value) = self.read_u128_packed(offset, 4);
        (new_offset, value.try_into().unwrap())
    }

    #[inline(always)]
    fn read_u128(self: @Bytes, offset: usize) -> (usize, u128) {
        self.read_u128_packed(offset, 16)
    }

    #[inline(always)]
    fn read_u256(self: @Bytes, offset: usize) -> (usize, u256) {
        // check
        println!("{:}", offset);
        assert(offset + 32 <= self.size(), 'out of bound');

        let (new_offset, high) = self.read_u128(offset);
        let (new_offset, low) = self.read_u128(new_offset);

        (new_offset, u256 { low, high })
    }

    fn read_u128_packed(self: @Bytes, offset: usize, size: usize) -> (usize, u128) {
        // check
        assert(offset + size <= self.size(), 'out of bound');
        assert(size <= 16, 'too large');

        // check value in one element or two
        // if value in one element, just read it
        // if value in two elements, read them and join them
        let (element_index, element_offset) = Self::locate(offset);
        let value_in_one_element = element_offset + size <= BYTES_PER_ELEMENT;
        let value = if value_in_one_element {
            read_sub_u128(*self.data[element_index], BYTES_PER_ELEMENT, element_offset, size)
        } else {
            let (_, end_element_offset) = Self::locate(offset + size);
            let left = read_sub_u128(
                *self.data[element_index],
                BYTES_PER_ELEMENT,
                element_offset,
                BYTES_PER_ELEMENT - element_offset,
            );
            let right = read_sub_u128(
                *self.data[element_index + 1], BYTES_PER_ELEMENT, 0, end_element_offset,
            );
            u128_join(left, right, end_element_offset)
        };
        (offset + size, value)
    }

    fn read_bytes(self: @Bytes, offset: usize, size: usize) -> (usize, Bytes) {
        // check
        assert(offset + size <= self.size(), 'out of bound');

        if size == 0 {
            return (offset, Self::blank());
        }

        let mut array = array![];

        // read full array element for sub_bytes
        let mut offset = offset;
        let mut sub_bytes_full_array_len = size / BYTES_PER_ELEMENT;
        while sub_bytes_full_array_len != 0 {
            let (new_offset, value) = self.read_u128(offset);
            array.append(value);
            offset = new_offset;
            sub_bytes_full_array_len -= 1;
        };

        // process last array element for sub_bytes
        // 1. read last element real value;
        // 2. make last element full with padding 0;
        let sub_bytes_last_element_size = size % BYTES_PER_ELEMENT;
        if sub_bytes_last_element_size > 0 {
            let (new_offset, value) = self.read_u128_packed(offset, sub_bytes_last_element_size);
            let padding = BYTES_PER_ELEMENT - sub_bytes_last_element_size;
            let value = u128_join(value, 0, padding);
            array.append(value);
            offset = new_offset;
        }

        return (offset, Self::new(size, array));
    }

    #[inline(always)]
    fn append_u32(ref self: Bytes, value: u32) {
        self.append_u128_packed(value.into(), 4)
    }

    #[inline(always)]
    fn append_u128(ref self: Bytes, value: u128) {
        self.append_u128_packed(value, 16)
    }

    #[inline(always)]
    fn append_u256(ref self: Bytes, value: u256) {
        self.append_u128(value.high);
        self.append_u128(value.low);
    }

    fn append_u128_packed(ref self: Bytes, value: u128, size: usize) {
        assert(size <= 16, 'size must be less than 16');

        let Bytes { size: old_bytes_size, mut data } = self;
        let (last_data_index, last_element_size) = Self::locate(old_bytes_size);

        if last_element_size == 0 {
            let padded_value = u128_join(value, 0, BYTES_PER_ELEMENT - size);
            data.append(padded_value);
        } else {
            let (last_element_value, _) = u128_split(*data[last_data_index], 16, last_element_size);
            data = u128_array_slice(@data, 0, last_data_index);
            if size + last_element_size > BYTES_PER_ELEMENT {
                let (left, right) = u128_split(value, size, BYTES_PER_ELEMENT - last_element_size);
                let value_full = u128_join(
                    last_element_value, left, BYTES_PER_ELEMENT - last_element_size,
                );
                let value_padded = u128_join(
                    right, 0, 2 * BYTES_PER_ELEMENT - size - last_element_size,
                );
                data.append(value_full);
                data.append(value_padded);
            } else {
                let value = u128_join(last_element_value, value, size);
                let value_padded = u128_join(
                    value, 0, BYTES_PER_ELEMENT - size - last_element_size,
                );
                data.append(value_padded);
            }
        }
        self = Bytes { size: old_bytes_size + size, data }
    }
}

pub fn read_sub_u128(value: u128, value_size: usize, offset: usize, size: usize) -> u128 {
    assert(offset + size <= value_size, 'too long');

    if (value_size == 0) || (size == 0) {
        return 0;
    }

    if size == value_size {
        return value;
    }

    let (_, right) = u128_split(value, value_size, offset);
    let (sub_value, _) = u128_split(right, value_size - offset, size);
    sub_value
}

pub fn u128_join(left: u128, right: u128, right_size: usize) -> u128 {
    let left_size = u128_bytes_len(left);
    assert(left_size + right_size <= 16, 'left shift overflow');
    let shift = pow2(right_size * 8);
    left * shift + right
}

fn u128_bytes_len(value: u128) -> usize {
    if value <= 0xff_u128 {
        1_usize
    } else if value <= 0xffff_u128 {
        2_usize
    } else if value <= 0xffffff_u128 {
        3_usize
    } else if value <= 0xffffffff_u128 {
        4_usize
    } else if value <= 0xffffffffff_u128 {
        5_usize
    } else if value <= 0xffffffffffff_u128 {
        6_usize
    } else if value <= 0xffffffffffffff_u128 {
        7_usize
    } else if value <= 0xffffffffffffffff_u128 {
        8_usize
    } else if value <= 0xffffffffffffffffff_u128 {
        9_usize
    } else if value <= 0xffffffffffffffffffff_u128 {
        10_usize
    } else if value <= 0xffffffffffffffffffffff_u128 {
        11_usize
    } else if value <= 0xffffffffffffffffffffffff_u128 {
        12_usize
    } else if value <= 0xffffffffffffffffffffffffff_u128 {
        13_usize
    } else if value <= 0xffffffffffffffffffffffffffff_u128 {
        14_usize
    } else if value <= 0xffffffffffffffffffffffffffffff_u128 {
        15_usize
    } else {
        16_usize
    }
}

pub fn u128_split(value: u128, value_size: usize, left_size: usize) -> (u128, u128) {
    assert(value_size <= 16, 'value_size can not be gt 16');
    assert(left_size <= value_size, 'size can not be gt value_size');

    if left_size == 0 {
        (0, value)
    } else {
        let power = pow2((value_size - left_size) * 8);
        DivRem::div_rem(value, power.try_into().expect('Division by 0'))
    }
}

pub fn u128_array_slice(src: @Array<u128>, mut begin: usize, len: usize) -> Array<u128> {
    let mut slice = array![];
    let end = begin + len;
    while begin < end && begin < src.len() {
        slice.append(*src[begin]);
        begin += 1;
    };
    slice
}
